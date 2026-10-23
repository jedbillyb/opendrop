"""
OpenDrop: an open source AirDrop implementation
Copyright (C) 2018  Milan Stute
Copyright (C) 2018  Alexander Heinrich

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import io
import json
import logging
import mmap
import os
import platform
import plistlib
import socket
import struct
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import libarchive
import libarchive.extract
import libarchive.read
from zeroconf import DNSOutgoing, IPVersion, ServiceInfo, Zeroconf, const

from .util import AirDropUtil

logger = logging.getLogger(__name__)

# AirDrop carries a shared link in the /Ask body's "Items" array rather than as
# a file, so a link arrives with an empty "Files" and never touches /Upload.
# Everything about links lives in these two helpers.
URL_SCHEMES = ("http://", "https://")


def ask_items(req):
    """URLs from an /Ask body. Empty for a normal file transfer."""
    items = req.get("Items") or []
    out = []
    for item in items:
        # iOS sends plain strings; be tolerant of a dict wrapper anyway, since
        # a shape we do not recognise should degrade to "no links", never to a
        # crash inside the consent path.
        if isinstance(item, bytes):
            item = item.decode("utf-8", "replace")
        elif isinstance(item, dict):
            item = item.get("URL") or item.get("url") or ""
        if isinstance(item, str) and item.lower().startswith(URL_SCHEMES):
            out.append(item)
    return out


def open_url(url):
    """
    Hand a received link to AIRDROP_URL_HOOK, or to xdg-open if unset.

    Detached deliberately: the /Ask response is what tells the phone the share
    succeeded, and blocking it on a browser start would stall the transfer and
    time the sender out.
    """
    import shutil
    import subprocess

    hook = os.environ.get("AIRDROP_URL_HOOK") or shutil.which("xdg-open")
    if not hook:
        logger.warning("received link %s but no AIRDROP_URL_HOOK and no xdg-open", url)
        return
    try:
        subprocess.Popen(
            [hook, url],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("opened received link: %s", url)
    except Exception as e:
        logger.error("could not open received link %s (%s)", url, e)


class AirDropServer:
    """
    Announces an HTTPS AirDrop server in the local network via mDNS.
    """

    def __init__(self, config):
        self.config = config

        # Use IPv6
        self.serveraddress = ("::", self.config.port)
        self.ServerClass = HTTPServerV6
        self.ServerClass.allow_reuse_address = False

        self.ip_addr = AirDropUtil.get_ip_for_interface(
            self.config.interface, ipv6=True
        )
        if self.ip_addr is None:
            if self.config.interface == "awdl0":
                raise RuntimeError(
                    f"Interface {self.config.interface} does not have an IPv6 address. Make sure that `owl` is running."
                )
            else:
                raise RuntimeError(
                    f"Interface {self.config.interface} does not have an IPv6 address"
                )

        self.Handler = AirDropServerHandler
        self.Handler.config = self.config

        self.zeroconf = Zeroconf(
            interfaces=[str(self.ip_addr)],
            ip_version=IPVersion.V6Only,
            apple_p2p=platform.system() == "Darwin",
        )

        self.http_server = self._init_server()
        self.service_info = self._init_service()

    def _init_service(self):
        properties = self.get_properties()
        server = self.config.host_name + ".local."
        service_name = self.config.service_id + "._airdrop._tcp.local."
        info = ServiceInfo(
            "_airdrop._tcp.local.",
            service_name,
            port=self.config.port,
            properties=properties,
            server=server,
            addresses=[self.ip_addr.packed],
        )
        return info

    def start_service(self):
        logger.info(
            f"Announcing service: host {self.config.host_name}, address {self.ip_addr}, port {self.config.port}"
        )
        self.zeroconf.register_service(self.service_info)
        self._start_repeat_announce()

    def _start_repeat_announce(self):
        """
        Re-send the unsolicited announcement at a fixed interval.

        python-zeroconf announces at registration and then goes quiet, and the
        iPhone does not poll for AirDrop receivers - it only ever learns we
        exist by catching an announce burst. Over AWDL that burst also has to
        survive a link we are only co-channel on for a fraction of each 1.048 s
        sequence, so a single burst at startup is routinely missed outright.

        The daemon used to get this effect by killing opendrop every 30 s and
        letting it re-register, which deregistered the service and dropped the
        HTTPS server for ~1.5 s each cycle - the receiver visibly appeared and
        vanished on the phone's share sheet on a 30 s period, and any transfer
        starting near the boundary lost its socket. Re-sending the records here
        keeps both the registration and the listener up the whole time.
        """
        interval = float(os.environ.get("OPENDROP_ANNOUNCE_INTERVAL", "5"))
        if interval <= 0:
            return
        self._announce_stop = threading.Event()

        def loop():
            while not self._announce_stop.wait(interval):
                try:
                    info = self.service_info
                    out = DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA)
                    for record in (
                        [info.dns_pointer(), info.dns_service(), info.dns_text()]
                        + list(info.dns_addresses())
                    ):
                        out.add_answer_at_time(record, 0)
                    self.zeroconf.send(out)
                except Exception as e:  # a failed burst must not end the loop
                    logger.debug(f"repeat announce failed: {e}")

        self._announce_thread = threading.Thread(
            target=loop, name="airdrop-repeat-announce", daemon=True
        )
        self._announce_thread.start()
        logger.debug(f"re-announcing _airdrop._tcp every {interval}s")

    def stop_repeat_announce(self):
        stop = getattr(self, "_announce_stop", None)
        if stop is not None:
            stop.set()
            self._announce_stop = None

    def _init_server(self):
        try:
            httpd = self.ServerClass(self.serveraddress, self.Handler)
        except OSError:
            # Address in use. Change port
            self.config.port = self.config.port + 1
            self.serveraddress = (self.serveraddress[0], self.config.port)
            httpd = self.ServerClass(self.serveraddress, self.Handler)

        # Adapt socket for awdl0
        if self.config.interface == "awdl0" and platform.system() == "Darwin":
            httpd.socket.setsockopt(socket.SOL_SOCKET, 0x1104, 1)

        httpd.socket = self.config.get_ssl_context().wrap_socket(
            sock=httpd.socket, server_side=True
        )

        return httpd

    def start_server(self):
        logger.info("Starting HTTPS server")
        self.http_server.serve_forever()

    def stop(self):
        self.zeroconf.unregister_all_services()
        self.http_server.shutdown()

    def get_properties(self):
        properties = {b"flags": str(self.config.flags).encode("utf-8")}
        return properties

        # Pin a large receive buffer, inherited by accepted connections.
        #
        # AWDL delivers in ~68 ms bursts separated by ~450 ms of silence, so a
        # connection gets only a couple of round trips per second. That makes the
        # kernel's receive-window recovery pathologically slow: measured on a real
        # transfer, the advertised window opened at 64766 B, collapsed to 528 B in
        # a single step when the sender's opening burst outran our first read(),
        # and then took ~40 s to crawl back to 10 kB - longer than the whole
        # transfer. Throughput was pinned at ~45 kB/s the entire time.
        #
        # A large fixed buffer means the opening burst cannot overrun us, so
        # rcv_ssthresh never collapses and never has to recover. Setting
        # SO_RCVBUF also disables autotuning, which is what we want here: the
        # kernel's bandwidth estimate is meaningless on a link this bursty.
        # The kernel clamps this to net.core.rmem_max and doubles what we ask for.
        try:
            httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            logger.debug(
                f"SO_RCVBUF = {httpd.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)} B"
            )
        except OSError as e:
            logger.warning(f"Could not enlarge the receive buffer ({e})")

class HTTPServerV6(ThreadingHTTPServer):
    """
    One thread per connection. This MUST NOT be the stock single-threaded
    HTTPServer: iOS sends `Connection: keep-alive` and then holds the
    connection open idle, so a single-threaded server stays parked in
    handle_one_request() on that socket and never returns to accept(). The
    next connection - the one actually carrying the file - then sits unread
    in the kernel queue forever, which the phone shows as "Waiting...".

    Observed exactly that: an established socket on 8771 with Recv-Q 1496
    while opendrop had logged nothing for twelve minutes. It is also the same
    single-thread bottleneck that let one slow consent prompt fill the listen
    backlog with iOS's validation connects and get us dropped from the share
    sheet; threading removes the whole class of stall.

    daemon_threads so a hung handler cannot keep the process alive on exit.
    """

    address_family = socket.AF_INET6
    daemon_threads = True


class AirDropServerHandler(BaseHTTPRequestHandler):
    """
    Server which responds to AirDrop HTTP POST requests
    """

    protocol_version = "HTTP/1.1"
    config = None

    # A timeout on EVERY socket read, not only on an upload body.
    #
    # handle_ask reads the request body BEFORE calling the consent hook: when
    # the phone's AWDL goes to sleep at exactly that moment, the read blocks
    # forever, no prompt is offered, nothing is logged, and the phone
    # eventually shows a refusal. Observed live on an /Ask left unanswered.
    # socketserver applies this attribute to each request's socket, so it
    # covers /Discover and /Ask as much as /Upload.
    timeout = float(os.environ.get("AIRDROP_STALL_TIMEOUT", "30"))

    def _set_response(self, content_length):
        """
        Setting the default values for a successful response
        """
        self.send_response(200)
        self.send_header("Content-Length", content_length)
        self.end_headers()

    def do_HEAD(self):
        """
        Answer head requests
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """
        Answer get requests
        """
        logger.debug(f"GET request at {self.path}")
        body = "\n".encode("utf-8")
        self._set_response(len(body))
        self.wfile.write(body)

    def _read_request_body(self):
        """
        Read a request body sent either with Content-Length or chunked.

        iOS 26 sends Discover and Ask with `Transfer-Encoding: chunked` and no
        Content-Length, which made `int(self.headers["Content-Length"])` raise
        TypeError on None and kill the connection before any reply was written.
        handle_upload already coped with chunked; these two paths did not.
        """
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            body = b""
            while True:
                length = int(self.rfile.readline().rstrip() or b"0", 16)
                if length == 0:
                    self.rfile.readline()  # trailing CRLF of the final chunk
                    break
                body += self.rfile.read(length)
                self.rfile.readline()  # CRLF after each chunk
            return body
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def handle_discover(self):
        post_data = self._read_request_body()

        AirDropUtil.write_debug(
            self.config, post_data, "receive_discover_request.plist"
        )

        # sample media capabilities as recorded from macOS 10.13.3
        media_capabilities = {
            "Version": 1,
            # don't advertise any codec/container support so we receive legacy file formats (JPEG instead of HEIF, etc.)
            # 'Codecs': {
            #     'hvc1': {
            #         'Profiles': {
            #             'VTPerProfileSupport': {
            #                 '1': {'VTMaxPlaybackLevel': 120},
            #                 '2': {'VTMaxPlaybackLevel': 120},
            #                 '3': {}
            #             },
            #             'VTSupportedProfiles': [1, 2, 3]
            #         }
            #     }
            # },
            # 'ContainerFormats': {
            #     'public.heif-standard': {
            #         'HeifSubtypes': ['public.avci', 'public.heic', 'public.heif']
            #     }
            # },
            # 'Vendor': {
            #     'com.apple': {
            #         'OSVersion': [10, 13, 3],
            #         'OSBuildVersion': '17D102',
            #         'LivePhotoFormatVersion': '1'
            #     }
            # }
        }
        media_capabilities_json = json.JSONEncoder().encode(media_capabilities)
        media_capabilities_binary = media_capabilities_json.encode("utf-8")
        discover_answer = {
            "ReceiverMediaCapabilities": media_capabilities_binary,
            "ReceiverComputerName": self.config.computer_name,
            "ReceiverModelName": self.config.computer_model,
        }
        if self.config.record_data:
            discover_answer["ReceiverRecordData"] = self.config.record_data

        discover_answer_binary = plistlib.dumps(
            discover_answer, fmt=plistlib.FMT_BINARY  # pylint: disable=no-member
        )

        AirDropUtil.write_debug(
            self.config, discover_answer_binary, "receive_discover_response.plist"
        )

        # Change to actual length
        self._set_response(len(discover_answer_binary))
        self.wfile.write(discover_answer_binary)

    # The confirmation hook. opendrop 0.13.0 accepts every /Ask
    # unconditionally: it returns 200 with the machine name, with no prompt and
    # no extension point. That is survivable for a harness a human launches for
    # one transfer, and unacceptable for an always-on receiver, where it means
    # anyone in range with AirDrop set to Everyone can write files to the
    # machine unattended and unlogged.
    #
    # AIRDROP_CONFIRM names a program that is asked. Non-zero exit refuses the
    # transfer with 403 and the phone shows "Declined". If the variable is
    # unset, behaviour is unchanged from upstream, so the research harness and
    # every existing FINDINGS run are unaffected.
    #
    # It fails CLOSED: if the hook cannot be run at all, the answer is no. An
    # unaskable question is not consent, and this is the one place where
    # guessing wrong hands a stranger a write primitive.
    def _ask_user(self, post_data):
        hook = os.environ.get("AIRDROP_CONFIRM")
        if not hook:
            return True
        sender = "unknown sender"
        detail = ""
        try:
            req = plistlib.loads(post_data)
            sender = req.get("SenderComputerName") or req.get(
                "SenderPseudonym") or sender
            files = req.get("Files") or []
            names = [f.get("FileName", "?") for f in files if isinstance(f, dict)]
            if names:
                detail = ", ".join(names[:3])
                if len(names) > 3:
                    detail += f" (+{len(names) - 3} more)"
            elif ask_items(req):
                # A link share carries no Files at all, so without this the
                # prompt would say "accept 0 files" and the user would have no
                # idea what they were agreeing to open.
                urls = ask_items(req)
                detail = urls[0] if len(urls) == 1 else f"{urls[0]} (+{len(urls) - 1} more)"
        except Exception:
            # A malformed body is exactly when we least want to auto-accept,
            # but it is also not a reason to crash - fall through and ask with
            # whatever we managed to learn.
            logger.warning("could not parse /Ask body; asking anyway")
        try:
            import subprocess
            rc = subprocess.call([hook, str(sender), str(detail)])
        except Exception as e:
            logger.error("confirm hook %s failed to run (%s) - DECLINING", hook, e)
            return False
        if rc != 0:
            logger.info("user declined transfer from %s", sender)
            return False
        logger.info("user accepted transfer from %s", sender)
        return True

    def handle_ask(self):
        try:
            post_data = self._read_request_body()
        except (socket.timeout, TimeoutError):
            # Without this the exception escapes into the request thread: the
            # phone gets nothing and the user never sees the prompt at all.
            #
            # And returning is not enough: with no status and no close, a
            # keep-alive connection is left open, the handler stays busy
            # waiting for a following request until another timeout, and the
            # phone never learns it was refused. So terminate explicitly.
            logger.warning("sender went quiet during /Ask - no prompt shown")
            try:
                self.send_response(408)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
            except OSError:
                pass
            self.close_connection = True
            return

        AirDropUtil.write_debug(self.config, post_data, "receive_ask_request.plist")

        if not self._ask_user(post_data):
            self.send_response(403)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return

        # A shared link never reaches /Upload - iOS puts it in the /Ask body's
        # "Items" and considers the transfer done the moment we answer 200. So
        # this is the only place a URL can be delivered from, and doing it
        # after the consent check means a declined share opens nothing.
        try:
            urls = ask_items(plistlib.loads(post_data))
        except Exception:
            urls = []
        for url in urls:
            open_url(url)

        ask_response = {
            "ReceiverModelName": self.config.computer_model,
            "ReceiverComputerName": self.config.computer_name,
        }
        ask_resp_binary = plistlib.dumps(
            ask_response, fmt=plistlib.FMT_BINARY  # pylint: disable=no-member
        )

        AirDropUtil.write_debug(
            self.config, ask_resp_binary, "receive_ask_response.plist"
        )

        self._set_response(len(ask_resp_binary))
        self.wfile.write(ask_resp_binary)

    # iOS 26 sends photos as application/x-dvzip, not the application/x-cpio
    # OpenDrop 0.13.0 hardcodes. Everything else about the transfer is identical,
    # and libarchive detects the container from the stream anyway, so the only
    # thing the old check accomplished was a 406 after the user had already
    # tapped send - which is exactly what the phone reported as "Failed".
    UPLOAD_CONTENT_TYPES = ("application/x-cpio", "application/x-dvzip")

    def handle_upload(self):
        if self.headers.get("content-type", "").lower() not in self.UPLOAD_CONTENT_TYPES:
            logger.warning(
                f"Unsupported content-type: {self.headers.get('content-type')}"
            )
            self.send_response(406)  # Unprocessable Entity
            self.send_header("Content-Type", "application/x-cpio")
            self.send_header("Content-Length", 0)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        if self.headers.get("transfer-encoding", "").lower() != "chunked":
            logger.warning("Expect chunked transfer encoding")
            self.send_response(400)  # Bad Request
            self.send_header("Transfer-Encoding", "Chunked")
            self.send_header("Content-Length", 0)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        class HTTPChunkedReader(io.RawIOBase):
            def __init__(self, rfile, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.rfile = rfile
                self.chunk = None
                self.total = 0

            def _next_chunk(self):
                if self.chunk is None or len(self.chunk) == 0:
                    length = int(self.rfile.readline().rstrip(), 16)
                    self.chunk = self.rfile.read(length)
                    self.rfile.readline()  # strip trailing \n\r

            def readinto(self, buf):
                self._next_chunk()
                length = min(len(self.chunk), len(buf))
                buf[:length] = self.chunk[:length]
                self.chunk = self.chunk[length:]
                self.total += length
                return length

        def extract_stream(stream, flags=0):
            """
            Extracts an archive from memory into the current directory.
            """

            with libarchive.read.stream_reader(stream) as archive:
                libarchive.extract.extract_entries(archive, flags)

        def dvzip_to_cpio(path):
            """
            Decode Apple's dvzip container into the cpio archive inside it.

            iOS 26 wraps the cpio in a sequence of length-prefixed blocks, which
            libarchive does not recognise ("Unrecognized archive format"):

                [4-byte big-endian header][block payload] ...

            Bit 31 of the header means the payload is STORED; otherwise it is a
            zlib stream. The low 31 bits are the payload length. Blocks
            decompress to 128 KiB each except the last. Verified against a
            2.06 MB photo transfer: 17 blocks, whole file consumed exactly,
            yielding an ODC cpio ("070707") holding IMG_8276.JPG.
            """
            out = bytearray()
            with open(path, "rb") as f:
                while True:
                    header = f.read(4)
                    if len(header) < 4:
                        break
                    (raw,) = struct.unpack(">I", header)
                    stored = raw >> 31
                    length = raw & 0x7FFFFFFF
                    if length == 0:
                        break
                    payload = f.read(length)
                    if len(payload) < length:
                        # A truncated block is NOT a lost file. Measured over
                        # 17 interrupted transfers: 9 of them already held the
                        # complete cpio and had lost only the container's
                        # terminator - the extracted JPEG matched the sender's
                        # sha256 exactly. Raising here therefore threw whole
                        # files away. Keep what arrived and let extraction
                        # decide what is usable.
                        logger.warning(
                            f"dvzip block truncated (wanted {length}, got "
                            f"{len(payload)}) - salvaging what arrived")
                        if stored:
                            out += payload
                        else:
                            try:
                                out += zlib.decompressobj().decompress(payload)
                            except zlib.error as exc:
                                logger.warning(f"  tail block unusable ({exc})")
                        break
                    out += payload if stored else zlib.decompress(payload)
            return bytes(out)

        logger.info("Receiving file(s) ...")
        start = time.time()
        reader = HTTPChunkedReader(self.rfile)

        # Buffer to disk first, then extract. Extracting straight off the socket
        # means a container libarchive cannot parse leaves us with a half-read
        # stream and nothing to show for it - and x-dvzip is new enough here that
        # it is worth keeping the bytes regardless. The raw archive is only
        # removed once extraction has actually succeeded.
        raw_path = os.path.join(
            os.getcwd(), f"airdrop-received-{int(start)}.{'dvzip' if 'dvzip' in self.headers.get('content-type', '') else 'cpio'}"
        )
        with open(raw_path, "wb") as raw:
            # Only now tell the sender to go ahead. Upstream answered
            # 'Expect: 100-continue' before the chunked check, the reader and this
            # open() - so the phone began transmitting while we were still getting
            # ready, and its opening burst collapsed our receive window (see the
            # SO_RCVBUF note in create_server). Answering once we are genuinely
            # ready to read costs nothing and removes that race.
            if self.headers.get("expect", "").lower() == "100-continue":
                self.send_response(100)
                self.send_header("Content-Length", 0)
                self.end_headers()

            # A read timeout. _next_chunk blocked in readline() with no
            # deadline: when the phone stops transmitting - which happens near
            # the end, regularly, on this link - the loop never ended, the
            # `with` never closed, and even the bytes already received stayed
            # in the write buffer. The value is wide compared to the measured
            # AWDL jitter (RTT ~400 ms, bursts ~450 ms apart) so that a merely
            # slow transfer is not cut off.
            stall = float(os.environ.get("AIRDROP_STALL_TIMEOUT", "30"))
            floor = float(os.environ.get("AIRDROP_STALL_FLOOR", "8"))

            # THE TIMEOUT FOLLOWS THE LINK'S RHYTHM; it is not a constant.
            #
            # A flat 30 s is added to EVERY salvaged transfer: of one measured
            # 43 s transfer, thirty were spent waiting on a sender that had
            # already gone quiet. But it cannot simply be shortened - the link
            # delivers in bursts, and cutting off a slow transfer would be
            # worse than waiting.
            #
            # First attempt, abandoned: trigger a short tier once close to
            # TotalBytes. That assumes the sender always stops at the edge,
            # which is false - measured, stops range from 440 bytes to 943,642
            # bytes short, 0.03% to 24%. No threshold covers both.
            #
            # So it no longer guesses where the end is: it watches the gap
            # between successful reads and waits a large multiple of the worst
            # gap seen so far. A steady link drops to the floor within
            # seconds; a choppy one lets the timeout climb on its own. The
            # floor stays ten times above the measured burst spacing (~450 ms,
            # 772 ms jitter), and the ceiling is the old value, so it can
            # never wait LONGER than before.
            _arm = lambda sec: self.connection.settimeout(sec)
            try:
                _arm(stall)
            except OSError:
                _arm = lambda sec: None

            armed = stall
            worst = 0.0
            last = time.monotonic()
            try:
                while True:
                    buf = reader.read(65536)
                    if not buf:
                        break
                    raw.write(buf)

                    now = time.monotonic()
                    gap, last = now - last, now
                    if gap > worst:
                        worst = gap
                        want = min(max(worst * 6.0, floor), stall)
                        # Only re-arm on a real change: calling settimeout on
                        # every 64 KiB block would be one syscall per block for
                        # nothing.
                        if abs(want - armed) > 0.5:
                            try:
                                _arm(want)
                            except OSError:
                                pass
                            armed = want
            except (socket.timeout, TimeoutError):
                logger.warning(
                    f"sender went quiet for {armed:.0f}s after {reader.total} B "
                    f"(worst gap seen {worst:.1f}s) - salvaging what arrived")
            except (ConnectionResetError, ValueError) as exc:
                logger.warning(f"upload stream broke ({exc}) - salvaging")
            finally:
                raw.flush()
                os.fsync(raw.fileno())

        def odc_members(cpio):
            """(name, data_is_complete, is_regular) for each ODC cpio member.

            ODC header: 76 fixed-width ASCII bytes, then the name (namesize,
            NUL included), then the data (filesize), all octal. The structure
            is walked by hand because libarchive ZERO-PADS a truncated member
            out to its declared size: measured, a JPEG handed back at exactly
            the right length ended in 949,265 null bytes with no end marker.
            Comparing sizes therefore detects nothing at all - only the bytes
            actually being present in the archive proves anything.
            """
            out, off, n = [], 0, len(cpio)
            while off + 76 <= n:
                if cpio[off:off + 6] != b"070707":
                    break
                try:
                    # ODC fields sit at fixed offsets: magic(6) dev(6) ino(6)
                    # mode(6) ... namesize at 59, filesize at 65.
                    mode = int(cpio[off + 18:off + 24], 8)
                    namesize = int(cpio[off + 59:off + 65], 8)
                    filesize = int(cpio[off + 65:off + 76], 8)
                except ValueError:
                    break
                # These fields come from the network. int(..., 8) accepts a
                # leading minus, and a negative filesize leaves `off` where it
                # was: the loop then spins forever IN THE REQUEST THREAD, on a
                # file crafted for it. A zero namesize does not advance either.
                if namesize <= 0 or filesize < 0:
                    break
                name_off = off + 76
                name = cpio[name_off:name_off + namesize].split(b"\0")[0]
                name = name.decode("utf-8", "replace")
                data_off = name_off + namesize
                if name == "TRAILER!!!":
                    break
                # The mode matters. An iOS archive starts with the WRAPPER
                # DIRECTORY, which has no data and is therefore always
                # "complete" - even in a transfer cut off at the first block.
                # Without this filter that directory alone was enough to make
                # the list of valid members non-empty, and so to have the raw
                # bytes deleted when not one file had been recovered. That is
                # the .partial guarantee falling over.
                regular = (mode & 0o170000) == 0o100000
                out.append((name, data_off + filesize <= n, regular))
                off = data_off + filesize
            return out

        def verify_extracted(cpio_bytes):
            """Separate what arrived whole from what did not.

            Incomplete members get a .partial suffix: silently delivering a
            half-empty photo that still opens would be worse than an honest
            failure.
            """
            good, bad = [], []
            for name, complete, regular in odc_members(cpio_bytes):
                base = os.path.basename(name)
                if not base or base == "." or base.startswith("._"):
                    continue
                if not regular:
                    continue   # wrapper directory: proves nothing
                # The member name is chosen by the peer. Joined as is, a
                # ../../ escapes the receive directory - and that path reaches
                # os.replace() below, so an arbitrary file of the user's would
                # be renamed. Resolve it and require the result to stay under
                # the current directory.
                root = os.path.realpath(os.getcwd())
                path = os.path.realpath(os.path.join(root, name))
                if path != root and not path.startswith(root + os.sep):
                    logger.warning(f"refusing member outside the receive dir: {name}")
                    continue
                if not os.path.exists(path):
                    continue
                if complete:
                    good.append(base)
                else:
                    bad.append(base)
                    try:
                        os.replace(path, path + ".partial")
                    except OSError:
                        pass
            return good, bad

        try:
            if raw_path.endswith(".dvzip"):
                cpio_bytes = dvzip_to_cpio(raw_path)
                try:
                    libarchive.extract_memory(cpio_bytes)
                except Exception as e:  # noqa: BLE001
                    # A truncated archive raises AFTER writing the complete
                    # members, so nothing already on disk is lost.
                    logger.warning(f"archive ended early ({e}) - checking what landed")
                good, bad = verify_extracted(cpio_bytes)
                if bad:
                    logger.warning(f"incomplete, kept as .partial: {', '.join(bad)}")
                if not good:
                    raise ValueError("no complete file in the transfer")
                logger.info(f"Extracted into {os.getcwd()}: {', '.join(good)}")
                os.remove(raw_path)
            else:
                # THE SAME VERIFICATION AS FOR dvzip. This path used to extract
                # and then delete the raw bytes without checking anything - and
                # libarchive zero-pads a truncated member here too, so an
                # interrupted cpio came out "successful" with a file full of
                # zeros and its source destroyed. The .partial guarantee only
                # held for dvzip.
                #
                # The extraction failure stays LOCAL: on a cut archive
                # libarchive can raise after writing whole members, and letting
                # that reach the outer handler left those files unclassified -
                # so incomplete ones were never renamed .partial. Verify in
                # every case.
                try:
                    with open(raw_path, "rb") as raw:
                        extract_stream(raw)
                except Exception as exc:  # noqa: BLE001 - verification decides
                    logger.warning(f"archive ended early ({exc}) - checking what landed")

                # x-cpio uploads are GZIP-COMPRESSED - opendrop's own sender
                # builds them with filter_name="gzip". Walking the raw bytes
                # for the ODC magic therefore finds nothing, `good` comes back
                # empty, and a perfectly good transfer is reported as "no
                # complete file" with its raw file kept beside the extracted
                # ones. Decompress first when the gzip magic is there.
                #
                # mmap rather than read() on the uncompressed path: it used to
                # stream, and loading it whole doubled the footprint on a 45 MB
                # video. odc_members only ever slices, so a mapping is enough.
                with open(raw_path, "rb") as fh:
                    size = os.fstat(fh.fileno()).st_size
                    if not size:
                        good, bad = [], []
                    elif fh.read(2) == b"\x1f\x8b":
                        # Not GzipFile.read(): on a cut-off transfer the gzip
                        # stream is truncated too, and read() raises EOFError.
                        # That skipped verification entirely, so the
                        # zero-padded members libarchive had written were never
                        # renamed .partial. A raw decompressobj returns every
                        # byte that did arrive without raising, and
                        # odc_members already reads a short buffer as
                        # incomplete members.
                        fh.seek(0)
                        gz = zlib.decompressobj(16 + zlib.MAX_WBITS)
                        good, bad = verify_extracted(gz.decompress(fh.read()))
                    else:
                        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as cpio_bytes:
                            good, bad = verify_extracted(cpio_bytes)
                if bad:
                    logger.warning(f"incomplete, kept as .partial: {', '.join(bad)}")
                if not good:
                    raise ValueError("no complete file in the transfer")
                logger.info(f"Extracted into {os.getcwd()}: {', '.join(good)}")
                os.remove(raw_path)
        except Exception as e:  # noqa: BLE001 - any failure here must not lose the bytes
            logger.warning(f"Could not extract the archive ({e}).")
            logger.warning(f"The raw transfer is kept at {raw_path}")

        transferred = reader.total / 1024.0 / 1024.0
        speed = transferred / (time.time() - start)
        logger.info(
            f"File(s) received (size {transferred:.02f} MB, speed {speed:.02f} MB/s)"
        )

        self.send_response(200)
        self.send_header("Content-Length", 0)
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self):
        """
        Handle post requests
        """

        logger.debug(f"POST request at {self.path}")
        logger.debug(f"Headers\n{self.headers}")

        if self.path == "/Discover":
            self.handle_discover()
        elif self.path == "/Ask":
            self.handle_ask()
        elif self.path == "/Upload":
            self.handle_upload()
        else:
            logger.debug(f"POST request at {self.path}")
            self.send_response(400)
            self.send_header("Content-Length", 0)
            self.end_headers()

    def log_message(self, format, *args):
        # pylint: disable=redefined-builtin
        logger.debug(
            f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}"
        )
