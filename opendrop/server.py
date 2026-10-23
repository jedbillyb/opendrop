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
import os
import platform
import plistlib
import socket
import struct
import time
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

import libarchive
import libarchive.extract
import libarchive.read
from zeroconf import IPVersion, ServiceInfo, Zeroconf

from .util import AirDropUtil

logger = logging.getLogger(__name__)


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

class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6


class AirDropServerHandler(BaseHTTPRequestHandler):
    """
    Server which responds to AirDrop HTTP POST requests
    """

    protocol_version = "HTTP/1.1"
    config = None

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
        post_data = self._read_request_body()

        AirDropUtil.write_debug(self.config, post_data, "receive_ask_request.plist")

        if not self._ask_user(post_data):
            self.send_response(403)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return

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
                        raise ValueError(
                            f"dvzip block truncated: wanted {length}, got {len(payload)}"
                        )
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

            while True:
                buf = reader.read(65536)
                if not buf:
                    break
                raw.write(buf)

        try:
            if raw_path.endswith(".dvzip"):
                libarchive.extract_memory(dvzip_to_cpio(raw_path))
            else:
                with open(raw_path, "rb") as raw:
                    extract_stream(raw)
        except Exception as e:  # noqa: BLE001 - any failure here must not lose the bytes
            logger.warning(f"Could not extract the archive ({e}).")
            logger.warning(f"The raw transfer is kept at {raw_path}")
        else:
            logger.info(f"Extracted into {os.getcwd()}")
            os.remove(raw_path)

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
