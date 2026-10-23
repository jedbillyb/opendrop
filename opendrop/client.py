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

import base64
import io
import ipaddress
import logging
import os
import platform
import plistlib
import socket
import ssl
import struct
import threading
import time
import uuid
import zlib
from http.client import HTTPException, HTTPSConnection

import fleep
import libarchive
from zeroconf import (
    DNSOutgoing,
    DNSQuestion,
    IPVersion,
    ServiceBrowser,
    Zeroconf,
    const,
)

from .util import AbsArchiveWrite, AirDropUtil

logger = logging.getLogger(__name__)


class AirDropBrowser:
    def __init__(self, config):
        self.ip_addr = AirDropUtil.get_ip_for_interface(config.interface, ipv6=True)
        if self.ip_addr is None:
            if config.interface == "awdl0":
                raise RuntimeError(
                    f"Interface {config.interface} does not have an IPv6 address. Make sure that `owl` is running."
                )
            else:
                raise RuntimeError(
                    f"Interface {config.interface} does not have an IPv6 address"
                )

        self.zeroconf = Zeroconf(
            interfaces=[str(self.ip_addr)],
            ip_version=IPVersion.V6Only,
            apple_p2p=platform.system() == "Darwin",
        )

        self.callback_add = None
        self.callback_remove = None
        self.browser = None
        self._repeat_stop = None
        self._repeat_thread = None

    def start(self, callback_add=None, callback_remove=None):
        """
        Start the AirDropBrowser to discover other AirDrop devices
        """
        if self.browser is not None:
            return  # already started
        self.callback_add = callback_add
        self.callback_remove = callback_remove
        self.browser = ServiceBrowser(self.zeroconf, "_airdrop._tcp.local.", self)
        self._start_repeat_query()

    def _start_repeat_query(self):
        """
        Re-ask the PTR question at a fixed short interval.

        ServiceBrowser backs its queries off 1s, 2s, 4s, 8s... which assumes a
        link where a lost query is unusual. AWDL over a single radio is not that
        link: we are only on the peer's channel for a fraction of each 1.048 s
        sequence, an mDNS query is one unacknowledged multicast frame, and the
        answer has to survive the same gauntlet coming back. Measured over a 75 s
        browse, the backoff produced just 7 queries - at t=0,1,3,7,15,31,63 - and
        none was answered. This keeps asking at a steady rate so the question and
        a co-channel window eventually coincide.
        """
        interval = float(os.environ.get("OPENDROP_QUERY_INTERVAL", "1.5"))
        if interval <= 0:
            return
        self._repeat_stop = threading.Event()

        def loop():
            while not self._repeat_stop.wait(interval):
                try:
                    out = DNSOutgoing(const._FLAGS_QR_QUERY)
                    out.add_question(
                        DNSQuestion(
                            "_airdrop._tcp.local.", const._TYPE_PTR, const._CLASS_IN
                        )
                    )
                    self.zeroconf.send(out)
                except Exception as e:  # keep browsing even if one send fails
                    logger.debug(f"repeat query failed: {e}")

        self._repeat_thread = threading.Thread(
            target=loop, name="airdrop-repeat-query", daemon=True
        )
        self._repeat_thread.start()
        logger.debug(f"repeating _airdrop._tcp query every {interval}s")

    def stop(self):
        if self._repeat_stop is not None:
            self._repeat_stop.set()
            self._repeat_stop = None
        self.browser.cancel()
        self.browser = None
        self.zeroconf.close()

    def add_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        logger.debug(f"Add service {name}")
        if self.callback_add is not None:
            self.callback_add(info)

    def remove_service(self, zeroconf, service_type, name):
        info = zeroconf.get_service_info(service_type, name)
        logger.debug(f"Remove service {name}")
        if self.callback_remove is not None:
            self.callback_remove(info)


class AirDropClient:
    def __init__(self, config, receiver):
        self.config = config
        self.receiver_host = receiver[0]
        self.receiver_port = receiver[1]
        self.http_conn = None
        # Sender identity for the Apple /Upload headers. Generated once per
        # client so a retried arm reuses the same values, and shaped to match
        # what the phone sends: a UUID in upper case, a "pseud:" prefix followed
        # by 22 characters of base64 (16 bytes, unpadded), and a 32-byte token
        # in upper-case hex. We have no Apple ID, so the pseudonym and token
        # cannot be real - the open question is whether the receiver merely
        # requires them to be present and well formed.
        self._transfer_id = str(uuid.uuid4()).upper()
        self._pseudonym = "pseud:" + base64.b64encode(os.urandom(16)).decode().rstrip(
            "="
        ).replace("+", "-").replace("/", "_")
        self._push_token = os.urandom(32).hex().upper()
        # Filled in by send_ask from the receiver's /Ask reply (FINDINGS §37).
        self._ask_response = {}

    def send_POST(
        self, url, body, headers=None, new_conn=False, minimal=False, raw=False
    ):
        logger.debug(f"Send {url} request")

        AirDropUtil.write_debug(
            self.config, body, f"send_{url.lower().strip('/')}_request.plist"
        )

        # `minimal` drops upstream's Accept/Accept-Language/Accept-Encoding.
        # Measured on 2026-07-31 by logging what the iPhone sends US: its
        # /Discover and /Ask carry exactly three headers - User-Agent,
        # Connection, Transfer-Encoding - and no Accept*, no Content-Type and no
        # Host. Upstream sends seven. See FINDINGS §33.
        _headers = {} if minimal else self._get_headers()
        if headers is not None:
            for key, val in headers.items():
                _headers[key] = val
        if new_conn and self.http_conn is not None:
            try:
                self.http_conn.close()
            except OSError:
                pass
            self.http_conn = None
        if self.http_conn is None:
            # Use single connection
            self.http_conn = HTTPSConnectionAWDL(
                self.receiver_host,
                self.receiver_port,
                interface_name=self.config.interface,
                context=self.config.get_ssl_context(),
            )
        if raw:
            # Byte-for-byte control of the request line and headers.
            # http.client.request() always inserts Host and Accept-Encoding,
            # and an iOS 26 sender emits neither (§34/§35). It also reorders
            # headers, and Apple's order is fixed. putrequest() can suppress
            # both insertions; the chunked framing is then ours to write, which
            # is a handful of bytes.
            self.http_conn.putrequest(
                "POST", url, skip_host=True, skip_accept_encoding=True
            )
            for key, val in _headers.items():
                self.http_conn.putheader(key, val)
            self.http_conn.endheaders()
            payload = body if isinstance(body, bytes) else body.read()
            self.http_conn.send(
                b"%x\r\n" % len(payload) + payload + b"\r\n0\r\n\r\n"
            )
        else:
            self.http_conn.request("POST", url, body=body, headers=_headers)
        http_resp = self.http_conn.getresponse()

        response_bytes = http_resp.read()
        AirDropUtil.write_debug(
            self.config,
            response_bytes,
            f"send_{url.lower().strip('/')}_response.plist",
        )

        if http_resp.status != 200:
            status = False
            logger.debug(f"{url} request failed: {http_resp.status}")
        else:
            status = True
            logger.debug(f"{url} request successful")
        return status, response_bytes

    def send_discover(self):
        discover_body = {}
        if self.config.record_data:
            discover_body["SenderRecordData"] = self.config.record_data

        discover_plist_binary = plistlib.dumps(
            discover_body, fmt=plistlib.FMT_BINARY  # pylint: disable=no-member
        )
        _, response_bytes = self.send_POST("/Discover", discover_plist_binary)
        response = plistlib.loads(response_bytes)

        # if name is returned, then receiver is discoverable
        return response.get("ReceiverComputerName")

    def send_ask(self, file_path, is_url=False, icon=None):
        ask_body = {
            "SenderComputerName": self.config.computer_name,
            "BundleID": "com.apple.finder",
            "SenderModelName": self.config.computer_model,
            "SenderID": self.config.service_id,
            "ConvertMediaFormats": False,
            # DECLARE THE TRANSFER ID IN THE ASK BODY. Captured from a real iOS 26
            # sender's /Ask (FINDINGS §37): the sender announces the transfer here
            # as a dict {'id': UUID} and then repeats the SAME id in the /Upload
            # TransferID header. The receiver correlates the two. Our sender used
            # to invent a fresh id on /Upload that /Ask never announced, so the
            # phone had no accepted transfer to bind it to and refused on the
            # headers ~31 ms in, before reading the body - the exact refusal shape
            # we saw all evening. This value must equal the /Upload TransferID.
            "TransferID": {"id": self._transfer_id},
            "TransferType": {"files": {}},
        }
        if self.config.record_data:
            ask_body["SenderRecordData"] = self.config.record_data

        def file_entries(files):
            for file in files:
                file_name = os.path.basename(file)
                file_entry = {
                    "FileName": file_name,
                    "FileType": AirDropUtil.get_uti_type(flp),
                    "FileBomPath": os.path.join(".", file_name),
                    "FileIsDirectory": os.path.isdir(file_name),
                    "ConvertMediaFormats": 0,
                }
                yield file_entry

        if isinstance(file_path, str):
            file_path = [file_path]
        if is_url:
            ask_body["Items"] = file_path
        else:
            # generate icon for first file
            with open(file_path[0], "rb") as f:
                file_header = f.read(128)
                flp = fleep.get(file_header)
                if not icon and len(flp.mime) > 0 and "image" in flp.mime[0]:
                    icon = AirDropUtil.generate_file_icon(f.name)
            ask_body["Files"] = [e for e in file_entries(file_path)]
        if icon:
            ask_body["FileIcon"] = icon

        ask_binary = plistlib.dumps(
            ask_body, fmt=plistlib.FMT_BINARY  # pylint: disable=no-member
        )
        success, response_bytes = self.send_POST("/Ask", ask_binary)

        # Keep whatever the receiver handed back. A real iOS 26 receiver answers
        # /Ask with a plist carrying IDSSessionID, ReceiverPseudonym and
        # ReceiverPushToken (FINDINGS §37) - values an Apple sender may be
        # expected to echo on /Upload, and which we can only obtain from this
        # reply. Parsed leniently: an empty or non-plist body must not break the
        # send.
        self._ask_response = {}
        if response_bytes:
            try:
                self._ask_response = plistlib.loads(response_bytes)
            except Exception:
                pass

        return success

    @staticmethod
    def _cpio_to_dvzip(cpio, block=128 * 1024, stored=False):
        """
        Wrap a cpio archive in Apple's dvzip container.

        The exact inverse of dvzip_to_cpio() in server.py, which was verified
        against a real 2.06 MB iOS 26 transfer (17 blocks, file consumed
        exactly). Each block is:

            [4-byte big-endian header][payload]

        Bit 31 of the header set means the payload is STORED; clear means it is
        a zlib stream. The low 31 bits are the payload length as it appears on
        the wire. Blocks hold 128 KiB of *decompressed* data except the last.
        There is no trailer - the decoder stops at EOF.
        """
        out = bytearray()
        for off in range(0, len(cpio), block):
            chunk = cpio[off : off + block]
            if stored:
                out += struct.pack(">I", 0x80000000 | len(chunk)) + chunk
            else:
                z = zlib.compress(chunk)
                out += struct.pack(">I", len(z)) + z
        return bytes(out)

    def send_upload(self, file_path, is_url=False, reask=None):
        """
        Send a file to a receiver.
        """
        # Don't send an upload request if we just sent a link
        if is_url:
            return

        # WHY ARMS. An iPhone on iOS 26 accepts /Ask, returns a full 200 with its
        # receiver plist, then takes a complete, well-formed chunked /Upload and
        # answers with a TLS close_notify instead of an HTTP status. It is not
        # transport loss - captured at 0% ping loss, every byte ACKed. A server
        # that dislikes a media type answers 406; a silent close points at
        # framing or connection handling, and one capture cannot say which.
        #
        # Each arm costs the user an Accept tap if tested across separate runs,
        # so they are tried in sequence within one accepted session instead. The
        # asymmetry to remember when reading the result: a SUCCESS is conclusive,
        # a FAILURE of a later arm is not, because the phone may have abandoned
        # the session after the first rejection.
        # The second round of arms is no longer guesswork. We have watched this
        # phone send /Upload to US, and it differs from what we send in two
        # observed ways: it sets `Expect: 100-continue` (our receiver had to be
        # taught to answer it - see FINDINGS on the 100-continue ordering) and it
        # wraps the cpio in an `application/x-dvzip` container. Copying what
        # Apple demonstrably does beats inventing a fifth theory.
        #
        # These all hold the connection constant (reused, as upstream does),
        # because the first round confounded connection reuse with framing and
        # so could not attribute its failures. Only arm 1 was interpretable.
        arms = os.environ.get(
            "OPENDROP_UPLOAD_ARMS",
            # Round four. dvzip and Expect are eliminated - three valid arms in
            # §30's successor all drew an identical close_notify, one of them
            # 70 microseconds after our headers, far too fast for the body to
            # have been read. That timing says the request is refused on its
            # HEADERS.
            #
            # The discriminator was already in our own captures. On the very
            # same connection:
            #
            #   POST /Ask     Content-Length: 333        -> 200, every run
            #   POST /Upload  Transfer-Encoding: chunked -> close_notify, always
            #
            # plistlib.dumps() returns bytes so http.client sets a length, while
            # send_upload handed it a BytesIO, which forces chunked. Nothing
            # else differs. Our own receiver needed chunked support ADDED for
            # /Discover and /Ask, so iOS sending chunked as a client never
            # implied it accepts chunked as a server.
            #
            # CANDIDATE FIRST, control last. Normally the control leads, but the
            # control here has been reproduced in every run of the evening,
            # three of them fully valid arms, so re-proving it is not worth what
            # it costs: arm 1 rides the /Ask that cli.send() already made, while
            # every later arm needs a fresh /Ask - another prompt, another tap,
            # and another chance for the re-Ask to die on a flaky link, which is
            # exactly what killed the previous run. Putting the untested arm
            # first buys the answer for one tap and no re-Ask.
            # §33: the phone sends three headers, we send seven. The minimal
            # arms come first because that is the largest untested difference.
            # §34: the phone's /Upload carries TotalBytes, TransferID,
            # SenderPseudonym and SenderPushToken. "applehdr" sends all four,
            # with dvzip and chunked, which is now a full copy of an observed
            # Apple upload rather than a theory about one.
            # §35: applehdr sent all four Apple headers and was still refused,
            # and the capture showed http.client had added Host and
            # Accept-Encoding, which Apple never sends. "rawhdr" emits Apple's
            # exact header set in Apple's exact order with neither of those.
            # That is the last difference left under our control.
            # Round five. §37 changed the question. Every arm to date sent a
            # /Upload TransferID that the /Ask never announced, so all of them
            # were malformed in the same way and none could have succeeded - the
            # earlier "eliminations" only proved the receiver rejects an
            # unannounced transfer, not that any container or framing is wrong.
            # send_ask now declares TransferID in the /Ask body exactly as a real
            # iOS 26 sender does, and this single arm is a byte-level copy of the
            # observed Apple /Upload: reused connection, chunked, dvzip container,
            # Apple's exact header set and order (rawhdr), carrying the announced
            # TransferID. One arm, one tap. A success is the whole goal; a failure
            # now isolates the remaining difference to SenderRecordData, the
            # Apple-signed Apple-ID validation record we cannot forge.
            "reuse-chunked-dvzip-rawhdr",
        ).split(",")

        for i, arm in enumerate(arms):
            arm = arm.strip()
            if not arm:
                continue
            # RE-ASK BEFORE EVERY ARM AFTER THE FIRST. Twice now an arms round
            # has produced four failures of which only the first was
            # interpretable, because a refused /Upload leaves the connection
            # dead: send_POST then finds http_conn is None and opens a fresh one,
            # so "reuse" silently becomes "new" and the arm is a different
            # experiment from the one it claims to be. Worse, that fresh
            # connection carries no /Ask, so the phone is being asked to accept
            # an upload for a session it never agreed to on that socket.
            #
            # The only honest fix costs the user an Accept tap per arm. Taps are
            # cheaper than another uninterpretable round.
            if i > 0:
                if reask is None:
                    logger.warning(
                        f"Skipping arm '{arm}': the connection is gone and there "
                        "is no way to re-Ask, so the arm would not test what its "
                        "name says."
                    )
                    continue
                logger.info(f"Re-sending /Ask before arm '{arm}' - EXPECT A PROMPT")
                if self.http_conn is not None:
                    try:
                        self.http_conn.close()
                    except OSError:
                        pass
                    self.http_conn = None
                # Retry the re-Ask. A single reset here is usually the AWDL link
                # rather than a decision by the phone (§28: our TX drops out in
                # bursts), and giving up on it wastes a run that has already cost
                # the user a share sheet and a tap.
                asked = False
                for attempt in range(3):
                    try:
                        if reask():
                            asked = True
                            break
                        logger.warning(f"Re-Ask before '{arm}' was refused")
                        break  # a considered "no" is not worth retrying
                    except (OSError, HTTPException) as e:
                        logger.warning(
                            f"Re-Ask before '{arm}' failed at the socket "
                            f"(attempt {attempt + 1}/3): {e}"
                        )
                        if self.http_conn is not None:
                            try:
                                self.http_conn.close()
                            except OSError:
                                pass
                            self.http_conn = None
                        time.sleep(2)
                if not asked:
                    logger.warning(f"Could not re-Ask before '{arm}'; stopping")
                    return False
            new_conn = arm.startswith("new")
            use_length = "length" in arm
            compress = "plain" not in arm and "dvzip" not in arm
            dvzip = "dvzip" in arm
            expect = "expect" in arm

            # Create archive in memory ...
            stream = io.BytesIO()
            with libarchive.custom_writer(
                stream.write,
                "cpio",
                filter_name="gzip" if compress else None,
                archive_write_class=AbsArchiveWrite,
            ) as archive:
                for f in [file_path]:
                    ff = os.path.basename(f)
                    archive.add_abs_file(f, os.path.join(".", ff))
            payload = stream.getvalue()

            if dvzip:
                payload = self._cpio_to_dvzip(payload)

            minimal = "minhdr" in arm or "applehdr" in arm or "rawhdr" in arm
            raw = "rawhdr" in arm
            headers = {}
            if raw:
                # Apple's exact set, in Apple's exact order (§34). dicts preserve
                # insertion order, and send_POST emits them in that order when
                # raw is set, so this literally reproduces the observed request.
                headers["User-Agent"] = "AirDrop/1.0"
                headers["TotalBytes"] = str(len(payload))
                headers["Content-Type"] = (
                    "application/x-dvzip" if dvzip else "application/x-cpio"
                )
                headers["SenderPseudonym"] = self._pseudonym
                headers["SenderPushToken"] = self._push_token
                headers["TransferID"] = self._transfer_id
                headers["Connection"] = "keep-alive"
                headers["Transfer-Encoding"] = "chunked"
            else:
                headers["Content-Type"] = (
                    "application/x-dvzip" if dvzip else "application/x-cpio"
                )
            if "applehdr" in arm:
                # The four headers an iOS 26 sender puts on /Upload that we have
                # never sent, captured 2026-07-31 22:09 by logging a real
                # phone-to-laptop transfer (FINDINGS §34):
                #
                #   TotalBytes: 1303171
                #   SenderPseudonym: pseud:RDUDcHgUEfGhmdJSNF0FmQ
                #   SenderPushToken: 1D0DD878...0493
                #   TransferID: 664D3979-F245-4E9E-9EAC-80453E255E31
                #
                # TransferID is the interesting one: without it the receiver has
                # no way to tie an upload to the session it just accepted, which
                # is exactly the shape of a refusal issued on the headers alone.
                headers["TotalBytes"] = str(len(payload))
                headers["TransferID"] = self._transfer_id
                headers["SenderPseudonym"] = self._pseudonym
                headers["SenderPushToken"] = self._push_token
            if minimal:
                # Match the shape the phone uses: User-Agent, Connection, and
                # the framing header http.client adds itself. Content-Type stays
                # because our own receiver reads it to pick a decoder, so an
                # Apple sender must set it on /Upload even though it sets none on
                # /Discover or /Ask.
                headers["User-Agent"] = "AirDrop/1.0"
                headers["Connection"] = "keep-alive"
            if expect:
                headers["Expect"] = "100-continue"
            if use_length:
                # Content-Length instead of chunked. http.client only chunks when
                # it cannot determine a length, so handing it bytes with an
                # explicit length changes the framing on the wire.
                headers["Content-Length"] = str(len(payload))
                body = payload
            else:
                body = io.BytesIO(payload)

            logger.info(
                f"Upload arm {i + 1}/{len(arms)}: {arm} "
                f"({len(payload)} B, {'Content-Length' if use_length else 'chunked'},"
                f" {headers['Content-Type']},"
                f" {'Expect: 100-continue' if expect else 'no Expect'},"
                f" {'new connection' if new_conn else 'reused connection'})"
            )
            try:
                success, _ = self.send_POST(
                    "/Upload",
                    body,
                    headers=headers,
                    new_conn=new_conn,
                    minimal=minimal,
                    raw=raw,
                )
            except (OSError, HTTPException) as e:
                logger.warning(f"Upload arm '{arm}' failed at the socket: {e}")
                # The connection is unusable now whatever happened to it.
                if self.http_conn is not None:
                    try:
                        self.http_conn.close()
                    except OSError:
                        pass
                    self.http_conn = None
                continue
            if success:
                logger.info(f"Upload arm '{arm}' ACCEPTED - this is the framing to use")
                return True
            logger.warning(f"Upload arm '{arm}' was answered, but not with 200")

        return False

    def _get_headers(self):
        """
        Get the headers for requests sent
        """
        headers = {
            "Content-Type": "application/octet-stream",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "User-Agent": "AirDrop/1.0",
            "Accept-Language": "en-us",
            "Accept-Encoding": "br, gzip, deflate",
        }
        return headers


class HTTPSConnectionAWDL(HTTPSConnection):
    """
    This class allows to bind the HTTPConnection to a specific network interface
    """

    def __init__(
        self,
        host,
        port=None,
        key_file=None,
        cert_file=None,
        timeout=None,
        source_address=None,
        *,
        context=None,
        check_hostname=None,
        interface_name=None,
    ):

        if interface_name is not None:
            if "%" not in host:
                if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
                    host = host + "%" + interface_name

        if timeout is None:
            timeout = socket.getdefaulttimeout()

        # key_file, cert_file and check_hostname were deprecated on
        # HTTPSConnection from Python 3.6 and REMOVED in 3.12, so forwarding them
        # raises e.g.
        #   TypeError: HTTPSConnection.__init__() got an unexpected keyword
        #              argument 'key_file'
        # and every send/find dies before a single packet goes out. All three now
        # live on the SSLContext instead. AirDropConfig.get_ssl_context() already
        # does the load_cert_chain(), so in normal use key_file/cert_file are None
        # and there is nothing to carry over. They stay in the signature for
        # callers that still pass them.
        if context is None and (key_file or cert_file):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.load_cert_chain(cert_file, keyfile=key_file)
        if check_hostname is not None and context is not None:
            context.check_hostname = check_hostname

        super(HTTPSConnectionAWDL, self).__init__(
            host=host,
            port=port,
            timeout=timeout,
            source_address=source_address,
            context=context,
        )

        self.interface_name = interface_name
        self._create_connection = self.create_connection_awdl

    def create_connection_awdl(
        self, address, timeout=socket.getdefaulttimeout(), source_address=None
    ):
        """Connect to *address* and return the socket object.

        Convenience function.  Connect to *address* (a 2-tuple ``(host,
        port)``) and return the socket object.  Passing the optional
        *timeout* parameter will set the timeout on the socket instance
        before attempting to connect.  If no *timeout* is supplied, the
        global default timeout setting returned by :func:`getdefaulttimeout`
        is used.  If *source_address* is set it must be a tuple of (host, port)
        for the socket to bind as a source address before making the connection.
        A host of '' or port 0 tells the OS to use the default.
        """

        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, _, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                if timeout is not socket.getdefaulttimeout():
                    sock.settimeout(timeout)
                if self.interface_name == "awdl0" and platform.system() == "Darwin":
                    sock.setsockopt(socket.SOL_SOCKET, 0x1104, 1)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                # Break explicitly a reference cycle
                return sock

            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        else:
            raise socket.error("getaddrinfo returns an empty list")
