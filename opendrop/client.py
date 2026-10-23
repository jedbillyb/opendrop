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
import ipaddress
import logging
import os
import platform
import plistlib
import socket
import ssl
import threading
from http.client import HTTPSConnection

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

    def send_POST(self, url, body, headers=None):
        logger.debug(f"Send {url} request")

        AirDropUtil.write_debug(
            self.config, body, f"send_{url.lower().strip('/')}_request.plist"
        )

        _headers = self._get_headers()
        if headers is not None:
            for key, val in headers.items():
                _headers[key] = val
        if self.http_conn is None:
            # Use single connection
            self.http_conn = HTTPSConnectionAWDL(
                self.receiver_host,
                self.receiver_port,
                interface_name=self.config.interface,
                context=self.config.get_ssl_context(),
            )
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
        success, _ = self.send_POST("/Ask", ask_binary)

        return success

    def send_upload(self, file_path, is_url=False):
        """
        Send a file to a receiver.
        """
        # Don't send an upload request if we just sent a link
        if is_url:
            return

        headers = {
            "Content-Type": "application/x-cpio",
        }

        # Create archive in memory ...
        stream = io.BytesIO()
        with libarchive.custom_writer(
            stream.write,
            "cpio",
            filter_name="gzip",
            archive_write_class=AbsArchiveWrite,
        ) as archive:
            for f in [file_path]:
                ff = os.path.basename(f)
                archive.add_abs_file(f, os.path.join(".", ff))
        stream.seek(0)

        # ... then send in chunked mode
        success, _ = self.send_POST("/Upload", stream, headers=headers)

        # TODO better: write archive chunk whenever send_POST does a read to avoid having the whole archive in memory

        return success

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
