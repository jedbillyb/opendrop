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

import argparse
import json
import logging
import os
import sys
import threading
import time

from .client import AirDropBrowser, AirDropClient
from .config import AirDropConfig, AirDropReceiverFlags
from .server import AirDropServer

logger = logging.getLogger(__name__)


def main():
    """Returns a process exit status, which the console script propagates.

    Nothing here used to: every failure path in send() was a bare `return`
    and main() returned None, so `opendrop send` exited 0 whether the
    receiver declined, the upload broke, or no such receiver existed. Every
    caller that reads the status - a wrapper script, a desktop notification,
    a progress indicator - was therefore told the transfer worked.
    """
    return AirDropCli(sys.argv[1:]).status


class AirDropCli:
    def __init__(self, args):
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["receive", "find", "send"])
        # REPEATABLE. The protocol carries several files in ONE transfer -
        # send_ask already builds one entry per file - but the command line
        # could not say so, so every caller had to loop around it: N
        # transfers, N Accepts on the phone. `-f a -f b` makes that one.
        # A single -f is still a one-element list, so nothing changes for
        # existing callers.
        parser.add_argument("-f", "--file", action="append", metavar="FILE",
                            help="File to be sent; repeat for several")
        parser.add_argument(
            "-u", "--url", help="'-f,--file is a URL", action="store_true"
        )
        parser.add_argument(
            "-r",
            "--receiver",
            help="Peer to send file to (can be index, ID, or hostname)",
        )
        parser.add_argument(
            "-e", "--email", nargs="*", help="User's email addresses (currently unused)"
        )
        parser.add_argument(
            "-p", "--phone", nargs="*", help="User's phone numbers (currently unused)"
        )
        parser.add_argument(
            "-n", "--name", help="Computer name (displayed in sharing pane)"
        )
        parser.add_argument(
            "-m", "--model", help="Computer model (displayed in sharing pane)"
        )
        parser.add_argument(
            "-d", "--debug", help="Enable debug mode", action="store_true"
        )
        parser.add_argument(
            "-i", "--interface", help="Which AWDL interface to use", default="awdl0"
        )
        args = parser.parse_args(args)

        if args.debug:
            logging.basicConfig(
                level=logging.DEBUG,
                format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            )
        else:
            logging.basicConfig(level=logging.INFO, format="%(message)s")

        # TODO put emails and phone in canonical form (lower case, no '+' sign, etc.)

        self.config = AirDropConfig(
            email=args.email,
            phone=args.phone,
            computer_name=args.name,
            computer_model=args.model,
            debug=args.debug,
            interface=args.interface,
        )
        self.server = None
        self.client = None
        self.browser = None
        self.sending_started = False
        self.discover = []
        self.lock = threading.Lock()
        self.status = 0

        try:
            if args.action == "receive":
                self.receive()
            elif args.action == "find":
                self.find()
            else:  # args.action == 'send'
                if not args.file:
                    parser.error("Need -f,--file when using send")
                if args.url and len(args.file) > 1:
                    parser.error("-u,--url takes a single -f,--file")
                if not args.url:
                    for path in args.file:
                        if not os.path.isfile(path):
                            parser.error("File in -f,--file not found: %s" % path)
                self.file = args.file
                self.is_url = args.url
                if args.receiver is None:
                    parser.error("Need -r,--receiver when using send")
                self.receiver = args.receiver
                self.status = self.send() or 0
        except KeyboardInterrupt:
            if self.browser is not None:
                self.browser.stop()
            if self.server is not None:
                self.server.stop()

    def find(self):
        logger.info("Looking for receivers. Press Ctrl+C to stop ...")
        self.browser = AirDropBrowser(self.config)
        self.browser.start(callback_add=self._found_receiver)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        finally:
            # Save BEFORE stopping the browser. browser.stop() ends in
            # zeroconf.close(), which tears down threads and sockets and does not
            # reliably return on this link -- measured hanging for over two
            # minutes. With the write ordered after it, a browse could discover a
            # receiver, print it, and still leave the report unwritten, so the
            # following `opendrop send` read a stale report and failed with
            # "Receiver does not exist". Nothing about serialising self.discover
            # needs the browser to be stopped first; take the lock instead, since
            # _send_discover appends from a callback thread.
            self._save_discovery_report()
            self.browser.stop()

    def _save_discovery_report(self):
        logger.debug(f"Save discovery results to {self.config.discovery_report}")
        self.lock.acquire()
        try:
            discover = list(self.discover)
        finally:
            self.lock.release()
        # Write via a temp file in the same directory and rename, so a reader can
        # never see a half-written report and an interrupted write cannot destroy
        # the previous one.
        tmp = self.config.discovery_report + ".tmp"
        with open(tmp, "w") as f:
            json.dump(discover, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.config.discovery_report)

    def _found_receiver(self, info):
        thread = threading.Thread(target=self._send_discover, args=(info,))
        thread.start()

    def _send_discover(self, info):
        try:
            address = info.parsed_addresses()[0]  # there should only be one address
        except IndexError:
            logger.warning(f"Ignoring receiver with missing address {info}")
            return
        identifier = info.name.split(".")[0]
        hostname = info.server
        port = int(info.port)
        logger.debug(f"AirDrop service found: {hostname}, {address}:{port}, ID {id}")
        client = AirDropClient(self.config, (address, int(port)))
        try:
            flags = int(info.properties[b"flags"])
        except KeyError:
            # TODO in some cases, `flags` are not set in service info; for now we'll try anyway
            flags = AirDropReceiverFlags.SUPPORTS_DISCOVER_MAYBE

        if flags & AirDropReceiverFlags.SUPPORTS_DISCOVER_MAYBE:
            try:
                receiver_name = client.send_discover()
            except TimeoutError:
                receiver_name = None
        else:
            receiver_name = None
        discoverable = receiver_name is not None

        index = len(self.discover)
        node_info = {
            "name": receiver_name,
            "address": address,
            "port": port,
            "id": identifier,
            "flags": flags,
            "discoverable": discoverable,
        }
        self.lock.acquire()
        self.discover.append(node_info)
        if discoverable:
            logger.info(f"Found  index {index}  ID {identifier}  name {receiver_name}")
        else:
            logger.debug(f"Receiver ID {identifier} is not discoverable")
        self.lock.release()
        # Persist on every discovery, not only at shutdown. A browse driven by a
        # script is liable to be killed outright once it has printed what the
        # caller wanted, and the report is the only channel through which `send`
        # learns the receiver's address and port.
        self._save_discovery_report()

    def receive(self):
        self.server = AirDropServer(self.config)
        self.server.start_service()
        self.server.start_server()

    def send(self):
        """0 when the file landed, 1 otherwise. See main()."""
        info = self._get_receiver_info()
        if info is None:
            return 1
        self.client = AirDropClient(self.config, (info["address"], info["port"]))
        logger.info("Asking receiver to accept ...")
        if not self.client.send_ask(self.file, is_url=self.is_url):
            logger.warning("Receiver declined")
            return 1
        logger.info("Receiver accepted")
        logger.info("Uploading file ...")
        if not self.client.send_upload(
            self.file,
            is_url=self.is_url,
            # Lets an upload arm re-establish an accepted session before it runs.
            # Without this every arm after the first tests a fresh connection the
            # phone never accepted anything on.
            reask=lambda: self.client.send_ask(self.file, is_url=self.is_url),
        ):
            logger.warning("Uploading has failed")
            return 1
        logger.info("Uploading has been successful")
        return 0

    def _get_receiver_info(self):
        if not os.path.exists(self.config.discovery_report):
            logger.error("No discovery report exists, please run 'opendrop find' first")
            return None
        age = time.time() - os.path.getmtime(self.config.discovery_report)
        if age > 60:  # warn if report is older than a minute
            logger.warning(
                f"Old discovery report ({age:.1f} seconds), consider running 'opendrop find' again"
            )
        with open(self.config.discovery_report, "r") as f:
            infos = json.load(f)

        # (1) try 'index'
        try:
            self.receiver = int(self.receiver)
            return infos[self.receiver]
        except ValueError:
            pass
        except IndexError:
            pass
        # (2) try 'id'
        if len(self.receiver) == 12:
            for info in infos:
                if info["id"] == self.receiver:
                    return info
        # (3) try hostname
        for info in infos:
            if info["name"] == self.receiver:
                return info
        # (fail)
        logger.error(
            "Receiver does not exist (check -r,--receiver format or try 'opendrop find' again"
        )
        return None
