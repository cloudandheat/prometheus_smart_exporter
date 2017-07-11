########################################################################
# File name: __init__.py
# This file is part of: Prometheus S.M.A.R.T. exporter
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
########################################################################
import contextlib
import logging
import pathlib
import re
import subprocess
import struct
import socket
import sys

import systemd.daemon
import systemd.journal


logger = logging.getLogger(__name__)


# one byte version, for future extensibility
Header = struct.Struct("=BQ")


DEVICE_PATH_PATTERN = re.compile(
    r"([0-9]+:){3}[0-9]+"
)

SERIAL_NUMBER = re.compile(
    r"^Serial Number:\s*(\S+)$",
    re.MULTILINE,
)

MODEL = re.compile(
    r"^Device Model:\s*(\S.*)$",
    re.MULTILINE,
)

MODEL_FAMILY = re.compile(
    r"^Model Family:\s*(\S.*)$",
    re.MULTILINE,
)

ATTR_LINE = re.compile(
    r"""^\s*
    (?P<id>\d+)\s+
    (?P<name>[\w_]+)\s+
    .+$""",
    re.MULTILINE | re.VERBOSE
)


def read_drive_info(device):
    try:
        data = subprocess.check_output(
            ["smartctl", "-iA", device],
        ).decode()
    except subprocess.CalledProcessError as exc:
        logger.error(
            "failed to read SMART data for %s (%s)",
            device,
            exc,
        )
        return {
            "error": 1,
        }

    info, smart_data = data.split("START OF READ SMART DATA", 1)

    serial_no = SERIAL_NUMBER.search(info)

    family = MODEL_FAMILY.search(info)
    if family is None:
        family = "unknown"
    else:
        family = family.group(1)

    model = MODEL.search(info)
    if model is None:
        model = "unknown"
    else:
        model = model.group(1)

    attrs = []

    for attr in ATTR_LINE.finditer(smart_data):
        full_match = attr.group(0).strip()
        fields = full_match.split()
        attrs.append(
            {
                "ID#": int(fields[0]),
                "Name": fields[1],
                "Value": int(fields[3]),
                "Worst": int(fields[4]),
                "Thresh": int(fields[5]),
                "Raw": int(fields[9]),
            }
        )

    return {
        "serial": serial_no.group(1),
        "model": model,
        "family": family,
        "attrs": attrs,
        "error": 0,
    }


def iter_drives():
    base = pathlib.Path("/sys/bus/scsi/devices/")
    for p in base.iterdir():
        basename = p.parts[-1]
        if DEVICE_PATH_PATTERN.match(basename):
            if (p / "block").is_dir():
                for blockdev in (p / "block").iterdir():
                    yield basename, blockdev.parts[-1]


def handle_client(sock):
    try:
        # we never want to read
        sock.shutdown(socket.SHUT_RD)

        drives = []
        for port, device in iter_drives():
            info = read_drive_info("/dev/"+device)
            info["port"] = port
            drives.append(info)

        data = repr(drives).encode("utf-8")
        header = Header.pack(1, len(data))

        sock.sendall(header)
        sock.sendall(data)
    finally:
        # shut the socket down cleanly
        sock.shutdown(socket.SHUT_RDWR)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--socket-path",
        default=None,
        help="Path at which the unix socket will be created. Required if the "
        "process is not started via systemd socket activation."
    )

    parser.add_argument(
        "--timeout",
        default=None,
        type=int,
        help="Time in seconds to wait between connections. Defaults to "
        " infinity."
    )

    parser.add_argument(
        "-v",
        dest="verbosity",
        action="count",
        default=0,
    )

    args = parser.parse_args()

    logging_kwargs = {}

    sd_fds = systemd.daemon.listen_fds()
    if len(sd_fds) == 0 and args.socket_path is None:
        print(
            "not started via socket activation. --socket-path is required but "
            "not given.",
            file=sys.stderr,
        )
        sys.exit(1)
    elif len(sd_fds) > 1:
        print(
            "too many sockets ({}) passed via systemd socket"
            " activation".format(
                len(sd_fds),
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    elif len(sd_fds) == 1:
        logging_kwargs["handlers"] = [
            systemd.journal.JournalHandler(),
        ]
        sock = socket.fromfd(
            sd_fds[0],
            socket.AF_UNIX,
            socket.SOCK_STREAM,
            0,
        )

        if args.timeout is not None:
            sock.settimeout(args.timeout)
    else:
        p = pathlib.Path(args.socket_path).absolute()
        if p.is_socket():
            p.unlink()

        sock = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
            0
        )
        sock.bind(args.socket_path)
        sock.listen()

        if args.timeout is not None:
            sock.settimeout(args.timeout)

    logging.basicConfig(
        level={
            0: logging.ERROR,
            1: logging.WARNING,
            2: logging.INFO,
        }.get(args.verbosity, logging.DEBUG),
        **logging_kwargs
    )

    while True:
        try:
            client_sock, addr = sock.accept()
        except socket.timeout:
            return

        try:
            with contextlib.closing(client_sock):
                handle_client(client_sock)
        except Exception as exc:
            logger.exception("while handling client")
