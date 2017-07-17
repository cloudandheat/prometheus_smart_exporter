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
import ast
import logging
import http.server
import pathlib
import socket
import struct
import sys

from prometheus_client import REGISTRY
from prometheus_client.core import (GaugeMetricFamily,
                                    CounterMetricFamily)
from prometheus_client.exposition import MetricsHandler

from . import attrmeta, devicedb


DEFAULT_DEVICE_DB = pathlib.Path("/etc/prometheus_smart_exporter/devices.json")
DEFAULT_ATTR_MAPPING = pathlib.Path(__file__).parent / "data" / "attrmap.json"

Header = struct.Struct("=BQ")

logger = logging.getLogger(__name__)


def recvall(sock, length):
    buf = bytearray(length)
    offset = 0
    while offset < length:
        # receive into buf, starting at the offset-ths byte
        offset += sock.recv_into(memoryview(buf)[offset:])
    return buf


class SMARTCollector(object):
    def __init__(self, socket_path, devicedb, attrmap, logger):
        self.logger = logger
        self.socket_path = socket_path
        self.devicedb = devicedb
        self.attrmap = attrmap
        self.labels = [
            "port",
            "model",
            "family",
            "serial",
        ]

    def _get_connected_socket(self):
        self.logger.debug("attempting UNIX connection to %s",
                          self.socket_path)
        s = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
            0,
        )

        s.connect(str(self.socket_path))

        return s

    def _recv_smart_info(self, sock):
        hdr = sock.recv(Header.size)
        ver, length = Header.unpack(hdr)

        if ver != 1:
            self.logger.error(
                "helper daemon responded with unknown version: %r",
                ver,
            )
            return None

        data = recvall(sock, length).decode("utf-8")

        return ast.literal_eval(data)

    def collect(self):
        self.logger.debug("starting collection ... ")

        global_error_metric = GaugeMetricFamily(
            "smart_system_error",
            "flag indicating that there is a problem with the helper daemon",
        )

        try:
            sock = self._get_connected_socket()
            data = self._recv_smart_info(sock)
        except OSError:
            self.logger.error(
                "failed to get data from helper daemon at %s",
                self.socket_path,
                exc_info=True,
            )
            global_error_metric.add_metric([], 1)
            return [global_error_metric]

        global_error_metric.add_metric([], 0)

        error_metrics = GaugeMetricFamily(
            "smart_access_error",
            "flag indicating that there is a problem accessing the device",
            labels=["port"],
        )

        warning_metrics = GaugeMetricFamily(
            "smart_metric_error",
            "flag indicating that there is a problem converting metrics "
            "from the device",
            labels=["port"],
        )

        attr_metrics = {}

        def get_attr_metric(device, id_, name):
            nonlocal attr_metrics

            try:
                metric_name, type_ = self.attrmap.get_metric_for_attribute(
                    device, id_, name
                )
            except KeyError:
                return None

            try:
                return attr_metrics[metric_name]
            except KeyError:
                class_ = {
                    attrmeta.MetricType.GAUGE: GaugeMetricFamily,
                    attrmeta.MetricType.COUNTER: CounterMetricFamily,
                }[type_]

                metric = class_(
                    "smart_{}".format(metric_name),
                    "S.M.A.R.T. metric based on attribute {}".format(name),
                    labels=self.labels,
                )

                attr_metrics[metric_name] = metric
                return metric

        for devinfo in data:
            port = devinfo["port"]

            if devinfo["error"]:
                error_metrics.add_metric(
                    [port],
                    1.
                )
                continue

            has_warnings = False

            error_metrics.add_metric(
                [port],
                0.
            )

            device = devinfo["model"]
            family = devinfo["family"]
            serial = devinfo["serial"]

            self.logger.debug("device %r", device)

            for attrinfo in devinfo["attrs"]:
                self.logger.debug("smart attribute %r", attrinfo)

                id_ = int(attrinfo["ID#"])
                name = attrinfo["Name"]

                try:
                    type_, _, _ = self.devicedb.get_info_for_attr(device, id_)
                except KeyError as exc:
                    try:
                        # check if attribute is explicitly configured
                        # in that case, we want to warn
                        self.attrmap.get_metric_for_attribute(
                            device, id_, name
                        )
                    except KeyError:
                        # not configured -> no warning
                        self.logger.debug(
                            "omitting unconfigured attribute which is missing"
                            " in device db: #%d (%s) on device %r"
                            " (lookup failed for %s)",
                            id_,
                            name,
                            device,
                            exc,
                        )
                    else:
                        self.logger.warning(
                            "explicitly configured attribute #%d (%s) on"
                            " device %r is missing in devicedb -- cannot"
                            " generate metric! (lookup failed for %s)",
                            id_,
                            name,
                            device,
                            exc,
                        )
                        has_warnings = True
                    continue

                metric = get_attr_metric(device, id_, name)
                if metric is None:
                    continue

                self.logger.debug(
                    "registering %s of #%d on metric %s",
                    type_,
                    id_,
                    metric,
                )

                metric.add_metric(
                    [port, device, family, serial],
                    float(attrinfo[type_])
                )

            if has_warnings:
                warning_metrics.add_metric(
                    [port],
                    int(has_warnings)
                )

        return [
            global_error_metric,
            error_metrics,
            warning_metrics,
        ] + list(attr_metrics.values())


class HTTP6Server(http.server.HTTPServer):
    address_family = socket.AF_INET6


def socket_path(s):
    p = pathlib.Path(s)
    if not p.is_socket():
        raise ValueError(
            "{!r} does not refer to a socket".format(s)
        )

    return p


def main():
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--device-db",
        type=argparse.FileType("r"),
        default=None,
        help="Device database in JSON format (default: {})".format(
            DEFAULT_DEVICE_DB
        )
    )

    parser.add_argument(
        "--attr-mapping",
        type=argparse.FileType("r"),
        default=None,
        help="Attribute mapping in JSON format (default: {})".format(
            DEFAULT_ATTR_MAPPING
        )
    )

    parser.add_argument(
        "-v",
        dest="verbosity",
        action="count",
        default=0,
        help="Increase verbosity (up to -vvv)",
    )

    parser.add_argument(
        "--journal",
        action="store_true",
        default=False,
        help="Log to systemd journal",
    )

    parser.add_argument(
        "-p", "--listen-port",
        default=9257,
        metavar="PORT",
        type=int,
        help="Port number to bind to (default: 9257)",
    )

    parser.add_argument(
        "-a", "--listen-address",
        metavar="ADDR",
        help="Address to bind to (default: 127.0.0.1)",
        default="127.0.0.1",
    )

    parser.add_argument(
        "socket",
        type=socket_path,
        help="Path to UNIX socket where the helper listens",
    )

    args = parser.parse_args()

    logging_kwargs = {}
    if args.journal:
        import systemd.journal
        logging_kwargs["handlers"] = [systemd.journal.JournalHandler()]

    logging.basicConfig(
        level={
            0: logging.ERROR,
            1: logging.WARNING,
            2: logging.INFO,
        }.get(args.verbosity, logging.DEBUG),
        **logging_kwargs
    )

    if args.device_db is None:
        logger.debug("no --device-db specified, using default %r",
                     DEFAULT_DEVICE_DB)
        try:
            args.device_db = DEFAULT_DEVICE_DB.open("r")
        except OSError as exc:
            logger.error("failed to open device database: %s", exc)
            logger.info(
                "check that it exists and is accessible, or use --device-db to"
                " specify a different database.",
            )
            sys.exit(2)

    with args.device_db as f:
        device_db = devicedb.DeviceDB(logging.getLogger("devdb"))
        try:
            device_db.load(f)
        except SyntaxError as exc:
            logger.error(
                "failed to load device database: %s", exc,
                exc_info=True,
            )
            sys.exit(2)
        else:
            logger.info(
                "device db loaded with %s",
                device_db.stats()
            )

    if args.attr_mapping is None:
        logger.debug("no --attr-mapping specified, using default %r",
                     DEFAULT_ATTR_MAPPING)
        try:
            args.attr_mapping = DEFAULT_ATTR_MAPPING.open("r")
        except OSError as exc:
            logger.error("failed to open attribute mapping: %s", exc)
            logger.info(
                "check that it exists and is accessible, or use --attr-mapping"
                " to specify a different file.",
            )
            sys.exit(2)

    with args.attr_mapping as f:
        attr_mapping = attrmeta.AttributeMapping(logging.getLogger("attrmap"))
        try:
            attr_mapping.load(f)
        except (SyntaxError, ValueError) as exc:
            logger.error(
                "failed to load attribute mapping: %s", exc,
                exc_info=True,
            )
            sys.exit(2)
        else:
            logger.info(
                "attribute_mapping loaded with %s",
                attr_mapping.stats()
            )

    REGISTRY.register(
        SMARTCollector(
            args.socket,
            device_db,
            attr_mapping,
            logger.getChild("collector")
        ),
    )

    if ":" in args.listen_address:
        class_ = HTTP6Server
    else:
        class_ = http.server.HTTPServer

    httpd = class_(
        (args.listen_address, args.listen_port),
        MetricsHandler
    )
    httpd.serve_forever()
