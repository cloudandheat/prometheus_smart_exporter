import ast
import functools
import logging
import http.server
import pathlib
import re
import socket
import struct
import sys

from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.exposition import MetricsHandler


DEFAULT_DEVICE_DB = "/etc/prometheus_smart_exporter/devices.json"
DEFAULT_ATTR_MAPPING = "/etc/prometheus_smart_exporter/attrmap.json"

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
            labels=self.labels,
        )

        attr_metrics = {}

        def get_attr_metric(device, id_, name):
            nonlocal attr_metrics

            try:
                metric_name = self.attrmap.get_metric_for_attribute(
                    device, id_, name
                )
            except KeyError:
                return None

            try:
                return attr_metrics[metric_name]
            except KeyError:
                metric = GaugeMetricFamily(
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

            error_metrics.add_metric(
                [port],
                0.
            )

            device = devinfo["model"]

            self.logger.debug("device %r", device)

            for attrinfo in devinfo["attrs"]:
                self.logger.debug("smart attribute %r", attrinfo)

                id_ = int(attrinfo["ID#"])
                name = attrinfo["Name"]

                try:
                    type_, _, _ = self.devicedb.get_info_for_attr(device, id_)
                except KeyError:
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
                            " in device db: #%d (%s) on device %r",
                            id_,
                            name,
                            device,
                        )
                    else:
                        self.logger.warning(
                            "explicitly configured attribute #%d (%s) on"
                            " device %r is missing in devicedb -- cannot"
                            " generate metric!",
                            id_,
                            name,
                            device,
                        )
                    continue

                metric = get_attr_metric(device, id_, name)

                self.logger.debug(
                    "registering %s of #%d on metric %s",
                    type_,
                    id_,
                    metric,
                )

                metric.add_metric(
                    [port],
                    float(attrinfo[type_])
                )

        return [global_error_metric, error_metrics] + list(attr_metrics.values())


class HTTP6Server(http.server.HTTPServer):
    address_family = socket.AF_INET6


def socket_path(s):
    p = pathlib.Path(s)
    if not p.is_socket():
        raise ValueError(
            "{!r} does not refer to a socket".format(s)
        )

    return p


class DeviceDB:
    def __init__(self, logger):
        super().__init__()
        self._logger = logger
        self._devices = {}

    def load(self, f):
        data = ast.literal_eval(f.read())

        devices = data["Devices"]

        for device_info in devices.values():
            logger.debug("interpreting %r", device_info)

            ids = {
                int(id_): {
                    "RAW_VALUE": "Raw",
                    "VALUE": "Value",
                }[type_]
                for id_, type_ in device_info["ID#"].items()
            }
            threshs = {
                int(id_): (warn, crit)
                for id_, (warn, crit) in device_info["Threshs"].items()
            }
            perfs = set(map(int, device_info["Perfs"]))
            logger.debug("found ID#=%r", ids)
            logger.debug("found Threshs=%r", threshs)
            logger.debug("found Perfs=%r", perfs)

            for device in device_info["Device"]:
                logger.debug("updating %r with said info", device)
                existing_ids, existing_threshs, existing_perfs = \
                    self._devices.setdefault(device, ({}, {}, set()))
                existing_ids.update(ids)
                existing_threshs.update(threshs)
                existing_perfs.update(perfs)

    def stats(self):
        return "{} devices".format(len(self._devices))

    def get_info_for_attr(self, device, id_):
        ids, threshs, perfs = self._devices[device]
        type_ = ids[id_]
        threshs = threshs.get(id_)
        generate_perf = id_ in perfs

        return type_, threshs, generate_perf


class AttributeMapping:
    TOPLEVEL_KNOWN_KEYS = [
        "generic",
        "per-device",
    ]

    PER_DEVICE_RULES_KNOWN_KEYS = [
        "Devices",
        "rules",
    ]

    PER_DEVICE_RULES_REQUIRED_KEYS = \
        PER_DEVICE_RULES_KNOWN_KEYS

    RULE_KNOWN_KEYS = [
        "ID#", "Name",
        "metric",
    ]
    RULE_REQUIRED_KEYS = [
        "ID#", "metric",
    ]

    def __init__(self, logger):
        super().__init__()
        self._logger = logger
        self._generic = {}
        self._per_device = {}

    def _check_keys(self, dict_, known_keys, required_keys, at):
        existing = set(dict_.keys())
        unknown = existing - set(known_keys)
        missing = set(required_keys) - existing

        for unknown_key in unknown:
            self._logger.warning(
                "unknown configuration key %r at %s",
                unknown_key, at,
            )

        if missing:
            raise ValueError("missing configuration keys at {}: {}".format(
                at,
                ", ".join(map(repr, missing))
            ))

    def _load_rules(self, rules):
        for rule in rules:
            self._logger.debug("interpreting rule %r", rule)
            self._check_keys(rule,
                             self.RULE_KNOWN_KEYS,
                             self.RULE_REQUIRED_KEYS,
                             "rule")

            idno = int(rule["ID#"])
            name_regex_src = rule.get("Name", None)
            if not name_regex_src:
                name_regex = None
            else:
                name_regex = re.compile(name_regex_src)
            metric = rule["metric"]

            yield (idno, name_regex, metric)

    def _extend_rules(self, rules, new_rules):
        for idno, name_regex, metric in new_rules:
            rules.setdefault(idno, []).append((name_regex, metric))

    def load(self, f):
        data = ast.literal_eval(f.read())

        self._check_keys(
            data,
            self.TOPLEVEL_KNOWN_KEYS,
            [],
            "toplevel",
        )

        self._logger.debug("loading generic rules")
        self._extend_rules(
            self._generic,
            self._load_rules(
                data.get("generic", []),
            )
        )

        self._logger.debug("loading per-device rules")
        for per_device_rule in data.get("per-device", []):
            self._logger.debug("interpreting per-device rules %r",
                               per_device_rule)
            self._check_keys(
                per_device_rule,
                self.PER_DEVICE_RULES_KNOWN_KEYS,
                self.PER_DEVICE_RULES_REQUIRED_KEYS,
                "per-device rule",
            )

            rules = list(
                self._load_rules(
                    per_device_rule["rules"],
                )
            )

            for device in per_device_rule["Devices"]:
                self._extend_rules(
                    self._per_device.setdefault(device, {}),
                    rules
                )

        self._logger.debug("finished")

    def stats(self):
        return "{} generic rules, {} per device rules for {} devices".format(
            len(self._generic),
            sum(len(rules) for rules in self._per_device.values()),
            len(self._per_device),
        )

    def _get_metric_for_attribute_from_rules(self, rules, id_, name):
        id_rules = rules.get(int(id_), [])
        for name_regex, metric in id_rules:
            if name_regex is None:
                return metric
            if name_regex.match(name):
                return metric
        raise KeyError((id_, name))

    @functools.lru_cache()
    def get_metric_for_attribute(self, device, id_, name):
        device_rules = self._per_device.get(device, {})
        try:
            return self._get_metric_for_attribute_from_rules(
                device_rules, id_, name
            )
        except KeyError:
            return self._get_metric_for_attribute_from_rules(
                self._generic, id_, name
            )


def process_attrmap(f, logger):
    mapping = AttributeMapping(logger)
    mapping.load(f)
    return mapping


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
        "-p", "--listen-port",
        default=9134,
        metavar="PORT",
        type=int,
        help="Port number to bind to (default: 9134)",
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

    logging.basicConfig(
        level={
            0: logging.ERROR,
            1: logging.WARNING,
            2: logging.INFO,
        }.get(args.verbosity, logging.DEBUG)
    )

    if args.device_db is None:
        logger.debug("no --device-db specified, using default %r",
                     DEFAULT_DEVICE_DB)
        try:
            args.device_db = open(DEFAULT_DEVICE_DB, "r")
        except OSError as exc:
            logger.error("failed to open device database: %s", exc)
            logger.info(
                "check that it exists and is accessible, or use --device-db to"
                " specify a different database.",
            )
            sys.exit(2)

    with args.device_db as f:
        device_db = DeviceDB(logging.getLogger("devdb"))
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
            args.attr_mapping = open(DEFAULT_ATTR_MAPPING, "r")
        except OSError as exc:
            logger.error("failed to open attribute mapping: %s", exc)
            logger.info(
                "check that it exists and is accessible, or use --attr-mapping"
                " to specify a different file.",
            )
            sys.exit(2)

    with args.attr_mapping as f:
        try:
            attr_mapping = process_attrmap(f, logging.getLogger("attrmap"))
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
