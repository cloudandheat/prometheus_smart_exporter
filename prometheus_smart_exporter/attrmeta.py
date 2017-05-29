########################################################################
# File name: attrmeta.py
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
import functools
import re

import enum


class MetricType(enum.Enum):
    GAUGE = "gauge"
    COUNTER = "counter"


class AttributeMapping:
    TOPLEVEL_KNOWN_KEYS = [
        "generic",
        "per-device",
    ]

    RULE_KNOWN_KEYS = [
        "id",
        "match",
        "name",
        "type",
    ]

    RULE_REQUIRED_KEYS = [
        "id",
        "name",
        "type",
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

            idno = int(rule["id"])
            name_regex_src = rule.get("match", None)
            if not name_regex_src:
                name_regex = None
            else:
                name_regex = re.compile(name_regex_src)
            metric_name = rule["name"]
            type_ = MetricType(rule["type"])

            yield (idno, name_regex, metric_name, type_)

    def _extend_rules(self, rules, new_rules):
        for idno, name_regex, metric_name, type_ in new_rules:
            rules.setdefault(idno, []).append((name_regex, metric_name, type_))

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

        # self._logger.debug("loading per-device rules")
        # for per_device_rule in data.get("per-device", []):
        #     self._logger.debug("interpreting per-device rules %r",
        #                        per_device_rule)
        #     self._check_keys(
        #         per_device_rule,
        #         self.PER_DEVICE_RULES_KNOWN_KEYS,
        #         self.PER_DEVICE_RULES_REQUIRED_KEYS,
        #         "per-device rule",
        #     )

        #     rules = list(
        #         self._load_rules(
        #             per_device_rule["rules"],
        #         )
        #     )

        #     for device in per_device_rule["Devices"]:
        #         self._extend_rules(
        #             self._per_device.setdefault(device, {}),
        #             rules
        #         )

        self._logger.debug("finished")

    def stats(self):
        return "{} generic rules, {} per device rules for {} devices".format(
            len(self._generic),
            sum(len(rules) for rules in self._per_device.values()),
            len(self._per_device),
        )

    def _get_metric_for_attribute_from_rules(self, rules, id_, name):
        id_rules = rules.get(int(id_), [])
        for name_regex, metric, type_ in id_rules:
            if name_regex is None:
                return metric, type_
            if name_regex.match(name):
                return metric, type_
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
