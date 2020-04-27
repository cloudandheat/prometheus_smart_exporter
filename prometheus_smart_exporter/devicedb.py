########################################################################
# File name: devicedb.py
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


class DeviceDB:
    def __init__(self, logger):
        super().__init__()
        self._logger = logger
        self._devices = {}

    def load(self, f):
        data = ast.literal_eval(f.read())

        devices = data["Devices"]

        for device_info in devices.values():
            self._logger.debug("interpreting %r", device_info)

            ids = {
                int(id_): {
                    "RAW_VALUE": "Raw",
                    "VALUE": "Value",
                }[type_['value']]
                for id_, type_ in device_info["ID#"].items()
            }
            threshs = {
                int(id_): (warn, crit)
                for id_, (warn, crit, *_) in device_info["Threshs"].items()
            }
            perfs = set(map(int, device_info["Perfs"]))
            self._logger.debug("found ID#=%r", ids)
            self._logger.debug("found Threshs=%r", threshs)
            self._logger.debug("found Perfs=%r", perfs)

            for device in device_info["Device"]:
                self._logger.debug("updating %r with said info", device)
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
