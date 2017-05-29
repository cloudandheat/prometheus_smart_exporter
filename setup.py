########################################################################
# File name: setup.py
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
from setuptools import setup, find_packages

setup(
    name="ch-prometheus-smart-exporter",
    version="0.1",
    description="S.M.A.R.T. exporter for Prometheus",
    url="https://gitlab.cloudandheat.com/jonas.wielicki/prometheus_smart_exporter",
    author="Jonas Wielicki",
    author_email="jonas.wielicki@cloudandheat.com",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "prometheus_smart_exporter=prometheus_smart_exporter:main",
            "smart_exporter_helper=smart_exporter_helper:main",
        ]
    },
    install_requires=[
        "prometheus_client>=0.0.14",
        "systemd_python"
    ]
)
