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
import os.path

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="prometheus_smart_exporter",
    version="0.2.2",
    description="S.M.A.R.T. exporter for Prometheus",
    long_description=long_description,
    url="https://github.com/cloudandheat/prometheus_smart_exporter",
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
    ],
    package_data={
        "prometheus_smart_exporter": [
            "data/attrmap.json",
        ]
    },
    keywords="prometheus smart monitoring hdd ssd",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Operating System :: Unix",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Monitoring",
    ]
)
