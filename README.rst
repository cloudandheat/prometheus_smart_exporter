S.M.A.R.T. exporter for Prometheus
##################################

This is a `Prometheus Exporter <https://prometheus.io/docs/instrumenting/exporters/>`_ which exports S.M.A.R.T. metrics.

Core Features
=============

* Secure: only the absolute necessary part of the code runs as root, in a separate process
* No guessing: re-uses the device database from the `check_smart_attributes`_ nagios check.

Architecture
============

We want to avoid having a service running as root exposed to the network. This is why the S.M.A.R.T. exporter is split in two parts:

1. a helper which runs as root (``smart_exporter_helper``)
2. the HTTP server which serves the data (``prometheus_smart_exporter``)

The helper runs as a service listening on UNIX socket (ideally managed by systemd, but can also be managed by the helper itself). When a client connects to the socket, the helper reads S.M.A.R.T. metrics and sends them to the client as serialised Python dict wrapped in a simple binary format.

The exporter listens on HTTP and when asked to export data, it connects to the UNIX socket and receives the current S.M.A.R.T. metrics. All interpretation, filtering and Prometheus-specific formatting of the data is done in the exporter and as unprivilegued user.

Socket Protocol
---------------

The binary protocol is dead-simple:

+-----------+-------------------+----------------------------------------------------------+
|Byte range |Type               |Usage                                                     |
+===========+===================+==========================================================+
|0          |unsigned           |Protocol Version. Must be ``1``.                          |
+-----------+-------------------+----------------------------------------------------------+
|1-8        |unsigned           |Length of the data in bytes                               |
+-----------+-------------------+----------------------------------------------------------+
|9..end     |UTF-8 encoded text |``repr()`` of python dict containing the S.M.A.R.T. data. |
+-----------+-------------------+----------------------------------------------------------+


Security
--------

Since part of this code runs as root, this deserves its own section. The helper is the only process which is supposed to run as root. Do **not** run the exporter itself as root.

The helper is less than 300 lines of nearly dependency-free (the exception are the systemd helpers for socket activation and journalling) python, making it easy to audit. It does not accept input from its clients (in fact, it immediately closes the receiving direction of the socket once it is accepted).


Installation
============

Install via PyPI:

.. code-block:: sh

   pip3 install prometheus_smart_exporter

Installation via PyPI does *not* install any system-wide configuration. You need to do that yourself.


Configuration
=============

Services and Sockets
--------------------

It is recommended to use systemd to manage the UNIX socket for the helper. It allows you fine control over the user, group and mode of the socket, thus allowing to expose the socket only to the exporter process. In addition, at allows for seamless restarts of the helper service.

Example service files for use with systemd are included in the `git repository`_.

.. _device-db:

S.M.A.R.T. device database
--------------------------

This exporter uses a device database in the same format as the famous nagios `check_smart_attributes`_ does. If you already use or have used the ``check_smart_attributes``, you can simply continue using your device database. Otherwise, you will find a device database in the linked github repository.

The only information used from the device DB is the information whether a ``RAW_VALUE`` or a ``VALUE`` should be exported. At some point, it may be configurable to only export metrics for values which have thresholds and/or perfs set.


.. _attr-mapping:

Attribute Mapping
-----------------

An additional JSON file specifies how S.M.A.R.T. attributes are mapped to Prometheus metric names. It defines rules which, based on the S.M.A.R.T. attribute ID and name, decide the type and name of the Prometheus metric.

The basic format is the following:

.. code-block:: json

   {
     "generic": [
       < rules ... >
     ]
   }

Each ``rule`` looks like this:

.. code-block:: json

   {
     "id": < integer >,
     "match": < regular expression as string >,
     "name": < string >,
     "type": < "counter" or "gauge" >
   }

``"id"``
  is mandatory and the S.M.A.R.T. attribute ID for which this rule is used
``"match"``
  is an optional regular expression. Only if the name of the attribute matches the regular expression, the rule is applied.
``"name"``
  the name of the Prometheus metric to use. All metric names are automatically prefixed with ``smart_``; the prefix must not be included in the ``"name"`` attribute.
``"type"``
  the type of the Prometheus metric to use (generally ``"gauge"`` or ``"counter"``).

A default attribute mapping is included in the package itself. Pull requests for additional rules are welcome.

Helper
------

The helper is configured using command line arguments only.

.. code-block::

   usage: smart_exporter_helper [-h] [--socket-path SOCKET_PATH]
                                [--timeout TIMEOUT] [-v]

   optional arguments:
     -h, --help            show this help message and exit
     --socket-path SOCKET_PATH
                           Path at which the unix socket will be created.
                           Required if the process is not started via systemd
                           socket activation.
     --timeout TIMEOUT     Time in seconds to wait between connections. Defaults
                           to infinity.
     -v

``--timeout``
  specifies the time for which the service stays alive after finishing the last request. This can be used to help conserve memory at the cost of measurement latency and CPU/disk-IO.

``--socket-path``
  If systemd socket activation is not used, this argument must be given to specify at which location the socket shall be created. If a socket is already present at that location, it is unlinked at startup and replaced with a fresh socket. In general, it is recommended to use systemd with socket activation instead.

HTTP Exporter
-------------

The HTTP exporter is configured using the aforementioned JSON files and command line arguments.

.. code-block::

   usage: prometheus_smart_exporter [-h] [--device-db DEVICE_DB]
                                    [--attr-mapping ATTR_MAPPING] [-v]
                                    [--journal] [-p PORT] [-a ADDR]
                                    socket

   positional arguments:
     socket                Path to UNIX socket where the helper listens

   optional arguments:
     -h, --help            show this help message and exit
     --device-db DEVICE_DB
                           Device database in JSON format (default:
                           /usr/share/ch-monitoring-smart-data/devices.json)
     --attr-mapping ATTR_MAPPING
                           Attribute mapping in JSON format (default: <...>)
     -v                    Increase verbosity (up to -vvv)
     --journal             Log to systemd journal
     -p PORT, --listen-port PORT
                           Port number to bind to (default: 9257)
     -a ADDR, --listen-address ADDR
                           Address to bind to (default: 127.0.0.1)

``--device-db``
  path to the S.M.A.R.T. device database (see above)

``--attr-mapping``
  path to the attribute map attr-mapping (see above). By default, the attribute map delivered with the package is used.

``--journal``
  enable logging to the systemd journal. By default, logs go to standard output.

``--listen-port``
  configure the TCP port to bind to

``--listen-address``
  configure the TCP address to bind to

``socket``
  path to the UNIX socket where the helper listens


.. _check_smart_attributes: https://github.com/thomas-krenn/check_smart_attributes
.. _git repository: https://github.com/cloudandheat/prometheus_smart_exporter
