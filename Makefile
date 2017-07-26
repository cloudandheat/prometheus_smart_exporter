PREFIX ?= /usr/local

systemd_units = $(wildcard systemd/*.service) $(wildcard systemd/*.socket)

all:

install:
	install -d 755 $(DESTDIR)/lib/systemd/system/
	install -m 644 $(systemd_units) $(DESTDIR)/lib/systemd/system/
	install -d 755 $(DESTDIR)/etc/prometheus_smart_exporter/

.PHONY: install
