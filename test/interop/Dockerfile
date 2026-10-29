# net-snmp's command line tools and libsmi's smilint, for the interop tests (test/interop/run.sh).
# Debian ships neither tool with the IETF MIB modules, so net-snmp's own copies of them come from
# its release tarball.
FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends snmp snmptrapd smitools libsnmp-base ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/net-snmp/net-snmp/archive/refs/tags/v5.9.4.tar.gz -o /tmp/ns.tgz \
 && mkdir -p /usr/share/snmp/mibs-ietf \
 && tar -xzf /tmp/ns.tgz -C /tmp net-snmp-5.9.4/mibs \
 && cp /tmp/net-snmp-5.9.4/mibs/*.txt /usr/share/snmp/mibs-ietf/ \
 && rm -rf /tmp/ns.tgz /tmp/net-snmp-5.9.4
ENV MIBDIRS=/usr/share/snmp/mibs:/usr/share/snmp/mibs-ietf:/mibs
ENV SMIPATH=/usr/share/snmp/mibs-ietf:/usr/share/snmp/mibs:/mibs
