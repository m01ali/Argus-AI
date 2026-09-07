# Kali-based scanner/attacker image for the Metasploitable lab.
#
# It's the vulhub-lab scanner toolset (the tools Argus-AI's Discovery/Validation
# allowlist may drive) PLUS the extra protocol clients you actually need to
# interact with Metasploitable2's many services — ftp, telnet, rpcinfo,
# showmount (NFS), mysql, psql, snmpwalk, nc, finger, hydra. Python 3 runs the
# argus package itself (stdlib-only, no pip install needed).
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        nikto \
        sqlmap \
        whatweb \
        gobuster \
        enum4linux \
        smbclient \
        dnsutils \
        whois \
        curl \
        nbtscan \
        redis-tools \
        exploitdb \
        ftp \
        telnet \
        rpcbind \
        nfs-common \
        default-mysql-client \
        postgresql-client \
        snmp \
        netcat-traditional \
        finger \
        hydra \
        python3 \
        python-is-python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Not chained with && above: the apt-installed exploitdb tree isn't a git
# checkout, so `searchsploit -u` fails there. Don't fail the build over it —
# the packaged database is fresh enough to detect the CVEs this lab targets.
RUN searchsploit -u || true

WORKDIR /opt/argus-ai
CMD ["/bin/bash"]
