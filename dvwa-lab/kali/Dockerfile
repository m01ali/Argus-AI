# Kali-based scanner/attacker image for the DVWA lab.
#
# Identical toolbox to the metasploitable-lab scanner (kept the same so the
# built image layers are cache-shared). For DVWA the web tools do the work —
# nikto, sqlmap, whatweb, gobuster, curl, hydra (login brute) — plus mysql to
# talk to the DB behind a successful SQL injection. Python 3 runs argus itself.
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
