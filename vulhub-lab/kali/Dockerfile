# Minimal Kali-based scanner/attacker image: just the tools Argus-AI's
# Discovery/Validation allowlist is permitted to drive, plus Python 3.10+ to
# run the argus package itself (stdlib-only, no pip install needed).
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
