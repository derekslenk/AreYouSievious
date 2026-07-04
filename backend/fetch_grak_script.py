#!/usr/bin/env python3
"""Fetch the active sieve scripts from a remote ManageSieve server for local testing.

Required environment variables:
    AYS_FETCH_HOST  — ManageSieve hostname (e.g. mail.example.com)
    AYS_FETCH_USER  — account username/email

Reads the password interactively via getpass. Outputs to test_scripts/<name>.sieve.

Usage:
    AYS_FETCH_HOST=mail.example.com AYS_FETCH_USER=you@example.com \\
        python backend/fetch_grak_script.py
"""

import os

from sievelib.managesieve import Client

HOST = os.environ["AYS_FETCH_HOST"]
PORT = 4190
USER = os.environ["AYS_FETCH_USER"]


def fetch():
    import getpass

    pw = getpass.getpass(f"Password for {USER}: ")
    c = Client(HOST, PORT)
    c.connect(USER, pw, starttls=True)
    scripts = c.listscripts()
    print(f"Scripts: {scripts}")
    for name, active in scripts:
        print(f"\n{'[ACTIVE] ' if active else ''}{name}:")
        ok, script = c.getscript(name)
        if ok:
            with open(f"test_scripts/{name}.sieve", "w") as f:
                f.write(script)
            print(f"  Saved to test_scripts/{name}.sieve ({len(script)} bytes)")


if __name__ == "__main__":
    os.makedirs("test_scripts", exist_ok=True)
    fetch()
