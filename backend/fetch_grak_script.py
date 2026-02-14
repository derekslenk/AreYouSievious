#!/usr/bin/env python3
"""Fetch the active grak sieve script for testing."""
from sievelib.managesieve import Client

HOST = "mail.slenk.email"
PORT = 4190
USER = "derek@slenk.com"

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
    import os
    os.makedirs("test_scripts", exist_ok=True)
    fetch()
