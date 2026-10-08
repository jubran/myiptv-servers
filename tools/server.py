#!/usr/bin/env python3
"""Manage the server details (host / port / username / password) used by My IPTV invites.

Each server entry is AES-256-GCM encrypted with a random 32-byte key. The key is kept ONLY in the local,
git-ignored file `keys.local.json` and inside the (encrypted) invites in the myiptv-invites repo — so the
public servers.json is unreadable on its own.

  python3 tools/server.py set NAME --host H --port P --user U [--https]   (asks for the password)
  python3 tools/server.py remove NAME
  python3 tools/server.py list

Updating a server (new host, password, port...) keeps the same key, so EXISTING INVITES KEEP WORKING and the
app picks the change up on its next launch:
  python3 tools/server.py set main --host new.example.com --port 8080 --user U
  git add servers.json && git commit -m "update server" && git push
Never commit keys.local.json. Back it up somewhere private: losing it means re-issuing invites.
"""
import argparse, base64, getpass, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
SERVERS = os.path.join(HERE, "..", "servers.json")
KEYS = os.environ.get("MYIPTV_KEYS", os.path.join(HERE, "..", "keys.local.json"))


def read(path, default):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return default


def write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set")
    s.add_argument("name")
    s.add_argument("--host", required=True)
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--user", required=True)
    s.add_argument("--https", action="store_true")
    s.add_argument("--password", help="omit to be prompted (keeps it out of shell history)")
    r = sub.add_parser("remove")
    r.add_argument("name")
    sub.add_parser("list")
    args = ap.parse_args()

    servers = read(SERVERS, {"version": 1, "servers": {}})
    keys = read(KEYS, {})

    if args.cmd == "list":
        for n in servers["servers"]:
            print(n, "(key present)" if n in keys else "(KEY MISSING)")
        return
    if args.cmd == "remove":
        servers["servers"].pop(args.name, None)
        keys.pop(args.name, None)
        write(SERVERS, servers); write(KEYS, keys)
        print("removed")
        return

    if args.name not in keys:
        keys[args.name] = base64.b64encode(os.urandom(32)).decode()
        print("new server: generated key (saved to keys.local.json)")
    key = base64.b64decode(keys[args.name])
    password = args.password or getpass.getpass("Password: ")
    payload = json.dumps(
        {"host": args.host, "port": args.port, "username": args.user, "password": password, "https": args.https},
        separators=(",", ":"),
    ).encode()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, payload, None)
    servers["servers"][args.name] = {"nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}
    write(SERVERS, servers); write(KEYS, keys)
    print("saved", args.name)


if __name__ == "__main__":
    main()
