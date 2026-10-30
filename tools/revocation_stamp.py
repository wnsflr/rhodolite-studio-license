#!/usr/bin/env python3
# Copyright (c) 2026 Jun Shik Kim. All rights reserved.
"""Daily stamp of the Rhodolite Studio revocation list (SPEC §34.17). Runs in the licence repository's GitHub Action.

The owner keeps publishing ``revocations.json`` (the list of revoked licence ids, signed with the OWNER key on the
owner's laptop; every app version reads it). This tool only adds a fresh, signed timestamp: it checks the owner's
signature, then writes ``revocations-v2.json`` = the owner's list unchanged + a *stamp* signed with a separate,
revocation-only Ed25519 key whose private half exists only as the Actions secret ``REVOCATION_STAMP_KEY``. A stamp can
never add or remove a revoked id: the app takes the ids from the owner's signature and the stamp only proves that this
exact list was current on that day. Rhodolite Studio 0.5.1+ reads it; a stamp older than 30 days only shows the user
a soft note (the 30-day offline grace is the app's only lock).

Commands (Python 3.10+ and the ``cryptography`` package; nothing else, no network):

    revocation_stamp.py keygen --source <app source> --config-out stamp-config.json | gh secret set REVOCATION_STAMP_KEY ...
        Make the stamp key pair in memory. The PRIVATE key (base64 seed, one line) goes to standard output only, and
        only into a pipe (refused on a terminal, so it is never shown); it is never written to a file. The PUBLIC key and
        the owner public key embedded in <app source> go to stamp-config.json (commit it to the licence repository;
        ``keytool.py embed-stamp-key --stamp-key-file stamp-config.json`` embeds it in the app).
    revocation_stamp.py stamp --config stamp-config.json --list revocations.json --out revocations-v2.json [--dry-run]
        The private key comes from the environment variable REVOCATION_STAMP_KEY and must match the config's public
        key. --dry-run checks and signs everything but writes nothing (without the variable: with a throw-away key).
        A list dated more than an hour after this machine's clock is refused (the signing laptop's clock was ahead).
    revocation_stamp.py verify --config stamp-config.json --file revocations-v2.json [--max-age-days 3]
    revocation_stamp.py selftest
        Throw-away keys only: stamp, verify, and refuse a forged list, a foreign key and a moved stamp.

Formats (shared with the app, ``uma_relax/licensing/verify.py``; the tests check that both agree):
* owner list: ``{"format": "uma-licence-revocations", "version": 1, "kid", "payload", "signature"}``, payload =
  canonical JSON ``{"kid", "sequence", "issued_at", "revoked"}`` signed over ``b"uma-licence-revocations/v1\\0" + payload``;
* stamped file: ``{"format": "uma-licence-revocations-stamped", "version": 1, "list": <owner list>, "stamp": {"kid",
  "payload", "signature"}}``, stamp payload = canonical JSON ``{"kid", "list_kid", "list_sequence", "list_sha256",
  "stamped_at"}`` signed over ``b"uma-licence-revocation-stamp/v1\\0" + payload``; key id = the first 4 bytes of
  SHA-256(``b"uma-licence-kid\\0"`` + public key), upper-case hex.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

LIST_FORMAT = "uma-licence-revocations"
STAMPED_FORMAT = "uma-licence-revocations-stamped"
CONFIG_FORMAT = "uma-licence-revocation-stamp-config"
LIST_DOMAIN = b"uma-licence-revocations/v1\0"
STAMP_DOMAIN = b"uma-licence-revocation-stamp/v1\0"
KID_DOMAIN = b"uma-licence-kid\0"
ENV_KEY = "REVOCATION_STAMP_KEY"
MAX_LIST_BYTES = 1 << 20
#: an owner's list dated later than this ahead of the runner's clock is refused: the laptop that signed it had its clock
#: ahead, and the failed run e-mails the owner before any app sees the list
MAX_ISSUED_AHEAD = timedelta(hours=1)


class StampError(Exception):
    """A refusal with a plain message (exit code 2)."""


# --------------------------------------------------------------------------------------
# Small helpers (the same encodings as the app)
# --------------------------------------------------------------------------------------
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: Any, *, length: int | None = None) -> bytes:
    if not isinstance(text, str):
        raise ValueError("not a string")
    data = base64.b64decode(text.strip().encode("ascii"), validate=True)
    if length is not None and len(data) != length:
        raise ValueError(f"expected {length} bytes")
    return data


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(KID_DOMAIN + public_key).digest()[:4].hex().upper()


def pin(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(text: Any) -> datetime | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def canonical(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError:  # pragma: no cover - the Action installs it
        raise StampError("the 'cryptography' package is needed (pip install cryptography)") from None
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def public_bytes(private_key: Any) -> bytes:
    _, serialization, _, _ = _crypto()
    return private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def verify_sig(public_key: bytes, message: bytes, signature: bytes) -> bool:
    InvalidSignature, _, _, Ed25519PublicKey = _crypto()
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def load_private_key(seed_b64: str) -> Any:
    _, _, Ed25519PrivateKey, _ = _crypto()
    try:
        seed = unb64(seed_b64, length=32)
    except (ValueError, binascii.Error):
        raise StampError(f"{ENV_KEY} is not a base64 Ed25519 private key (32 bytes)") from None
    return Ed25519PrivateKey.from_private_bytes(seed)


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------------------
# Config, owner list, stamp
# --------------------------------------------------------------------------------------
def read_config(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StampError(f"cannot read the config {path} ({exc})") from None
    if not isinstance(doc, dict) or doc.get("format") != CONFIG_FORMAT:
        raise StampError(f"{path} is not a stamp config (format {CONFIG_FORMAT})")
    try:
        owner = unb64(doc.get("owner_public_key"), length=32)
        stamp = unb64(doc.get("stamp_public_key"), length=32)
    except (ValueError, binascii.Error):
        raise StampError(f"{path}: a public key is damaged") from None
    if doc.get("owner_key_id") and doc["owner_key_id"] != key_id(owner):
        raise StampError(f"{path}: owner_key_id does not match owner_public_key")
    if doc.get("stamp_key_pin") != pin(stamp):
        raise StampError(f"{path}: the stamp public key does not match its pin")
    if owner == stamp:
        raise StampError(f"{path}: the stamp key must be a separate key, never the owner key")
    return {"owner": owner, "stamp": stamp, "doc": doc}


def verify_owner_list(raw: bytes | str | dict[str, Any], owner_key: bytes) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """``(list document, its payload as JSON, payload bytes)``; StampError unless the owner signed it."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MAX_LIST_BYTES:
            raise StampError("the owner's list is too large")
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw.lstrip("﻿"))
        except ValueError:
            raise StampError("the owner's list is not JSON") from None
    if not isinstance(raw, dict) or raw.get("format") != LIST_FORMAT or raw.get("version") != 1:
        raise StampError(f"the owner's list is not a {LIST_FORMAT} v1 document")
    try:
        payload = unb64(raw.get("payload"))
        signature = unb64(raw.get("signature"), length=64)
    except (ValueError, binascii.Error):
        raise StampError("the owner's list has a damaged payload or signature") from None
    if not verify_sig(owner_key, LIST_DOMAIN + payload, signature):
        raise StampError("the owner's list is NOT signed by the owner key: refusing to stamp it")
    try:
        body = json.loads(payload.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise StampError("the owner's list has a damaged payload") from None
    if not isinstance(body, dict) or body.get("kid") != key_id(owner_key):
        raise StampError("the owner's list was made for another owner key")
    if not isinstance(body.get("sequence"), int) or body["sequence"] < 0 or parse_iso(body.get("issued_at")) is None:
        raise StampError("the owner's list has no sequence or date")
    return raw, body, payload


def make_stamp(list_doc: dict[str, Any], body: dict[str, Any], payload: bytes, private_key: Any,
               now: datetime) -> dict[str, Any]:
    stamp_pub = public_bytes(private_key)
    stamp_payload = canonical({
        "kid": key_id(stamp_pub),
        "list_kid": body["kid"],
        "list_sequence": body["sequence"],
        "list_sha256": hashlib.sha256(payload).hexdigest(),
        "stamped_at": iso_utc(now),
    })
    signature = private_key.sign(STAMP_DOMAIN + stamp_payload)
    return {
        "format": STAMPED_FORMAT,
        "version": 1,
        "list": list_doc,
        "stamp": {"kid": key_id(stamp_pub), "payload": b64(stamp_payload), "signature": b64(signature)},
    }


def stamped_text(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2) + "\n"


def verify_stamped(raw: bytes | str, owner_key: bytes, stamp_key: bytes) -> dict[str, Any]:
    """Check a stamped file like the app does; returns ``{sequence, revoked, issued_at, stamped_at}``."""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    try:
        doc = json.loads(raw.lstrip("﻿"))
    except ValueError:
        raise StampError("the stamped file is not JSON") from None
    if not isinstance(doc, dict) or doc.get("format") != STAMPED_FORMAT or doc.get("version") != 1:
        raise StampError(f"not a {STAMPED_FORMAT} v1 document")
    list_doc, body, payload = verify_owner_list(doc.get("list"), owner_key)
    stamp = doc.get("stamp")
    if not isinstance(stamp, dict):
        raise StampError("the stamp is missing")
    try:
        sp = unb64(stamp.get("payload"))
        sig = unb64(stamp.get("signature"), length=64)
    except (ValueError, binascii.Error):
        raise StampError("the stamp is damaged") from None
    if not verify_sig(stamp_key, STAMP_DOMAIN + sp, sig):
        raise StampError("the stamp's signature does not match the stamp key")
    try:
        s = json.loads(sp.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise StampError("the stamp is damaged") from None
    if not isinstance(s, dict):
        raise StampError("the stamp is damaged")
    if s.get("kid") != key_id(stamp_key) or s.get("list_kid") != body["kid"] or s.get("list_sequence") != body["sequence"] \
            or s.get("list_sha256") != hashlib.sha256(payload).hexdigest():
        raise StampError("the stamp belongs to another list or key")
    stamped_at = parse_iso(s.get("stamped_at"))
    if stamped_at is None:
        raise StampError("the stamp has no date")
    return {"sequence": body["sequence"], "revoked": len(body.get("revoked") or []), "issued_at": body["issued_at"],
            "stamped_at": stamped_at}


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------
def _embedded_owner_key(source: Path) -> bytes:
    """The owner public key embedded in the app source (``uma_relax/licensing/public_key.py``), checked against
    ``_pin.py``. Plain constants files: read with exec, nothing of the app is imported."""
    pkg = source / "uma_relax" / "licensing"
    ns_key: dict[str, Any] = {}
    ns_pin: dict[str, Any] = {}
    try:
        exec(compile((pkg / "public_key.py").read_text(encoding="utf-8"), "public_key.py", "exec"), ns_key)  # noqa: S102
        exec(compile((pkg / "_pin.py").read_text(encoding="utf-8"), "_pin.py", "exec"), ns_pin)  # noqa: S102
    except (OSError, SyntaxError) as exc:
        raise StampError(f"{source} is not the app source folder (no readable uma_relax/licensing/public_key.py: {exc})") from None
    try:
        owner = unb64(str(ns_key.get("OWNER_PUBLIC_KEY_B64") or ""), length=32)
    except (ValueError, binascii.Error):
        raise StampError(f"no owner public key is embedded in {source} (run keytool.py embed first)") from None
    if pin(owner) != str(ns_pin.get("PUBLIC_KEY_PIN") or "").lower():
        raise StampError(f"the owner public key in {source} does not match its pin")
    return owner


def cmd_keygen(args: argparse.Namespace) -> int:
    out = sys.stdout
    if out.isatty() and not args.allow_terminal:
        raise StampError("keygen writes the PRIVATE key to standard output, which is a terminal here: pipe it straight "
                         "into the secret instead, e.g.  ... keygen ... | gh secret set REVOCATION_STAMP_KEY --repo OWNER/REPO")
    config_out = Path(args.config_out)
    if config_out.exists() and not args.force:
        raise StampError(f"{config_out} exists already (a key pair was made before); pass --force to replace it, "
                         "then also replace the secret and re-embed the key")
    owner = _embedded_owner_key(Path(args.source).expanduser().resolve())
    _, _, Ed25519PrivateKey, _ = _crypto()
    sk = Ed25519PrivateKey.generate()
    pub = public_bytes(sk)
    from cryptography.hazmat.primitives import serialization

    seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    config = {
        "format": CONFIG_FORMAT,
        "version": 1,
        "owner_public_key": b64(owner),
        "owner_key_id": key_id(owner),
        "stamp_public_key": b64(pub),
        "stamp_key_id": key_id(pub),
        "stamp_key_pin": pin(pub),
        "list_file": "revocations.json",
        "stamped_file": "revocations-v2.json",
        "created": iso_utc(datetime.now(timezone.utc)),
        "note": "PUBLIC keys only. The stamp key's private half is only the Actions secret REVOCATION_STAMP_KEY.",
    }
    # the secret first: if the pipe is broken, no config is left behind for a key nobody holds
    out.write(b64(seed) + "\n")
    out.flush()
    _write_atomic(config_out, json.dumps(config, indent=2) + "\n")
    print(f"stamp key {key_id(pub)} made; private key written to the pipe only; public config: {config_out} "
          f"(owner key {key_id(owner)})", file=sys.stderr)
    return 0


def cmd_stamp(args: argparse.Namespace) -> int:
    cfg = read_config(Path(args.config))
    try:
        raw = Path(args.list).read_bytes()
    except OSError as exc:
        raise StampError(f"cannot read the owner's list {args.list} ({exc})") from None
    list_doc, body, payload = verify_owner_list(raw, cfg["owner"])
    try:  # the list stamped so far (none, or one under an earlier stamp key: nothing to compare with)
        previous = verify_stamped(Path(args.out).read_bytes(), cfg["owner"], cfg["stamp"])["sequence"]
    except (OSError, StampError):
        previous = None
    if previous is not None and body["sequence"] < previous:
        raise StampError(f"the owner's list is #{body['sequence']}, but {args.out} already stamps #{previous}: apps never "
                         "go back to a lower list number. Upload the newest revocations.json (keytool.py publish).")
    seed = os.environ.get(ENV_KEY, "")
    throwaway = False
    if seed.strip():
        sk = load_private_key(seed)
        if public_bytes(sk) != cfg["stamp"]:
            raise StampError(f"the secret {ENV_KEY} is not the private half of the stamp key in {args.config} "
                             f"(key id {key_id(public_bytes(sk))}, expected {key_id(cfg['stamp'])})")
    elif args.dry_run:
        _, _, Ed25519PrivateKey, _ = _crypto()
        sk = Ed25519PrivateKey.generate()
        throwaway = True
    else:
        raise StampError(f"the environment variable {ENV_KEY} is empty (the Actions secret is missing)")
    now = parse_iso(args.now) if args.now else datetime.now(timezone.utc)
    if now is None:
        raise StampError("--now must be an ISO time")
    issued = parse_iso(body["issued_at"])
    if issued is not None and issued - now > MAX_ISSUED_AHEAD:
        raise StampError(f"the owner's list #{body['sequence']} is dated {body['issued_at']}, later than this runner's "
                         f"clock ({iso_utc(now)}): the clock of the PC that signed it was ahead. Set that PC's date and "
                         "time correctly and publish again (keytool.py publish); nothing was stamped.")
    doc = make_stamp(list_doc, body, payload, sk, now)
    text = stamped_text(doc)
    check = verify_stamped(text, cfg["owner"], public_bytes(sk))
    summary = (f"list #{body['sequence']} ({check['revoked']} revoked, issued {body['issued_at']}) stamped "
               f"{iso_utc(now)} with key {key_id(public_bytes(sk))}")
    if args.dry_run:
        print(f"DRY RUN{' with a THROW-AWAY key (no ' + ENV_KEY + ')' if throwaway else ''}: {summary}; "
              f"{args.out} not written ({len(text)} bytes)")
        return 0
    _write_atomic(Path(args.out), text)
    verify_stamped(Path(args.out).read_bytes(), cfg["owner"], cfg["stamp"])
    print(f"{summary} -> {args.out}")
    if issued is not None and now - issued > timedelta(days=365):
        print("note: the owner's list itself is more than a year old (that is fine: the stamp keeps it fresh)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cfg = read_config(Path(args.config))
    try:
        raw = Path(args.file).read_bytes()
    except OSError as exc:
        raise StampError(f"cannot read {args.file} ({exc})") from None
    info = verify_stamped(raw, cfg["owner"], cfg["stamp"])
    age = datetime.now(timezone.utc) - info["stamped_at"]
    print(f"OK: list #{info['sequence']} ({info['revoked']} revoked), stamped {iso_utc(info['stamped_at'])} "
          f"({age.total_seconds() / 86400:.1f} days ago)")
    if args.max_age_days is not None and age > timedelta(days=args.max_age_days):
        raise StampError(f"the stamp is older than {args.max_age_days} days")
    if args.list:
        _, body, _ = verify_owner_list(Path(args.list).read_bytes(), cfg["owner"])
        if body["sequence"] != info["sequence"]:
            raise StampError(f"{args.file} carries list #{info['sequence']}, {args.list} is #{body['sequence']}: stamp again")
    return 0


def cmd_selftest(_args: argparse.Namespace) -> int:
    _, _, Ed25519PrivateKey, _ = _crypto()
    owner_sk, stamp_sk, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    owner_pub, stamp_pub = public_bytes(owner_sk), public_bytes(stamp_sk)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    body = {"kid": key_id(owner_pub), "sequence": 3, "issued_at": iso_utc(now - timedelta(days=90)),
            "revoked": [{"id": "0000-0000-0000-0001", "date": "2026-10-29"}]}
    payload = canonical(body)
    owner_list = {"format": LIST_FORMAT, "version": 1, "kid": key_id(owner_pub), "payload": b64(payload),
                  "signature": b64(owner_sk.sign(LIST_DOMAIN + payload))}
    lst, body2, payload2 = verify_owner_list(json.dumps(owner_list), owner_pub)
    text = stamped_text(make_stamp(lst, body2, payload2, stamp_sk, now))
    info = verify_stamped(text, owner_pub, stamp_pub)
    assert info["sequence"] == 3 and info["stamped_at"] == now and info["revoked"] == 1
    failures = []
    # a list the owner did not sign is never stamped
    forged = dict(owner_list, payload=b64(canonical(dict(body, revoked=[]))))
    try:
        verify_owner_list(json.dumps(forged), owner_pub)
        failures.append("a forged owner list was accepted")
    except StampError:
        pass
    # a stamp by another key, and a stamp moved onto another list, are refused
    try:
        verify_stamped(stamped_text(make_stamp(lst, body2, payload2, other, now)), owner_pub, stamp_pub)
        failures.append("a stamp by a foreign key was accepted")
    except StampError:
        pass
    doc = json.loads(text)
    body3 = dict(body, sequence=4)
    payload3 = canonical(body3)
    doc["list"] = dict(owner_list, payload=b64(payload3), signature=b64(owner_sk.sign(LIST_DOMAIN + payload3)))
    try:
        verify_stamped(json.dumps(doc), owner_pub, stamp_pub)
        failures.append("a stamp moved onto another list was accepted")
    except StampError:
        pass
    if failures:
        raise StampError("selftest FAILED: " + "; ".join(failures))
    print("selftest OK: stamp + verify, forged list refused, foreign key refused, moved stamp refused")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="revocation_stamp.py", description=__doc__.splitlines()[1] if __doc__ else None)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="make the stamp key pair (private key to a pipe only, public config to a file)")
    k.add_argument("--source", required=True, help="the app source folder (its embedded owner public key goes into the config)")
    k.add_argument("--config-out", required=True, help="stamp-config.json to write (public keys only)")
    k.add_argument("--force", action="store_true", help="replace an existing config (a new key pair)")
    k.add_argument("--allow-terminal", action="store_true", help=argparse.SUPPRESS)  # tests only
    s = sub.add_parser("stamp", help="stamp the owner's list (private key from $REVOCATION_STAMP_KEY)")
    s.add_argument("--config", required=True)
    s.add_argument("--list", required=True, help="the owner's revocations.json")
    s.add_argument("--out", required=True, help="revocations-v2.json to write")
    s.add_argument("--dry-run", action="store_true", help="check and sign, write nothing")
    s.add_argument("--now", default=None, help=argparse.SUPPRESS)  # tests only: a fixed stamp time
    v = sub.add_parser("verify", help="check a stamped file like the app does")
    v.add_argument("--config", required=True)
    v.add_argument("--file", required=True)
    v.add_argument("--list", default=None, help="also require the same list sequence as this owner's file")
    v.add_argument("--max-age-days", type=float, default=None)
    sub.add_parser("selftest", help="throw-away keys: stamp, verify, refusals")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"keygen": cmd_keygen, "stamp": cmd_stamp, "verify": cmd_verify, "selftest": cmd_selftest}[args.cmd](args)
    except StampError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
