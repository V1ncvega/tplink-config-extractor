#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tplink_config_extract.py — extract/decrypt TP-Link router backup files
(config.bin, backup-*.bin) into human-readable form.

Auto-detects the container scheme among the ones publicly known so far:

  1. plain XML (unencrypted)
  2. DES-ECB + MD5 + LZTP compression   (classic; key 478DA50BF9E3D2CF & friends)
  3. DES-ECB + MD5 + plain XML          (very old models, uncompressed)
  4. AES-128-CBC "0123…" / "1234…" → tar (firmware ~2022, e.g. Archer C7 v5)
  5. OpenSSL salted EVP aes-256-cbc -k <model name> (LuCI-era, e.g. Archer C9 v5)
  6. AES-256-CBC with RE200 hardcoded key/iv (single layer)
  7. DES after stripping a 80-148 byte header → zlib (WR841N generation)
  8. LuCI two-layer stack (2022-2025, AX/RE generation, LuCI firmware):
       AES-256-CBC → zlib/gzip → [MD5] → tar → per-file AES-256-CBC → zlib/gzip → XML

Usage:
    python3 tplink_config_extract.py config.bin
    python3 tplink_config_extract.py backup-ArcherC7-2026-01-31.bin -o out/
    python3 tplink_config_extract.py config.bin --password ArcherC9
    python3 tplink_config_extract.py config.bin --show-secrets

Dependency: pycryptodome   (pip install pycryptodome)

Credits:
  - LZTP (de)compression logic adapted from tpconf_bin_xml by Alain Ducharme
    (GPL-3.0), https://github.com/sta-c0000/tpconf_bin_xml
  - Classic DES key discovered by teknoraver.net
  - crypto.lua AES-256 key/IV from the CVE-2022-30075 PoC by Tomas Melicher
    (Archer AX50), https://github.com/aaronsvk/CVE-2022-30075
  - Two-layer 2024-2025 structure documented by Cisco Talos (TALOS-2025-2304)
  - AES-128-CBC "2022" scheme by github.com/ret5et/tplink_backup_decrypt_2022.bin

License: GPL-3.0 (see LICENSE)
"""

import argparse
import bz2
import hashlib
import io
import lzma
import os
import re
import struct
import sys
import tarfile
import zlib

try:
    from Crypto.Cipher import DES, AES
    from Crypto.Util.Padding import unpad as pkcs7_unpad
except ImportError:
    sys.exit("pycryptodome is required:  pip install pycryptodome")

__version__ = "1.0.0"

md5 = hashlib.md5

# ----------------------------------------------------------------------
# Container format constants
# ----------------------------------------------------------------------

AES_BLOCK = 16
MD5_LEN = 16                      # classic formats prepend md5(payload)

TAR_MAGIC = b"ustar"
TAR_MAGIC_OFFSET = 257            # magic sits inside the first header block
TAR_MAGIC_END = TAR_MAGIC_OFFSET + len(TAR_MAGIC)

OPENSSL_MAGIC = b"Salted__"
OPENSSL_SALT_START = 8            # right after the magic
OPENSSL_SALT_END = OPENSSL_SALT_START + 8

MAX_UNCOMPRESSED = 4 * 1024 * 1024   # sanity limit for decompressed data
PROBE_OFFSETS = (0, 2, 4, 8, 16, 20, 24)  # skip possible size/header prefixes
ZLIB_GZIP_PROBE_OFFSETS = (0, 2, 4)
HEADER_STRIP_SIZES = (144, 148, 128, 96, 80)  # WR841N-era cleartext headers
MAX_TRAILING_PAD = 8                   # payload may carry up to 7 pad bytes

LZTP_GUARD_MULT = 4    # iteration cap relative to output size (runaway guard)
LZTP_GUARD_EXTRA = 100

PRINT_SAMPLE = 4096        # bytes sampled by printable_ratio
PRINTABLE_THRESHOLD = 0.9  # share of printable bytes that means "text"
TAG_COL_WIDTH = 42         # column width in the settings summary

# ----------------------------------------------------------------------
# Known firmware keys (public research; see the module docstring credits)
# ----------------------------------------------------------------------

DEFAULT_DES_KEY = b"\x47\x8D\xA5\x0B\xF9\xE3\xD2\xCF"

DES_KEYS = {
    "default (478DA50BF9E3D2CF)": DEFAULT_DES_KEY,
    "variant (478DA50FF9E3D2CB)": b"\x47\x8D\xA5\x0F\xF9\xE3\xD2\xCB",
    "xz005-g6":                   b"\x45\xEE\x92\x32\xCF\x5B\x1D\xFE",
    "ex230v-v1":                  b"\x40\xB4\x93\x33\xC9\x0B\x1D\xFE",
    "vc220-g3u":                  b"\x40\xEC\xC4\x3A\xCA\x0A\x1D\xFE",
    "bsn3000x-v1":                b"\x44\xBF\xC3\x3B\x9D\x0C\x1D\xFD",
    "ex221-g5v1":                 b"\x45\xE8\x90\x6F\x9A\x0A\x1D\xFE",
    "ex530v-v1":                  b"\x40\xBA\xC6\x6C\xCA\x5A\x1C\xFE",
}

# AES-128 "2022 scheme" (produces a tar archive)
AES128_KEY = b"0123456789abcdef"
AES128_IV  = b"1234567890abcdef"

# AES-256-CBC hardcoded in /usr/lib/lua/luci/model/crypto.lua
# (AX and RE generations, 2022-2025)
LUCI_KEY = bytes.fromhex("2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836")
LUCI_IV  = bytes.fromhex("360028C9064242F81074F4C127D299F6")

# Extra guesses for the OpenSSL-EVP scheme (the router's product name family,
# most common product-name spellings first)
DEFAULT_PASSWORD_GUESSES = (
    "ArcherC7", "ArcherC7v5", "ArcherC9", "ArcherC9v5", "ArcherA7",
    "ArcherAX23", "ArcherAX50", "ArcherAX53", "ArcherAX55",
    "Archer", "TP-LINK", "tplink",
)


def step(msg):   print(f"  [i] {msg}")
def good(msg):   print(f"  [+] {msg}")
def bad(msg):    print(f"  [-] {msg}")


def hexdump(data, n=64):
    """Classic hexdump preview: offset, hex bytes, printable ASCII."""
    out = []
    for i in range(0, min(len(data), n), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:08x}  {hexs:<48}  {text}")
    return "\n".join(out)


def printable_ratio(data, sample=PRINT_SAMPLE):
    """Share of printable ASCII in the first `sample` bytes."""
    if not data:
        return 0.0
    data = data[:sample]
    ok = sum(1 for b in data if b in b"\t\n\r" or 32 <= b < 127)
    return ok / len(data)


def looks_like_xml(data):
    """Heuristic: starts with <?xml or is overwhelmingly printable markup."""
    head = data[:64].lstrip(b"\x00 \t\r\n")
    if head.startswith(b"<?xml"):
        return True
    return printable_ratio(data) > PRINTABLE_THRESHOLD and b"</" in data[:8192]


def strip_pkcs7_padding(plain):
    """Remove PKCS#7 padding; return the input unchanged if it looks invalid."""
    if not plain:
        return plain
    pad = plain[-1]
    if 0 < pad <= AES_BLOCK and plain[-pad:] == bytes([pad]) * pad:
        return plain[:-pad]
    return plain


# ---------------------------------------------------------------------- LZTP
def lztp_uncompress(src):
    """LZTP (cen_uncompressBuff) — TP-Link's custom LZ, ported from tpconf_bin_xml.

    First 4 bytes: uncompressed size (either endianness); 16-bit control words
    use native byte order of the compressing host — both variants are tried.
    """
    for size_endian in (">I", "<I"):
        size = struct.unpack_from(size_endian, src, 0)[0]
        if not (0 < size <= MAX_UNCOMPRESSED):
            continue
        for bit_endian in ("<H", ">H"):
            block16_countdown = 0
            block16_dict_bits = 0
            s_p = 5

            def get_bit():
                nonlocal block16_countdown, block16_dict_bits, s_p
                if block16_countdown:
                    block16_countdown -= 1
                else:
                    block16_dict_bits = struct.unpack_from(bit_endian, src, s_p)[0]
                    s_p += 2
                    block16_countdown = 0xF
                block16_dict_bits <<= 1
                return 1 if block16_dict_bits & 0x10000 else 0

            def get_dict_ld():
                bits = 1
                while True:
                    bits = (bits << 1) + get_bit()
                    if not get_bit():
                        break
                return bits

            dst = bytearray(size)
            try:
                dst[0] = src[4]
                d_p = 1
                guard = 0
                while d_p < size:
                    guard += 1
                    if guard > size * LZTP_GUARD_MULT + LZTP_GUARD_EXTRA:
                        raise ValueError("runaway")
                    if get_bit():
                        num_chars = get_dict_ld() + 2
                        msb = (get_dict_ld() - 2) << 8
                        lsb = src[s_p]; s_p += 1
                        offset = d_p - (lsb + 1 + msb)
                        if offset < 0:
                            raise ValueError("bad offset")
                        for _ in range(num_chars):
                            dst[d_p] = dst[offset]; d_p += 1; offset += 1
                    else:
                        dst[d_p] = src[s_p]; s_p += 1; d_p += 1
                return bytes(dst), f"{size_endian}/{bit_endian}"
            except Exception:
                continue
    return None, None


# ----------------------------------------------------------- generic unpackers
DECOMPRESS_LABELS = {"zlib": "zlib", "gzip": "gzip", "xz": "xz/lzma", "bz2": "bzip2"}


def decompress_capped(sub, kind):
    """One decompression attempt, output capped at MAX_UNCOMPRESSED bytes.

    The cap is the zip-bomb guard: a tiny crafted input must not inflate
    into gigabytes in memory.
    """
    try:
        if kind == "zlib":
            out = zlib.decompressobj().decompress(sub, MAX_UNCOMPRESSED)
        elif kind == "gzip":
            out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(sub, MAX_UNCOMPRESSED)
        elif kind == "deflate":
            out = zlib.decompressobj(-zlib.MAX_WBITS).decompress(sub, MAX_UNCOMPRESSED)
        elif kind == "bz2":
            out = bz2.BZ2Decompressor().decompress(sub, MAX_UNCOMPRESSED)
        elif kind == "xz":
            out = lzma.LZMADecompressor().decompress(sub, max_length=MAX_UNCOMPRESSED)
        else:
            return None
    except Exception:
        return None
    return out or None


def generic_decompress(data):
    """Try zlib/gzip/xz/bzip2 at several offsets; return [(how, out), ...]."""
    results = []
    for off in PROBE_OFFSETS:
        if off >= len(data):
            break
        sub = data[off:]
        for kind in ("zlib", "gzip", "xz", "bz2"):
            out = decompress_capped(sub, kind)
            if out:
                results.append((f"{DECOMPRESS_LABELS[kind]} (offset {off})", out))
    return results


def decompress_zlib_gzip(data):
    """zlib / gzip / raw-deflate at common offsets; first hit wins."""
    for off in ZLIB_GZIP_PROBE_OFFSETS:
        sub = data[off:]
        for kind, nm in (("zlib", "zlib"), ("gzip", "gzip")):
            out = decompress_capped(sub, kind)
            if out:
                return out, f"{nm}@{off}"
    out = decompress_capped(data, "deflate")
    if out:
        return out, "rawdeflate@0"
    return None, None


def md5_payload(plain):
    """Classic layout: first 16 bytes = MD5 of the rest (up to 7 padding bytes)."""
    for i in range(MAX_TRAILING_PAD):
        body = plain[MD5_LEN:len(plain) - i] if i else plain[MD5_LEN:]
        if md5(body).digest() == plain[:MD5_LEN]:
            return body, True
    return plain[MD5_LEN:], False  # hash check failed, still try the payload


# --------------------------------------------------------------- OpenSSL EVP
def evp_bytes_to_key(password, salt, key_len=32, iv_len=16):
    """OpenSSL EVP_BytesToKey KDF: chained MD5 rounds."""
    d = b""
    prev = b""
    while len(d) < key_len + iv_len:
        prev = md5(prev + password + salt).digest()
        d += prev
    return d[:key_len], d[key_len:key_len + iv_len]


def openssl_evp_decrypt(data, password):
    """Decrypt an `openssl enc -aes-256-cbc -k <pwd>` blob, or return None."""
    if not data.startswith(OPENSSL_MAGIC):
        return None
    if len(data) < OPENSSL_SALT_END + AES_BLOCK:
        return None
    salt = data[OPENSSL_SALT_START:OPENSSL_SALT_END]
    key, iv = evp_bytes_to_key(password.encode(), salt)
    try:
        plain = AES.new(key, AES.MODE_CBC, iv).decrypt(data[OPENSSL_SALT_END:])
    except Exception:
        return None
    return strip_pkcs7_padding(plain)


# ------------------------------------------------------------------ tar/IO
def is_tar(data):
    """Check for the ustar magic a few bytes into the first header block."""
    return len(data) > TAR_MAGIC_END + 3 and data[TAR_MAGIC_OFFSET:TAR_MAGIC_END] == TAR_MAGIC


def save_result(data, out_path):
    """Write bytes and report the path."""
    with open(out_path, "wb") as f:
        f.write(data)
    good(f"saved: {out_path} ({len(data)} bytes)")


def is_within(base, path):
    """True when `path` resolves inside `base`.

    Unlike a startswith() check this survives both .. hops and sibling
    directories whose names share a text prefix with the target.
    """
    try:
        return (os.path.commonpath((os.path.abspath(base), os.path.abspath(path)))
                == os.path.abspath(base))
    except ValueError:
        return False  # e.g. different drive letters on Windows


def safe_member_name(name):
    """Normalize a tar entry name; None if it could reach outside the target."""
    if not name:
        return None
    normed = name.replace("\\", "/").lstrip("/")
    parts = []
    for part in normed.split("/"):
        if part in ("", "."):
            continue  # drop leading ./ and doubled separators
        if part == "..":
            return None  # any upward hop rejects the entry outright
        parts.append(part)
    return "/".join(parts) or None


def extract_tar(data, out_dir):
    """Safely unpack a tar archive in memory into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            if not m.isfile():  # also skips links and device entries
                continue
            if not is_within(out_dir, os.path.join(out_dir, m.name)):
                continue  # path traversal guard
            try:
                tf.extract(m, out_dir, filter="data")
            except TypeError:  # Python < 3.12 has no filter=
                tf.extract(m, out_dir)
            good(f"  -> {m.name} ({m.size} bytes)")


def untar_bytes(data, prefix=""):
    """All regular files of a tar archive as (relpath, bytes), names sanitized."""
    out = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                safe = safe_member_name(m.name)
                if safe is None:  # path traversal attempt, drop the entry
                    continue
                f = tf.extractfile(m)
                if f:
                    out.append((prefix + safe, f.read()))
    except Exception:
        return []
    return out


# ------------------------------------------------------------ settings summary
INTERESTING = re.compile(
    r"(ssid|passw|passwd|pwd|psk|secret|username|user|login|wan|pppoe|l2tp|pptp|"
    r"conn.*type|ip.?addr|ip4?|mask|gateway|gw|dns|channel|bw|band|freq|wlan|"
    r"wireless|radio|encrypt|cipher|dhcp|lease|domain|host|mac|vlan|iptv|ipv6|"
    r"ddns|upnp|nat|mesh|vpn|region|country|mode|enable)", re.I)

SECRET_TAGS = re.compile(r"(passw|passwd|pwd|psk|secret|key|wep|pin)", re.I)


def summarize(xml_data, show_secrets=False):
    """Print interesting tag=value pairs found in the recovered XML."""
    try:
        text = xml_data.decode("utf-8", errors="replace")
    except Exception:
        return
    pairs = re.findall(r"<([A-Za-z0-9_]+)>([^<>]{0,200})</\1>", text)
    seen = {}
    for tag, val in pairs:
        val = val.strip()
        if not val or not INTERESTING.search(tag):
            continue
        key = tag.lower()
        if key not in seen:
            seen[key] = (tag, val)
    if not seen:
        step("no recognizable settings fields found — inspect the file manually")
        return
    print("\n===== Key settings found in the config =====")
    masked = False
    for key in sorted(seen):
        tag, val = seen[key]
        if not show_secrets and SECRET_TAGS.search(tag) and val:
            val = "******** (use --show-secrets to reveal)"
            masked = True
        print(f"  {tag:<{TAG_COL_WIDTH}} = {val}")
    if masked:
        print("  (secret values are masked — rerun with --show-secrets)")


# ---------------------------------------- LuCI-era stacked scheme (2022+)
def aes_luci_decrypt(blob):
    """One AES-256-CBC layer with the hardcoded crypto.lua key/iv."""
    plain = AES.new(LUCI_KEY, AES.MODE_CBC, LUCI_IV).decrypt(blob)
    try:
        plain = pkcs7_unpad(plain, AES_BLOCK)
    except Exception:
        pass
    return plain


def tar_payload_candidates(blob):
    """Payload variants: the tar may sit right away or after a 16-byte MD5 prefix."""
    if (len(blob) > MD5_LEN + TAR_MAGIC_END + 3
            and blob[MD5_LEN + TAR_MAGIC_OFFSET:MD5_LEN + TAR_MAGIC_END] == TAR_MAGIC):
        yield blob[MD5_LEN:]
    yield blob


def decode_luci_member(name, blob):
    """Decrypt+inflate one LUCI tar member; return {relpath: bytes} or {}."""
    safe = safe_member_name(name)  # also rejects any ../ hops
    if safe is None:
        return {}
    decoded, _how = decompress_zlib_gzip(aes_luci_decrypt(blob))
    if decoded is None:
        return {}
    if is_tar(decoded):  # nested archive, e.g. OpenVPN certificates
        base_dir = safe[:-4] if safe.endswith(".bin") else safe
        files = dict(untar_bytes(decoded, prefix=base_dir + "/"))
        files[safe] = decoded  # keep the archive itself too
        return files
    out_name = (safe[:-4] + ".xml") if safe.endswith(".bin") else (safe + ".xml")
    return {out_name: decoded}


def try_luci_stack(data):
    """LuCI-based firmware (2022-2025, AX/RE generation):
    AES-256-CBC -> zlib/gzip -> [16-byte MD5] -> tar -> per-file AES-256-CBC
    -> zlib/gzip -> XML (or a tar of OpenVPN certificates).
    Returns (tag, {relpath: bytes}) or None."""
    if len(data) % AES_BLOCK:
        return None
    blob, how = decompress_zlib_gzip(aes_luci_decrypt(data))
    if blob is None:
        return None
    for payload in tar_payload_candidates(blob):
        if not is_tar(payload):
            continue
        members = untar_bytes(payload)
        if not members:
            continue
        files = {}
        for name, member_blob in members:
            files.update(decode_luci_member(name, member_blob))
        if files:
            return (f"LuCI stack: AES-256-CBC (crypto.lua key) -> {how} -> tar "
                    f"-> AES -> gz/zlib"), files
    return None


# ------------------------------------------------------------ other schemes
def try_plain(data):
    """Match if the file is already plaintext XML."""
    if looks_like_xml(data):
        return "plain (file is not encrypted)", data
    return None


def try_des_lztp(data):
    """Classic scheme: DES-ECB under a known key, MD5 header, LZTP/zlib/XML."""
    if len(data) % 8:
        return None
    for name, key in DES_KEYS.items():
        try:
            plain = DES.new(key, DES.MODE_ECB).decrypt(data)
        except Exception:
            continue
        body, verified = md5_payload(plain)
        if looks_like_xml(body):
            tag = f"DES-ECB {name}: XML" + ("" if verified else " (MD5 check failed)")
            return tag, body
        out, combo = lztp_uncompress(body)
        if out and looks_like_xml(out):
            good(f"LZTP decompressed (size {combo})")
            tag = f"DES-ECB {name} + LZTP" + ("" if verified else " (MD5 check failed)")
            return tag, out
        for comp_name, out in generic_decompress(body):
            if looks_like_xml(out) or is_tar(out):
                return f"DES-ECB {name} + {comp_name}", out
    return None


def try_aes128_2022(data):
    """~2022 firmware: AES-128-CBC with the published fixed key/iv -> tar/XML."""
    if len(data) % AES_BLOCK:
        return None
    try:
        plain = AES.new(AES128_KEY, AES.MODE_CBC, AES128_IV).decrypt(data)
    except Exception:
        return None
    plain = strip_pkcs7_padding(plain)
    if is_tar(plain):
        return "AES-128-CBC (2022 scheme) -> tar", plain
    if looks_like_xml(plain):
        return "AES-128-CBC (2022 scheme) -> XML", plain
    return None


def try_openssl_salted(data, passwords):
    """OpenSSL EVP format (Salted__ magic) with a password-derived key/iv."""
    if not data.startswith(OPENSSL_MAGIC):
        return None
    for pwd in passwords:
        plain = openssl_evp_decrypt(data, pwd)
        if not plain:
            continue
        if is_tar(plain):
            return f"OpenSSL aes-256-cbc -k '{pwd}' -> tar", plain
        for comp_name, out in generic_decompress(plain):
            if is_tar(out):
                return f"OpenSSL aes-256-cbc -k '{pwd}' + {comp_name} -> tar", out
            if looks_like_xml(out):
                return f"OpenSSL aes-256-cbc -k '{pwd}' + {comp_name} -> XML", out
        if looks_like_xml(plain):
            return f"OpenSSL aes-256-cbc -k '{pwd}' -> XML", plain
    return None


def try_re200(data):
    """Single-layer AES-256-CBC with the RE200-era hardcoded key/iv."""
    if len(data) % AES_BLOCK:
        return None
    try:
        plain = AES.new(LUCI_KEY, AES.MODE_CBC, LUCI_IV).decrypt(data)
    except Exception:
        return None
    for comp_name, out in generic_decompress(plain):
        if looks_like_xml(out) or is_tar(out):
            return f"AES-256-CBC (RE200 key) + {comp_name}", out
    return None


def try_header_strip(data):
    """WR841N generation: fixed-size cleartext header, then DES-ECB + zlib."""
    for skip in HEADER_STRIP_SIZES:
        if len(data) <= skip or (len(data) - skip) % 8:
            continue
        try:
            plain = DES.new(DEFAULT_DES_KEY, DES.MODE_ECB).decrypt(data[skip:])
        except Exception:
            continue
        for comp_name, out in generic_decompress(plain):
            if looks_like_xml(out):
                return f"strip {skip} bytes + DES-ECB + {comp_name}", out
        out, _ = lztp_uncompress(plain)
        if out and looks_like_xml(out):
            return f"strip {skip} bytes + DES-ECB + LZTP", out
        if looks_like_xml(plain):
            return f"strip {skip} bytes + DES-ECB -> XML", plain
    return None


def scan_for_xml(data):
    """Fallback: salvage any embedded <?xml document as-is."""
    idx = data.find(b"<?xml")
    if idx != -1:
        return f"found raw <?xml> at offset {idx} (partial extraction)", data[idx:]
    return None


# --------------------------------------------------------------------- main
def build_parser():
    """Construct the command-line argument parser."""
    ap = argparse.ArgumentParser(
        prog="tplink-config-extract",
        description="Extract TP-Link router backup files (config.bin, backup-*.bin)")
    ap.add_argument("infile", help="config.bin / backup-*.bin")
    ap.add_argument("-o", "--outdir", default=None,
                    help="output directory (default: next to the input file)")
    ap.add_argument("--password", action="append", default=[],
                    help="extra password candidate for the OpenSSL-EVP scheme "
                         "(usually the product name, e.g. ArcherC7v5); repeatable")
    ap.add_argument("--show-secrets", action="store_true",
                    help="show passwords in the settings summary")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def build_strategies(data, passwords):
    """Every known decoder, in the order they are attempted."""
    return [
        ("LuCI stack 2022-2025 (AX/RE generation)", lambda: try_luci_stack(data)),
        ("plain XML",                            lambda: try_plain(data)),
        ("DES-ECB + LZTP",                       lambda: try_des_lztp(data)),
        ("AES-128-CBC 2022",                     lambda: try_aes128_2022(data)),
        ("OpenSSL salted EVP",                   lambda: try_openssl_salted(data, passwords)),
        ("AES-256 single layer (RE200)",         lambda: try_re200(data)),
        ("header-strip + DES",                   lambda: try_header_strip(data)),
        ("raw scan for <?xml",                   lambda: scan_for_xml(data)),
    ]


def save_file_package(payload_files, dest):
    """Write a {relpath: bytes} package to disk; return combined XML content."""
    os.makedirs(dest, exist_ok=True)
    all_xml = b""
    for rel, content in payload_files.items():
        path = os.path.join(dest, rel)
        if not is_within(dest, path):
            bad(f"skipping unsafe member name: {rel}")  # defense in depth
            continue
        os.makedirs(os.path.dirname(path) or dest, exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        good(f"  -> {rel} ({len(content)} bytes)")
        if rel.endswith(".xml"):
            all_xml += content + b"\n"
    return all_xml


def handle_decoded(tag, payload, out_dir, base, show_secrets):
    """Persist one decoded result: a file package, a tar, or raw XML."""
    good(f"SCHEME DETECTED: {tag}")
    if isinstance(payload, dict):  # file package (LuCI stack)
        dest = os.path.join(out_dir, base + "_files")
        all_xml = save_file_package(payload, dest)
        if all_xml:
            summarize(all_xml, show_secrets)
        return
    if is_tar(payload):
        out_bin = os.path.join(out_dir, base + "_extracted.tar")
        save_result(payload, out_bin)
        print("[*] unpacking tar:")
        extract_tar(payload, os.path.join(out_dir, base + "_files"))
        m = re.search(rb"<\?xml[\s\S]*", payload)
        if m:
            summarize(payload[m.start():], show_secrets)
        return
    out_xml = os.path.join(out_dir, base + "_extracted.xml")
    save_result(payload, out_xml)
    summarize(payload, show_secrets)


def print_failure_hint():
    print("\n[!] No known scheme matched.")
    print("    The backup is either from a newer firmware with a rotated key, or it")
    print("    uses a container layout this tool does not know yet.")
    print("    The hexdump above, plus the exact model, hardware and firmware")
    print("    versions, is what identifies the layout. The current key can usually")
    print("    be recovered from /usr/lib/lua/luci/model/crypto.lua inside the")
    print("    device's firmware image.")
    print("    Do not publish the config.bin itself: it contains your credentials.")


def main():
    args = build_parser().parse_args()

    if not os.path.exists(args.infile):
        sys.exit(f"File not found: {args.infile}")
    with open(args.infile, "rb") as fh:
        data = fh.read()
    out_dir = args.outdir or os.path.dirname(os.path.abspath(args.infile))
    base = os.path.splitext(os.path.basename(args.infile))[0]
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] {args.infile}: {len(data)} bytes")
    step("first bytes:\n" + hexdump(data, 48))

    passwords = args.password + list(DEFAULT_PASSWORD_GUESSES)

    for name, fn in build_strategies(data, passwords):
        print(f"[*] trying: {name}")
        try:
            result = fn()
        except Exception as e:
            bad(f"error: {e}")
            continue
        if not result:
            bad("no match")
            continue
        handle_decoded(result[0], result[1], out_dir, base, args.show_secrets)
        print("\nDone.")
        return

    print_failure_hint()


if __name__ == "__main__":
    main()
