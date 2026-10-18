# tplink-config-extract

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)

A command-line tool that decrypts TP-Link router backup files from any
device generation. It writes the complete configuration to disk as files:
the full settings XML plus every certificate found in the backup. On screen
it prints a summary of the key items: WAN type, PPPoE login, SSIDs, channels,
DNS servers.

## Quick start

```bash
pip install pycryptodome

python tplink_config_extract.py <your-backup-file>
```

Download the backup in the router web UI (System > Backup & Restore > BACK
UP). The downloaded file is named differently from model to model: `conf.bin`,
`config.bin`, `backup-<model>-<date>.bin`. Pass whatever you got; detection
does not depend on the name.

What you get:

- `<backup>_extracted.xml` or a `<backup>_files/` folder: the complete router
  configuration as plain XML, plus any certificates the backup contained
  (for example the OpenVPN certs on AX/RE models). Everything the router
  stores is in these files, including the fields the summary does not show.
- an on-screen summary of the settings you usually need first.

The output looks like this:

```
[*] config.bin: 14048 bytes
[*] trying: LuCI stack 2022-2025 (AX/RE generation)
  [+] SCHEME DETECTED: LuCI stack: AES-256-CBC (crypto.lua key) -> gzip@0 -> tar -> AES -> gz/zlib
  [+]   -> ori-backup-user-config.xml (96342 bytes)
  [+]   -> ori-backup-certificate/ca.crt (1261 bytes)

===== Key settings found in the config =====
  channel                                    = 36
  pppoeUsername                              = user123@provider
  wanConnectionType                          = PPPoE
  pppoePassword                              = ******** (use --show-secrets to reveal)
```

## Usage

```bash
python tplink_config_extract.py <backup-file> [options]
```

| Option | What it does |
|--------|--------------|
| `-o DIR` | write results into DIR instead of the folder of the input file |
| `--password NAME` | extra candidate for the OpenSSL-EVP scheme, usually the product name, e.g. `--password ArcherC9v5`; repeatable |
| `--show-secrets` | show passwords in the summary (masked by default) |
| `--version` | print the version and exit |

Python 3.9 or newer; `pycryptodome` is the only dependency.

## Recognized containers

TP-Link has changed its backup format many times, from DES-era builds of
the 2000s to the two-layer AES container in current AX and RE generation
firmware (2022-2025). The tool is not tied to any one model: it tries every
known scheme in order until one works.

| # | Scheme | Typical devices / era |
|---|--------|----------------------|
| 1 | LuCI two-layer stack: `AES-256-CBC → gz/zlib → [MD5] → tar → per-file AES → gz/zlib → XML` | AX/RE generation, stock firmware 2022-2025 |
| 2 | Plain XML | any |
| 3 | `DES-ECB + MD5 + LZTP`, 8 known keys | classic routers, modem routers, C-series |
| 4 | `DES-ECB + MD5` + plain XML | very old models |
| 5 | `AES-128-CBC → tar`, fixed published key | firmware around 2022 (Archer C7 v5) |
| 6 | OpenSSL salted EVP `aes-256-cbc -k <product name>` | some LuCI-era models (Archer C9 v5, Archer C1200) |
| 7 | `AES-256-CBC` with the RE200 key + zlib | RE200 and similar |
| 8 | 80-148 byte header strip + `DES → zlib/LZTP` | WR841N generation |
| 9 | Raw `<?xml>` scan, partial salvage | last resort for unknown layouts |

If nothing matches, the backup uses a container this tool does not know, for
example newer firmware with a rotated key that is not public yet. The script
prints a hexdump of the first bytes, which is what identifies the layout.
Never post the file itself anywhere: it holds your ISP
and Wi-Fi credentials.

## Security

Passwords in the on-screen summary are masked unless you pass
`--show-secrets`. The extracted files hold the same secrets as the backup,
in plain text: store them accordingly and never post any of this anywhere.

## Credits and references

- [sta-c0000/tpconf_bin_xml](https://github.com/sta-c0000/tpconf_bin_xml)
  (Alain Ducharme, GPL-3.0). The LZTP routines are adapted from this project.
- [teknoraver.net](https://teknoraver.net/software/hacks/tplink/). First public
  write-up of the classic DES key.
- [aaronsvk/CVE-2022-30075](https://github.com/aaronsvk/CVE-2022-30075)
  (Tomas Melicher). The AES-256 key/IV from `crypto.lua` and the LuCI-era
  tar structure.
- [Cisco Talos TALOS-2025-2304](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2304).
  Documents the two-layer container in 2024-2025 firmware.
- [ret5et/tplink_backup_decrypt_2022.bin](https://github.com/ret5et/tplink_backup_decrypt_2022.bin).
  The AES-128-CBC 2022 scheme.
- [lisenet.com](https://www.lisenet.com/2023/gaining-ssh-access-to-tp-link-re200-wi-fi-range-extender/).
  The RE200 key in use.

## Disclaimer

This is an independent, unofficial tool. It is not affiliated with or endorsed
by TP-Link, and it comes with no warranty of any kind. The author assumes no
liability for what you do with it or for any consequences of using it. Use it
on your own devices and your own backups.

## License

GPL-3.0, see [LICENSE](LICENSE). Do what you want with the code within those
terms; the LZTP routines are adapted from `tpconf_bin_xml`, so GPL applies.
Everything this tool knows comes from the public research credited above.
