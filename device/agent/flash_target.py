# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure parsers that turn captured IOS-XE `show` output into staging facts:
install-vs-bundle mode, the boot/target filesystem and its free space, and the
unused image artifacts that are safe to reclaim. No `cli` import — the agent's
build_deps runs the show-commands and feeds the text in (mirrors flashcheck /
verify_image so this unit-tests off-box)."""
import re

_IMG_RE = re.compile(r'System image file is "([^"]+)"')
_BOOTVAR_RE = re.compile(r"BOOT variable\s*=\s*(\S+?);", re.M)


def _basename(path):
    # "flash:dir/cat9k...bin" -> "cat9k...bin"
    return path.rsplit(":", 1)[-1].rsplit("/", 1)[-1]


def _mode_from_path(path):
    if not path:
        return None
    base = _basename(path).lower()
    if base.endswith(".conf"):
        return "install"
    if base.endswith(".bin"):
        return "bundle"
    return None


def boot_path(show_boot_text):
    """The resolved BOOT variable path from `show boot` (e.g.
    'flash:cat9k...bin'), or None. Works whether or not a `boot system`
    run-config line exists — IOS resolves the .bin on flash either way."""
    m = _BOOTVAR_RE.search(show_boot_text or "")
    return m.group(1) if m else None


def detect_mode(show_version_text, show_boot_text):
    """'install' | 'bundle' | None. Primary: `show version` 'System image file
    is' (the RUNNING image, authoritative). Corroborate with `show boot` BOOT
    variable. Disagree -> trust show version. Neither parseable -> None (caller
    skips destructive actions and retries next tick)."""
    m = _IMG_RE.search(show_version_text or "")
    ver = _mode_from_path(m.group(1)) if m else None
    if ver is not None:
        return ver
    return _mode_from_path(boot_path(show_boot_text))


def running_image(show_version_text):
    """Basename of the running image (never delete this), or None."""
    m = _IMG_RE.search(show_version_text or "")
    return _basename(m.group(1)) if m else None


def parse_file_systems(text):
    """Parse `show file systems` into a list of dicts:
    {prefixes:[str], size:int|None, free:int|None, type:str, flags:str,
     is_default:bool}. The '*' default-FS marker, multi-alias prefixes
    ('flash: bootflash:') and '-' pseudo-FS sizes are handled. Rows whose
    trailing tokens are not all 'prefix:'-style are skipped."""
    out = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith("File System") or s.startswith("Size("):
            continue
        is_default = s.startswith("*")
        if is_default:
            s = s[1:].strip()
        parts = s.split()
        if len(parts) < 5:
            continue
        size_s, free_s, typ, flags = parts[0], parts[1], parts[2], parts[3]
        prefixes = parts[4:]
        if not all(p.endswith(":") for p in prefixes):
            continue
        def _num(x):
            return None if x == "-" else int(x)
        try:
            size, free = _num(size_s), _num(free_s)
        except ValueError:
            continue
        out.append({"prefixes": prefixes, "size": size, "free": free,
                    "type": typ, "flags": flags, "is_default": is_default})
    return out


def choose_target_fs(file_systems, boot_path=None):
    """Prefix (e.g. 'flash:') of the filesystem the device boots from / stages
    to: prefer the writable disk FS whose prefixes include the boot path's
    prefix; else the '*' default writable disk FS. Never crashinfo:, never
    non-disk or read-only. Returns None if nothing suitable."""
    disks = [f for f in file_systems
             if f["type"] == "disk" and "rw" in f["flags"]
             and "crashinfo:" not in f["prefixes"]]
    if not disks:
        return None
    if boot_path and ":" in boot_path:
        want = boot_path.split(":", 1)[0] + ":"
        for f in disks:
            if want in f["prefixes"]:
                return f["prefixes"][0]
    for f in disks:
        if f["is_default"]:
            return f["prefixes"][0]
    return disks[0]["prefixes"][0]


def _is_ie3k(model):
    # IE-3400-8T2S, IE-3300-8T2S, ... — the IE-3x00 family whose IOx runs from SD.
    return bool(model) and model.upper().startswith("IE-3")


def choose_stage_fs(file_systems, model=None, guest_share_fs=None,
                    preferred_fs=None):
    """Prefix of the filesystem IRIS should STAGE on — download the scratch and
    place the image copy — or None to defer to choose_target_fs (the boot FS).

    The staging FS is the writable disk that hosts the guestshell scratch
    (guest-share/). On the C9300 that's flash: (returns None -> caller uses the
    boot FS). On the IE3k, IOx runs from sdflash:, so the scratch and copy live
    there.

      preferred_fs   : operator-selected IOS prefix. Used only when it names a
                       writable non-crash disk returned by `show file systems`.
      guest_share_fs : IOS prefix actually containing guest-share/ (probed on-box).
                       Authoritative when it names a writable disk.
      model          : device model; an IE3k selects sdflash: when present — a
                       fast path used before the probe resolves.

    Never returns crashinfo:/ro/non-disk. Returns None when nothing applies."""
    disks = [f for f in file_systems
             if f["type"] == "disk" and "rw" in f["flags"]
             and "crashinfo:" not in f["prefixes"]]
    prefixes = {p for f in disks for p in f["prefixes"]}
    if preferred_fs and preferred_fs in prefixes:
        return preferred_fs
    if guest_share_fs and guest_share_fs in prefixes:
        return guest_share_fs
    if _is_ie3k(model) and "sdflash:" in prefixes:
        return "sdflash:"
    return None


# Cisco image-artifact names only — anchored on the platform image prefix so we
# never match unrelated files. Plus the literal packages.conf.
_ARTIFACT_RE = re.compile(r"^(cat9k|ie3x00)[A-Za-z0-9._-]*\.(bin|pkg|conf)$")


def reclaimable_artifacts(dir_output, protect):
    """Basenames of UNUSED image artifacts at the FS root (from `dir <fs>:`)
    that are safe to delete: match the platform-image allowlist (or are
    'packages.conf'), are regular files (perms start '-', never directories),
    and are NOT in `protect` (running image, staging filename + .aria2/.torrent,
    IRIS's own placed root copy). The seeding scratch lives under guest-share/
    (a subdir, never a root regular-file row) so it is never a candidate."""
    out = []
    for raw in (dir_output or "").splitlines():
        parts = raw.split()
        if len(parts) < 3:
            continue
        perms = parts[1]
        if not perms.startswith("-"):       # regular files only
            continue
        name = parts[-1]
        if name in protect:
            continue
        if name == "packages.conf" or _ARTIFACT_RE.match(name):
            out.append(name)
    return out


# `show version` prints the hardware model on a lowercase "cisco <MODEL>
# (<arch>) processor" line, e.g. "cisco C9300-48UXM (X86) processor with ..."
# or "cisco IE-3400-8T2S (ARM) processor (revision V06) ...". (The product
# banner starts with a capital "Cisco IOS XE Software", so the lowercase anchor
# targets the hardware line specifically.)
_MODEL_RE = re.compile(r"^cisco\s+(\S+)\s+\(", re.M)


def device_model(show_version_text):
    """The Cisco hardware model from `show version` (e.g. 'C9300-48UXM',
    'IE-3400-8T2S'), or None if absent. Reported in the agent heartbeat so the
    swarm map can label each device by model (color = image, model = device)."""
    m = _MODEL_RE.search(show_version_text or "")
    return m.group(1) if m else None
