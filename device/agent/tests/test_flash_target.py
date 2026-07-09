# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import flash_target as ft

# Real captures (2026-06-18, read-only) — both lab boxes are in BUNDLE mode.
_C9300_VER = 'System image file is "flash:cat9k_iosxe.26.01.01.SPA.bin"\n'
_C9300_BOOT = "BOOT variable = flash:cat9k_iosxe.26.01.01.SPA.bin;\n"
_IE3400_VER = 'System image file is "flash:ie3x00-universalk9.17.15.04.SPA.bin"\n'
_IE3400_BOOT = "BOOT variable = flash:ie3x00-universalk9.17.15.04.SPA.bin;\n"
# Synthesized install-mode shapes (documented Cisco output).
_INSTALL_VER = 'System image file is "flash:packages.conf"\n'
_INSTALL_BOOT = "BOOT variable = flash:packages.conf;\n"


def test_detect_mode_bundle_c9300():
    assert ft.detect_mode(_C9300_VER, _C9300_BOOT) == "bundle"


def test_detect_mode_bundle_ie3400():
    assert ft.detect_mode(_IE3400_VER, _IE3400_BOOT) == "bundle"


def test_detect_mode_install():
    assert ft.detect_mode(_INSTALL_VER, _INSTALL_BOOT) == "install"


def test_detect_mode_no_boot_system_line_uses_show_version():
    # IE3400 has no `boot system` run-config line; show boot still resolves the
    # .bin, but even with an empty show boot the running image decides.
    assert ft.detect_mode(_IE3400_VER, "") == "bundle"


def test_detect_mode_disagreement_trusts_show_version():
    # version says bundle (.bin running), boot var stale points at packages.conf
    assert ft.detect_mode(_C9300_VER, _INSTALL_BOOT) == "bundle"


def test_detect_mode_unparseable_returns_none():
    assert ft.detect_mode("", "") is None
    assert ft.detect_mode("garbage", "garbage") is None


def test_running_image_basename():
    assert ft.running_image(_C9300_VER) == "cat9k_iosxe.26.01.01.SPA.bin"
    assert ft.running_image(_INSTALL_VER) == "packages.conf"
    assert ft.running_image("") is None


# Real `show file systems` captures.
_C9300_FS = """File Systems:

               Size(b)               Free(b)      Type  Flags  Prefixes
                     -                     -    opaque     rw   system:
            1651314688            1440706560      disk     rw   crashinfo:
*          11353194496            2627305472      disk     rw   flash: bootflash:
            3304124416            3059441664      disk     ro   webui:
                     -                     -   network     rw   tftp:
               2097152               1979262     nvram     rw   nvram:
"""
_IE3400_FS = """File Systems:

       Size(b)       Free(b)      Type  Flags  Prefixes
             -             -    opaque     rw   system:
     518885376     465213440      disk     rw   crashinfo:
*   1697755136    1053401088      disk     rw   flash: bootflash:
    1717055488    1626525696      disk     ro   webui:
      33554432      33472528     nvram     rw   nvram:
"""


def test_parse_file_systems_c9300():
    fss = ft.parse_file_systems(_C9300_FS)
    flash = [f for f in fss if "flash:" in f["prefixes"]][0]
    assert flash["free"] == 2627305472
    assert flash["size"] == 11353194496
    assert flash["type"] == "disk"
    assert flash["flags"] == "rw"
    assert flash["is_default"] is True
    assert "bootflash:" in flash["prefixes"]
    # crashinfo present but not default
    crash = [f for f in fss if "crashinfo:" in f["prefixes"]][0]
    assert crash["is_default"] is False


def test_parse_file_systems_pseudo_rows_have_none_size():
    fss = ft.parse_file_systems(_C9300_FS)
    system = [f for f in fss if "system:" in f["prefixes"]][0]
    assert system["size"] is None and system["free"] is None


def test_parse_file_systems_ie3400_no_sdflash():
    fss = ft.parse_file_systems(_IE3400_FS)
    assert not any("sdflash:" in f["prefixes"] for f in fss)
    flash = [f for f in fss if "flash:" in f["prefixes"]][0]
    assert flash["free"] == 1053401088


def test_parse_file_systems_empty():
    assert ft.parse_file_systems("") == []
    assert ft.parse_file_systems(None) == []


def test_choose_target_fs_prefers_boot_path_match():
    fss = ft.parse_file_systems(_C9300_FS)
    assert ft.choose_target_fs(fss, "flash:cat9k.bin") == "flash:"


def test_choose_target_fs_falls_back_to_default():
    fss = ft.parse_file_systems(_C9300_FS)
    assert ft.choose_target_fs(fss, None) == "flash:"


def test_choose_target_fs_never_crashinfo_or_ro():
    # only crashinfo (rw disk but excluded) + webui (ro) -> nothing suitable
    fss = [f for f in ft.parse_file_systems(_C9300_FS)
           if "flash:" not in f["prefixes"]]
    assert ft.choose_target_fs(fss, None) is None


def test_choose_target_fs_empty():
    assert ft.choose_target_fs([], "flash:x.bin") is None


# Trimmed real `dir flash:` from the C9300 (running 26.01.01 .bin + leftover
# 17.18.03 install set + non-image files + a directory).
_C9300_DIR = """Directory of flash:/

466948  drwx             4096  Jun 18 2026 11:33:09 +00:00  .installer
467220  -rw-       1260618344  Jun 17 2026 09:59:48 +00:00  cat9k_iosxe.26.01.01.SPA.bin
131187  drwx             4096  Jun 17 2026 09:20:31 +00:00  guest-share
467256  -rw-             7585  Apr 29 2026 11:44:52 +00:00  packages.conf
467252  -rw-             7585  Apr 29 2026 11:39:04 +00:00  cat9k_iosxe.17.18.03.SPA.conf
548876  -rw-       1094640640  Apr 14 2026 09:26:55 +00:00  cat9k-rpbase.17.18.03.SPA.pkg
548874  -rw-          1963012  Apr 14 2026 09:23:32 +00:00  cat9k-guestshell.17.18.03.SPA.pkg
467028  -rw-            20893  Apr 29 2026 11:45:25 +00:00  cat9k_kr_helper.log
466985  -rw-             2134  Sep 22 2023 19:52:12 +00:00  NACert.pem

11353194496 bytes total (2627305472 bytes free)
"""


def test_reclaimable_excludes_running_and_protected():
    protect = {"cat9k_iosxe.26.01.01.SPA.bin"}   # running image
    got = set(ft.reclaimable_artifacts(_C9300_DIR, protect))
    assert got == {
        "packages.conf",
        "cat9k_iosxe.17.18.03.SPA.conf",
        "cat9k-rpbase.17.18.03.SPA.pkg",
        "cat9k-guestshell.17.18.03.SPA.pkg",
    }
    # running image, non-image files, directories never returned
    assert "cat9k_iosxe.26.01.01.SPA.bin" not in got
    assert "cat9k_kr_helper.log" not in got
    assert "NACert.pem" not in got
    assert "guest-share" not in got and ".installer" not in got


def test_reclaimable_protects_staging_filename():
    # staging the 17.18.03 .bin: its name (+ artifacts) must be protected
    protect = {"cat9k_iosxe.26.01.01.SPA.bin", "cat9k_iosxe.17.18.03.SPA.bin"}
    got = set(ft.reclaimable_artifacts(_C9300_DIR, protect))
    assert "cat9k_iosxe.17.18.03.SPA.conf" in got   # .conf still reclaimable
    # (the .bin we're staging isn't in this dir listing, but the protect set is
    # honored regardless)


def test_reclaimable_empty():
    assert ft.reclaimable_artifacts("", {"x"}) == []
    assert ft.reclaimable_artifacts(None, set()) == []


# --- device_model: hardware model from `show version`, for the swarm map ---

def test_device_model_c9300():
    sv = ("Cisco IOS XE Software, Version 26.01.01\n"
          "cisco C9300-48UXM (X86) processor with 1300268K/6147K bytes of memory.\n")
    assert ft.device_model(sv) == "C9300-48UXM"


def test_device_model_ie3400():
    sv = ("Cisco IOS XE Software, Version 17.15.04\n"
          "cisco IE-3400-8T2S (ARM) processor (revision V06) with 649067K bytes.\n")
    assert ft.device_model(sv) == "IE-3400-8T2S"


def test_device_model_absent_returns_none():
    assert ft.device_model("") is None
    assert ft.device_model(None) is None
    assert ft.device_model("Cisco IOS XE Software, Version 17.18.03\n") is None


# Real IE3400 `show file systems` WITH the SD card inserted (2026-06-23 capture).
_IE3400_FS_SD = """File Systems:

       Size(b)       Free(b)      Type  Flags  Prefixes
             -             -    opaque     rw   system:
     518885376     465176576      disk     rw   crashinfo:
*   1697755136    1053401088      disk     rw   flash: bootflash:
    1717055488    1626517504      disk     ro   webui:
    9675177984    9675169792      disk     rw   sdflash:
      33554432      33472528     nvram     rw   nvram:
"""


def test_parse_file_systems_ie3400_with_sdflash():
    fss = ft.parse_file_systems(_IE3400_FS_SD)
    sd = [f for f in fss if "sdflash:" in f["prefixes"]][0]
    assert sd["size"] == 9675177984
    assert sd["free"] == 9675169792
    assert sd["type"] == "disk" and sd["flags"] == "rw"
    assert sd["is_default"] is False


def test_choose_stage_fs_ie3k_with_sdflash_picks_sdflash():
    fss = ft.parse_file_systems(_IE3400_FS_SD)
    assert ft.choose_stage_fs(fss, model="IE-3400-8T2S") == "sdflash:"


def test_choose_stage_fs_guest_share_fs_wins_over_model():
    # The on-box probe found guest-share on flash: -> overrides the IE3k fast-path.
    fss = ft.parse_file_systems(_IE3400_FS_SD)
    assert ft.choose_stage_fs(fss, model="IE-3400-8T2S",
                              guest_share_fs="flash:") == "flash:"


def test_choose_stage_fs_cat9k_defers_to_boot_fs():
    fss = ft.parse_file_systems(_C9300_FS)
    assert ft.choose_stage_fs(fss, model="C9300-48UXM") is None


def test_choose_stage_fs_ie3k_without_sdflash_defers():
    fss = ft.parse_file_systems(_IE3400_FS)        # no sdflash row -> safe degrade
    assert ft.choose_stage_fs(fss, model="IE-3400-8T2S") is None


def test_choose_stage_fs_ignores_ro_or_nondisk_guest_share_fs():
    fss = ft.parse_file_systems(_IE3400_FS_SD)
    # webui: is ro -> not a valid stage target; no model -> defer.
    assert ft.choose_stage_fs(fss, guest_share_fs="webui:") is None


def test_choose_stage_fs_empty():
    assert ft.choose_stage_fs([], model="IE-3400-8T2S") is None
