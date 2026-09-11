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


# A Catalyst 8000V publishes ONE writable disk under three names, crashinfo:
# among them. Filtering the whole row out left the box with no writable disk,
# so every agent tick died before its heartbeat (issue #236).
_C8000V_FS = """File Systems:

       Size(b)       Free(b)      Type  Flags  Prefixes
             -             -    opaque     rw   system:
             -             -    opaque     rw   tmpsys:
*   5173313536     473923584      disk     rw   bootflash: flash: crashinfo:
    4110950400    3975962624      disk     ro   webui:
             -             -   network     rw   tftp:
             -             -    opaque     rw   null:
      33554432      33534101     nvram     rw   nvram:
"""


def test_c8000v_aliases_crashinfo_onto_its_only_writable_disk():
    fss = ft.parse_file_systems(_C8000V_FS)
    disk = [f for f in fss if f["type"] == "disk" and "rw" in f["flags"]]
    assert len(disk) == 1
    assert disk[0]["prefixes"] == ["bootflash:", "flash:", "crashinfo:"]
    assert ft.selectable_prefixes(disk[0]) == ["bootflash:", "flash:"]


def test_choose_target_fs_uses_a_disk_that_merely_aliases_crashinfo():
    fss = ft.parse_file_systems(_C8000V_FS)
    assert ft.choose_target_fs(fss, None) == "bootflash:"
    assert ft.choose_target_fs(
        fss, "bootflash:packages.conf") == "bootflash:"
    # The boot path may name any selectable alias of that same disk.
    assert ft.choose_target_fs(fss, "flash:packages.conf") == "flash:"


def test_choose_stage_fs_honours_preferred_bootflash_on_c8000v():
    fss = ft.parse_file_systems(_C8000V_FS)
    assert ft.choose_stage_fs(
        fss, model="C8000V", guest_share_fs=None,
        preferred_fs="bootflash:") == "bootflash:"
    assert ft.choose_stage_fs(
        fss, model="C8000V", guest_share_fs="bootflash:",
        preferred_fs="") == "bootflash:"


def test_crashinfo_is_never_selected_even_when_asked_for():
    fss = ft.parse_file_systems(_C8000V_FS)
    assert ft.choose_stage_fs(
        fss, model="C8000V", guest_share_fs=None,
        preferred_fs="crashinfo:") is None
    assert ft.choose_stage_fs(
        fss, model="C8000V", guest_share_fs="crashinfo:",
        preferred_fs="") is None
    assert ft.choose_target_fs(fss, "crashinfo:x.bin") == "bootflash:"


def test_a_disk_offering_only_crashinfo_is_still_refused():
    only_crash = [{"prefixes": ["crashinfo:"], "size": 1, "free": 1,
                   "type": "disk", "flags": "rw", "is_default": True}]
    assert ft.choose_target_fs(only_crash, None) is None
    assert ft.choose_stage_fs(only_crash, model="C9300",
                              preferred_fs="crashinfo:") is None


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


def test_reclaimable_includes_root_copy_temp_name_leftovers():
    # A root-copy replacement (iris_agent._copy_to_root_impl /
    # _copy_to_root_direct_impl) stages under "<real name>.iris-tmp" and only
    # renames into place once verified. A leftover from an attempt that
    # crashed before its own cleanup ran must still be visible to the
    # generic low-space sweep, or a device stuck full because of exactly that
    # leftover could never recover space to retry.
    dir_out = (
        "467220  -rw-  100  Jun 17 2026 09:59:48 +00:00  "
        "cat9k_iosxe.26.01.01.SPA.bin.iris-tmp\n"
        "467256  -rw-    7  Apr 29 2026 11:44:52 +00:00  packages.conf.iris-tmp\n"
        "11353194496 bytes total (2627305472 bytes free)\n"
    )
    got = set(ft.reclaimable_artifacts(dir_out, set()))
    assert got == {"cat9k_iosxe.26.01.01.SPA.bin.iris-tmp", "packages.conf.iris-tmp"}


def test_reclaimable_temp_name_still_honours_protect_set():
    dir_out = ("467220  -rw-  100  Jun 17 2026 09:59:48 +00:00  "
               "cat9k_iosxe.26.01.01.SPA.bin.iris-tmp\n"
               "11353194496 bytes total (2627305472 bytes free)\n")
    protect = {"cat9k_iosxe.26.01.01.SPA.bin.iris-tmp"}
    assert ft.reclaimable_artifacts(dir_out, protect) == []


# --- Catalyst 8000V (#237) ---
# Real captures from Iris-c8kv-101 (C8000V, IOS-XE 17.15.05), 2026-09-10,
# read-only. The box was deployed from the ISO: it runs in INSTALL mode from
# cdrom0:packages.conf, has no BOOT variable at all, and bootflash: root holds
# the committed 17.15.05 package set (`show install summary`: one IMG,
# Activated & Committed) beside the IRIS-staged 26.01.01 bundle.
_C8000V_VER = (
    "Cisco IOS XE Software, Version 17.15.05\n"
    "System returned to ROM by reload\n"
    'System image file is "cdrom0:packages.conf"\n'
    "cisco C8000V (VXE) processor (revision VXE) with 1890892K/3075K bytes "
    "of memory.\n")
_C8000V_BOOT = (
    "BOOT variable does not exist\n"
    "CONFIG_FILE variable does not exist\n"
    "BOOTLDR variable does not exist\n"
    "Configuration register is 0x2102\n")
_C8000V_DIR = """Directory of bootflash:/

131103  drwx             4096  Sep 10 2026 13:13:09 +00:00  guest-share
13      drwx             4096  Sep 10 2026 12:54:07 +00:00  .installer
46      -rw-        973065200  Sep 10 2026 12:52:31 +00:00  c8000v-universalk9.26.01.01.SPA.bin
131077  drwx            20480  Sep 10 2026 12:47:28 +00:00  tracelogs
131076  drwx             4096  Sep 10 2026 11:59:30 +00:00  core
44      -rw-              257  Sep 10 2026 10:00:48 +00:00  .iox_dir_list
43      -rw-              412  Sep 10 2026 10:00:41 +00:00  cvac.log
131102  drwx             4096  Sep 10 2026 10:00:41 +00:00  license_evlog
45      -rw-              157  Sep 10 2026 10:00:38 +00:00  csrlxc-cfg.log
131073  drwx             4096  Sep 10 2026 10:00:37 +00:00  SHARED-IOX
42      -rw-               30  Sep 10 2026 10:00:26 +00:00  throughput_monitor_params
12      -rwx             1368  Sep 10 2026 09:59:04 +00:00  mode_event_log
48      -rw-             1484  Sep 10 2026 09:55:17 +00:00  collated_log_20260910-095516
131090  drwx             4096  Jul 25 2026 03:43:13 +00:00  .dbpersist
131152  drwx             4096  Jul 25 2026 03:36:13 +00:00  pnp-tech
131106  drwx             4096  Jul 25 2026 03:34:39 +00:00  iox_host_data_share
131100  drwx             4096  Jul 25 2026 03:34:37 +00:00  onep
131099  drwx             4096  Jul 25 2026 03:34:36 +00:00  pnp-info
131092  drwx             4096  Jul 25 2026 03:33:55 +00:00  virtual-instance
29      -rw-            34967  Jul 25 2026 03:33:50 +00:00  ios_core.p7b
30      -rw-             1939  Jul 25 2026 03:33:50 +00:00  trustidrootx3_ca_062035.ca
131080  drwx             4096  Jul 25 2026 03:33:40 +00:00  bootlog_history
25      -rw-        825640024  Jul 25 2026 03:32:13 +00:00  c8000v-mono-universalk9.17.15.05.SPA.pkg
27      -rw-             5759  Jul 25 2026 03:32:13 +00:00  packages.conf
26      -rw-         57288817  Jul 25 2026 03:32:13 +00:00  c8000v-rpboot.17.15.05.SPA.pkg
18      -rw-            54348  Jul 25 2026 03:32:11 +00:00  c8000v-firmware_dreamliner.17.15.05.SPA.pkg
22      -rw-          2937928  Jul 25 2026 03:32:11 +00:00  c8000v-firmware_nim_ge.17.15.05.SPA.pkg
24      -rw-          5575752  Jul 25 2026 03:32:11 +00:00  c8000v-firmware_nim_xdsl.17.15.05.SPA.pkg
23      -rw-         11568204  Jul 25 2026 03:32:11 +00:00  c8000v-firmware_nim_shdsl.17.15.05.SPA.pkg
19      -rw-         11310156  Jul 25 2026 03:32:11 +00:00  c8000v-firmware_ngwic_t1e1.17.15.05.SPA.pkg
21      -rw-         17675336  Jul 25 2026 03:32:11 +00:00  c8000v-firmware_nim_cwan.17.15.05.SPA.pkg
20      -rw-         12928076  Jul 25 2026 03:32:11 +00:00  c8000v-firmware_nim_async.17.15.05.SPA.pkg
17      drwx             4096  Jul 25 2026 03:31:56 +00:00  appqoe-service
14      drwx             4096  Jul 25 2026 03:31:55 +00:00  .rollback_timer
131075  drwx             4096  Jul 25 2026 03:31:41 +00:00  pcap
131074  drwx             4096  Jul 25 2026 03:31:40 +00:00  .prst_sync
11      drwx            16384  Jul 25 2026 03:31:32 +00:00  lost+found

5173313536 bytes total (2880884736 bytes free)
"""
_C8000V_INSTALL_SET = {
    "c8000v-mono-universalk9.17.15.05.SPA.pkg",
    "packages.conf",
    "c8000v-rpboot.17.15.05.SPA.pkg",
    "c8000v-firmware_dreamliner.17.15.05.SPA.pkg",
    "c8000v-firmware_nim_ge.17.15.05.SPA.pkg",
    "c8000v-firmware_nim_xdsl.17.15.05.SPA.pkg",
    "c8000v-firmware_nim_shdsl.17.15.05.SPA.pkg",
    "c8000v-firmware_ngwic_t1e1.17.15.05.SPA.pkg",
    "c8000v-firmware_nim_cwan.17.15.05.SPA.pkg",
    "c8000v-firmware_nim_async.17.15.05.SPA.pkg",
}
_C8000V_NON_IMAGE_FILES = {
    ".iox_dir_list", "cvac.log", "csrlxc-cfg.log", "throughput_monitor_params",
    "mode_event_log", "collated_log_20260910-095516", "ios_core.p7b",
    "trustidrootx3_ca_062035.ca",
}


def test_c8000v_install_mode_never_reaches_the_bundle_sweep():
    # The lab box's committed .pkg set at bootflash: root is NOT protected by
    # name -- running_image() is the bare "packages.conf", which says nothing
    # about c8000v-mono/rpboot/firmware. It is protected by ROUTING: this
    # capture resolves to install mode, and iris_agent._reclaim_for_mode
    # consults reclaimable_artifacts() only in bundle mode. Pin the facts
    # that routing rests on, straight from the device.
    assert ft.detect_mode(_C8000V_VER, _C8000V_BOOT) == "install"
    assert ft.running_image(_C8000V_VER) == "packages.conf"
    # No BOOT variable: boot_path() is None, and iris_agent's boot_image()
    # turns that into "" (known to be absent), not an unreadable None.
    assert ft.boot_path(_C8000V_BOOT) is None
    assert ft.detect_mode("", _C8000V_BOOT) is None


def test_reclaimable_c8000v_bundle_mode_pins_the_leftover_install_set():
    # A C8000V that has since booted the staged 26.01.01 bundle: the running
    # image is protected by the caller, and exactly the 17.15.05 install set
    # it no longer runs is reclaimable -- the same contract the C9300 test
    # above pins for cat9k. Nothing else at bootflash: root is ever named.
    protect = {"c8000v-universalk9.26.01.01.SPA.bin"}   # running image
    got = set(ft.reclaimable_artifacts(_C8000V_DIR, protect))
    assert got == _C8000V_INSTALL_SET
    assert "c8000v-universalk9.26.01.01.SPA.bin" not in got
    assert not (got & _C8000V_NON_IMAGE_FILES)
    for d in ("guest-share", ".installer", "tracelogs", "core", "SHARED-IOX",
              "virtual-instance", "lost+found"):
        assert d not in got


def test_reclaimable_c8000v_names_iris_own_stale_bundle_when_unprotected():
    # The case #237 is about: IRIS's own staged c8000v .bin that has left the
    # assigned set (parked/replaced, so no longer in the protect set) must be
    # something the low-space sweep may free. Before the fix the allowlist
    # could not name a c8000v-* file at all.
    got = set(ft.reclaimable_artifacts(_C8000V_DIR, set()))
    assert got == _C8000V_INSTALL_SET | {"c8000v-universalk9.26.01.01.SPA.bin"}


def test_reclaimable_c8000v_temp_name_leftover():
    dir_out = (
        "47  -rw-  973065200  Sep 10 2026 12:52:31 +00:00  "
        "c8000v-universalk9.26.01.01.SPA.bin.iris-tmp\n"
        "5173313536 bytes total (2880884736 bytes free)\n")
    assert ft.reclaimable_artifacts(dir_out, set()) == [
        "c8000v-universalk9.26.01.01.SPA.bin.iris-tmp"]
    protect = {"c8000v-universalk9.26.01.01.SPA.bin.iris-tmp"}
    assert ft.reclaimable_artifacts(dir_out, protect) == []


def test_reclaimable_allowlist_stays_anchored_on_the_platform_prefix():
    # Widening to c8000v must not loosen the anchor: an unrelated file that
    # merely ends in .bin/.pkg, or a family the agent has no evidence for, is
    # still never a candidate.
    dir_out = (
        "50  -rw-  100  Sep 10 2026 12:52:31 +00:00  vc8000v-universalk9.17.15.05.SPA.bin\n"
        "51  -rw-  100  Sep 10 2026 12:52:31 +00:00  c8000be-universalk9.17.15.05.SPA.bin\n"
        "52  -rw-  100  Sep 10 2026 12:52:31 +00:00  isr4300-universalk9.16.03.01.SPA.bin\n"
        "53  -rw-  100  Sep 10 2026 12:52:31 +00:00  backup.pkg\n"
        "54  -rw-  100  Sep 10 2026 12:52:31 +00:00  c8000v-universalk9.17.15.05.SPA.bin.bak\n"
        "5173313536 bytes total (2880884736 bytes free)\n")
    assert ft.reclaimable_artifacts(dir_out, set()) == []


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


def test_choose_stage_fs_operator_preference_wins_when_writable():
    fss = ft.parse_file_systems(_IE3400_FS_SD)
    assert ft.choose_stage_fs(fss, model="IE-3400-8T2S",
                              guest_share_fs="sdflash:",
                              preferred_fs="flash:") == "flash:"


def test_choose_stage_fs_ignores_unavailable_or_readonly_preference():
    fss = ft.parse_file_systems(_IE3400_FS_SD)
    assert ft.choose_stage_fs(fss, preferred_fs="usbflash1:") is None
    assert ft.choose_stage_fs(fss, preferred_fs="webui:") is None


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
