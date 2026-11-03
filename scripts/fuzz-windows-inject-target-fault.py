#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Long-running target-fault soak test for the vioscsi (virtio-scsi) Windows
# guest driver, built on the SCSI target fault branch (x-scsi-fault-*, see
# docs/devel/storage-error-injection.rst, "SCSI Target Faults").
#
# Derived from scripts/fuzz-windows-inject-tail-latency.py, which holds a
# random fraction of every LUN's requests for a fixed time and lets them go
# whatever the guest does. Real storage doesn't fail like that: a target
# stops answering and stays stuck until the initiator does the right kind
# of error recovery -- an abort, a LUN reset, a target reset -- and then
# comes back. This harness boots one VM and, for the whole run, takes one
# target at a time and makes it misbehave in one of a rotating set of ways
# (SCENARIOS): hung until a LUN reset, hung until a target reset with LUN
# resets refused or left hanging, slow, completing late, dead until the
# harness "replaces" it. Each fault is armed over QMP, lasts until the
# guest's recovery clears it (SCSI_FAULT_CLEARED) or a deadline passes, and
# is followed by a cooldown before the next one, on a target picked at
# random. Every cycle is recorded: what cleared it and how long that took,
# how many commands it held, and the TMFs the guest sent meanwhile.
#
# Commands a fault holds are held before they run, so a held write never
# reaches the disk: a recovery that cancels it really does throw it away.
# Everything else is as in the tail-latency harness: sustained I/O is
# driven from inside the guest via qemu-guest-agent for the full test
# duration, and the harness watches for the guest going dark (guest agent
# stops answering, screen stops changing, LUN I/O stops) as a bugcheck
# signal, and for virtio-scsi rings QEMU has marked broken, capturing a
# win-dmp crash dump via '-device vmcoreinfo' + QMP 'dump-guest-memory'
# (requires the fwcfg driver in the guest for a fully symbolized dump).
# With --hv-crash (the default) a bugcheck needs no guessing: Windows
# reports it through the Hyper-V crash MSRs, QEMU pauses the VM in
# guest-panicked, and the run ends there with the STOP code in the result.
#
# Prerequisites: identical to fuzz-windows-inject-scsi-reset.py -- see that
# script's usage_note() / module docstring, or run this one with --help.
#
# Expect I/O on the faulted target to stop dead while a stall scenario is
# armed. How much a fault holds depends on the writer. The default
# PowerShell writer keeps one command outstanding per LUN, so a fault holds
# about one command per LUN behind it. diskspd and fio keep a deep queue
# per LUN (WRITER_THREADS * WRITER_QUEUE_DEPTH): a stall then holds the
# whole queue, and during late-completion, with each command rolling the
# dice as it is issued, nearly every slot ends up held for the 61-65s hold
# at about the same time -- the same burst-then-silence duty cycle the
# tail-latency harness documents. The other targets carry on, which is what
# the I/O-stall detector watches while a fault is armed.
#
# All of those drivers do raw-disk I/O from an application buffer. The
# cached-read driver instead formats each LUN NTFS, writes one file bigger
# than guest RAM to it before the soak, and reads it over and over through
# the file cache: paging reads into physical pages the memory manager
# recycles, which is where a read completing after the driver gave up on it
# would land (see docs/devel/vioscsi-reset-race-investigation.md). Every
# chunk of those files says which LUN and offset it belongs to, and the
# readers check each one they read, so such a read is caught both ways: as
# wrong data in someone else's page, or as a bugcheck.
#
# --bsod puts that together into one recipe meant to bugcheck a driver
# that completes requests the device still owns: the late-dma scenario
# (see SCENARIOS) on the cached-read driver, with hv-crash so the bugcheck
# is caught with its STOP code. It is not part of a normal soak.

import argparse
import base64
import collections
import dataclasses
import hashlib
import itertools
import json
import math
import random
import re
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Optional

# The shared machinery lives next to this script, which is not necessarily
# the directory the harness is run from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# pylint: disable=wrong-import-position
from vioscsi_soak_common import (AGENT_CHECK_ATTEMPTS, AGENT_CHECK_TIMEOUT_S,
                                 AGENT_SILENCE_THRESHOLD_S, BOOT_DISK,
                                 BOOT_TIMEOUT_S, CHR_EVENTS,
                                 CHR_SOCKET_LABEL_RE, CLEAN_OUTCOMES,
                                 DEFAULT_CPUS,
                                 DEFAULT_DISKSPD_PATH, DEFAULT_FIO_PATH,
                                 DEFAULT_HEARTBEAT_S, DEFAULT_RAM,
                                 DEFAULT_VIOSCSI_TELEMETRY_SCRIPT, DIAG_EVENTS,
                                 DUMP_POLL_INTERVAL_S, DUMP_START_TIMEOUT_S,
                                 DUMP_TIMEOUT_S, FAILURE_OUTCOMES,
                                 FILL_POLL_INTERVAL_S,
                                 FILL_PROGRESS_INTERVAL_S, FILL_STALL_S,
                                 GUEST_EXEC_TIMEOUT_S,
                                 GuestExecError, IO_PROBE_ATTEMPTS,
                                 IO_STALL_MARGIN_S, LAUNCH_PROBE_INTERVAL_S,
                                 MIN_WRITE_OPS_PER_S, NoReplyError, OVMF_CODE,
                                 OVMF_VARS, POLL_INTERVAL_S, QEMU_BIN,
                                 QGA_PORT_SILENCE_CAPTURES, QGA_TRACE_EVENTS,
                                 QGA_TRACE_FIELD_RE, QGA_TRACE_LINE_RE,
                                 QMP_CMD_TIMEOUT_S, QTREE_NAME_RE,
                                 QTREE_PORT_RE, RESOLVE_REQUEST,
                                 STATIC_SCREEN_THRESHOLD_S,
                                 STOP_ON_BROKEN_SETTLE_S,
                                 TMF_RESPONSES, TMF_SUBTYPES, TMF_TRACE_EVENTS,
                                 TRACE_CONTEXT_LINES, TRACE_FIELD_RE,
                                 TRACE_LINE_RE, VIRTIO_BROKEN_PATTERNS,
                                 VIRTIO_SCSI_QUEUE_KINDS, VM_DIR, WARMUP_S,
                                 WRITER_BLOCK_BYTES, WRITER_DURATION_SLACK_S,
                                 WRITER_LAUNCH_TIMEOUT_S, WRITER_QUEUE_DEPTH,
                                 WRITER_THREADS,
                                 WRITER_WINDOW_BYTES, _covers_luns, _qga_call,
                                 b64_text, build_writer_script,
                                 capture_qemu_stacks,
                                 capture_vioscsi_telemetry, check_prereqs,
                                 classify_writer_exit, connect_qmp,
                                 count_guest_processes,
                                 explain_break, first_sight, guest_panic_info,
                                 image_bytes_on_disk, load_qmp_module,
                                 make_blank_image, make_overlay, ps_exec,
                                 qga_exec, qga_exec_wait, qga_ping,
                                 record_run_error, start_swtpm, stop_writers,
                                 utc_now, wall_time, writer_states)

SOAK_DIR = VM_DIR / "soak-target-fault"

# Writers that check what they read back and exit non-zero on the first
# mismatch: fio under '--verify_fatal=1'. Only for those does an early exit
# mean the data came back wrong rather than the writer merely dying, so
# only those are polled for it during the soak (see writers_failed).
# Deliberately narrower than the shared default: this harness does not
# drive paranoid.exe. The cached-read loop is not one either: it counts the
# reads that fail to it, and the chunks that read back wrong, and carries
# on, so it never exits early and is never classified
# (classify_writer_exit); its counts are asked for instead
# (cached_reads_corrupted).
VERIFYING_IO_DRIVERS = ("fio",)
# A dump the harness stopped the VM for can outlive DUMP_TIMEOUT_S, and
# QEMU refuses 'cont' while it runs. How much longer to wait for it to end
# before leaving the VM paused and saying so.
DUMP_RESUME_WAIT_S = 900
# How long LUN writes may stop before that counts towards "the guest has
# gone dark". Only LUNs no fault is holding are watched (see IoProgress
# and FaultCycler.unfaulted), but they can still sit out a while: the guest
# resetting the faulted target can pause the whole adapter, and a request
# it already timed out is retried only after the guest's own I/O timeout.
# So: that timeout, plus the longest hold any scenario puts on a command
# (late-completion's), plus slack (IO_STALL_MARGIN_S).
GUEST_IO_TIMEOUT_S = 60  # storport's default per-request timeout

# The pre-flight I/O probe runs before the first fault is armed, so nothing
# is held and a healthy writer shows up within seconds. The retry
# (IO_PROBE_ATTEMPTS) covers a writer that was slow to get going.
IO_PROBE_WINDOW_S = 10.0

# After an agent request before the soak (resolving drives, launching a
# writer) went unanswered, keep watching the agent and the LUNs this long
# before calling the agent gone. No fault is armed yet, so LUNs that stop
# are not being held; the time is for a guest too starved to schedule
# qemu-ga to come back.
LAUNCH_PROBE_S = 120.0

# After a virtio-scsi ring breaks, how long to watch which adapters still
# complete writes. The faults are removed first, so nothing is held; the
# window only has to outlast a guest busy recovering a timed-out request.
ADAPTER_ACTIVITY_WINDOW_S = 30.0

# Fault scenario defaults; see SCENARIOS and --help.
DEFAULT_RECOVERY_DEADLINE_S = 300.0
DEFAULT_WINDOW_S = 300.0
DEFAULT_DEAD_TARGET_S = 240.0
DEFAULT_COOLDOWN_S = 60.0
DEFAULT_TMF_HANG_MS = 30000
DEFAULT_LATE_PROBABILITY = 0.05
# late-dma: how long after its trigger (LATE_DMA_TRIGGERS) the held reads
# are let go. Long enough for the memory manager to hand the pages of a
# read that failed to someone else -- the readers on the other adapter
# (BSOD_ADAPTERS) churn through more than RAM, so freed pages are reused
# within seconds --
# and well short of the guest's ~60s timeout, so the release lands before
# the reads the guest reissued meanwhile time out and bring the next reset.
DEFAULT_LATE_DMA_DELAY_S = 10.0
# Between letting the held commands go and letting the hung LUN reset go:
# long enough for the released reads to finish on their own, so their data
# reaches guest memory as a normal completion rather than racing the reset
# that would cancel them (see the late-dma scenario). Waited out across
# ticks, not slept, so a bugcheck meanwhile is seen at once.
LATE_DMA_SETTLE_S = 5.0
# How a late-dma cycle ends having run its course, the held reads let go
# with the LUN reset still hung: what --bsod-cycles counts. Not interrupted
# (the harness removed everything at once, for a break, a dump or an
# error) nor removed (someone else did, when they chose).
LATE_DMA_DONE_OUTCOMES = ("released", "not-recovered")
# How often a late-dma cycle waiting for a read error asks the readers.
LATE_DMA_READ_POLL_S = 5.0
LATE_DMA_TRIGGERS = {"read-error": "first read error on the target",
                     "recovery": "first recovery attempt"}
# --bsod defaults, where they differ from a soak's. Several of the guest's
# 60s timeout-and-reset rounds can pass before Windows gives up retrying a
# read and fails it to the reader, so a cycle waits that much longer for
# it; 4G of guest RAM halves the cached-read files the soak first has to
# write, and makes the memory manager reuse freed pages sooner.
BSOD_RECOVERY_DEADLINE_S = 900.0
BSOD_RAM = "4G"
# The upstream driver's DeviceReset() pauses its whole adapter for up to
# 60s (StorPortPause), so readers on the faulted adapter's other targets
# stop with it, through the --late-dma-delay-s window when their churn is
# what reuses the failed reads' pages. Under --bsod the churn comes from a
# second adapter instead, and one target each is enough: more on the
# faulted adapter would only add files to write.
DEFAULT_ADAPTERS = 1
DEFAULT_TARGETS = 2
BSOD_ADAPTERS = 2
BSOD_TARGETS = 1
DEFAULT_BSOD_CYCLES = 3
# After a ring breaks under --bsod, how long to keep watching for a
# bugcheck before ending the run as virtio-broken. The faults are removed
# at the break, which lets every held read go: a late completion like any
# other, whose damage shows when the kernel next uses the page.
BSOD_BREAK_WATCH_S = 300.0
LATE_DELAY_MS = (61000, 65000)  # just past storport's ~60s timeout
SLOW_DELAY_MS = (5000, 15000)   # slow, but answering well within it
# How many of a cycle's TMFs are kept verbatim in its record; the rest
# are only counted.
CYCLE_TMF_LINES = 40
# --io-driver=cached-read: each LUN gets an NTFS volume, mounted on a
# folder rather than a drive letter so any number of LUNs fit, holding one
# file that is read over and over through the cache manager. The readers
# report what they have done to a status file each on C:, the SATA boot
# disk, which no fault can hold.
CACHED_READ_ROOT = r"C:\vioscsi-soak"
CACHED_READ_MOUNT_DIR = CACHED_READ_ROOT + r"\mnt"
CACHED_READ_STATUS_DIR = CACHED_READ_ROOT + r"\status"
CACHED_READ_FILE_NAME = "data.bin"
CACHED_READ_CHUNK_BYTES = 1024 * 1024
# The default file size, as a multiple of guest RAM: each LUN's file on its
# own has to outgrow the cache, or once a fault holds one target the
# readers left on the others are served from memory, issue no paging
# reads, and look to the stall check like a guest gone dark.
CACHED_READ_RAM_FACTOR = 1.25
# --ram as QEMU's -m reads it (qemu_ram_bytes), to size the file by.
QEMU_RAM_RE = re.compile(r"^\s*(\d+(?:\.\d*)?)\s*([BKMGTPE]?)\s*$", re.I)
QEMU_SIZE_UNITS = {u: 1024**i for i, u in enumerate("BKMGTPE")}
# The LUN image is the file plus room for NTFS and the partition table.
CACHED_READ_IMAGE_SLACK_GIB = 1
# How slowly the fill may go before the harness gives up on it: the
# images may sit on NFS (see --disk-dir), so allow for a crawl.
CACHED_READ_FILL_MIN_MIB_S = 4
CACHED_READ_FILL_BASE_S = 600
# Formatting goes one LUN at a time (build_cached_read_format_script):
# how long it may take.
CACHED_READ_FORMAT_BASE_S = 120
CACHED_READ_FORMAT_PER_LUN_S = 120
# Every chunk of a LUN's file says what it is, so a reader can check what
# it read and, when that is wrong, tell where it came from: it starts with
# CACHED_READ_HEADER -- magic, format, the run's seed, the LUN's index and
# serial, and the chunk's index (little-endian) -- and the rest is the
# LUN's own random template, rotated by CACHED_READ_BODY_STRIDE bytes per
# chunk so that no two chunks of a file under a PiB hold the same bytes at
# the same offset (build_cached_read_chunk_ps).
CACHED_READ_HEADER = struct.Struct("<4sIIIQ32s8x")
CACHED_READ_MAGIC = b"VSCR"
CACHED_READ_FORMAT = 1
CACHED_READ_SEED_AT = 8
CACHED_READ_CHUNK_INDEX_AT = 16
CACHED_READ_SERIAL_AT = 24
CACHED_READ_SERIAL_BYTES = 32
CACHED_READ_BODY_BYTES = CACHED_READ_CHUNK_BYTES - CACHED_READ_HEADER.size
CACHED_READ_BODY_STRIDE = 4099  # prime, so it shares no factor with the body
CACHED_READ_PAGE_BYTES = 4096
# How often a reader rewrites its status file between errors.
CACHED_READ_STATUS_EVERY_S = 5
CACHED_READ_STATUS_TIMEOUT_S = 30
CACHED_READ_STATUS_RE = re.compile(
    r"^STATUS (\S+) reads=(\d+) errors=(\d+) mismatches=(\d+) "
    r"passes=(\d+)\tlast_error=([^\t]*)\tlast_mismatch=([^\t]*)$")

# query-blockstats counters that make up a LUN's I/O for the stall and
# activity checks. Writes only, unless the workload only reads.
WRITE_OPS = ("wr_operations",)
READ_WRITE_OPS = ("rd_operations", "wr_operations")
IO_DRIVER_OPS = {"cached-read": READ_WRITE_OPS}

# Arming failures in a row before the run gives up: a QEMU without
# x-scsi-fault-*, or adapters the faults can't find, fail every time.
MAX_CONSECUTIVE_ARM_FAILURES = 3


def scenario_list() -> str:
    width = max(len(sc.name) for sc in SCENARIOS)
    return "\n".join(f"  {sc.name:<{width}}  {sc.summary}"
                     for sc in SCENARIOS)


def usage_note() -> str:
    return f"""
Prerequisites (one-time, on the golden image) -- same as
fuzz-windows-inject-scsi-reset.py:
  1. ./scripts/setup-windows-inject-vm.sh create
     WIN_ISO=/path/to/Win.iso ./scripts/setup-windows-inject-vm.sh install
  2. In the guest: install qemu-guest-agent and the vioscsi driver.
  3. Disable automatic restart on bugcheck (elevated PowerShell):
       Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name AutoReboot -Value 0
  4. For symbolized crash dumps (optional but recommended): install the
     fwcfg driver from the virtio-win ISO.
  5. For --io-driver=diskspd (optional): copy diskspd.exe into the guest
     at the path given by --diskspd-path (default: {DEFAULT_DISKSPD_PATH}).
  6. For --io-driver=fio (optional, runs with data-integrity verification):
     copy a Windows fio.exe build into the guest at the path given by
     --fio-path (default: {DEFAULT_FIO_PATH}).
  7. For --io-driver=cached-read, nothing beyond the Storage cmdlets every
     Windows has. The LUNs are formatted and the files written before the
     soak; that takes a while on NFS (progress is printed).
  8. For vioscsi telemetry collection (optional, on by default): have the
     script given by --vioscsi-telemetry-script (default:
     {DEFAULT_VIOSCSI_TELEMETRY_SCRIPT}) present in the guest.
  9. Shut down cleanly.

Fault scenarios (--scenarios), each armed on one whole target per cycle;
all but late-dma rotate by default:
{scenario_list()}

Each cycle in the result records what ended it: recovered (with cleared_by,
the recovery that did it, and time_to_clear_s), not-recovered (the guest
never got there within --recovery-deadline-s, or late-dma never saw its
trigger), window-ended, replaced (dead-target), released (late-dma let its
held commands run; its late_dma record says when and why), removed
(someone else removed it over QMP), interrupted (the harness removed every
fault: for a dump, a broken virtio ring, an error or the end of the run)
or arm-failed (the run ends after {MAX_CONSECUTIVE_ARM_FAILURES} in a row);
along with the commands it held, the recovery attempts it saw and the TMFs
the guest sent the target. scenario_summary rolls those up per scenario.

A/B for the reset race (docs/devel/vioscsi-reset-race-investigation.md):
run --bsod once with each driver build installed in the golden image. It
formats the LUNs and writes their files first (several GiB per LUN; on
NFS, expect a while), then runs late-dma cycles until the guest bugchecks
(guest-panicked, the STOP code printed and in guest_panic, panic.dmp in
the run directory) or survives --bsod-cycles of them: cycles-complete if
every chunk the readers read back was what was written, data-corruption
if late DMA left wrong data in the cache without crashing anything.
The upstream driver is expected to bugcheck; one that waits for the TMF
response before completing anything, to survive.

Environment overrides for running on different machines:
  QEMU_SRC, QEMU_BUILD   default to this script's own checkout
  VM_DIR                 default to $HOME/VirtualMachines/qemu/windows_inject
  OVMF_CODE              default to {OVMF_CODE}
"""


# ------------------------------------------------------------------
# QEMU guest agent client (same protocol/plumbing as the reset-race harness)
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# Guest-side PowerShell payloads
# ------------------------------------------------------------------


def build_resolve_script(serials: list) -> str:
    serial_list = ",".join(f"'{s}'" for s in serials)
    return f"""
$serials = @({serial_list})
foreach ($s in $serials) {{
    $d = Get-Disk | Where-Object {{ $_.SerialNumber -eq $s }}
    if ($d) {{
        if ($d.IsOffline) {{ Set-Disk -Number $d.Number -IsOffline $false }}
        if ($d.IsReadOnly) {{ Set-Disk -Number $d.Number -IsReadOnly $false }}
        Write-Output "MAP $s $($d.Number)"
    }} else {{
        Write-Output "MISSING $s"
    }}
}}
"""


def build_diskspd_args(drive_number: int, duration_s: float) -> list:
    # See fuzz-windows-inject-scsi-reset.py's build_diskspd_args for why this
    # is '#N' (raw physical drive), '-w100' + no '-c', and '-Sh'.
    return [
        f"-d{int(round(duration_s))}",
        "-w50",              # mixed read/write -- a pure-write workload
                              # would never have a read held by a fault
        f"-b{WRITER_BLOCK_BYTES}",
        "-s",
        f"-t{WRITER_THREADS}",
        f"-o{WRITER_QUEUE_DEPTH}",
        "-Sh",
        f"#{drive_number}",
    ]


def build_fio_args(drive_number: int, duration_s: float) -> list:
    # Single job at a high iodepth (rather than --numjobs>1) so concurrent
    # I/Os never target overlapping offsets from independent jobs -- that
    # would make verify failures indistinguishable from a held write landing
    # out of order. --serialize_overlap guards the same race within the one
    # job's own in-flight queue. Random read/write against a fixed window
    # lets fio verify previously-written blocks on every read for the life
    # of the run, rather than only checking data written-then-read in a
    # single pass. That is the check that matters here: a fault holds a
    # write before it runs, a recovery that cancels it throws it away, and
    # one the harness releases runs late, so a driver that completes a
    # write it gave up on, or re-issues it while QEMU still holds the
    # original, shows up as a verify failure.
    return [
        "--name=target-fault-soak",
        f"--filename=\\\\.\\PhysicalDrive{drive_number}",
        "--rw=randrw",
        "--rwmixread=50",
        f"--bs={WRITER_BLOCK_BYTES}",
        f"--size={WRITER_WINDOW_BYTES}",
        "--direct=1",
        "--thread",
        "--ioengine=windowsaio",
        f"--iodepth={WRITER_THREADS * WRITER_QUEUE_DEPTH}",
        "--serialize_overlap=1",
        "--time_based",
        f"--runtime={int(round(duration_s))}",
        "--verify=crc32c",
        "--do_verify=1",
        "--verify_fatal=1",
        "--continue_on_error=none",
    ]


def resolve_drive_numbers(qga_sock: Path, serials: list,
                          resyncs: Optional[list] = None) -> dict:
    pid = ps_exec(qga_sock, RESOLVE_REQUEST,
                   build_resolve_script(serials), capture=True,
                   resyncs=resyncs)
    status = qga_exec_wait(qga_sock, pid, timeout=GUEST_EXEC_TIMEOUT_S,
                           silent_raises=RESOLVE_REQUEST)
    if status is None:
        raise RuntimeError(f"guest-exec ({RESOLVE_REQUEST}) timed out")
    out = b64_text(status.get("out-data"))
    mapping: dict = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "MAP":
            mapping[parts[1]] = int(parts[2])
    missing = [s for s in serials if s not in mapping]
    if missing:
        raise RuntimeError(f"guest could not find disk(s) with serial(s): {missing}\n"
                            f"guest-exec output was:\n{out}")
    return mapping


def qemu_ram_bytes(size: str) -> int:
    """--ram in bytes, read the way QEMU reads -m: a bare number is MiB,
    and a B, K, M, G, T, P or E suffix, in either case, says otherwise.
    ValueError for anything else."""
    m = QEMU_RAM_RE.match(size)
    if not m:
        raise ValueError(f"not a QEMU memory size: {size!r}")
    return int(float(m.group(1)) * QEMU_SIZE_UNITS[(m.group(2) or "M").upper()])


def cached_read_paths(serial: str) -> tuple:
    """(mount folder, data file, status file) of a cached-read LUN."""
    mount = f"{CACHED_READ_MOUNT_DIR}\\{serial}"
    return (mount, f"{mount}\\{CACHED_READ_FILE_NAME}",
            f"{CACHED_READ_STATUS_DIR}\\{serial}.txt")


def cached_read_header(seed: int, lun_index: int, serial: str) -> bytes:
    """The header every chunk of a LUN's file starts with, chunk index 0
    (see CACHED_READ_HEADER)."""
    raw = serial.encode("ascii")
    if len(raw) > CACHED_READ_SERIAL_BYTES:
        raise ValueError(f"serial {serial!r} is longer than "
                         f"{CACHED_READ_SERIAL_BYTES} bytes")
    return CACHED_READ_HEADER.pack(CACHED_READ_MAGIC, CACHED_READ_FORMAT,
                                   seed, lun_index, 0, raw)


def cached_read_template_seed(seed: int, lun_index: int) -> int:
    """The System.Random seed of a LUN's chunk body template: the run's
    seed and the LUN, so no two LUNs of a run, nor two runs, share it."""
    return (seed ^ (lun_index * 0x9E3779B1)) & 0x7FFFFFFF


def cached_read_rotation(chunk: int) -> int:
    """Where in its LUN's template chunk number chunk's body starts."""
    return chunk * CACHED_READ_BODY_STRIDE % CACHED_READ_BODY_BYTES


def build_cached_read_chunk_ps(seed: int, lun_index: int, serial: str) -> str:
    """PowerShell defining Build-Chunk $dst $i, which writes chunk $i of a
    LUN's file into $dst: the LUN's header with $i patched in, then the
    LUN's template rotated by cached_read_rotation($i). Two array copies
    and a patch per chunk, so the fill and the reader's check stay cheap
    in PowerShell; the template is made once, from System.Random seeded
    with cached_read_template_seed, which the fill and the reader share."""
    hdr = base64.b64encode(cached_read_header(seed, lun_index,
                                              serial)).decode("ascii")
    body = CACHED_READ_BODY_BYTES
    head = CACHED_READ_HEADER.size
    return f"""
$hdr = [Convert]::FromBase64String('{hdr}')
$tpl = New-Object byte[] {body}
(New-Object System.Random -ArgumentList {cached_read_template_seed(seed, lun_index)}).NextBytes($tpl)
function Build-Chunk([byte[]]$dst, [int64]$i) {{
    [Array]::Copy($hdr, 0, $dst, 0, {head})
    [Array]::Copy([BitConverter]::GetBytes($i), 0, $dst, {CACHED_READ_CHUNK_INDEX_AT}, 8)
    $r = [int](($i * {CACHED_READ_BODY_STRIDE}) % {body})
    [Array]::Copy($tpl, $r, $dst, {head}, {body} - $r)
    if ($r -gt 0) {{ [Array]::Copy($tpl, 0, $dst, {head + body} - $r, $r) }}
}}
"""


def build_cached_read_format_script(luns: list) -> str:
    """Partition and format every cached-read LUN, one after another, and
    mount each on its folder. luns is (drive number, serial) pairs. Prints
    FORMATTED for each LUN done, and FAILED with the reason at the first
    that fails. One at a time: the Storage cmdlets run concurrently on
    several disks from separate PowerShells are asking for trouble, and
    formatting is quick next to the fill that follows."""
    # One ,@(...) per LUN: a lone @(...) inside @() would be flattened.
    rows = "\n".join(f"$luns += ,@({n}, '{serial}', "
                     f"'{cached_read_paths(serial)[0]}')"
                     for n, serial in luns)
    return f"""
$ErrorActionPreference = 'Stop'
$luns = @()
{rows}
New-Item -ItemType Directory -Force -Path '{CACHED_READ_STATUS_DIR}' | Out-Null
foreach ($l in $luns) {{
    $n, $serial, $mount = $l
    try {{
        if ((Get-Disk -Number $n).PartitionStyle -eq 'RAW') {{
            Initialize-Disk -Number $n -PartitionStyle GPT
        }}
        $p = New-Partition -DiskNumber $n -UseMaximumSize
        Format-Volume -Partition $p -FileSystem NTFS -NewFileSystemLabel $serial -Confirm:$false -Force | Out-Null
        New-Item -ItemType Directory -Force -Path $mount | Out-Null
        Add-PartitionAccessPath -DiskNumber $n -PartitionNumber $p.PartitionNumber -AccessPath "$mount\\"
        Write-Output "FORMATTED $serial"
    }} catch {{
        Write-Output "FAILED $serial $($_.Exception.Message)"
        exit 1
    }}
}}
"""


def build_cached_read_fill_script(serial: str, file_bytes: int, seed: int,
                                  lun_index: int) -> str:
    """Write the file the reader will read to one formatted LUN, chunk by
    chunk (build_cached_read_chunk_ps). Prints READY or FAILED with the
    reason.

    The file has to be written for real: a file only extended (SetLength,
    fsutil createnew) reads back as zeros from NTFS without touching the
    disk, past its valid data length, so the reader would never page
    anything in."""
    _, data, _ = cached_read_paths(serial)
    chunks = -(-file_bytes // CACHED_READ_CHUNK_BYTES)
    return f"""
$ErrorActionPreference = 'Stop'
try {{
{build_cached_read_chunk_ps(seed, lun_index, serial)}
    $buf = New-Object byte[] {CACHED_READ_CHUNK_BYTES}
    $fs = New-Object System.IO.FileStream('{data}', [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read, 4096)
    try {{
        for ($i = [int64]0; $i -lt {chunks}; $i++) {{
            Build-Chunk $buf $i
            $fs.Write($buf, 0, $buf.Length)
        }}
        $fs.Flush($true)
    }} finally {{
        $fs.Close()
    }}
    Write-Output "READY {serial} $((Get-Item '{data}').Length)"
}} catch {{
    Write-Output "FAILED {serial} $($_.Exception.Message)"
    exit 1
}}
"""


def build_cached_read_script(serial: str, duration_s: float, seed: int,
                             lun_index: int) -> str:
    """Read one LUN's file end to end, over and over, through a buffered
    FileStream: the handle is cached, so every read is the cache manager
    paging the file in, into whatever physical pages the memory manager
    hands it. A read that fails -- an in-page error after the driver
    completed the request with a bus reset, say -- is counted and skipped,
    never fatal: the loop is there to keep paging I/O going until the
    harness stops it.

    Each chunk read is checked against what the fill wrote there
    (Build-Chunk), by comparing SHA-1s, which runs at native speed where
    a byte loop in PowerShell would not. A chunk that differs is counted
    as a mismatch, apart from the errors, and described: how many of its
    pages differ, the first, whether that one is all zeros, and whose
    chunk header page 0 holds if it isn't this chunk's own. Data from
    another LUN, or another place in this one, says where a late transfer
    came from.

    The counts go to the LUN's status file soon after an error or a
    mismatch and every CACHED_READ_STATUS_EVERY_S otherwise, written to a
    temporary file and swapped in with File.Replace, so the harness never
    reads a half-written one. A write that fails (the harness reading the
    file at that moment, say) is retried on a later pass with the totals
    as they are then, so no update is lost."""
    _, data, status = cached_read_paths(serial)
    tmp = status[:-len(".txt")] + ".tmp"
    chunk = CACHED_READ_CHUNK_BYTES
    page = CACHED_READ_PAGE_BYTES
    pages = chunk // page
    return f"""
{build_cached_read_chunk_ps(seed, lun_index, serial)}
$buf = New-Object byte[] {chunk}
$exp = New-Object byte[] {chunk}
$sha = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$zeroHash = [BitConverter]::ToString($sha.ComputeHash((New-Object byte[] {page})))
$reads = [int64]0
$errors = [int64]0
$mismatches = [int64]0
$passes = [int64]0
$lastError = ''
$lastMismatch = ''
$chunk = [int64]0
$fs = $null
function Hash-Of([byte[]]$a, [int]$off, [int]$len) {{
    [BitConverter]::ToString($sha.ComputeHash($a, $off, $len))
}}
function Describe-Mismatch([int64]$i, [int]$got) {{
    if ($got -ne {chunk}) {{
        return "chunk $i at offset $($i * {chunk}): short read of $got bytes"
    }}
    $bad = 0
    $first = -1
    for ($p = 0; $p -lt {pages}; $p++) {{
        if ((Hash-Of $buf ($p * {page}) {page}) -ne (Hash-Of $exp ($p * {page}) {page})) {{
            $bad++
            if ($first -lt 0) {{ $first = $p }}
        }}
    }}
    $what = "chunk $i at offset $($i * {chunk}): $bad of {pages} pages differ, first page $first"
    if ($first -ge 0 -and (Hash-Of $buf ($first * {page}) {page}) -eq $zeroHash) {{
        $what += ' (all zeros)'
    }}
    if ($first -eq 0) {{
        if ([Text.Encoding]::ASCII.GetString($buf, 0, 4) -eq '{CACHED_READ_MAGIC.decode()}') {{
            $who = [Text.Encoding]::ASCII.GetString($buf, {CACHED_READ_SERIAL_AT}, {CACHED_READ_SERIAL_BYTES}).TrimEnd([char]0)
            $what += "; page 0 holds the header of $who chunk $([BitConverter]::ToInt64($buf, {CACHED_READ_CHUNK_INDEX_AT})) seed $([BitConverter]::ToUInt32($buf, {CACHED_READ_SEED_AT}))"
        }} else {{
            $what += '; page 0 holds no chunk header'
        }}
    }}
    return $what
}}
function Save-Status {{
    try {{
        [System.IO.File]::WriteAllText('{tmp}', "reads=$reads errors=$errors mismatches=$mismatches passes=$passes`tlast_error=$lastError`tlast_mismatch=$lastMismatch")
        if ([System.IO.File]::Exists('{status}')) {{
            [System.IO.File]::Replace('{tmp}', '{status}', [NullString]::Value)
        }} else {{
            [System.IO.File]::Move('{tmp}', '{status}')
        }}
        return $true
    }} catch {{
        return $false
    }}
}}
$statusDue = -not (Save-Status)
$lastStatus = Get-Date
$lastTry = $lastStatus
$deadline = (Get-Date).AddSeconds({duration_s})
while ((Get-Date) -lt $deadline) {{
    try {{
        if ($fs -eq $null) {{
            $fs = New-Object System.IO.FileStream('{data}', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite, 4096, [System.IO.FileOptions]::None)
        }}
        $fs.Position = $chunk * {chunk}
        $got = 0
        while ($got -lt {chunk}) {{
            $n = $fs.Read($buf, $got, {chunk} - $got)
            if ($n -le 0) {{ break }}
            $got += $n
        }}
        if ($got -eq 0) {{
            $chunk = [int64]0
            $passes++
        }} else {{
            $reads++
            Build-Chunk $exp $chunk
            if ($got -ne {chunk} -or (Hash-Of $buf 0 {chunk}) -ne (Hash-Of $exp 0 {chunk})) {{
                $mismatches++
                $lastMismatch = (Describe-Mismatch $chunk $got) -replace '\\s+', ' '
                $statusDue = $true
            }}
            $chunk++
        }}
    }} catch {{
        $errors++
        $lastError = $_.Exception.GetBaseException().Message -replace '\\s+', ' '
        $chunk++
        if ($fs -ne $null) {{ try {{ $fs.Dispose() }} catch {{ }}; $fs = $null }}
        $statusDue = $true
        Start-Sleep -Milliseconds 200
    }}
    $now = Get-Date
    if (($statusDue -or ($now - $lastStatus).TotalSeconds -ge {CACHED_READ_STATUS_EVERY_S}) -and ($now - $lastTry).TotalSeconds -ge 1) {{
        $lastTry = $now
        if (Save-Status) {{
            $statusDue = $false
            $lastStatus = $now
        }} else {{
            $statusDue = $true
        }}
    }}
}}
if ($fs -ne $null) {{ $fs.Dispose() }}
for ($try = 0; $try -lt 10 -and -not (Save-Status); $try++) {{ Start-Sleep -Milliseconds 500 }}
"""


def build_cached_read_status_script() -> str:
    """Print every reader's status file. Opened sharing delete, so a
    reader swapping in a new one is not refused for it; a file that can't
    be read right now is left out (the harness keeps what it had)."""
    return f"""
Get-ChildItem -Path '{CACHED_READ_STATUS_DIR}' -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {{
    try {{
        $fs = New-Object System.IO.FileStream($_.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]'ReadWrite, Delete'))
        try {{
            $text = (New-Object System.IO.StreamReader($fs)).ReadToEnd()
        }} finally {{
            $fs.Dispose()
        }}
        Write-Output "STATUS $($_.BaseName) $text"
    }} catch {{ }}
}}
"""


def parse_cached_read_status(out: str) -> dict:
    """serial -> what its reader last wrote to its status file. A line
    that doesn't parse (an empty or cut-short file) is left out."""
    status: dict = {}
    for line in out.splitlines():
        m = CACHED_READ_STATUS_RE.match(line.rstrip("\r\n"))
        if m:
            status[m.group(1)] = {"reads": int(m.group(2)),
                                  "errors": int(m.group(3)),
                                  "mismatches": int(m.group(4)),
                                  "passes": int(m.group(5)),
                                  "last_error": m.group(6) or None,
                                  "last_mismatch": m.group(7) or None}
    return status


def read_cached_read_status(qga_sock: Path) -> Optional[dict]:
    """Every cached-read LUN's status (parse_cached_read_status), or None
    if the guest agent could not be asked. A reader whose file could not
    be read is missing, not zero."""
    try:
        pid = ps_exec(qga_sock, "cached-read status",
                      build_cached_read_status_script(), capture=True,
                      timeout=CACHED_READ_STATUS_TIMEOUT_S)
        st = qga_exec_wait(qga_sock, pid, timeout=CACHED_READ_STATUS_TIMEOUT_S)
    except GuestExecError:
        return None
    if st is None:
        return None
    return parse_cached_read_status(b64_text(st.get("out-data")))


class CachedReadStatus:
    """The last status each cached-read LUN's reader reported. A poll
    that misses a LUN -- its file being swapped in, or the agent busy --
    keeps what that LUN said before rather than forgetting it."""

    def __init__(self, qga_sock: Path):
        self.qga_sock = qga_sock
        self.luns: dict = {}

    def poll(self) -> bool:
        """Ask the guest again. False if it couldn't be asked."""
        status = read_cached_read_status(self.qga_sock)
        if status is None:
            return False
        self.luns.update(status)
        return True

    def mismatched(self) -> dict:
        """serial -> (mismatches, the last one) for every LUN with any."""
        return {serial: (st["mismatches"], st["last_mismatch"])
                for serial, st in sorted(self.luns.items())
                if st["mismatches"]}


def cached_read_fill_timeout_s(total_bytes: int) -> float:
    return (CACHED_READ_FILL_BASE_S
            + total_bytes / (CACHED_READ_FILL_MIN_MIB_S * 1024 * 1024))


def _guest_script_result(qga_sock: Path, pid: int) -> Optional[dict]:
    """exitcode and the tail of the output of a guest script that has
    exited, or None while it runs."""
    resp, _, _ = _qga_call(qga_sock, "guest-exec-status", {"pid": pid}, 5.0)
    ret = (resp or {}).get("return") or {}
    if not ret.get("exited"):
        return None
    out = (b64_text(ret.get("out-data")).strip()
           or b64_text(ret.get("err-data")).strip())
    return {"exitcode": ret.get("exitcode"), "output": out[-400:]}


def prepare_cached_read(qga_sock: Path, lun_specs: list, drive_numbers: dict,
                        file_bytes: int, seed: int,
                        abort: Callable[[], Optional[str]],
                        resyncs: Optional[list] = None) -> dict:
    """Format every LUN (build_cached_read_format_script, one LUN at a
    time), then write every LUN's file at once
    (build_cached_read_fill_script) and wait for all of them. abort() is
    asked on every poll and ends the wait with its answer as the status
    (QEMU gone, the guest bugchecked).

    The fill is the slow part, and the guest only says how it went at the
    end, so progress comes from the host: how much of the LUN images is
    allocated, against the files' total. Returns a summary whose 'status'
    is 'ready' on success, otherwise 'failed', 'stalled', 'timeout' or
    abort()'s answer."""
    t0 = time.monotonic()
    info: dict = {"file_bytes": file_bytes, "seed": seed, "luns": {}}
    fmt_pid = ps_exec(qga_sock, "cached-read format",
                      build_cached_read_format_script(
                          [(drive_numbers[s.serial], s.serial)
                           for s in lun_specs]),
                      capture=True, resyncs=resyncs)
    fmt_deadline = t0 + CACHED_READ_FORMAT_BASE_S + (
        CACHED_READ_FORMAT_PER_LUN_S * len(lun_specs))
    while True:
        fmt = _guest_script_result(qga_sock, fmt_pid)
        now = time.monotonic()
        info["elapsed_s"] = round(now - t0, 1)
        if fmt is not None:
            info["format"] = fmt
            if fmt["exitcode"] != 0 or fmt["output"].count(
                    "FORMATTED") != len(lun_specs):
                info["status"] = "failed"
                info["failed"] = {"format": fmt}
                return info
            break
        why = abort()
        if why is not None:
            info["status"] = why
            return info
        if now >= fmt_deadline:
            info["status"] = "timeout"
            return info
        time.sleep(FILL_POLL_INTERVAL_S)

    pids: dict = {}
    for index, spec in enumerate(lun_specs):
        pids[spec.serial] = ps_exec(
            qga_sock, f"cached-read fill for {spec.serial}",
            build_cached_read_fill_script(spec.serial, file_bytes, seed,
                                          index),
            capture=True, resyncs=resyncs)
    want = file_bytes * len(lun_specs)
    t1 = time.monotonic()
    timeout_s = cached_read_fill_timeout_s(want)
    info["timeout_s"] = round(timeout_s)
    last_report = last_growth = t1
    prev_total = -1
    while True:
        for serial, pid in pids.items():
            if serial not in info["luns"]:
                done = _guest_script_result(qga_sock, pid)
                if done is not None:
                    info["luns"][serial] = done
        now = time.monotonic()
        info["elapsed_s"] = round(now - t0, 1)
        failed = {s: v for s, v in info["luns"].items()
                  if v["exitcode"] != 0 or "READY" not in v["output"]}
        if failed:
            info["status"] = "failed"
            info["failed"] = failed
            return info
        if len(info["luns"]) == len(pids):
            info["status"] = "ready"
            return info
        why = abort()
        if why is not None:
            info["status"] = why
            return info
        total = sum(image_bytes_on_disk(s.image) for s in lun_specs)
        info["bytes_on_disk"] = total
        if total > prev_total:
            prev_total = total
            last_growth = now
        if now - last_growth >= FILL_STALL_S:
            info["status"] = "stalled"
            return info
        if now - t1 >= timeout_s:
            info["status"] = "timeout"
            return info
        if now - last_report >= FILL_PROGRESS_INTERVAL_S:
            last_report = now
            print(f"    preparing cached-read LUNs: {total / 1024**3:.1f} of "
                  f"{want / 1024**3:.1f} GiB on disk, "
                  f"{len(info['luns'])}/{len(pids)} LUN(s) ready, "
                  f"{now - t0:.0f}s elapsed", file=sys.stderr)
        time.sleep(FILL_POLL_INTERVAL_S)


def launch_writer(qga_sock: Path, drive_number: int, duration_s: float,
                   io_driver: str = "powershell",
                   diskspd_path: str = DEFAULT_DISKSPD_PATH,
                   fio_path: str = DEFAULT_FIO_PATH,
                   resyncs: Optional[list] = None,
                   serial: Optional[str] = None,
                   data_seed: int = 0, lun_index: int = 0) -> int:
    """data_seed and lun_index are the cached-read reader's, which have to
    match the fill's (prepare_cached_read) for its check to pass."""
    what = f"writer for PhysicalDrive{drive_number}"
    if io_driver == "cached-read":
        return ps_exec(qga_sock, f"cached reader for {serial}",
                       build_cached_read_script(serial, duration_s,
                                                data_seed, lun_index),
                       capture=False, resyncs=resyncs)
    if io_driver == "diskspd":
        return qga_exec(qga_sock, what, diskspd_path,
                         build_diskspd_args(drive_number, duration_s),
                         capture=False, resyncs=resyncs)
    if io_driver == "fio":
        # Captured, unlike the other drivers': fio writes "verify: bad
        # magic header ..." and the failing offset to stderr, and the agent
        # only hands that back for a process started with capture-output.
        # The exit code alone would say a verify failed but not where.
        return qga_exec(qga_sock, what, fio_path,
                         build_fio_args(drive_number, duration_s),
                         capture=True, resyncs=resyncs)
    return ps_exec(qga_sock, what,
                    build_writer_script(drive_number, duration_s),
                    capture=False, resyncs=resyncs)


def diskspd_diagnostic(qga_sock: Path, diskspd_path: str,
                        drive_number: int) -> str:
    # Only run before the first fault is armed, so nothing it issues is
    # held and the ordinary guest-exec timeout is enough.
    diag_timeout = GUEST_EXEC_TIMEOUT_S
    try:
        pid = qga_exec(qga_sock, "diskspd diagnostic", diskspd_path,
                        build_diskspd_args(drive_number, 1),
                        capture=True, timeout=diag_timeout)
    except GuestExecError as exc:
        return f"diskspd failed to even launch at {diskspd_path!r}: {exc}"
    status = qga_exec_wait(qga_sock, pid, timeout=diag_timeout)
    if status is None:
        return "diskspd diagnostic run timed out"
    out = b64_text(status.get("out-data")).strip()
    err = b64_text(status.get("err-data")).strip()
    return (f"diskspd exitcode={status.get('exitcode')}; "
            f"stdout={out[:400]!r}; stderr={err[:400]!r}")


def fio_diagnostic(qga_sock: Path, fio_path: str, drive_number: int) -> str:
    # Like diskspd_diagnostic, only run before any fault is armed.
    diag_timeout = GUEST_EXEC_TIMEOUT_S
    try:
        pid = qga_exec(qga_sock, "fio diagnostic", fio_path,
                        build_fio_args(drive_number, 1),
                        capture=True, timeout=diag_timeout)
    except GuestExecError as exc:
        return f"fio failed to even launch at {fio_path!r}: {exc}"
    status = qga_exec_wait(qga_sock, pid, timeout=diag_timeout)
    if status is None:
        return "fio diagnostic run timed out"
    out = b64_text(status.get("out-data")).strip()
    err = b64_text(status.get("err-data")).strip()
    return (f"fio exitcode={status.get('exitcode')}; "
            f"stdout={out[:400]!r}; stderr={err[:400]!r}")


# ------------------------------------------------------------------
# QEMU process / QMP plumbing
# ------------------------------------------------------------------


@dataclasses.dataclass
class LunSpec:
    adapter: int  # which virtio-scsi-pci adapter (bus "scsi{adapter}.0")
    target: int   # SCSI target (scsi-id) within that adapter
    lun: int      # LUN within that target
    image: Path
    file_node: str
    fmt_node: str
    dev_id: str
    serial: str


def build_qemu_argv(boot_overlay: Path, vars_overlay: Path, qmp_sock: Path,
                     qga_sock: Path, serial_log: Path, tpm_sock: Path,
                     adapters: int, lun_specs: list, ram: str,
                     cpus: str, taskset_cores: Optional[str],
                     iothreads: Optional[int] = None,
                     tmf_trace: bool = True,
                     stop_on_broken: bool = True,
                     ring_diag: bool = True,
                     qga_trace: bool = True,
                     hv_crash: bool = True) -> list:
    argv: list = []
    if taskset_cores:
        argv += ["taskset", "-c", taskset_cores]

    argv += [
        str(QEMU_BIN),
        "-machine", "q35,accel=kvm,smm=on",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-cpu", "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,"
                "hv-synic,hv-stimer,hv-time,hv-ipi,hv-tlbflush"
                + (",hv-crash" if hv_crash else ""),
        "-smp", cpus,
        "-m", ram,
        "-device", "vmcoreinfo",
        "-drive", f"if=pflash,format=qcow2,unit=0,file={OVMF_CODE},readonly=on",
        "-drive", f"if=pflash,format=qcow2,unit=1,file={vars_overlay}",
        "-chardev", f"socket,id=chrtpm,path={tpm_sock}",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-crb,tpmdev=tpm0",
        "-display", "none",
        "-vga", "std",
        "-qmp", f"unix:{qmp_sock},server=on,wait=off",
        # Puts a timestamp on virtio_error()'s messages, and on trace lines
        # too, since they share the stream -- see TMF_TRACE_EVENTS.
        "-msg", "timestamp=on",
        "-serial", f"file:{serial_log}",
        "-chardev", f"socket,path={qga_sock},server=on,wait=off,id=qga0",
        "-device", "virtio-serial",
        "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        # Boot disk is SATA/AHCI, so target faults, which live on the
        # virtio-scsi adapters below, never touch it. Its inject-error
        # filter has no rules here and passes everything through.
        "-device", "ahci,id=ahci0",
        "-blockdev", f"driver=file,filename={boot_overlay},node-name=file0",
        "-blockdev", "driver=qcow2,file=file0,node-name=raw0",
        "-blockdev", "driver=inject-error,image=raw0,node-name=err0",
        "-device", "ide-hd,bus=ahci0.0,drive=err0,bootindex=0,id=disk0",
    ]

    if hv_crash:
        # A bugcheck then parks the VM in guest-panicked, with the STOP code
        # in the GUEST_PANICKED event, instead of QEMU's default of powering
        # it off and taking the crashed guest's memory with it.
        argv += ["-action", "panic=pause"]

    # The faults' own add/recovery/clear lines: a few per cycle, on the same
    # clock as the TMFs, so qemu.log shows what each TMF did to the fault
    # (cleared it, or was let through, refused or left hanging). Always on:
    # the per-cycle record is built from them.
    for event in FAULT_TRACE_EVENTS:
        argv += ["-trace", f"enable={event}"]
    if tmf_trace:
        for event in TMF_TRACE_EVENTS:
            argv += ["-trace", f"enable={event}"]
    if qga_trace:
        for event in QGA_TRACE_EVENTS:
            argv += ["-trace", f"enable={event}"]

    # Give each adapter its own iothread so LUN I/O stops sharing a thread
    # with the guest agent's virtio-serial channel and the QMP socket the
    # harness polls -- otherwise the harness's own control plane queues
    # behind the data plane it is trying to stress. It also makes the
    # workload harsher where it matters: completions arrive on several
    # threads at once, which is far better at finding races in vioscsi's
    # per-adapter locking than one thread serializing everything.
    n_iothreads = adapters if iothreads is None else iothreads
    for i in range(n_iothreads):
        argv += ["-object", f"iothread,id=iothread{i}"]

    for a in range(adapters):
        props = f"virtio-scsi-pci,id=scsi{a}"
        if n_iothreads:
            props += f",iothread=iothread{a % n_iothreads}"
        if stop_on_broken:
            props += ",x-stop-on-broken=on"
        if not ring_diag:
            props += ",x-diag=off"
        argv += ["-device", props]

    for spec in lun_specs:
        argv += [
            "-blockdev", f"driver=file,filename={spec.image},node-name={spec.file_node}",
            "-blockdev", f"driver=qcow2,file={spec.file_node},node-name={spec.fmt_node}",
            "-device", f"scsi-hd,drive={spec.fmt_node},bus=scsi{spec.adapter}.0,"
                       f"scsi-id={spec.target},lun={spec.lun},"
                       f"id={spec.dev_id},serial={spec.serial}",
        ]

    return argv


_qmp_ids = itertools.count()


class QmpCommandError(RuntimeError):
    """QEMU answered the command with an error, as opposed to not
    answering it at all (a timeout or a dropped connection)."""


def qmp_call(qmp, name: str, **kwargs) -> Any:
    args = {k.replace("_", "-"): v for k, v in kwargs.items()}
    msg = {"execute": name, "id": f"soak-{next(_qmp_ids)}"}
    if args:
        msg["arguments"] = args
    resp = qmp.cmd_obj(msg)
    if "error" in resp:
        raise QmpCommandError(f"{name}: {resp['error']}")
    return resp.get("return")


def screendump_hash(qmp, path: Path) -> Optional[str]:
    try:
        qmp_call(qmp, "screendump", filename=str(path))
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def virtio_serial_ports(qmp) -> list:
    """Each virtio-serial port as info qtree reports it: whether the guest
    has it open, whether a host client is connected, and whether QEMU is
    holding a guest write it could not pass on (throttled). Asked between
    agent calls, host_connected=False is normal: the harness connects only
    for the length of a call. So is throttled=False, even if a write was
    lost: the close that ends each call unthrottles the port and discards
    what it held, leaving nothing here to see. Throttled with no host
    connected only follows a write that disconnected the socket itself
    (see QGA_TRACE_EVENTS), and then QEMU holds nothing."""
    text = qmp_call(qmp, "human-monitor-command", command_line="info qtree")
    ports, name = [], None
    for line in text.splitlines():
        if line.lstrip().startswith("dev:"):
            name = None
        m = QTREE_NAME_RE.match(line)
        if m:
            name = m.group(1)
            continue
        m = QTREE_PORT_RE.search(line)
        if m:
            ports.append({"port": int(m.group(1)), "name": name,
                          "guest_open": m.group(2) == "on",
                          "host_connected": m.group(3) == "on",
                          "throttled": m.group(4) == "on"})
    return ports


def try_dump_guest_memory(qmp, path: Path, qemu_pid: int,
                          disarm: Callable[[], None],
                          notes: Optional[dict] = None) -> bool:
    """Dump guest memory to path in win-dmp format. Removes every target
    fault first, by calling disarm(), and leaves them removed.

    Faults could stay for the dump itself: a held command never reaches
    the block layer, so neither stopping the VM nor the dump waits on it.
    They go because of what follows a dump -- telemetry, writers being
    stopped, the end of the run -- which needs the guest's I/O to work.

    The faults are removed with the VM stopped. Commands they release then
    wait for the VM to run again (see x-scsi-fault-add), so the dump still
    shows them in flight, as the driver last saw them; removed with the VM
    running, they would complete into guest memory before the dump. If the
    VM was running, this stops it and resumes it afterwards: dump-guest-
    memory only resumes a VM it stopped itself. If that fails -- a dump
    that is still writing after DUMP_TIMEOUT_S + DUMP_RESUME_WAIT_S -- the
    VM stays paused, and notes["vm_left_paused"] says why, so nothing
    after it mistakes a paused guest for a dead one."""
    stopped_here = False
    try:
        if (qmp_call(qmp, "query-status") or {}).get("running"):
            qmp_call(qmp, "stop")
            stopped_here = True
    except Exception as exc:
        print(f"    could not stop the VM before the dump: {exc!r}",
              file=sys.stderr)
    try:
        disarm()
        return _dump_guest_memory(qmp, path, qemu_pid)
    finally:
        if stopped_here:
            why = resume_after_dump(qmp)
            if why is not None and notes is not None:
                notes["vm_left_paused"] = why


def resume_after_dump(qmp) -> Optional[str]:
    """'cont' once no dump is running any more. QEMU refuses it while one
    is ("There is a dump in process"), so a dump that outlived
    _dump_guest_memory's wait would otherwise leave the VM paused for
    good. Returns None once the VM runs, else why it is still paused."""
    deadline = time.monotonic() + DUMP_RESUME_WAIT_S
    state = "unknown"
    while True:
        try:
            state = (qmp_call(qmp, "query-dump") or {}).get("status", "?")
        except Exception as exc:
            state = f"query-dump failed: {exc!r}"
        if state != "active" and not state.startswith("query-dump failed"):
            break
        if time.monotonic() >= deadline:
            why = (f"the dump was still running {DUMP_RESUME_WAIT_S}s after "
                   f"the harness stopped waiting for it ({state})")
            print(f"    VM left paused: {why}", file=sys.stderr)
            return why
        time.sleep(DUMP_POLL_INTERVAL_S)
    try:
        qmp_call(qmp, "cont")
    except Exception as exc:
        why = f"cont after the dump failed: {exc!r}"
        print(f"    VM left paused: {why}", file=sys.stderr)
        return why
    return None


def _dump_guest_memory(qmp, path: Path, qemu_pid: int) -> bool:
    path.unlink(missing_ok=True)

    qmp.settimeout(DUMP_START_TIMEOUT_S)
    try:
        qmp_call(qmp, "dump-guest-memory", paging=False, detach=True,
                 protocol=f"file:{path}", format="win-dmp")
    except TimeoutError:
        print(f"    dump-guest-memory not acknowledged after "
              f"{DUMP_START_TIMEOUT_S}s, checking whether it started",
              file=sys.stderr)
        capture_qemu_stacks(qemu_pid, path.with_name("qemu-stacks.txt"))
    except Exception as exc:
        print(f"    dump-guest-memory refused: {exc!r}", file=sys.stderr)
        return False
    finally:
        qmp.settimeout(QMP_CMD_TIMEOUT_S)

    deadline = time.monotonic() + DUMP_TIMEOUT_S
    status: dict = {}
    while time.monotonic() < deadline:
        try:
            status = qmp_call(qmp, "query-dump")
        except TimeoutError:
            continue
        except Exception as exc:
            print(f"    query-dump failed: {exc!r}", file=sys.stderr)
            return False
        if status["status"] == "none":
            print("    dump-guest-memory never started (see qemu.log)",
                  file=sys.stderr)
            return False
        if status["status"] == "completed":
            return True
        if status["status"] == "failed":
            print("    dump-guest-memory failed while writing (see qemu.log)",
                  file=sys.stderr)
            return False
        time.sleep(DUMP_POLL_INTERVAL_S)
    print(f"    dump-guest-memory still running after {DUMP_TIMEOUT_S}s "
          f"({status.get('completed')}/{status.get('total')} bytes), giving up",
          file=sys.stderr)
    capture_qemu_stacks(qemu_pid, path.with_name("qemu-stacks.txt"))
    return False


# ------------------------------------------------------------------
# Telemetry
# ------------------------------------------------------------------


# The target faults' tracepoints the harness always enables (see
# build_qemu_argv): the fault being armed, each recovery attempt on it and
# what the fault made of it, and the fault clearing. Not scsi_fault_hold
# and scsi_fault_release, which fire per command -- tens of thousands of
# lines in a late-completion window.
FAULT_TRACE_EVENTS = ("scsi_fault_add", "scsi_fault_recovery",
                      "scsi_fault_clear")
FAULT_TRACE_LINE_RE = re.compile(r"^(?:(\S+Z) )?scsi_fault_(\w+) ")

# TMF tracepoints that name a target, and so can be pinned to a fault cycle,
# plus the adapter reset, which names none but resets every target on the
# bus -- the faulted one included, when the guest escalates that far
CYCLE_TMF_EVENTS = ("tmf_req", "tmf_resp", "tmf_hang", "tmf_drop",
                    "tmf_delay", "reset")


class CycleTrace:
    """The trace lines that belong to one fault cycle: TMFs the guest sent
    to the faulted target, adapter resets on its bus, and what the fault
    made of each recovery attempt (scsi_fault_recovery's action). Fed by
    QemuStderr while the cycle is watched; lines stamped before the fault
    was armed are skipped, since QemuStderr only reads the log once per
    poll."""

    def __init__(self, bus: str, target: int, fault_id: str, since: str):
        self.bus = bus
        self.target = target
        self.fault_id = fault_id
        self.since = since
        self.tmf_counts: dict = {}
        self.tmf_lines: list = []
        self.fault_actions: dict = {}

    def _current(self, ts: Optional[str]) -> bool:
        # Both are UTC_FORMAT, which sorts as text. A line without a
        # timestamp (QEMU run without -msg timestamp=on) counts.
        return ts is None or ts >= self.since

    def feed_tmf(self, ts: Optional[str], key: str, fields: dict,
                 line: str) -> None:
        if (fields.get("bus") != self.bus
                or (key != "reset" and fields.get("target") != str(self.target))
                or not self._current(ts)):
            return
        self.tmf_counts[key] = self.tmf_counts.get(key, 0) + 1
        if len(self.tmf_lines) < CYCLE_TMF_LINES:
            self.tmf_lines.append(line)

    def feed_fault(self, ts: Optional[str], event: str, fields: dict) -> None:
        if (event != "recovery" or fields.get("bus") != self.bus
                or fields.get("id") != self.fault_id
                or not self._current(ts)):
            return
        key = f"{fields.get('recovery', '?')}:{fields.get('action', '?')}"
        self.fault_actions[key] = self.fault_actions.get(key, 0) + 1

    def as_dict(self) -> dict:
        return {"tmfs": self.tmf_counts,
                "tmf_lines": self.tmf_lines,
                # Every counted line, requests and responses alike, is
                # kept until CYCLE_TMF_LINES.
                "tmf_lines_truncated":
                    sum(self.tmf_counts.values()) > len(self.tmf_lines),
                "fault_actions": self.fault_actions}


class QemuStderr:
    """Incremental reader for QEMU's stderr log.

    QEMU writes a handful of lines here over a whole run and the harness
    used to ignore all of them, which is how a wedged virtio device went
    unnoticed for 45 minutes. Plain lines are kept for the result, and the
    virtio_error() family is called out because it means a device is
    broken for good rather than merely complaining.

    virtio-scsi trace lines are tallied per adapter instead of kept
    verbatim (there can be thousands; qemu.log has them all). When an
    adapter's virtio_scsi_broken line arrives, the last few trace lines
    for that same adapter are attached to it: that is the question this
    exists to answer -- what was this adapter being asked to do right
    before its ring went bad?

    The guest agent port's trace lines (QGA_TRACE_EVENTS) are tallied in
    qga, along with whether the port is throttled now and the last line of
    each kind that matters when the agent goes quiet. closed_while_throttled
    and short_writes_with_no_client count the two orders in which a client
    leaving can throw away a guest write QEMU was holding -- the leak the
    56-minute hang in run-1791602155 is suspected of.

    Target fault lines (FAULT_TRACE_EVENTS) are tallied per adapter with
    the virtio-scsi ones, as fault_<event>, and recovery attempts by what
    the fault did with them; they are part of the history attached to a
    broken event too. A fault cycle in progress gets its own lines through
    watch() (see CycleTrace)."""

    def __init__(self, path: Path):
        self.path = path
        self.pos = 0
        self.lines: list = []
        self.qga: dict = {"counts": {}, "throttled": None,
                          "client_open": None}
        self.trace_counts: dict = {}
        self.broken_events: list = []
        self.overlaps: dict = {}
        self._recent: dict = {}
        self._pending_broken: list = []
        self._chain: dict = {}
        self._watchers: list = []

    def watch(self, trace: CycleTrace) -> None:
        self._watchers.append(trace)

    def unwatch(self, trace: CycleTrace) -> None:
        if trace in self._watchers:
            self._watchers.remove(trace)

    def poll(self) -> None:
        try:
            with self.path.open("r", errors="replace") as f:
                f.seek(self.pos)
                new = f.readlines()
                self.pos = f.tell()
        except OSError:
            return
        for line in new:
            line = line.strip()
            if not line:
                continue
            m = TRACE_LINE_RE.match(line)
            if m:
                if m.group(2) == "virtqueue_chain":
                    self._chain_line(m.group(3), line)
                else:
                    self._trace(m.group(3), line, m.group(1))
                continue
            m = FAULT_TRACE_LINE_RE.match(line)
            if m:
                self._fault_trace(m.group(2), line, m.group(1))
                continue
            m = QGA_TRACE_LINE_RE.match(line)
            if m:
                self._qga_trace(m.group(2), line)
                continue
            self.lines.append(line)
            if any(pat.search(line) for pat in VIRTIO_BROKEN_PATTERNS):
                self._pending_broken.append(line)

    def has_broken(self) -> bool:
        """Whether take_broken() has lines to return."""
        return bool(self._pending_broken)

    def take_broken(self) -> list:
        """virtio_error() lines seen since the last call.

        Kept until claimed rather than returned from poll(), so one seen
        while reading boot and pre-flight output is still reported once
        the soak starts instead of being silently dropped with the rest of
        the boot noise."""
        lines, self._pending_broken = self._pending_broken, []
        return lines

    def take_counts(self) -> dict:
        """Per-adapter trace tallies so far, and start a fresh tally.

        Only the tallies restart. The per-adapter history attached to a
        broken event is one continuous, timestamped timeline: an adapter
        reset during pre-flight is exactly the context worth seeing if
        that adapter breaks soon after."""
        counts, self.trace_counts = self.trace_counts, {}
        return counts

    def tmf_requests(self) -> int:
        return sum(n for per_bus in self.trace_counts.values()
                   for k, n in per_bus.items() if k.startswith("tmf_req"))

    def _chain_line(self, event: str, line: str) -> None:
        """The virtio core's dump of the chain a ring broke on. It comes
        just before that adapter's virtio_scsi_broken line, which picks it
        up."""
        fields = dict(TRACE_FIELD_RE.findall(line))
        bus = fields.get("dev", "?") + ".0"
        if event == "error":
            self._chain[bus] = {**fields, "descs": []}
            return
        chain = self._chain.setdefault(bus, {"descs": []})
        if event == "summary":
            chain.update(fields)
        elif event == "entry":
            chain["descs"].append(fields)

    def _qga_trace(self, event: str, line: str) -> None:
        fields = {k: int(v) for k, v in QGA_TRACE_FIELD_RE.findall(line)}
        if event == "virtio_console_flush_buf":
            key = "writes"
            self.qga["last_write"] = line
            if fields.get("out_len", 0) < fields.get("in_len", 0):
                self._qga_count("short_writes")
                self.qga["last_short_write"] = line
                if self.qga["client_open"] is False:
                    self._qga_count("short_writes_with_no_client")
                    self.qga["last_short_write_with_no_client"] = line
        elif event == "virtio_serial_throttle_port":
            throttled = bool(fields.get("throttle"))
            key = "throttle_on" if throttled else "throttle_off"
            self.qga["throttled"] = throttled
            self.qga["last_throttle"] = line
        elif event == "virtio_console_chr_event":
            n = fields.get("event", -1)
            key = "client_" + CHR_EVENTS.get(n, str(n))
            if n == 1:
                self.qga["client_open"] = True
            elif n == 4:
                self.qga["client_open"] = False
                if self.qga["throttled"]:
                    # QEMU unthrottles here without a trace line.
                    self.qga["throttled"] = False
                    self._qga_count("closed_while_throttled")
                    self.qga["last_closed_while_throttled"] = line
        else:  # chr_socket_poll_err, which also covers the QMP socket
            m = CHR_SOCKET_LABEL_RE.search(line)
            key = "socket_write_errors:" + (m.group(1) if m else "?")
            self.qga["last_socket_write_error"] = line
        self._qga_count(key)

    def _qga_count(self, key: str) -> None:
        counts = self.qga["counts"]
        counts[key] = counts.get(key, 0) + 1

    def _last_broken(self, bus: str) -> Optional[dict]:
        return next((ev for ev in reversed(self.broken_events)
                     if ev["bus"] == bus), None)

    def _diag(self, event: str, bus: str, fields: dict) -> None:
        if "overlaps" in fields or event == "req_overlap":
            n = int(fields.get("count", fields.get("overlaps", 0)))
            self.overlaps[bus] = max(self.overlaps.get(bus, 0), n)
        ev = self._last_broken(bus)
        if ev is None:
            return
        if event == "broken_before":
            ev["before"] = {**fields, "descs": []}
        elif event == "broken_before_detail":
            ev.setdefault("before", {"descs": []}).update(fields)
        elif event == "broken_before_entry":
            ev.setdefault("before", {"descs": []})["descs"].append(fields)
        elif event == "broken_verdict":
            ev["verdict"] = fields.get("verdict")
            ev["verdict_detail"] = fields
        elif event == "stop_on_broken":
            ev["stopped_vm"] = True
        if "verdict" in ev:
            ev["mechanism"] = explain_break(ev)

    def _fault_trace(self, event: str, line: str, ts: Optional[str]) -> None:
        fields = dict(TRACE_FIELD_RE.findall(line))
        bus = fields.get("bus", "?")
        key = f"fault_{event}"
        if event == "recovery":
            key += f":{fields.get('recovery', '?')}:{fields.get('action', '?')}"
        per_bus = self.trace_counts.setdefault(bus, {})
        per_bus[key] = per_bus.get(key, 0) + 1
        for w in self._watchers:
            w.feed_fault(ts, event, fields)
        self._recent.setdefault(
            bus, collections.deque(maxlen=TRACE_CONTEXT_LINES)).append(line)

    def _trace(self, event: str, line: str, ts: Optional[str] = None) -> None:
        fields = dict(TRACE_FIELD_RE.findall(line))
        bus = fields.get("bus", "?")
        if event in DIAG_EVENTS:
            self._diag(event, bus, fields)
            return
        key = event
        if event == "tmf_req":
            key += ":" + TMF_SUBTYPES.get(int(fields.get("subtype", -1)),
                                          fields.get("subtype", "?"))
        elif event == "tmf_resp":
            key += ":" + TMF_RESPONSES.get(int(fields.get("response", -1)),
                                           fields.get("response", "?"))
        per_bus = self.trace_counts.setdefault(bus, {})
        per_bus[key] = per_bus.get(key, 0) + 1
        if event in CYCLE_TMF_EVENTS:
            for w in self._watchers:
                w.feed_tmf(ts, key, fields, line)

        recent = self._recent.setdefault(
            bus, collections.deque(maxlen=TRACE_CONTEXT_LINES))
        if event == "broken":
            queue = int(fields.get("queue", -1))
            self.broken_events.append({
                "bus": bus,
                "queue": queue,
                "queue_kind": VIRTIO_SCSI_QUEUE_KINDS.get(queue, "request"),
                "line": line,
                "preceding": list(recent),
                "chain": self._chain.pop(bus, None),
            })
        recent.append(line)


def write_ops_by_node(qmp, counted: tuple = WRITE_OPS) -> dict:
    """identifier -> cumulative completed write operations, or the sum of
    whichever query-blockstats counters counted names (IO_DRIVER_OPS: a
    workload that only reads has to be judged by its reads). See
    fuzz-windows-inject-scsi-reset.py's write_ops_by_node for why both
    query-blockstats views (device/qdev accounting lives on the
    BlockBackend, not the per-node view) have to be merged."""
    out: dict = {}
    for query_nodes in (False, True):
        try:
            stats = qmp_call(qmp, "query-blockstats",
                             query_nodes=query_nodes) or []
        except Exception:
            continue
        for entry in stats:
            st = entry.get("stats", {})
            wr = sum(st.get(c, 0) for c in counted)
            for key in ("device", "qdev", "node-name"):
                ident = entry.get(key)
                if ident:
                    out[ident] = max(out.get(ident, 0), wr)
    return out


def lun_write_delta(before: dict, after: dict, spec: "LunSpec") -> int:
    return max(after.get(k, 0) - before.get(k, 0)
               for k in (spec.dev_id, spec.fmt_node, spec.file_node))


def lun_writes(wops: dict, spec: "LunSpec") -> int:
    """One LUN's cumulative writes. query-blockstats reports them under
    several identifiers, which must not be added together."""
    return max(wops.get(k, 0)
               for k in (spec.dev_id, spec.fmt_node, spec.file_node))


class IoProgress:
    """When writes last completed on a LUN no fault was holding: the I/O
    half of "the guest has gone dark".

    Compares each LUN with itself, sample to sample, and only counts LUNs
    that were unfaulted in both samples. So the set being watched can
    change with every cycle without the clock starting over -- which it
    did when the check compared totals over the watched set, and so had to
    restart it whenever the set changed: with cycles shorter than the
    threshold, a dead guest was never caught. A LUN leaving a fault is
    left out for the one sample in which it does: what completes on it
    then is the commands the fault released, which QEMU runs whether or
    not the guest is alive.

    With --io-driver=cached-read the samples count reads as well (see
    IO_DRIVER_OPS), since that workload does nothing else.

    Only the data LUNs count, never the boot disk: it is SATA/AHCI and no
    fault can touch it, so Windows keeps writing to C: -- pagefile, event
    log, registry -- long after every LUN under test has stopped dead,
    which made an earlier version of the check think the guest was making
    progress forever."""

    def __init__(self, now: float, wops: dict, lun_specs: list):
        self.lun_specs = lun_specs
        self.last_progress_t = now
        self._prev: Optional[dict] = (self._counts(wops)
                                      if _covers_luns(wops, lun_specs)
                                      else None)
        self._prev_watched = {s.dev_id for s in lun_specs}

    def _counts(self, wops: dict) -> dict:
        return {s.dev_id: lun_writes(wops, s) for s in self.lun_specs}

    def update(self, now: float, wops: dict, watched: list) -> bool:
        """Take a write_ops_by_node() sample, watched being the LUNs no
        fault is holding right now. True if a watched LUN made progress."""
        if not _covers_luns(wops, self.lun_specs):
            return False  # a failed query; see _covers_luns
        counts = self._counts(wops)
        ids = {s.dev_id for s in watched}
        progressed = self._prev is not None and any(
            counts[d] > self._prev[d] for d in ids & self._prev_watched)
        self._prev = counts
        self._prev_watched = ids
        if progressed:
            self.last_progress_t = now
        return progressed

    def stalled_s(self, now: float) -> float:
        return now - self.last_progress_t


def lun_activity_by_adapter(qmp, lun_specs: list, window_s: float,
                            counted: tuple = WRITE_OPS) -> dict:
    """Per-adapter liveness, sampled over window_s.

    QEMU's virtio_error() messages don't say which device went broken,
    and x-query-virtio-status -- the command that would -- aborts QEMU on
    this tree. But LUNs are grouped by adapter, so watching which ones
    still complete writes identifies the dead adapter(s) by elimination:
    a broken virtio device stops servicing its queues, so all its LUNs go
    quiet together while the other adapters carry on.

    Only meaningful with every fault removed: a target that is being held
    is quiet on a perfectly healthy adapter. Deciding which adapters are
    dead from these counts is adapters_without_io()'s job -- "zero writes"
    is not the test. "Writes" are whatever counted says (write_ops_by_node)."""
    before = write_ops_by_node(qmp, counted)
    time.sleep(window_s)
    after = write_ops_by_node(qmp, counted)
    out: dict = {}
    for spec in lun_specs:
        a = out.setdefault(f"scsi{spec.adapter}",
                           {"luns": 0, "live_luns": 0, "writes": 0})
        delta = lun_write_delta(before, after, spec)
        a["luns"] += 1
        a["writes"] += delta
        if delta > 0:
            a["live_luns"] += 1
    return out


def adapters_without_io(activity: dict, held: dict) -> list:
    """Adapters whose writes over the window don't exceed what they held.

    A broken device still runs the commands a target fault was holding
    once the fault is removed: they were popped before it broke, and
    releasing them only needs the block layer. So "no writes at all"
    could miss a dead adapter that happened to be the faulted one. What a
    dead adapter can still complete is bounded by what it was holding when
    it broke; held is that, per adapter, from fault_holds() taken then."""
    return [a for a, v in sorted(activity.items())
            if v["writes"] <= held.get(a, 0)]


def adapter_ids(adapters: int) -> list:
    return [f"scsi{a}" for a in range(adapters)]


def list_faults(qmp, adapters: int) -> dict:
    """adapter id -> its armed faults (x-scsi-fault-list), or the error
    if the query failed."""
    out: dict = {}
    for dev in adapter_ids(adapters):
        try:
            out[dev] = qmp_call(qmp, "x-scsi-fault-list", device=dev) or []
        except Exception as exc:
            out[dev] = {"error": repr(exc)}
    return out


def fault_holds(faults: dict) -> dict:
    """adapter id -> commands its faults hold right now, from list_faults()."""
    return {dev: sum(f.get("held", 0) for f in fl)
            for dev, fl in faults.items() if isinstance(fl, list)}


def _lun_writes_phrase(writes: dict, complete: bool) -> str:
    # "With writes", not "live": an adapter that stopped popping still
    # completes the requests it had already started.
    with_writes = sum(1 for n in writes.values() if n)
    phrase = (f"{sum(writes.values())} LUN writes completed meanwhile, with "
              f"writes on {with_writes}/{len(writes)} adapter(s)")
    if not complete:
        phrase += " (some query-blockstats samples failed)"
    return phrase


def no_faults_armed() -> None:
    """try_dump_guest_memory's disarm for dumps taken before the soak,
    which is when the first fault is armed."""


def diagnose_launch_failure(diag: dict, persist, qmp, qga_sock: Path,
                            qemu_pid: int, run_dir: Path, lun_specs: list,
                            launched: int, probe_s: float,
                            writer_exe: Optional[str], screenshot: Path,
                            dump_path: Path, dump_at_failure: bool = False,
                            counted: tuple = WRITE_OPS) -> str:
    """Record why the guest agent stopped answering a request before the
    soak -- resolving drives or launching a writer -- into diag, calling
    persist() after each step. Returns a one-line summary.

    "No reply" has three causes that look identical from the host: QEMU's
    main loop not servicing the agent's chardev -- for one, while it sits
    in a TMF drain, which nests across adapters -- a guest too starved to
    schedule qemu-ga for a while, or qemu-ga / virtio-serial stuck for
    good. QEMU's stacks at the failure show the first. A ping loop that
    also watches the LUNs separates the other two: an agent that comes
    back was starved, one that stays silent while the LUNs keep
    completing writes is stuck. A dump is only worth its cost in that
    last case.

    dump_at_failure dumps before the probe instead, while the agent is
    still silent: a recovering agent otherwise never gets dumped at all,
    and what it was blocked on is gone by the time it answers. The probe
    then follows a VM stop. There is no second dump unless that one
    failed and the agent then stays silent.

    This all happens before the soak, so no target fault is armed and the
    dumps have none to remove.

    Stops early if the VM pauses (x-stop-on-broken at a ring break) and
    sets diag["vm_paused"]; the caller owns that dump."""
    t0 = time.monotonic()
    stacks = run_dir / "launch-failure-stacks.txt"
    # gdb's attach stops every QEMU thread, vCPUs included, so the first
    # probe sample follows a brief freeze of the whole VM.
    capture_qemu_stacks(qemu_pid, stacks)
    diag["stacks"] = str(stacks)
    diag["screenshot"] = screendump_hash(qmp, screenshot) is not None
    diag["writers_launched"] = launched
    diag["probe_s"] = probe_s
    persist()
    dump_phrase = ""
    if dump_at_failure:
        diag["dump_at"] = "failure"
        persist()
        # So that a file found afterwards is this dump's.
        dump_path.unlink(missing_ok=True)
        try:
            diag["dump"] = try_dump_guest_memory(qmp, dump_path, qemu_pid,
                                                 no_faults_armed, diag)
        except Exception as exc:
            # A QMP timeout gets through try_dump_guest_memory. The probe's
            # pings don't need QMP, so don't lose them to it.
            diag["dump"] = False
            diag["dump_error"] = repr(exc)
        # QEMU creates the file as the dump starts, and stops the VM for
        # it, so a file left behind means the probe follows a stop even
        # if the dump then failed.
        stopped = diag["dump"] or dump_path.exists()
        diag["probe_after_dump"] = stopped
        persist()
        if diag["dump"]:
            dump_phrase = (f"; guest memory dump at the failure saved to "
                           f"{dump_path}, so the probe followed a VM stop")
        elif stopped:
            dump_phrase = ("; guest memory dump at the failure started but "
                           "failed, so the probe followed a VM stop")
        else:
            why = diag.get("dump_error", "refused or never started")
            dump_phrase = (f"; guest memory dump at the failure failed "
                           f"({why})")

    adapters = sorted({f"scsi{s.adapter}" for s in lun_specs})
    writes = dict.fromkeys(adapters, 0)
    complete = True
    samples: list = []
    diag["probe"] = samples
    agent_back_s: Optional[float] = None
    prev: Optional[dict] = write_ops_by_node(qmp, counted)
    if not _covers_luns(prev, lun_specs):
        prev = None
    # From here, not t0: the stacks alone can take minutes, and probe_s is
    # what the summary claims was watched.
    deadline = time.monotonic() + probe_s
    while agent_back_s is None and time.monotonic() < deadline:
        time.sleep(LAUNCH_PROBE_INTERVAL_S)
        ping_t = time.monotonic()
        # For a silent agent, the stage says whether anything comes back
        # over the channel at all ("sync") or the agent echoed the sync
        # and then sat on the ping ("command"). Any reply, even an error,
        # means both the channel and the agent work, so it counts as an
        # answer, and agent_stage None always means "answered".
        resp, stage, _ = _qga_call(qga_sock, "guest-ping", None,
                                   AGENT_CHECK_TIMEOUT_S)
        agent = resp is not None
        rtt = round(time.monotonic() - ping_t, 2) if agent else None
        cur = write_ops_by_node(qmp, counted)
        sample: dict = {"t_s": round(time.monotonic() - t0, 1), "agent": agent,
                        "agent_rtt_s": rtt, "agent_stage": stage}
        if resp is not None and "error" in resp:
            sample["agent_error"] = resp["error"]
        if not _covers_luns(cur, lun_specs):
            complete = False
            sample["lun_writes"] = None
        else:
            if prev is None:
                complete = False  # nothing to diff against yet
                sample["lun_writes"] = None
            else:
                step = dict.fromkeys(adapters, 0)
                for spec in lun_specs:
                    step[f"scsi{spec.adapter}"] += lun_write_delta(prev, cur, spec)
                for a, n in step.items():
                    writes[a] += n
                sample["lun_writes"] = step
            prev = cur
        try:
            sample["vm"] = (qmp_call(qmp, "query-status") or {}).get("status")
        except Exception as exc:
            sample["vm"] = f"query-status failed: {exc!r}"
        samples.append(sample)
        diag["lun_writes"] = writes
        diag["lun_writes_complete"] = complete
        persist()
        if agent:
            agent_back_s = sample["t_s"]
        if sample["vm"] == "paused":
            diag["vm_paused"] = True
            return (f"VM paused {sample['t_s']:.0f}s after the failed "
                    f"request{dump_phrase}")
    diag["agent_answered_after_s"] = agent_back_s
    diag["lun_writes"] = writes
    diag["lun_writes_complete"] = complete
    writes_phrase = _lun_writes_phrase(writes, complete)
    if launched == 0:
        # A request before any writer (resolving drives): the LUN writes
        # are Windows' own, not a workload, and say little either way.
        writes_phrase += " (no writers were running yet)"

    if agent_back_s is not None:
        # One more writer running than launch_writer() returned a pid for
        # means the unanswered guest-exec did reach the agent, and only
        # its reply was lost.
        if writer_exe is None:
            diag["writer_processes"] = None
            persist()
            return (f"guest agent answered {agent_back_s:.0f}s after "
                    f"the failed request; {writes_phrase}; writer processes "
                    f"not counted (PowerShell writers look like any other "
                    f"PowerShell process){dump_phrase}")
        count = count_guest_processes(qga_sock, writer_exe)
        diag["writer_processes"] = count
        persist()
        name = PureWindowsPath(writer_exe).name
        counted = ("could not count them" if count is None else
                   f"{count} {name} process(es) running")
        return (f"guest agent answered {agent_back_s:.0f}s after the "
                f"failed request; {writes_phrase}; {counted}, {launched} "
                f"launched{dump_phrase}")

    # Before the dump, which stops the VM and drains everything.
    end_stacks = run_dir / "launch-failure-stacks-end.txt"
    capture_qemu_stacks(qemu_pid, end_stacks)
    diag["stacks_end"] = str(end_stacks)
    if diag.get("dump"):
        persist()
        return (f"guest agent silent for the whole {probe_s:.0f}s probe; "
                f"{writes_phrase}{dump_phrase}")
    # No dump yet, or the one at the failure didn't complete: an agent
    # that never came back is the case a dump is for, so try (again) now.
    diag["dump_at"] = "end"
    persist()
    diag["dump"] = try_dump_guest_memory(qmp, dump_path, qemu_pid,
                                         no_faults_armed, diag)
    persist()
    return (f"guest agent silent for the whole {probe_s:.0f}s probe; "
            f"{writes_phrase}; guest memory dump "
            f"{'saved to ' + str(dump_path) if diag['dump'] else 'failed'}")


# ------------------------------------------------------------------
# Target fault scenarios
# ------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class FaultSettings:
    """The knobs the scenarios share; see --help."""
    recovery_deadline_s: float = DEFAULT_RECOVERY_DEADLINE_S
    window_s: float = DEFAULT_WINDOW_S
    dead_target_s: float = DEFAULT_DEAD_TARGET_S
    cooldown_s: float = DEFAULT_COOLDOWN_S
    tmf_hang_ms: int = DEFAULT_TMF_HANG_MS
    late_probability: float = DEFAULT_LATE_PROBABILITY
    late_dma_delay_s: float = DEFAULT_LATE_DMA_DELAY_S
    late_dma_release_after: str = "recovery"


@dataclasses.dataclass(frozen=True)
class Scenario:
    """One way of making a target misbehave.

    ends says what ends a cycle: "recovery" waits for the guest's recovery
    to clear the fault and gives up after --recovery-deadline-s; "window"
    and "dead" faults only clear when removed, which the harness does after
    --window-s or --dead-target-s; "late-dma" is removed by the harness
    --late-dma-delay-s after its trigger (LATE_DMA_TRIGGERS), and given up
    on after --recovery-deadline-s without one.

    companion is a second fault armed on the same target alongside the
    first and removed after it; target pins the target instead of picking
    one at random; in_default says whether the default --scenarios
    rotation includes it."""
    name: str
    ends: str
    summary: str
    options: Callable[[FaultSettings], dict]
    companion: Optional[Callable[[FaultSettings], dict]] = None
    target: Optional[int] = None
    in_default: bool = True

    def limit_s(self, settings: FaultSettings) -> float:
        return {"recovery": settings.recovery_deadline_s,
                "late-dma": settings.recovery_deadline_s,
                "window": settings.window_s,
                "dead": settings.dead_target_s}[self.ends]

    def longest_hold_ms(self, settings: FaultSettings) -> int:
        """Longest a command can be held before it runs on its own: a
        delay fault's upper bound, 0 for a stall (the fault, not time,
        decides)."""
        return self.options(settings).get("delay-max-ms", 0)


# Each cycle arms one of these on a whole target (every LUN behind it).
# Outcomes per ends: "recovery" -> recovered (by the level in cleared_by)
# or not-recovered; "window" -> window-ended; "dead" -> replaced;
# "late-dma" -> released or not-recovered. Any cycle can also end removed
# (a manual clear the harness didn't make), interrupted (the harness
# removed every fault: for a dump, a broken virtio ring, an error or the
# end of the run) or arm-failed.
#
# late-dma is the one meant to bugcheck a driver that completes requests
# the device still owns (docs/devel/vioscsi-reset-race-investigation.md):
# the guest's reads are held before they run, the guest times them out and
# resets the LUN, QEMU leaves the reset hanging, and a driver that does not
# wait for it completes the reads to Windows with nothing transferred.
# After the trigger, by default a read failing to the reader -- by which
# point Windows should have stopped retrying it and freed its pages, though
# that is an expectation about Windows that no run has confirmed yet --
# the harness lets the held reads run, so their data lands in memory that
# is no longer theirs. Which QEMU ordering makes that happen:
#
# - The fault has to hold the commands, not the TMF alone. Commands it
#   holds have not been sent to the device (scsi-fault.c:scsi_fault_hold),
#   and a LUN reset carried out while they are held cancels them before
#   anything reaches the backend (virtio-scsi.c:virtio_scsi_run_tmf ->
#   device_cold_reset -> scsi-bus.c:scsi_device_purge_requests, and
#   scsi_req_dequeue's "Held, so it never ran" case).
# - Removing the one fault that both holds the commands and hangs the
#   reset does not let the reads complete. x-scsi-fault-remove schedules
#   the release in each request's AioContext (scsi_fault_let_go ->
#   scsi_fault_release_orphans) and, through virtio_scsi_fault_removed,
#   the hung reset's recheck in the main loop (virtio_scsi_tmf_bh ->
#   virtio_scsi_tmf_recheck_hung -> virtio_scsi_tmf_resume), and nothing
#   orders the two. In a throwaway qtest of exactly that, 15 runs each,
#   the read never came back GOOD. In the main loop it came back RESET
#   every time, but its data had been transferred: BHs run newest first,
#   so the reset's ran first, and blk_drain in scsi_device_purge_requests
#   polls BHs itself, which ran the release before the purge, so the read
#   was sent and only its completion cancelled. With an iothread (the
#   harness's default) 13 came back RESET with nothing transferred and 2
#   ABORTED with the data in. Either way the guest sees the read fail,
#   never complete late. storage-error-injection.rst says as much: the
#   held count in SCSI_FAULT_CLEARED is only an upper bound on what runs.
# - So the reset is hung by a second fault, the companion, which holds no
#   commands (probability 0; scsi_fault_recovery does not look at
#   probability, so it still hangs the TMF). Removing the first fault then
#   lets the held reads run with the reset still hung by the companion:
#   virtio_scsi_tmf_recheck_hung finds it still hung and leaves it be. The
#   reads complete normally, into guest memory, LATE_DMA_SETTLE_S before
#   the companion goes and the reset is carried out. tests/qtest/
#   virtio-scsi-test.c:test_fault_below_hang_holds_none pins exactly this,
#   in the main loop and with an iothread: the held READ completes GOOD
#   with its data in the buffer while the reset stays hung, and the reset
#   is answered once the companion goes.
#
# Always target 0: the upstream driver's DeviceReset() addresses its LUN
# reset to target 0 LUN 0 whatever timed out, and a LUN reset only reaches
# a fault on the target it names (scsi_fault_in_scope). A fault elsewhere
# would never see the upstream driver's reset, though it would still have
# its reads completed under it. An adapter reset (bus-reset) cancels every
# held command and drops the hung reset, which ruins the cycle; its
# record says whether one came first.
SCENARIOS = [
    Scenario("lun-reset-clears", "recovery",
             "hung until a LUN reset; aborts cancel what it holds but leave "
             "it hung",
             lambda st: {"clear-on": "lun-reset", "below-clear": "proceed"}),
    Scenario("abort-clears", "recovery",
             "hung until the guest aborts a command to it (or does "
             "anything stronger)",
             lambda st: {"clear-on": "abort-task"}),
    Scenario("needs-target-reset", "recovery",
             "hung until a target (I_T nexus) reset; LUN resets go through "
             "but leave it hung",
             lambda st: {"clear-on": "target-reset", "below-clear": "proceed"}),
    Scenario("reject-lun-reset", "recovery",
             "hung until a target reset; LUN resets fail with FUNCTION "
             "REJECTED",
             lambda st: {"clear-on": "target-reset", "below-clear": "reject"}),
    Scenario("hang-lun-reset", "recovery",
             "hung until a target reset; a LUN reset gets no answer for "
             "--tmf-hang-ms, then goes through and leaves it hung",
             lambda st: {"clear-on": "target-reset", "below-clear": "hang",
                         "tmf-hang-ms": st.tmf_hang_ms}),
    Scenario("slow-target", "window",
             f"every command held {SLOW_DELAY_MS[0] // 1000}-"
             f"{SLOW_DELAY_MS[1] // 1000}s, then run, for --window-s",
             lambda st: {"delay-ms": SLOW_DELAY_MS[0],
                         "delay-max-ms": SLOW_DELAY_MS[1],
                         "clear-on": "manual"}),
    Scenario("late-completion", "window",
             f"--late-probability of commands held {LATE_DELAY_MS[0] // 1000}"
             f"-{LATE_DELAY_MS[1] // 1000}s, past the guest's timeout, then "
             f"run, for --window-s (what the tail-latency harness does all "
             f"run long)",
             lambda st: {"delay-ms": LATE_DELAY_MS[0],
                         "delay-max-ms": LATE_DELAY_MS[1],
                         "probability": st.late_probability,
                         "clear-on": "manual"}),
    Scenario("dead-target", "dead",
             "hung whatever the guest does, until the harness removes it "
             "after --dead-target-s (the drive being replaced)",
             lambda st: {"clear-on": "manual"}),
    # Not in the default rotation: it is built to bugcheck the guest, and a
    # soak that did so on its first late-dma cycle would test nothing else.
    Scenario("late-dma", "late-dma",
             "target 0 hung, and the LUN reset left hanging, until the "
             "harness lets the held reads run --late-dma-delay-s after the "
             "guest has given up on one (--late-dma-release-after); see "
             "--bsod",
             lambda st: {"clear-on": "manual", "below-clear": "hang"},
             companion=lambda st: {"probability": 0.0, "clear-on": "manual",
                                   "below-clear": "hang"},
             target=0, in_default=False),
]
SCENARIOS_BY_NAME = {sc.name: sc for sc in SCENARIOS}
DEFAULT_SCENARIOS = [sc.name for sc in SCENARIOS if sc.in_default]

CYCLE_END_OUTCOMES = {"recovery": "not-recovered", "window": "window-ended",
                      "dead": "replaced", "late-dma": "not-recovered"}
# Keys of a cycle in progress that only the cycler uses.
CYCLE_PRIVATE_KEYS = ("trace", "armed_t", "armed_epoch", "end_t",
                      "trigger_t", "read_poll_t")

# QMP events worth a line on the console if one arrives during the soak:
# the guest rebooting or crashing in a way QEMU sees.
NOTABLE_QMP_EVENTS = ("RESET", "SHUTDOWN", "GUEST_PANICKED",
                      "GUEST_CRASHLOADED")


class FaultArmError(RuntimeError):
    """Arming kept failing; the run has nothing left to test."""


def _fault_gone(exc: Exception) -> bool:
    """Whether a failed x-scsi-fault-remove by id means the fault is not
    armed. QEMU refusing it -- "No fault named ...", or no such adapter --
    does; no answer at all (a timeout) says nothing either way."""
    return isinstance(exc, QmpCommandError)


def _median(values: list) -> Optional[float]:
    if not values:
        return None
    v = sorted(values)
    mid = len(v) // 2
    return v[mid] if len(v) % 2 else (v[mid - 1] + v[mid]) / 2


class FaultCycler:
    """Arms one target fault at a time, rotating through the scenarios,
    and records how each cycle ended.

    tick() is called from the soak loop on every pass. It drains QMP
    events without waiting -- SCSI_FAULT_CLEARED is the only one it acts
    on, and it keeps the first GUEST_PANICKED for the harness, which
    reads no events itself -- and either ends the current cycle
    (cleared, or out of time), refreshes its x-scsi-fault-list snapshot,
    or arms the next one once the cooldown is over. So cycle times are
    only as fine as the loop's period (a few seconds), except
    time_to_clear_s, which comes from the event's own timestamp."""

    def __init__(self, scenarios: list, settings: FaultSettings,
                 adapters: int, targets: int, seed: int, start: float,
                 stderr: "QemuStderr", tmf_trace: bool,
                 read_errors: Optional[Callable[[int, int],
                                                Optional[int]]] = None):
        """read_errors(adapter, target) is how many reads the guest's
        readers on that target have seen fail so far, or None if that
        can't be told right now; late-dma's read-error trigger needs it."""
        self.scenarios = scenarios
        self.read_errors = read_errors
        self.settings = settings
        self.adapters = adapters
        self.targets = targets
        self.rng = random.Random(seed)
        self.start = start
        self.stderr = stderr
        self.tmf_trace = tmf_trace
        self.cycles: list = []
        self.current: Optional[dict] = None
        self.next_arm_t: Optional[float] = None
        self.disarmed: Optional[str] = None
        self.other_events: collections.Counter = collections.Counter()
        self.pre_soak_events: collections.Counter = collections.Counter()
        # The first GUEST_PANICKED, for the bugcheck code (hv-crash).
        self.panic_event: Optional[dict] = None
        self._next = itertools.cycle(scenarios)
        self._cleared: dict = {}
        self._done: set = set()
        # (device, id) of faults a failed QMP call may have left armed;
        # removed before the next one is armed.
        self._orphans: dict = {}
        self._arm_failures = 0
        # The companion fault of the cycle that ended last, until it is
        # removed: device, id, when (due_t) and the cycle's record.
        self._companion: Optional[dict] = None

    def begin(self, qmp, now: float) -> None:
        """Start cycling. Events queued since QMP connected -- boot's own
        resets among them -- are counted apart from the soak's."""
        try:
            events = qmp.get_events(wait=False)
        except Exception:
            events = []
        self.pre_soak_events.update(ev.get("event", "?") for ev in events)
        self._keep_panic(events)
        self.next_arm_t = now

    def _keep_panic(self, events: list) -> None:
        if self.panic_event is None:
            self.panic_event = next((ev for ev in events
                                     if ev.get("event") == "GUEST_PANICKED"),
                                    None)

    # -- event handling -------------------------------------------------

    def pump_events(self, qmp) -> None:
        try:
            events = qmp.get_events(wait=False)
        except Exception as exc:
            print(f"    reading QMP events failed: {exc!r}", file=sys.stderr)
            return
        self._keep_panic(events)
        for ev in events:
            if ev.get("event") != "SCSI_FAULT_CLEARED":
                name = ev.get("event", "?")
                self.other_events[name] += 1
                if name in NOTABLE_QMP_EVENTS:
                    print(f"    QMP event during the soak: {name} "
                          f"{ev.get('data', {})}", file=sys.stderr)
                continue
            data = ev.get("data", {})
            key = (data.get("device"), data.get("id"))
            if key in self._done:
                continue  # our own removal, after the cycle was recorded
            ts = ev.get("timestamp", {})
            self._cleared[key] = {**data, "at_epoch": ts.get("seconds", 0)
                                  + ts.get("microseconds", 0) / 1e6}

    # -- cycle lifecycle ------------------------------------------------

    def tick(self, qmp, now: float) -> None:
        self.pump_events(qmp)
        self._remove_companion(qmp, now)
        cur = self.current
        if cur is not None:
            ev = self._cleared.pop((cur["device"], cur["fault_id"]), None)
            if ev is not None:
                self._finish(cur, ev, now)
            elif cur["ends"] == "late-dma":
                self._late_dma_tick(qmp, cur, now)
            elif now >= cur["end_t"]:
                self._remove(qmp, cur, CYCLE_END_OUTCOMES[cur["ends"]], now)
            else:
                self._snapshot(qmp, cur)
        elif (self.disarmed is None and self._companion is None
              and self.next_arm_t is not None
              and now >= self.next_arm_t and self._remove_orphans(qmp)):
            self._arm(qmp, now)

    def _remove_orphans(self, qmp) -> bool:
        """Retry removing the faults a failed call may have left armed.
        True once none is left, so the next one can be armed: one fault at
        a time means one, not one plus a stray stall somewhere."""
        for key in list(self._orphans):
            device, fault_id = key
            try:
                qmp_call(qmp, "x-scsi-fault-remove", device=device,
                         id=fault_id)
            except Exception as exc:
                if not _fault_gone(exc):
                    self._orphans[key] = repr(exc)
                    continue
            del self._orphans[key]
        self.pump_events(qmp)
        return not self._orphans

    def _arm(self, qmp, now: float) -> None:
        sc = next(self._next)
        index = len(self.cycles)
        adapter = self.rng.randrange(self.adapters)
        target = (sc.target if sc.target is not None
                  else self.rng.randrange(self.targets))
        fault = {"id": f"c{index}-{sc.name}", "target": target,
                 **sc.options(self.settings)}
        companion = (None if sc.companion is None else
                     {"id": f"{fault['id']}-tmf", "target": target,
                      **sc.companion(self.settings)})
        cur = {"index": index, "scenario": sc.name, "ends": sc.ends,
               "adapter": adapter, "target": target,
               "device": f"scsi{adapter}", "fault_id": fault["id"],
               "fault": fault, "armed_at": utc_now(),
               "armed_s": round(now - self.start, 1),
               "armed_t": now, "end_t": now + sc.limit_s(self.settings)}
        if companion is not None:
            cur["companion"] = companion
            cur["companion_id"] = companion["id"]
            # Its own clearing is never a cycle's end; see _remove_companion.
            self._done.add((cur["device"], companion["id"]))
        if sc.ends == "late-dma":
            cur["late_dma"] = {
                "release_after": self.settings.late_dma_release_after,
                "delay_s": self.settings.late_dma_delay_s,
                "first_attempt_s": None, "first_attempt": None,
                "first_read_error_s": None, "read_errors_before": None,
                "released_s": None}
            cur["read_poll_t"] = now
        trace = CycleTrace(f"scsi{adapter}.0", target, fault["id"],
                           cur["armed_at"])
        self.stderr.watch(trace)
        cur["trace"] = trace
        added: list = []
        try:
            for f in [fault] + ([companion] if companion else []):
                added.append(f["id"])
                qmp_call(qmp, "x-scsi-fault-add", device=cur["device"],
                         fault=f)
        except Exception as exc:
            self.stderr.unwatch(trace)
            del cur["trace"]
            cur["error"] = repr(exc)
            # Unanswered rather than refused, it may be armed after all;
            # and a companion that failed leaves the first one armed.
            for fault_id in added:
                self._orphans[(cur["device"], fault_id)] = repr(exc)
            self._remove_orphans(qmp)
            self._record(cur, "arm-failed", now)
            self._arm_failures += 1
            if self._arm_failures >= MAX_CONSECUTIVE_ARM_FAILURES:
                self.disarmed = (f"arming failed {self._arm_failures} times "
                                 f"in a row, last: {exc!r}")
                raise FaultArmError(f"target faults: {self.disarmed}")
            return
        # Taken on the reply, not before the call: a busy monitor can sit
        # on the command for seconds before running it, while the reply
        # lags the install only by its transit back to us.
        cur["armed_epoch"] = time.time()
        self._arm_failures = 0
        self.current = cur
        # A baseline, in case the guest clears it before the next tick.
        self._snapshot(qmp, cur)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] cycle "
              f"{index} {sc.name}: armed on {cur['device']} target {target} "
              f"({sc.summary})")

    def _snapshot(self, qmp, cur: dict) -> None:
        try:
            faults = qmp_call(qmp, "x-scsi-fault-list",
                              device=cur["device"]) or []
        except Exception:
            return  # keep the last one; the cycle record says how old
        for f in faults:
            if f.get("id") == cur["fault_id"]:
                cur["snapshot"] = {k: f.get(k) for k in
                                   ("hits", "held", "attempts",
                                    "last-attempt")}
                cur["snapshot_at"] = utc_now()

    def _remove(self, qmp, cur: dict, outcome: str, now: float) -> None:
        key = (cur["device"], cur["fault_id"])
        self._snapshot(qmp, cur)
        try:
            qmp_call(qmp, "x-scsi-fault-remove", device=cur["device"],
                     id=cur["fault_id"])
        except Exception as exc:
            # "No fault named ..." is the guest having cleared it since
            # the last tick, which the event below shows. No answer may
            # have left it armed.
            if not _fault_gone(exc):
                cur["remove_error"] = repr(exc)
                self._orphans[key] = repr(exc)
        # Whatever the removal returned: the event says who cleared it.
        self.pump_events(qmp)
        ev = self._cleared.pop(key, None)
        if ev is not None and ev.get("recovery") != "manual":
            # The guest's recovery got there first, between the last tick
            # and this removal.
            self._finish(cur, ev, now)
            return
        if ev is not None:
            cur["held_at_clear"] = ev.get("held")
        self._record(cur, outcome, now)

    def _schedule_companion(self, cur: dict, outcome: str,
                            now: float) -> None:
        """Have the companion fault of a cycle that just ended removed,
        however it ended. For late-dma that lets the hung LUN reset go
        ahead, so unless the harness is clearing up anyway (interrupted),
        first give the commands the first fault's removal released
        LATE_DMA_SETTLE_S to finish on their own (see the late-dma
        scenario). Nothing is armed until it is gone."""
        settle = 0.0 if outcome == "interrupted" else LATE_DMA_SETTLE_S
        cur["companion_removed_s"] = None
        self._companion = {"device": cur["device"], "id": cur["companion_id"],
                           "due_t": now + settle, "cycle": cur}

    def _remove_companion(self, qmp, now: float, force: bool = False) -> None:
        """Remove the scheduled companion fault once it is due, or now if
        force. A removal that gets no answer leaves it to _remove_orphans,
        which the next arming waits for."""
        comp = self._companion
        if comp is None or (not force and now < comp["due_t"]):
            return
        self._companion = None
        cycle = comp["cycle"]
        try:
            qmp_call(qmp, "x-scsi-fault-remove", device=comp["device"],
                     id=comp["id"])
        except Exception as exc:
            if not _fault_gone(exc):
                cycle["companion_remove_error"] = repr(exc)
                self._orphans[(comp["device"], comp["id"])] = repr(exc)
        cycle["companion_removed_s"] = round(now - self.start, 1)
        self.pump_events(qmp)

    def idle(self) -> bool:
        """No cycle armed, and nothing of the last one left to remove."""
        return self.current is None and self._companion is None

    def _late_dma_tick(self, qmp, cur: dict, now: float) -> None:
        """Watch a late-dma cycle for its trigger, release it
        --late-dma-delay-s after, and give up on it at its deadline if the
        trigger never came. The first recovery attempt comes from the
        fault's own count of them (x-scsi-fault-list), so it is only as
        exact as the loop's period; a read error from the readers' status
        files, asked every LATE_DMA_READ_POLL_S."""
        ld = cur["late_dma"]
        self._snapshot(qmp, cur)
        snap = cur.get("snapshot") or {}
        if ld["first_attempt_s"] is None and any(
                (snap.get("attempts") or {}).values()):
            ld["first_attempt_s"] = round(now - cur["armed_t"], 1)
            ld["first_attempt"] = snap.get("last-attempt")
            if ld["release_after"] == "recovery":
                cur["trigger_t"] = now
        if (ld["release_after"] == "read-error" and "trigger_t" not in cur
                and self.read_errors is not None
                and now >= cur["read_poll_t"]):
            cur["read_poll_t"] = now + LATE_DMA_READ_POLL_S
            errors = self.read_errors(cur["adapter"], cur["target"])
            if errors is not None:
                # Errors from earlier cycles don't count. The baseline is
                # the first answer, which may be a poll or two in.
                if ld["read_errors_before"] is None:
                    ld["read_errors_before"] = errors
                elif errors > ld["read_errors_before"]:
                    ld["first_read_error_s"] = round(now - cur["armed_t"], 1)
                    cur["trigger_t"] = now
        trigger_t = cur.get("trigger_t")
        if trigger_t is not None and now >= trigger_t + ld["delay_s"]:
            ld["released_s"] = round(now - cur["armed_t"], 1)
            attempts = snap.get("attempts") or {}
            ld["attempts_at_release"] = attempts
            ld["adapter_reset_before_release"] = bool(
                attempts.get("bus-reset"))
            self._remove(qmp, cur, "released", now)
        elif trigger_t is None and now >= cur["end_t"]:
            self._remove(qmp, cur, CYCLE_END_OUTCOMES[cur["ends"]], now)

    def late_dma_cycles(self) -> int:
        """late-dma cycles that have run their course
        (LATE_DMA_DONE_OUTCOMES)."""
        return sum(1 for c in self.cycles if c["scenario"] == "late-dma"
                   and c["outcome"] in LATE_DMA_DONE_OUTCOMES)

    def _finish(self, cur: dict, ev: dict, now: float) -> None:
        cur["cleared_by"] = ev.get("recovery")
        cur["held_at_clear"] = ev.get("held")
        cur["time_to_clear_s"] = round(ev["at_epoch"] - cur["armed_epoch"], 2)
        outcome = "recovered" if ev.get("recovery") != "manual" else "removed"
        self._record(cur, outcome, now)

    def _record(self, cur: dict, outcome: str, now: float) -> None:
        trace = cur.pop("trace", None)
        if trace is not None:
            self.stderr.poll()  # the TMF that cleared it may just be in
            self.stderr.unwatch(trace)
            cur.update(trace.as_dict())
            if not self.tmf_trace:
                cur["tmfs"] = "not traced (--no-tmf-trace)"
        cur["outcome"] = outcome
        cur["ended_at"] = utc_now()
        cur["ended_s"] = round(now - self.start, 1)
        cur["duration_s"] = round(now - cur.pop("armed_t"), 1)
        for k in CYCLE_PRIVATE_KEYS:
            cur.pop(k, None)
        self._done.add((cur["device"], cur["fault_id"]))
        self.cycles.append(cur)
        self.current = None
        # A cycle that failed to arm left its faults to _remove_orphans.
        if cur.get("companion_id") and outcome != "arm-failed":
            self._schedule_companion(cur, outcome, now)
        self.next_arm_t = now + self.settings.cooldown_s
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
              f"{self.describe(cur)}")

    def disarm_all(self, qmp, reason: str) -> None:
        """Remove every fault on every adapter and arm no more. A cycle in
        progress ends interrupted. Safe to call more than once and with
        the VM stopped (commands it releases then wait for the VM to
        run)."""
        if self.disarmed is None:
            self.disarmed = reason
        now = time.monotonic()
        cur = self.current
        if cur is not None:
            cur["interrupted_by"] = reason
            self._remove(qmp, cur, "interrupted", now)
        # The last cycle's companion too, settling or not: the removal
        # below takes it anyway, and this way its record says so.
        self._remove_companion(qmp, now, force=True)
        for dev in adapter_ids(self.adapters):
            try:
                qmp_call(qmp, "x-scsi-fault-remove", device=dev)
            except Exception as exc:
                print(f"    removing the faults on {dev} failed: {exc!r}",
                      file=sys.stderr)
                continue
            for key in [k for k in self._orphans if k[0] == dev]:
                del self._orphans[key]
        self.pump_events(qmp)

    # -- what the rest of the harness asks ------------------------------

    def faulted_target(self) -> Optional[tuple]:
        """(adapter, target) of the fault armed right now, if any."""
        cur = self.current
        return None if cur is None else (cur["adapter"], cur["target"])

    def in_progress(self) -> Optional[dict]:
        """The cycle armed right now, as far as it has got, for a result
        written before it ends."""
        cur = self.current
        if cur is None:
            return None
        return {k: v for k, v in cur.items() if k not in CYCLE_PRIVATE_KEYS}

    def panic_context(self, now: float) -> Optional[dict]:
        """Where the cycling was when the guest bugchecked: the cycle
        armed then, or else the last one to end and how long before."""
        cur = self.current
        if cur is not None:
            return {"index": cur["index"], "scenario": cur["scenario"],
                    "state": "armed",
                    "armed_s_ago": round(now - cur["armed_t"], 1)}
        if not self.cycles:
            return None
        last = self.cycles[-1]
        return {"index": last["index"], "scenario": last["scenario"],
                "state": f"ended {last['outcome']}",
                "ended_s_ago": round(now - self.start - last["ended_s"], 1)}

    def unfaulted(self, lun_specs: list) -> list:
        """The LUNs no fault is holding right now."""
        cur = self.current
        if cur is None:
            return lun_specs
        return [s for s in lun_specs
                if (s.adapter, s.target) != (cur["adapter"], cur["target"])]

    def describe(self, cur: dict) -> str:
        where = f"{cur['device']} target {cur['target']}"
        head = f"cycle {cur['index']} {cur['scenario']} on {where}: "
        outcome = cur["outcome"]
        if outcome == "recovered":
            head += (f"recovered by {cur['cleared_by']} after "
                     f"{cur['time_to_clear_s']:.1f}s")
        elif outcome == "arm-failed":
            return head + f"arming failed: {cur.get('error')}"
        elif outcome == "interrupted":
            head += (f"interrupted ({cur.get('interrupted_by')}) after "
                     f"{cur['duration_s']:.0f}s")
        elif outcome == "released":
            ld = cur["late_dma"]
            head += (f"let {cur.get('held_at_clear', '?')} held command(s) "
                     f"run {ld['delay_s']:.0f}s after the "
                     f"{LATE_DMA_TRIGGERS[ld['release_after']]}, "
                     f"{ld['released_s']:.0f}s after arming")
            if ld.get("adapter_reset_before_release"):
                head += " (an adapter reset came first, cancelling them)"
        else:
            head += f"{outcome} after {cur['duration_s']:.0f}s"
            if "late_dma" in cur and outcome == "not-recovered":
                trigger = LATE_DMA_TRIGGERS[cur["late_dma"]["release_after"]]
                head += f", no {trigger} seen"
        # The snapshot is from the last tick, so for a fault the guest
        # cleared it may be a few seconds short; the trace lines are exact.
        snap = cur.get("snapshot") or {}
        hits = snap.get("hits")
        held = ("? command(s) held" if hits is None else
                f"{hits}{'+' if outcome == 'recovered' else ''} command(s) "
                f"held")
        actions = cur.get("fault_actions")
        if not actions:
            actions = {k: n for k, n in (snap.get("attempts") or {}).items()
                       if n}
        tmfs = cur.get("tmfs")
        reqs = ({k.split(":", 1)[1]: n for k, n in tmfs.items()
                 if k.startswith("tmf_req:")}
                if isinstance(tmfs, dict) else None)
        resets = tmfs.get("reset") if isinstance(tmfs, dict) else None
        return (head + f"; {held}"
                + (f", recovery attempts {actions}" if actions else
                   ", no recovery attempts")
                + (f", TMFs {reqs}" if reqs else "")
                + (f", {resets} adapter reset(s)" if resets else ""))

    def status(self, now: float) -> dict:
        """For heartbeats."""
        cur = self.current
        out: dict = {"cycles_done": len(self.cycles),
                     "outcomes": dict(collections.Counter(
                         c["outcome"] for c in self.cycles))}
        if cur is not None:
            out["current"] = {
                "index": cur["index"], "scenario": cur["scenario"],
                "device": cur["device"], "target": cur["target"],
                "age_s": round(now - cur["armed_t"], 0),
                "held": (cur.get("snapshot") or {}).get("held")}
        if self._companion is not None:
            out["companion_pending"] = self._companion["id"]
        if self.disarmed:
            out["disarmed"] = self.disarmed
        if self._orphans:
            out["orphans"] = self.orphans()
        return out

    def orphans(self) -> dict:
        """Faults a failed call may have left armed, "device/id" -> the
        error, until a removal gets through."""
        return {f"{d}/{i}": err for (d, i), err in self._orphans.items()}

    def summary(self) -> dict:
        """Per scenario: how its cycles ended, what cleared the ones that
        recovered, and how long that took."""
        out: dict = {}
        for name in dict.fromkeys(c["scenario"] for c in self.cycles):
            mine = [c for c in self.cycles if c["scenario"] == name]
            times = [c["time_to_clear_s"] for c in mine
                     if c["outcome"] == "recovered"]
            # From the trace, which is exact; the snapshot misses whatever
            # the guest did after the last tick, the clearing attempt
            # included.
            attempts: collections.Counter = collections.Counter()
            for c in mine:
                attempts.update(c.get("fault_actions") or {})
            out[name] = {
                "cycles": len(mine),
                "outcomes": dict(collections.Counter(
                    c["outcome"] for c in mine)),
                "cleared_by": dict(collections.Counter(
                    c["cleared_by"] for c in mine if c.get("cleared_by"))),
                "time_to_clear_s": ({"min": min(times),
                                     "median": _median(times),
                                     "max": max(times)} if times else None),
                "recovery_attempts": {k: n for k, n in attempts.items() if n},
            }
        return out


# ------------------------------------------------------------------
# Harness
# ------------------------------------------------------------------


def run_soak(adapters: int, targets: int, luns_per_target: int, duration_s: float,
             ram: str, cpus: str, taskset_cores: Optional[str], keep_all: bool,
             qmp_module, io_driver: str, diskspd_path: str, fio_path: str,
             scenarios: list, settings: FaultSettings,
             seed: int, heartbeat_s: float, vioscsi_telemetry_script: str,
             disk_dir: Optional[Path] = None,
             iothreads: Optional[int] = None,
             tmf_trace: bool = True,
             stop_on_broken: bool = True,
             ring_diag: bool = True,
             dump_on_agent_stall: bool = False,
             qga_trace: bool = True,
             hv_crash: bool = True,
             cached_read_file_bytes: int = 0,
             bsod_cycles: Optional[int] = None) -> dict:
    """bsod_cycles is --bsod: end the run once that many late-dma cycles
    have run their course (LATE_DMA_DONE_OUTCOMES) with no bugcheck, and
    treat a writer exiting or a chunk read back wrong as something to note
    rather than the end of the run, since either can come before the
    bugcheck the run is waiting for. A broken ring is watched
    BSOD_BREAK_WATCH_S for a bugcheck, then ends the run virtio-broken."""
    run_dir = SOAK_DIR / f"run-{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    # LUN images (the disks under I/O test) may live on a different
    # filesystem than the rest of the run artifacts.
    lun_dir = disk_dir if disk_dir is not None else run_dir
    lun_dir.mkdir(parents=True, exist_ok=True)
    status_path = run_dir / "status.json"
    # What counts as a LUN doing I/O, and what to call its rate.
    counted = IO_DRIVER_OPS.get(io_driver, WRITE_OPS)
    ops_unit = "wps" if counted == WRITE_OPS else "ops/s"

    boot_overlay = run_dir / "boot.qcow2"
    vars_overlay = run_dir / "vars.qcow2"
    qmp_sock = run_dir / "qmp.sock"
    qga_sock = run_dir / "qga.sock"
    tpm_sock = run_dir / "swtpm.sock"
    serial_log = run_dir / "serial.log"
    vioscsi_telemetry_log = run_dir / "vioscsi-telemetry.log"
    screenshot = run_dir / "screen.ppm"
    dump_path = run_dir / "crash.dmp"
    break_dump_path = run_dir / "break.dmp"
    panic_dump_path = run_dir / "panic.dmp"
    panic_screenshot = run_dir / "panic.ppm"
    qemu_log_path = run_dir / "qemu.log"

    qmp = None
    proc = None
    swtpm = None
    lun_specs: list = []
    result: dict = {"outcome": "error", "elapsed_s": 0.0, "run_dir": str(run_dir),
                    "duration_s": duration_s,
                    "scenarios": [sc.name for sc in scenarios],
                    "fault_settings": dataclasses.asdict(settings)}
    start = time.monotonic()
    # Created when the soak starts (it needs the log reader); until then no
    # fault is armed and there is nothing to remove.
    cycler: Optional[FaultCycler] = None

    def disarm(reason: str) -> None:
        """Remove every target fault and arm no more, recording why. For
        try_dump_guest_memory, the end of the run and anything else that
        needs the guest's I/O to work."""
        if cycler is None:
            return
        cycler.disarm_all(qmp, reason)
        result["faults_removed"] = cycler.disarmed
        record_cycles()

    def record_cycles() -> None:
        if cycler is None:
            return
        result["cycles"] = cycler.cycles
        result["scenario_summary"] = cycler.summary()
        result["cycle_in_progress"] = cycler.in_progress()
        if cycler.other_events:
            result["other_qmp_events"] = dict(cycler.other_events)
        if cycler.pre_soak_events:
            result["pre_soak_qmp_events"] = dict(cycler.pre_soak_events)
        result["fault_orphans"] = cycler.orphans()

    def write_status(extra: dict) -> None:
        status_path.write_text(json.dumps({**result, **extra}, indent=2))

    qemu_stderr: Optional[QemuStderr] = None

    def record_trace() -> None:
        """Fold QEMU's stderr and per-adapter TMF tallies into the result."""
        if qemu_stderr is None:
            return
        qemu_stderr.poll()
        result["qemu_stderr"] = qemu_stderr.lines
        result["tmf_trace"] = qemu_stderr.trace_counts
        result["broken_events"] = qemu_stderr.broken_events
        result["req_overlaps"] = qemu_stderr.overlaps
        if qemu_stderr.qga["counts"]:
            result["qga_trace"] = qemu_stderr.qga

    def capture_qga_port(context: str, **extra) -> None:
        """Record the guest agent port as QEMU sees it, for an agent that
        has gone quiet: info qtree's view of it (see virtio_serial_ports
        for what that can and cannot show) and the trace tallies so far,
        including whether a client has left while QEMU held a write.
        Appended to result["qga_port"]; never fails the run."""
        entry: dict = {"context": context, "at": utc_now(),
                       "elapsed_s": round(time.monotonic() - start, 1),
                       **extra}
        result.setdefault("qga_port", []).append(entry)
        try:
            entry["ports"] = virtio_serial_ports(qmp)
            if qga_trace:
                # Before the soak there is no reader yet; a throwaway one
                # reads the whole log, which is still short then.
                src = qemu_stderr or QemuStderr(qemu_log_path)
                src.poll()
                # Copied: the reader keeps counting after this.
                entry["trace"] = {**src.qga, "counts": dict(src.qga["counts"])}
            desc = "; ".join(
                f"port {p['port']} ({p['name']}): guest "
                f"{'open' if p['guest_open'] else 'closed'}, host "
                f"{'connected' if p['host_connected'] else 'not connected'}"
                f", {'THROTTLED' if p['throttled'] else 'not throttled'}"
                for p in entry["ports"]) or "no virtio-serial ports found"
            lost = entry.get("trace", {}).get("counts", {})
            lost = (lost.get("closed_while_throttled", 0)
                    + lost.get("short_writes_with_no_client", 0))
            if lost:
                desc += (f"; {lost} guest write(s) held when a client left "
                         f"(qga_trace in the result)")
        except Exception as exc:
            entry["error"] = repr(exc)
            desc = f"capture failed: {exc!r}"
        print(f"    guest agent port ({context}): {desc}", file=sys.stderr)

    def dump_if_stopped_on_broken() -> bool:
        """If x-stop-on-broken paused the VM at a ring break, dump guest
        memory while the failing request is still where the driver left
        it, then resume. True if it did.

        The dump removes every target fault first (see
        try_dump_guest_memory), and no more are armed after it."""
        if not stop_on_broken or "break_dump" in result:
            return False
        settle_deadline = time.monotonic() + STOP_ON_BROKEN_SETTLE_S
        while True:
            try:
                status = qmp_call(qmp, "query-status")
            except Exception as exc:
                print(f"    query-status failed: {exc!r}", file=sys.stderr)
                return False
            if status.get("status") == "paused":
                break
            if time.monotonic() >= settle_deadline:
                return False
            time.sleep(0.1)
        print(f"    VM paused at the ring break (x-stop-on-broken); dumping "
              f"guest memory to {break_dump_path}", file=sys.stderr)
        write_status({"elapsed_s": time.monotonic() - start})
        result["break_dump"] = try_dump_guest_memory(
            qmp, break_dump_path, proc.pid, lambda: disarm("break dump"),
            result)
        result["break_dump_path"] = str(break_dump_path)
        # x-stop-on-broken paused it, so the dump didn't: resume it here,
        # once the dump is really over.
        why = resume_after_dump(qmp)
        if why is not None:
            result["vm_left_paused"] = why
        write_status({"elapsed_s": time.monotonic() - start})
        return True

    def guest_panicked() -> bool:
        """Whether hv-crash has parked the VM in guest-panicked."""
        if not hv_crash:
            return False
        try:
            return (qmp_call(qmp, "query-status") or {}).get(
                "status") == "guest-panicked"
        except Exception:
            return False

    def record_guest_panic(elapsed: float) -> dict:
        """Fill in the result for a guest that bugchecked: the STOP code
        and parameters from GUEST_PANICKED, a screenshot and a win-dmp,
        taken with the VM still panicked, so it shows the guest as it
        crashed. The dump removes every target fault first; with the VM
        not running, what they held stays where it was (see
        try_dump_guest_memory). Nothing goes through the guest agent
        afterwards: the guest is gone, and telemetry would only wait out
        its timeouts and take a second dump."""
        event = cycler.panic_event if cycler is not None else None
        if event is None:
            # Before the soak, nothing else reads QMP events.
            try:
                event = next((ev for ev in qmp.get_events(wait=False)
                              if ev.get("event") == "GUEST_PANICKED"), None)
            except Exception:
                event = None
        panic = guest_panic_info(event)
        if cycler is not None:
            panic["cycle"] = cycler.panic_context(time.monotonic())
        result["outcome"] = "guest-panicked"
        result["elapsed_s"] = elapsed
        result["guest_panic"] = panic
        if bsod_cycles:
            result["bsod_verdict"] = (f"bugcheck {panic['bugcheck']}"
                                      f"{bsod_corruption_note()}")
        print(f"    guest bugchecked after {elapsed:.0f}s: "
              f"{panic['bugcheck']}; dumping guest memory to "
              f"{panic_dump_path}", file=sys.stderr)
        write_status({"elapsed_s": elapsed})
        panic["screenshot"] = (str(panic_screenshot)
                               if screendump_hash(qmp, panic_screenshot)
                               else None)
        panic["dump"] = try_dump_guest_memory(
            qmp, panic_dump_path, proc.pid, lambda: disarm("guest panicked"),
            result)
        panic["dump_path"] = str(panic_dump_path)
        record_cycles()
        record_trace()
        write_status({"elapsed_s": elapsed})
        return result

    def capture_postmortem() -> None:
        result["telemetry_failure_screenshot"] = (
            screendump_hash(qmp, screenshot) is not None)
        if result.get("break_dump"):
            return  # the one taken at the break is the one that matters
        result["telemetry_failure_dump"] = try_dump_guest_memory(
            qmp, dump_path, proc.pid, lambda: disarm("postmortem dump"),
            result)

    def collect_vioscsi_telemetry() -> None:
        if not vioscsi_telemetry_script:
            return
        # Everything below goes through the guest agent, and with the agent
        # gone each step waits out its own timeout: stop_writers alone is a
        # status poll plus a taskkill per writer, about three hours at 75
        # LUNs, for nothing. Go straight to what QMP can still capture.
        if not any(qga_ping(qga_sock, AGENT_CHECK_TIMEOUT_S)
                   for _ in range(AGENT_CHECK_ATTEMPTS)):
            result["vioscsi_telemetry"] = "skipped: guest agent not responding"
            print("    guest agent not responding -- skipping writer stop and "
                  "telemetry; capturing a screenshot and a guest memory dump "
                  "for postmortem", file=sys.stderr)
            capture_qga_port("agent silent at the end")
            capture_postmortem()
            return
        if io_driver == "cached-read":
            # Before they are stopped: how many reads each reader got
            # through, how many failed to it and how many read back wrong.
            cached_read.poll()
            result["cached_read_status"] = cached_read.luns
        # Stop the writers first: they're still live (see stop_writers'
        # docstring), and leaving them running races the telemetry query
        # against a guest saturated with I/O.
        result["writer_states"] = stop_writers(qga_sock, writer_pids,
                                                seen=writer_seen,
                                                output_dir=run_dir)
        print(f"    collecting vioscsi telemetry via {vioscsi_telemetry_script}",
              file=sys.stderr)
        ok, msg = capture_vioscsi_telemetry(qga_sock, vioscsi_telemetry_script,
                                             vioscsi_telemetry_log)
        result["vioscsi_telemetry"] = msg
        result["vioscsi_telemetry_log"] = str(vioscsi_telemetry_log)
        if not ok:
            print(f"    telemetry collection failed ({msg}) -- capturing a "
                  "screenshot and a guest memory dump for postmortem",
                  file=sys.stderr)
            capture_postmortem()

    def writers_failed(elapsed: float) -> bool:
        """Whether a verifying writer has exited on its own, and why.
        Fills in the whole result -- outcome, error and the evidence the
        writer left -- and returns True, so the caller only has to return
        it.

        The outcome is not assumed: a writer can exit because it read back
        data that did not match what it wrote, or because a request was
        failed to it -- which a dead-target or not-recovered fault invites,
        since storport fails what it gives up on back to fio --
        and classify_writer_exit() decides which from the evidence. Both
        end the run; only the first is a data-integrity finding.

        Not called on every 2s poll: a writer's exit status is its own
        guest-agent round trip per LUN, far too costly at high LUN counts.
        Only the heartbeat and the end of the run ask. An exit is always a
        failure for these drivers, never a clean finish, since
        writer_duration outlasts duration_s.

        The cached-read readers never exit early; what they find is asked
        for instead (cached_reads_corrupted).
        """
        if io_driver == "cached-read":
            return cached_reads_corrupted(elapsed)
        if io_driver not in VERIFYING_IO_DRIVERS:
            return False
        exited = [st for st in writer_states(qga_sock, writer_pids,
                                             writer_seen, run_dir)
                  if st["exited"]]
        if not exited:
            return False
        outcome, why = classify_writer_exit(exited)
        if bsod_cycles:
            noted = {st["pid"] for st in result.get("writer_exits", [])}
            new = [st for st in exited if st["pid"] not in noted]
            if new:
                result.setdefault("writer_exits", []).extend(new)
                print(f"    {io_driver} writer(s) exited ({outcome}: {why}) "
                      f"on {sorted(writer_luns.get(st['pid']) for st in new)}"
                      f"; not the end of a --bsod run", file=sys.stderr)
            return False
        result["outcome"] = outcome
        result["elapsed_s"] = elapsed
        # The writers that ended the run, as against the ones
        # collect_vioscsi_telemetry() force-stops a moment later. Its
        # stop_writers() sweep overwrites result["writer_states"] with
        # every pid, and a killed writer is indistinguishable there from
        # one that died on its own -- same "exited", same exit code -- so
        # the set that actually failed has to be recorded under its own
        # key before that happens.
        result["writer_states"] = exited
        result["failed_writers"] = [st["pid"] for st in exited]
        # One writer per LUN, so the pids that exited name the LUNs that
        # failed. The verify message or the OS error and its offset are in
        # each one's stderr_tail.
        lost = sorted(writer_luns.get(s["pid"], f"pid {s['pid']}")
                      for s in exited)
        codes = sorted({s["exitcode"] for s in exited},
                       key=lambda c: (c is None, c))
        print(f"    {io_driver} writer(s) exited early (exitcode={codes}) "
              f"after {elapsed:.0f}s on {lost} -- {why}", file=sys.stderr)
        result["error"] = (
            f"{io_driver} writer(s) exited early on {lost}: {why}; see "
            f"writer_states' stderr_tail for the failing offset(s)")
        # Same postmortem the clean path records, and for more reason: the
        # trace fold and the fault tallies are how many commands the run
        # had held, and how the guest answered, when the data went wrong.
        # Taken over QMP before collect_vioscsi_telemetry(), which stops
        # the writers and may find the agent gone; the disarm is also what
        # lets the surviving writers finish being killed.
        disarm(outcome)
        record_trace()
        write_status({"elapsed_s": elapsed})
        collect_vioscsi_telemetry()
        write_status({"elapsed_s": elapsed})
        return True

    def cached_reads_corrupted(elapsed: float) -> bool:
        """Whether a cached-read reader has read back a chunk that is not
        what the fill wrote there. Like writers_failed: fills in the result
        as data-corruption and returns True. A failed read is not this --
        it is counted, and is what a forced bus reset is expected to cause
        -- but wrong data in a read that succeeded is a data-integrity
        finding on any run."""
        cached_read.poll()
        if bsod_cycles:
            note_cached_read_corruption(elapsed)
            return False
        bad = cached_read.mismatched()
        if not bad:
            return False
        result["outcome"] = "data-corruption"
        result["elapsed_s"] = elapsed
        result["cached_read_mismatches"] = {
            serial: {"mismatches": n, "last": last}
            for serial, (n, last) in bad.items()}
        result["error"] = (
            "cached-read data read back wrong: "
            + "; ".join(f"{serial}: {n} chunk(s), last {last}"
                        for serial, (n, last) in bad.items()))
        print(f"    {result['error']}", file=sys.stderr)
        disarm("data-corruption")
        record_trace()
        write_status({"elapsed_s": elapsed})
        collect_vioscsi_telemetry()
        write_status({"elapsed_s": elapsed})
        return True

    def note_cached_read_corruption(elapsed: float) -> None:
        """--bsod: record the chunks read back wrong so far, as
        cached_read last saw them, without ending the run. Wrong data is
        late DMA landing somewhere harmless enough; the run goes on for
        the bugcheck, and the verdict says what was found."""
        bad = cached_read.mismatched()
        if not bad:
            return
        before = result.get("cached_read_mismatches") or {}
        if not before:
            result["cached_read_mismatch_first_s"] = round(elapsed, 1)
        result["cached_read_mismatches"] = {
            serial: {"mismatches": n, "last": last}
            for serial, (n, last) in bad.items()}
        if result["cached_read_mismatches"] != before:
            print("    cached-read data read back wrong (not the end of a "
                  "--bsod run): " + "; ".join(
                      f"{serial}: {n} chunk(s), last {last}"
                      for serial, (n, last) in bad.items()), file=sys.stderr)

    def bsod_corruption_note() -> str:
        bad = result.get("cached_read_mismatches")
        if not bad:
            return ""
        luns = ", ".join(f"{serial} ({v['mismatches']} chunk(s))"
                         for serial, v in bad.items())
        return (f"; cached data read back wrong from "
                f"{result['cached_read_mismatch_first_s']:.0f}s on, on {luns}")

    def diagnose_failed_launch(reason: str, request: Optional[str] = None,
                               request_sent_at: Optional[str] = None,
                               no_reply: Optional[NoReplyError] = None,
                               drive_no: Optional[int] = None) -> None:
        # Never let the diagnostics replace the failure they explain.
        try:
            diagnose_failed_launch_unguarded(reason, request, request_sent_at,
                                             no_reply, drive_no)
        except Exception as exc:
            result["launch_failure_error"] = repr(exc)
            print(f"    launch-failure diagnostics failed: {exc!r}",
                  file=sys.stderr)

    def diagnose_failed_launch_unguarded(reason: str, request: Optional[str],
                                         request_sent_at: Optional[str],
                                         no_reply: Optional[NoReplyError],
                                         drive_no: Optional[int]) -> None:
        failed_at = utc_now()
        # A ring break pauses the VM, and that is the whole reason the agent
        # went quiet; the dump taken at the break is what matters.
        if dump_if_stopped_on_broken():
            return
        diag = result["launch_failure"] = {"reason": reason,
                                           "failed_at": failed_at}
        if reason == "no-reply":
            # request_sent_at..failed_at is the window to hold against the
            # TMF/drain timestamps in qemu.log.
            diag["request"] = request
            if drive_no is not None:
                diag["writer"] = f"PhysicalDrive{drive_no}"
            diag["request_sent_at"] = request_sent_at
            diag["no_reply_stage"] = no_reply.stage
            diag["no_reply_to"] = no_reply.command
            diag["sync"] = dataclasses.asdict(no_reply.sync)
            # Before the stacks, probe and dump take minutes.
            capture_qga_port("no reply before the soak")
        probe_s = LAUNCH_PROBE_S
        how = f"{reason} at {no_reply.stage}" if no_reply else reason
        # Only for an agent that went quiet: a deadline that ran out on a
        # slow but answering agent has nothing stuck to catch.
        dump_now = dump_on_agent_stall and reason == "no-reply"
        print(f"    {request or 'writer launch'} failed ({how}) at "
              f"{failed_at}; capturing "
              f"QEMU stacks{', dumping guest memory' if dump_now else ''} "
              f"and watching the guest agent and LUNs for {probe_s:.0f}s",
              file=sys.stderr)
        writer_exe = {"diskspd": diskspd_path, "fio": fio_path}.get(io_driver)
        summary = diagnose_launch_failure(
            diag,
            lambda: write_status({"elapsed_s": time.monotonic() - start}),
            qmp, qga_sock, proc.pid, run_dir, lun_specs,
            len(writer_pids), probe_s, writer_exe, screenshot, dump_path,
            dump_now, counted)
        diag["summary"] = summary
        print(f"    {summary}", file=sys.stderr)
        if diag.get("vm_paused"):
            dump_if_stopped_on_broken()

    # A cached-read LUN has to hold its file; otherwise the library's size.
    lun_image_size: tuple = ()
    # What the cached-read readers last said, and the seed their files'
    # contents are made from (see CACHED_READ_HEADER): fresh every run, so
    # a chunk can't pass for one written by another.
    cached_read = CachedReadStatus(qga_sock)
    data_seed = 0
    if io_driver == "cached-read":
        image_gib = (-(-cached_read_file_bytes // 1024**3)
                     + CACHED_READ_IMAGE_SLACK_GIB)
        lun_image_size = (f"{image_gib}G",)
        data_seed = random.SystemRandom().randrange(1, 2**31)

    try:
        make_overlay(BOOT_DISK, boot_overlay)
        make_overlay(OVMF_VARS, vars_overlay)

        for a in range(adapters):
            for t in range(targets):
                for l in range(luns_per_target):
                    tag = f"{a}-{t}-{l}"
                    img = lun_dir / f"lun{tag}-{run_dir.name}.qcow2"
                    make_blank_image(img, *lun_image_size)
                    lun_specs.append(LunSpec(
                        adapter=a, target=t, lun=l, image=img,
                        file_node=f"lfile{tag}", fmt_node=f"lraw{tag}",
                        dev_id=f"lun{tag}", serial=f"TF{tag}"))
        total_luns = len(lun_specs)

        writer_duration = (duration_s + WARMUP_S
                           + IO_PROBE_ATTEMPTS * IO_PROBE_WINDOW_S
                           + WRITER_DURATION_SLACK_S)

        argv = build_qemu_argv(boot_overlay, vars_overlay, qmp_sock, qga_sock,
                                serial_log, tpm_sock, adapters, lun_specs,
                                ram, cpus, taskset_cores, iothreads, tmf_trace,
                                stop_on_broken, ring_diag, qga_trace,
                                hv_crash)

        meta = {"adapters": adapters, "targets": targets,
                "luns_per_target": luns_per_target, "total_luns": total_luns,
                "duration_s": duration_s,
                "scenarios": [sc.name for sc in scenarios],
                "fault_settings": dataclasses.asdict(settings),
                "seed": seed,
                "iothreads": adapters if iothreads is None else iothreads,
                "tmf_trace": tmf_trace,
                "stop_on_broken": stop_on_broken,
                "ring_diag": ring_diag,
                "dump_on_agent_stall": dump_on_agent_stall,
                "qga_trace": qga_trace,
                "hv_crash": hv_crash,
                "cached_read_file_bytes": cached_read_file_bytes,
                "bsod_cycles": bsod_cycles,
                "argv": argv}
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))

        swtpm = start_swtpm(run_dir, tpm_sock)
        with qemu_log_path.open("wb") as qemu_log:
            proc = subprocess.Popen(argv, stdout=qemu_log, stderr=subprocess.STDOUT)

        def qemu_died_error(context: str) -> RuntimeError:
            output = qemu_log_path.read_text(errors="replace").strip()
            swtpm_log_path = run_dir / "swtpm-startup.log"
            swtpm_output = (swtpm_log_path.read_text(errors="replace").strip()
                            if swtpm_log_path.exists() else "")
            msg = (f"QEMU exited early (code {proc.returncode}) {context}. "
                   f"QEMU output:\n{output}")
            if swtpm_output:
                msg += f"\nswtpm output:\n{swtpm_output}"
            return RuntimeError(msg)

        qmp = connect_qmp(qmp_module, qmp_sock, proc, qemu_died_error)

        boot_deadline = start + BOOT_TIMEOUT_S
        booted = False
        while time.monotonic() < boot_deadline:
            if qga_ping(qga_sock):
                booted = True
                break
            time.sleep(1.0)
        if not booted:
            result["outcome"] = "boot-failed"
            result["elapsed_s"] = time.monotonic() - start
            return result

        # Agent calls before the soak whose sync had to be resent, or was
        # slow: each one is a stall the run survived. Published by
        # reference, like writer_pids, so a later failure keeps them.
        qga_resyncs: list = []
        result["qga_resyncs"] = qga_resyncs
        writer_pids = []
        # Published by reference, before any launch, so a launch that fails
        # part way through still records how many writers did come up --
        # "32 of 75 started" is the whole diagnosis in that case.
        result["writer_pids"] = writer_pids
        # pid -> LUN: which LUN a writer that exited was driving. One
        # writer per LUN, so this names the failing LUNs on its own.
        writer_luns: dict = {}
        # pid -> the state it was last polled in, shared by every poll in
        # this run so an exit and the stderr it carried survive the polls
        # that come after it. See writer_states().
        writer_seen: dict = {}

        serials = [s.serial for s in lun_specs]
        request_sent_at = utc_now()
        try:
            drive_numbers = resolve_drive_numbers(qga_sock, serials,
                                                  qga_resyncs)
        except NoReplyError as exc:
            # The first guest-exec after the boot ping, with nothing else
            # running yet: run-1791557706 lost the agent right here.
            diagnose_failed_launch("no-reply", RESOLVE_REQUEST,
                                   request_sent_at, exc)
            raise
        result["drive_numbers"] = drive_numbers
        if io_driver == "cached-read":
            gib = cached_read_file_bytes / 1024**3
            allow_s = cached_read_fill_timeout_s(cached_read_file_bytes
                                                 * total_luns)
            print(f"    preparing {total_luns} cached-read LUN(s): NTFS and a "
                  f"{gib:.1f} GiB file on each (allowing up to "
                  f"{allow_s / 60:.0f} min)", file=sys.stderr)

            def prepare_abort() -> Optional[str]:
                if proc.poll() is not None:
                    return "qemu-exited"
                return "guest-panicked" if guest_panicked() else None

            prep = prepare_cached_read(qga_sock, lun_specs, drive_numbers,
                                       cached_read_file_bytes, data_seed,
                                       prepare_abort, qga_resyncs)
            result["cached_read_prepare"] = prep
            if prep["status"] == "guest-panicked":
                return record_guest_panic(time.monotonic() - start)
            if prep["status"] != "ready":
                result["outcome"] = ("qemu-exited"
                                     if prep["status"] == "qemu-exited"
                                     else "fill-failed")
                result["elapsed_s"] = time.monotonic() - start
                result["error"] = (
                    f"preparing the cached-read LUNs ended {prep['status']} "
                    f"after {prep['elapsed_s']:.0f}s: "
                    f"{prep.get('failed') or prep.get('bytes_on_disk')}")
                print(f"    {result['error']}", file=sys.stderr)
                return result
            print(f"    cached-read LUNs ready after {prep['elapsed_s']:.0f}s",
                  file=sys.stderr)
        launch_deadline = time.monotonic() + WRITER_LAUNCH_TIMEOUT_S
        for spec in lun_specs:
            drive_no = drive_numbers[spec.serial]
            if time.monotonic() > launch_deadline:
                diagnose_failed_launch("deadline")
                raise RuntimeError(
                    f"only got {len(writer_pids)} of {total_luns} writer(s) "
                    f"started within {WRITER_LAUNCH_TIMEOUT_S}s")
            # A refused guest-exec answered, so it fails as before: the
            # diagnostics are for an agent that went quiet.
            request_sent_at = utc_now()
            try:
                pid = launch_writer(qga_sock, drive_no, writer_duration,
                                     io_driver, diskspd_path, fio_path,
                                     qga_resyncs, spec.serial, data_seed,
                                     lun_specs.index(spec))
                writer_pids.append(pid)
                writer_luns[pid] = spec.dev_id
            except NoReplyError as exc:
                diagnose_failed_launch("no-reply",
                                       f"writer for PhysicalDrive{drive_no}",
                                       request_sent_at, exc, drive_no)
                raise

        time.sleep(WARMUP_S)

        # No fault is armed until this has seen the writers drive I/O, so a
        # short window is enough: nothing is held. The first fault waiting
        # for it also means a run whose writers never started ends as
        # "no-io" rather than as a string of cycles nobody was there for.
        total_wps = 0.0
        wps_per_lun: dict = {}
        broke_in_preflight = False
        for attempt in range(IO_PROBE_ATTEMPTS):
            w_before = write_ops_by_node(qmp, counted)
            time.sleep(IO_PROBE_WINDOW_S)
            w_after = write_ops_by_node(qmp, counted)
            wps_per_lun = {s.serial: lun_write_delta(w_before, w_after, s) / IO_PROBE_WINDOW_S
                           for s in lun_specs}
            total_wps = sum(wps_per_lun.values())
            if total_wps >= MIN_WRITE_OPS_PER_S:
                break
            # A ring that broke during the probe has paused the VM, which
            # is why there was no I/O. The soak loop reports the break.
            if dump_if_stopped_on_broken():
                broke_in_preflight = True
                break
            if attempt + 1 < IO_PROBE_ATTEMPTS:
                print(f"    no write I/O seen yet (attempt {attempt + 1}/"
                      f"{IO_PROBE_ATTEMPTS}), retrying...", file=sys.stderr)
        result["writer_states"] = writer_states(qga_sock, writer_pids,
                                                writer_seen)
        result["pre_test_write_ops_per_s"] = wps_per_lun
        result["pre_test_write_ops_per_s_total"] = round(total_wps, 1)
        if total_wps < MIN_WRITE_OPS_PER_S and guest_panicked():
            return record_guest_panic(time.monotonic() - start)
        if total_wps < MIN_WRITE_OPS_PER_S and not broke_in_preflight:
            result["outcome"] = "no-io"
            result["elapsed_s"] = time.monotonic() - start
            diag = ""
            if io_driver == "diskspd":
                result["diskspd_diagnostic"] = diskspd_diagnostic(
                    qga_sock, diskspd_path, drive_numbers[lun_specs[0].serial])
                diag = f" diskspd diagnostic: {result['diskspd_diagnostic']}"
            elif io_driver == "fio":
                result["fio_diagnostic"] = fio_diagnostic(
                    qga_sock, fio_path, drive_numbers[lun_specs[0].serial])
                diag = f" fio diagnostic: {result['fio_diagnostic']}"
            result["error"] = (
                f"writers are not driving I/O: only {total_wps:.1f} {ops_unit} "
                f"across all {total_luns} LUN(s) (need >= {MIN_WRITE_OPS_PER_S}). "
                f"Check --io-driver / --diskspd-path / --fio-path; writer "
                f"states: {result['writer_states']}.{diag}")
            collect_vioscsi_telemetry()
            return result

        print(f"    soak running: {duration_s / 3600:.1f}h, {total_wps:.1f} {ops_unit} "
              f"across {total_luns} LUN(s) ({adapters} adapter(s) x {targets} "
              f"target(s) x {luns_per_target} lun(s)), scenarios "
              f"{', '.join(sc.name for sc in scenarios)}, heartbeat every "
              f"{heartbeat_s:.0f}s")

        test_start = time.monotonic()
        monitor_deadline = test_start + duration_s
        last_heartbeat = test_start
        prev_wops = write_ops_by_node(qmp, counted)

        qemu_stderr = QemuStderr(qemu_log_path)
        qemu_stderr.poll()
        # Firmware, driver init and the pre-flight probe all issue resets
        # and TMFs of their own (each adapter resets three times on a bare
        # boot). Keep those apart so the soak's tallies mean something.
        # Any virtio_error() already seen stays pending and is reported on
        # the first pass of the loop below -- an adapter that broke during
        # pre-flight is just as broken.
        result["tmf_trace_pre_soak"] = qemu_stderr.take_counts()

        def target_read_errors(adapter: int, target: int) -> Optional[int]:
            """Reads failed so far on a target's cached-read LUNs."""
            serials = [s.serial for s in lun_specs
                       if (s.adapter, s.target) == (adapter, target)]
            if not cached_read.poll() or any(sr not in cached_read.luns
                                             for sr in serials):
                return None
            return sum(cached_read.luns[sr]["errors"] for sr in serials)

        cycler = FaultCycler(scenarios, settings, adapters, targets, seed,
                             start, qemu_stderr, tmf_trace,
                             target_read_errors
                             if io_driver == "cached-read" else None)
        cycler.begin(qmp, test_start)

        agent_alive = True
        agent_lost_t: Optional[float] = None
        # One port capture per silence, for the first few: a missed 2s
        # ping that answers next time is routine under this load, while
        # the hang in run-1791602155 never recovered, so a silence that
        # lasts is worth catching within seconds rather than at the end.
        # The last answered ping bounds when it began.
        agent_answered_t = test_start
        silence_captured = False
        silence_captures = 0
        last_hash = None
        last_change_t = test_start
        # A guest that is still completing writes is alive no matter what the
        # (static) screen or a starved guest agent look like. Only the LUNs
        # no fault is holding count (see GUEST_IO_TIMEOUT_S for why even
        # they get a while, and IoProgress for how a cycle changing which
        # LUNs those are is handled). main() refuses a geometry where a
        # fault would cover every LUN, so there is always one to watch.
        longest_hold_s = max(sc.longest_hold_ms(settings)
                             for sc in scenarios) / 1000.0
        io_stall_threshold_s = (GUEST_IO_TIMEOUT_S + longest_hold_s
                                + IO_STALL_MARGIN_S)
        result["io_stall_threshold_s"] = io_stall_threshold_s
        io_progress = IoProgress(test_start, prev_wops, lun_specs)
        # --bsod: a ring that broke, kept until BSOD_BREAK_WATCH_S has
        # passed without a bugcheck.
        broken_pending: list = []
        broken_watch_end: Optional[float] = None

        # A --bsod break watch outlasts --duration-hours: it only ends
        # virtio-broken or guest-panicked, never completed.
        while (time.monotonic() < monitor_deadline
               or broken_watch_end is not None):
            now = time.monotonic()
            elapsed = now - start

            qemu_stderr.poll()
            broken_lines = qemu_stderr.take_broken()
            if bsod_cycles and (broken_lines or broken_pending):
                if broken_watch_end is None:
                    broken_watch_end = now + BSOD_BREAK_WATCH_S
                    result["faults_at_break"] = list_faults(qmp, adapters)
                    result["broken_at_s"] = round(elapsed, 1)
                    print(f"    virtio device broken after {elapsed:.0f}s: "
                          f"{broken_lines[0]}; removing the faults and "
                          f"watching {BSOD_BREAK_WATCH_S:.0f}s for a "
                          f"bugcheck", file=sys.stderr)
                    disarm("virtio-broken")
                    write_status({"elapsed_s": elapsed})
                broken_pending += broken_lines
                broken_lines = (broken_pending if now >= broken_watch_end
                                else [])
            if broken_lines:
                result["outcome"] = "virtio-broken"
                result["elapsed_s"] = elapsed
                result["qemu_stderr"] = qemu_stderr.lines
                if "faults_at_break" not in result:
                    result["faults_at_break"] = list_faults(qmp, adapters)
                held_at_break = fault_holds(result["faults_at_break"])
                # Before anything that needs the guest: it may be paused.
                dump_if_stopped_on_broken()
                # Without the break dump, which does this itself. A target
                # being held is quiet on a healthy adapter, and the run is
                # over anyway.
                disarm("virtio-broken")
                # Sampled here rather than left to the heartbeat: breakage
                # often lands before the first one is due, and then the
                # result says nothing about whether the guest was still
                # answering when its adapters died.
                result["agent_alive"] = qga_ping(qga_sock)
                result["error"] = (
                    "QEMU marked a virtio device broken (NEEDS_RESET) -- it "
                    "will not service that device's queues again, so every "
                    "LUN behind it is dead for the rest of the run: "
                    + "; ".join(broken_lines))
                print(f"    virtio device broken after {elapsed:.0f}s: "
                      f"{broken_lines[0]}", file=sys.stderr)
                # Persist what is already known before anything slow: the
                # window below takes a while, and telemetry talks to a guest
                # that has just lost its disks. Neither must be able to take
                # the finding down with it.
                write_status({"elapsed_s": elapsed})

                if result.get("vm_left_paused"):
                    # Every adapter is quiet in a paused VM; a window now
                    # would call them all dead.
                    result["dead_adapters"] = None
                    result["error"] += (". Adapters no longer doing I/O: "
                                        "not sampled, the VM was left paused "
                                        "after the break dump")
                else:
                    window_s = ADAPTER_ACTIVITY_WINDOW_S
                    act = lun_activity_by_adapter(qmp, lun_specs, window_s,
                                                  counted)
                    dead = adapters_without_io(act, held_at_break)
                    result["adapter_activity"] = act
                    result["activity_window_s"] = window_s
                    result["dead_adapters"] = dead
                    result["write_ops_per_s"] = round(
                        sum(v["writes"] for v in act.values()) / window_s, 1)
                    result["error"] += (f". Adapters no longer doing I/O: "
                                        f"{dead or 'none'}")
                    print(f"    adapters no longer doing I/O: "
                          f"{dead or 'none'} (of {len(act)}, over a "
                          f"{window_s:.0f}s window)", file=sys.stderr)
                # The virtio_scsi_broken trace line lands a moment after
                # virtio_error()'s message and may have missed the poll
                # that saw the message; the window above has given it time.
                record_trace()
                for ev in result["broken_events"]:
                    last_tmf = next((ln for ln in reversed(ev["preceding"])
                                     if "virtio_scsi_tmf_" in ln), None)
                    print(f"    {ev['bus']} broke on queue {ev['queue']} "
                          f"({ev['queue_kind']}); last TMF on that adapter: "
                          f"{last_tmf or 'none in the last ' + str(TRACE_CONTEXT_LINES) + ' events'}",
                          file=sys.stderr)
                    verdict = ev.get("verdict", "none")
                    seen = (f" ({first_sight(ev['before'])})"
                            if "before" in ev else "")
                    print(f"    {ev['bus']} verdict: {verdict}{seen} -- "
                          f"{ev.get('mechanism') or explain_break(ev)}",
                          file=sys.stderr)
                if result["req_overlaps"]:
                    print(f"    requests popped while the device still held "
                          f"one with the same header or head: "
                          f"{result['req_overlaps']}", file=sys.stderr)
                write_status({"elapsed_s": elapsed})

                if bsod_cycles:
                    result["bsod_verdict"] = (
                        f"no answer: a virtio ring broke after "
                        f"{result.get('broken_at_s', elapsed):.0f}s and the "
                        f"guest did not bugcheck within "
                        f"{BSOD_BREAK_WATCH_S:.0f}s of it"
                        f"{bsod_corruption_note()}")
                    print(f"    {result['bsod_verdict']}")
                collect_vioscsi_telemetry()
                # Adapters keep falling over while telemetry is collected.
                record_trace()
                write_status({"elapsed_s": elapsed})
                return result

            if proc.poll() is not None:
                result["outcome"] = "qemu-exited"
                result["qemu_returncode"] = proc.returncode
                result["elapsed_s"] = elapsed
                record_cycles()
                write_status({"elapsed_s": elapsed})
                return result

            # Ahead of everything that takes a bugcheck for a guest gone
            # dark: hv-crash says so outright, with the STOP code.
            if guest_panicked():
                return record_guest_panic(elapsed)

            # Once the last late-dma cycle's cooldown has passed with no
            # bugcheck, which is the guest's grace to crash in. Never with
            # a ring broken: that run ends virtio-broken, or guest-panicked
            # if the bugcheck comes in the watch, whenever it broke.
            if (bsod_cycles and broken_watch_end is None and cycler.idle()
                    and cycler.late_dma_cycles() >= bsod_cycles
                    and cycler.next_arm_t is not None
                    and now >= cycler.next_arm_t):
                # A break since this pass's poll goes round again first.
                qemu_stderr.poll()
                if qemu_stderr.has_broken():
                    continue
                writers_failed(elapsed)  # only noted, under --bsod
                result["elapsed_s"] = elapsed
                released = sum(1 for c in cycler.cycles
                               if c["outcome"] == "released")
                if result.get("cached_read_mismatches"):
                    result["outcome"] = "data-corruption"
                    result["bsod_verdict"] = (
                        f"late DMA corrupted cached data but no bugcheck: "
                        f"{bsod_cycles} late-DMA cycle(s), {released} of them "
                        f"with the held reads let go after the trigger"
                        f"{bsod_corruption_note()}")
                else:
                    result["outcome"] = "cycles-complete"
                    result["bsod_verdict"] = (
                        f"no bugcheck: the guest survived {bsod_cycles} "
                        f"late-DMA cycle(s), {released} of them with the held "
                        f"reads let go after the trigger, and every chunk "
                        f"read back as written")
                print(f"    {result['bsod_verdict']}")
                disarm("end of run")
                record_trace()
                collect_vioscsi_telemetry()
                write_status({"elapsed_s": elapsed})
                return result

            cycler.tick(qmp, now)
            if bsod_cycles:
                # What the late-dma trigger's polls saw, at no extra cost.
                note_cached_read_corruption(elapsed)

            if qga_ping(qga_sock):
                agent_alive = True
                agent_lost_t = None
                agent_answered_t = time.monotonic()
                silence_captured = False
            else:
                if agent_alive:
                    agent_lost_t = now
                agent_alive = False

            if (not agent_alive and not silence_captured
                    and silence_captures < QGA_PORT_SILENCE_CAPTURES
                    and now - agent_lost_t > AGENT_SILENCE_THRESHOLD_S):
                silence_captured = True
                silence_captures += 1
                capture_qga_port("agent silent during the soak",
                                 agent_last_answered_at=wall_time(
                                     agent_answered_t),
                                 agent_lost_at=wall_time(agent_lost_t),
                                 agent_silent_s=round(now - agent_lost_t, 1))
                write_status({"elapsed_s": elapsed})

            h = screendump_hash(qmp, screenshot)
            if h is not None:
                if h != last_hash:
                    last_hash = h
                    last_change_t = now

            io_progress.update(now, write_ops_by_node(qmp, counted),
                               cycler.unfaulted(lun_specs))

            if (not agent_alive and agent_lost_t is not None
                    and now - agent_lost_t > AGENT_SILENCE_THRESHOLD_S
                    and now - last_change_t > STATIC_SCREEN_THRESHOLD_S
                    and io_progress.stalled_s(now) > io_stall_threshold_s):
                result["outcome"] = "crash-suspected"
                result["elapsed_s"] = elapsed
                result["faults_at_dark"] = list_faults(qmp, adapters)
                print(f"    guest appears dark after {elapsed:.0f}s -- "
                      f"capturing crash dump", file=sys.stderr)
                # Not subject to the silence cap: this one ends the run.
                capture_qga_port("guest dark", agent_silent_s=round(
                    now - agent_lost_t, 1))
                result["dump_ok"] = try_dump_guest_memory(
                    qmp, dump_path, proc.pid, lambda: disarm("crash dump"),
                    result)
                record_cycles()
                write_status({"elapsed_s": elapsed})
                return result

            if now - last_heartbeat >= heartbeat_s:
                if writers_failed(elapsed):
                    return result
                cur_wops = write_ops_by_node(qmp, counted)
                sample_s = now - last_heartbeat
                wps = sum(lun_write_delta(prev_wops, cur_wops, s) for s in lun_specs) / sample_s
                prev_wops = cur_wops
                last_heartbeat = now
                faults = cycler.status(now)
                record_cycles()
                hb = {"elapsed_s": round(elapsed, 0), "write_ops_per_s": round(wps, 1),
                      "faults": faults, "agent_alive": agent_alive,
                      "tmf_trace": qemu_stderr.trace_counts}
                cur = faults.get("current")
                now_phrase = (f"{cur['scenario']} on {cur['device']} target "
                              f"{cur['target']} for {cur['age_s']:.0f}s, "
                              f"holding {cur['held']}" if cur else
                              "no fault armed")
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"{elapsed / 3600:.2f}h elapsed, {wps:.1f} {ops_unit}, "
                      f"{faults['cycles_done']} cycle(s) done, {now_phrase}, "
                      f"TMFs={qemu_stderr.tmf_requests()}")
                write_status(hb)

            time.sleep(POLL_INTERVAL_S)

        # The soak ran its duration, but the last heartbeat can be up to
        # heartbeat_s old: a verify failure since then would otherwise be
        # reported as a clean run.
        if writers_failed(time.monotonic() - start):
            return result

        result["outcome"] = "completed"
        result["elapsed_s"] = time.monotonic() - start
        if bsod_cycles:
            if result.get("cached_read_mismatches"):
                result["outcome"] = "data-corruption"
                head = "late DMA corrupted cached data but no bugcheck"
            else:
                head = "no bugcheck"
            result["bsod_verdict"] = (
                f"{head}, and only {cycler.late_dma_cycles()} of "
                f"{bsod_cycles} late-DMA cycle(s) ran their course before "
                f"--duration-hours ran out{bsod_corruption_note()}")
            print(f"    {result['bsod_verdict']}")
        # Before telemetry, which stops the writers: they can't finish
        # while a target holds their I/O.
        disarm("end of run")
        record_trace()
        collect_vioscsi_telemetry()
        write_status({"elapsed_s": result["elapsed_s"]})
        return result

    except Exception as exc:
        record_run_error(result, exc)
        # A ring that breaks before the soak loop watches for it -- during
        # writer launch, say -- pauses the VM, and what fails is the agent
        # call stuck behind the pause. Dump it anyway: a paused guest is
        # still exactly as the break left it.
        if qmp is not None and proc is not None and proc.poll() is None:
            if qemu_stderr is None:
                qemu_stderr = QemuStderr(qemu_log_path)
            record_trace()
            try:
                dump_if_stopped_on_broken()
            except Exception as dump_exc:
                result["break_dump_error"] = repr(dump_exc)
            try:
                disarm("error")
            except Exception as disarm_exc:
                result["disarm_error"] = repr(disarm_exc)
        record_cycles()
        result["elapsed_s"] = time.monotonic() - start
        return result

    finally:
        try:
            if qmp is not None:
                qmp_call(qmp, "quit")
        except Exception:
            pass
        if proc is not None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if qmp is not None:
            try:
                qmp.close()
            except Exception:
                pass
        if swtpm is not None:
            swtpm.terminate()
            try:
                swtpm.wait(timeout=5)
            except subprocess.TimeoutExpired:
                swtpm.kill()
                swtpm.wait()

        keep_debug_artifacts = (keep_all or result.get("telemetry_failure_screenshot")
                                 or result.get("telemetry_failure_dump"))
        if result["outcome"] in CLEAN_OUTCOMES and not keep_debug_artifacts:
            for f in [boot_overlay, vars_overlay, screenshot] + [s.image for s in lun_specs]:
                f.unlink(missing_ok=True)
        else:
            result["screenshot"] = str(screenshot) if screenshot.exists() else None
            result["serial_log"] = str(serial_log)
            result["qemu_log"] = str(qemu_log_path)
            result["dump"] = str(dump_path) if dump_path.exists() else None


def bsod_banner(args) -> str:
    """What --bsod does and how to read its result, for the start."""
    trigger = LATE_DMA_TRIGGERS[args.late_dma_release_after]
    return f"""--bsod: each cycle holds every command sent to target 0 of one adapter
(the target the upstream driver's LUN reset always names) and leaves the
guest's LUN reset hanging. A driver that completes pending requests
without waiting for that reset (upstream vioscsi) hands the held reads
back to Windows with nothing read. {args.late_dma_delay_s:.0f}s after the {trigger},
the harness lets the held reads run, and their data lands in whatever
Windows has put in those pages since; the readers on the other
adapter(s) are what put something there. Up to {args.bsod_cycles} cycle(s).
  guest-panicked   a bugcheck, with its STOP code: expected from upstream
  data-corruption  no bugcheck, but a reader read back a chunk that is not
                   what was written there: late DMA landed in reused pages
                   without crashing anything
  cycles-complete  survived every cycle with every chunk intact: expected
                   from a driver that waits for the TMF response
                   (reset_via_tmf)
Any other outcome means the recipe never got to an answer; see the
result."""


def apply_bsod(args) -> Optional[str]:
    """Fill in the defaults that depend on --bsod, and refuse what
    contradicts it. An error message, or None. Options given explicitly
    are kept where the recipe still works with them (--ram, the
    deadlines); the ones it can't work without are refused rather than
    quietly overridden."""
    if args.bsod:
        if args.scenarios not in (None, "late-dma"):
            return ("--bsod runs the late-dma scenario only; leave out "
                    "--scenarios")
        if args.io_driver not in (None, "cached-read"):
            return ("--bsod needs --io-driver=cached-read: the raw-disk "
                    "drivers put a late read into their own buffer, which "
                    "can't bugcheck the guest")
        if args.hv_crash is False:
            return "--bsod needs --hv-crash to see the bugcheck it waits for"
        if args.stop_on_broken:
            return ("--bsod runs with --no-stop-on-broken: the break dump "
                    "would remove the faults and end the cycling before a "
                    "bugcheck could come")
        args.scenarios = "late-dma"
        args.io_driver = "cached-read"
        args.stop_on_broken = False
        if args.bsod_cycles is None:
            args.bsod_cycles = DEFAULT_BSOD_CYCLES
        if args.bsod_cycles < 1:
            return "--bsod-cycles must be >= 1"
        if args.recovery_deadline_s is None:
            args.recovery_deadline_s = BSOD_RECOVERY_DEADLINE_S
        if args.ram is None:
            args.ram = BSOD_RAM
        if args.adapters is None:
            args.adapters = BSOD_ADAPTERS
            if args.targets is None:
                args.targets = BSOD_TARGETS
        elif args.adapters == 1:
            print("Warning: --bsod with --adapters 1: the upstream driver's "
                  "LUN reset pauses the whole adapter (StorPortPause, up to "
                  "60s), so the readers that should reuse the failed reads' "
                  "pages may be paused with it until after the release. "
                  f"Leave out --adapters for {BSOD_ADAPTERS}.",
                  file=sys.stderr)
    elif args.bsod_cycles is not None:
        return "--bsod-cycles only applies to --bsod"
    if args.adapters is None:
        args.adapters = DEFAULT_ADAPTERS
    if args.targets is None:
        args.targets = DEFAULT_TARGETS
    if args.scenarios is None:
        args.scenarios = ",".join(DEFAULT_SCENARIOS)
    if args.io_driver is None:
        args.io_driver = "powershell"
    if args.hv_crash is None:
        args.hv_crash = True
    if args.stop_on_broken is None:
        args.stop_on_broken = True
    if args.recovery_deadline_s is None:
        args.recovery_deadline_s = DEFAULT_RECOVERY_DEADLINE_S
    if args.ram is None:
        args.ram = DEFAULT_RAM
    if args.late_dma_release_after is None:
        args.late_dma_release_after = ("read-error"
                                       if args.io_driver == "cached-read"
                                       else "recovery")
    elif (args.late_dma_release_after == "read-error"
          and args.io_driver != "cached-read"):
        return ("--late-dma-release-after=read-error needs "
                "--io-driver=cached-read, whose readers report the errors")
    if not (math.isfinite(args.late_dma_delay_s)
            and args.late_dma_delay_s >= 0):
        return "--late-dma-delay-s must be a finite number >= 0"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Hours-long target-fault soak test for the vioscsi "
                     "Windows guest driver: one SCSI target at a time stops "
                     "answering, or answers slowly or late, in a rotating set "
                     "of ways, and recovers when the guest does the right "
                     "kind of error recovery (or the harness gives up on "
                     "it). Each cycle's outcome is recorded, and the harness "
                     "watches for a bugcheck or a broken ring over the full "
                     "run.",
        epilog=usage_note(), formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tmf-trace", action=argparse.BooleanOptionalAction,
                     default=True,
                     help="trace virtio-scsi TMFs, device resets and broken "
                          "rings per adapter into qemu.log, and attach each "
                          "adapter's recent TMFs to the result when it "
                          "breaks (default: on)")
    ap.add_argument("--stop-on-broken", action=argparse.BooleanOptionalAction,
                     default=None,
                     help="pause the VM the moment a virtio-scsi ring breaks "
                          "(x-stop-on-broken), dump guest memory to break.dmp "
                          "while the failing request is still where the "
                          "driver left it, then resume. The dump removes "
                          "every target fault and no more are armed "
                          "(default: on, off under --bsod)")
    ap.add_argument("--ring-diag", action=argparse.BooleanOptionalAction,
                     default=True,
                     help="virtio-scsi's healthy-path break diagnostics: "
                          "per-request overlap tracking, TMF and drain "
                          "snapshots, and the drain watch, which changes "
                          "when the guest kicks during a reset. "
                          "--no-ring-diag (x-diag=off) leaves only the "
                          "chain captured at a break, to A/B their effect "
                          "on timing (default: on)")
    ap.add_argument("--dump-on-agent-stall",
                     action=argparse.BooleanOptionalAction, default=False,
                     help="when the guest agent never answers a request "
                          "before the soak (resolving drives, launching a "
                          "writer), dump guest memory to crash.dmp right "
                          "away, while it is still stuck, rather than only "
                          "if it stays silent for the whole probe. The guest "
                          "is paused for the dump (minutes, 8+ GB in the run "
                          "dir). No fault is armed yet at that point "
                          "(default: off)")
    ap.add_argument("--qga-trace", action=argparse.BooleanOptionalAction,
                     default=True,
                     help="trace the guest agent's virtio-serial port into "
                          "qemu.log (each guest write reaching the socket, "
                          "the port being throttled and released, the "
                          "harness connecting and leaving) and tally it in "
                          "the result. The port's info qtree state is "
                          "recorded either way when the agent goes quiet: "
                          "the first few silences of 15s+ in the soak, a "
                          "pre-soak request it never answers, the guest "
                          "going dark, and an agent found silent when "
                          "telemetry is collected (default: on)")
    ap.add_argument("--hv-crash", action=argparse.BooleanOptionalAction,
                     default=None,
                     help="give the guest the Hyper-V crash MSRs (hv-crash) "
                          "and pause the VM when it reports a bugcheck "
                          "(-action panic=pause). The run then ends as "
                          "guest-panicked with the STOP code and its "
                          "parameters in the result, a screenshot and a "
                          "win-dmp in panic.dmp, instead of being caught "
                          "later as crash-suspected once the agent, the "
                          "screen and the LUNs have all gone quiet "
                          "(default: on; --bsod needs it)")
    ap.add_argument("--iothreads", type=int, default=None,
                     help="number of QEMU iothreads to create, assigned "
                          "round-robin to the adapters (default: one per "
                          "adapter). 0 leaves all adapter I/O in QEMU's main "
                          "loop, where it contends with the guest agent and "
                          "QMP -- useful only to reproduce an old run")
    ap.add_argument("--adapters", type=int, default=None,
                     help="number of vioscsi (virtio-scsi-pci) adapters to "
                          f"create (default: {DEFAULT_ADAPTERS}, "
                          f"{BSOD_ADAPTERS} under --bsod); --targets and "
                          "--luns-per-target apply to each adapter")
    ap.add_argument("--targets", type=int, default=None,
                     help="number of SCSI targets per adapter (default: "
                          f"{DEFAULT_TARGETS}, or {BSOD_TARGETS} under --bsod "
                          "when --adapters is left out too). Faults are per "
                          "target, and the "
                          "VM needs at least two targets in all (--adapters "
                          "x --targets): the check for a guest gone dark "
                          "watches the LUNs no fault is holding, so with a "
                          "single target there would be nothing to watch "
                          "whenever a fault is armed")
    ap.add_argument("--luns-per-target", type=int, default=1,
                     help="number of LUNs per target; a fault holds all of "
                          "them (default: %(default)s)")
    ap.add_argument("--duration-hours", type=float, default=4.0,
                     help="how long to run the soak test (default: %(default)s)")
    ap.add_argument("--scenarios", default=None,
                     help="comma list of fault scenarios to rotate through, "
                          "in order (default: all of them but late-dma; "
                          "late-dma alone under --bsod; see the list below)")
    ap.add_argument("--recovery-deadline-s", type=float, default=None,
                     help="how long a scenario that waits for the guest's "
                          "recovery gets before the harness removes the "
                          "fault itself and records not-recovered, and how "
                          "long late-dma waits for its trigger (default: "
                          f"{DEFAULT_RECOVERY_DEADLINE_S:.0f}, "
                          f"{BSOD_RECOVERY_DEADLINE_S:.0f} under --bsod). "
                          "Allow for the guest's ~60s timeout and a few "
                          "rounds of escalation")
    ap.add_argument("--late-dma-delay-s", type=float,
                     default=DEFAULT_LATE_DMA_DELAY_S,
                     help="how long after its trigger late-dma lets the "
                          "held reads run (default: %(default)s)")
    ap.add_argument("--late-dma-release-after",
                     choices=sorted(LATE_DMA_TRIGGERS), default=None,
                     help="late-dma's trigger: 'read-error', the first read "
                          "the guest's readers on the faulted target see "
                          "fail (by then Windows should have given up on it "
                          "and freed its pages; needs --io-driver="
                          "cached-read), or "
                          "'recovery', the first recovery attempt the fault "
                          "sees (Windows may still be retrying the read "
                          "into the same pages then). Default: read-error "
                          "with cached-read, otherwise recovery")
    ap.add_argument("--bsod", action="store_true",
                     help="run the recipe meant to bugcheck a vioscsi that "
                          "completes requests the device still owns: "
                          "late-dma cycles with the cached-read driver and "
                          "hv-crash, stop-on-broken off, and neither a "
                          "broken ring nor a writer exiting ending the run. "
                          "It ends guest-panicked at the first bugcheck, "
                          "data-corruption if --bsod-cycles late-dma cycles "
                          "pass without one but a reader read back wrong "
                          "data, or cycles-complete if they pass clean; a "
                          "broken ring ends it virtio-broken. Also defaults "
                          f"--ram to {BSOD_RAM}, --recovery-deadline-s to "
                          f"{BSOD_RECOVERY_DEADLINE_S:.0f} and --adapters x "
                          f"--targets to {BSOD_ADAPTERS} x {BSOD_TARGETS}; "
                          "options given explicitly win where they don't "
                          "defeat the recipe")
    ap.add_argument("--bsod-cycles", type=int, default=None,
                     help="late-dma cycles a --bsod run gets to bugcheck the "
                          f"guest (default: {DEFAULT_BSOD_CYCLES})")
    ap.add_argument("--window-s", type=float, default=DEFAULT_WINDOW_S,
                     help="how long slow-target and late-completion stay "
                          "armed (default: %(default)s)")
    ap.add_argument("--dead-target-s", type=float,
                     default=DEFAULT_DEAD_TARGET_S,
                     help="how long dead-target stays dead before the "
                          "harness removes it (default: %(default)s)")
    ap.add_argument("--cooldown-s", type=float, default=DEFAULT_COOLDOWN_S,
                     help="pause between one cycle ending and the next "
                          "being armed, so the guest finishes recovering "
                          "first (default: %(default)s)")
    ap.add_argument("--tmf-hang-ms", type=int, default=DEFAULT_TMF_HANG_MS,
                     help="how long hang-lun-reset leaves a LUN reset "
                          "unanswered (default: %(default)s)")
    ap.add_argument("--late-probability", type=float,
                     default=DEFAULT_LATE_PROBABILITY,
                     help="fraction of commands late-completion holds "
                          "(default: %(default)s)")
    ap.add_argument("--io-driver",
                     choices=["powershell", "diskspd", "fio", "cached-read"],
                     default=None,
                     help="how to drive guest I/O: 'powershell' (default; "
                          "cached-read under --bsod) runs "
                          "the built-in raw-write loop (writes only -- use "
                          "diskspd or fio to also exercise reads); 'diskspd' "
                          "launches Microsoft's diskspd.exe with a 50/50 "
                          "read/write mix against each LUN's PhysicalDriveN; "
                          "'fio' launches fio.exe with a 50/50 random "
                          "read/write mix and crc32c data-integrity "
                          "verification against each LUN's PhysicalDriveN; "
                          "'cached-read' formats each LUN NTFS, writes one "
                          "big file to it before the soak, then reads that "
                          "file over and over through the file cache, so "
                          "the LUN I/O is paging reads into pages the memory "
                          "manager recycles (read-only; failed reads are "
                          "counted, not fatal; every chunk read is checked, "
                          "and one read back wrong ends the run as "
                          "data-corruption)")
    ap.add_argument("--cached-read-file-gib", type=float, default=None,
                     help="size of each LUN's file for --io-driver="
                          "cached-read (default: "
                          f"{CACHED_READ_RAM_FACTOR}x --ram, so that even one "
                          "LUN's file can't stay cached). Writing it is slow "
                          "on NFS-backed images; lower --ram to make it "
                          "smaller")
    ap.add_argument("--diskspd-path", default=DEFAULT_DISKSPD_PATH,
                     help="guest-side path to diskspd.exe, used when "
                          "--io-driver=diskspd (default: %(default)s)")
    ap.add_argument("--fio-path", default=DEFAULT_FIO_PATH,
                     help="guest-side path to fio.exe, used when "
                          "--io-driver=fio (default: %(default)s)")
    ap.add_argument("--vioscsi-telemetry-script",
                     default=DEFAULT_VIOSCSI_TELEMETRY_SCRIPT,
                     help="guest-side PowerShell script to run and collect "
                          "vioscsi telemetry from after the run finishes "
                          "(default: %(default)s); its combined stdout/"
                          "stderr is saved to vioscsi-telemetry.log in the "
                          "run directory. Pass an empty string to disable")
    ap.add_argument("--heartbeat-seconds", type=float, default=DEFAULT_HEARTBEAT_S,
                     help="how often to print/record a progress line during "
                          "the run (default: %(default)s). Its write rate is "
                          "the average since the last heartbeat across all "
                          "LUNs, so it swings with whatever fault happened to "
                          "be armed meanwhile; the per-cycle records, not "
                          "the heartbeats, say what each fault did")
    ap.add_argument("--ram", default=None,
                     help=f"guest RAM (default: {DEFAULT_RAM}, {BSOD_RAM} "
                          f"under --bsod)")
    ap.add_argument("--cpus", default=DEFAULT_CPUS)
    ap.add_argument("--host-pressure-cores", default=None, metavar="CPULIST",
                     help="restrict QEMU to these host cores via taskset "
                          "(e.g. '0-1')")
    ap.add_argument("--seed", type=int, default=1,
                     help="seed for the harness's choice of which target "
                          "each cycle faults. QEMU picks which commands a "
                          "probability or delay fault holds, and for how "
                          "long, by itself")
    ap.add_argument("--disk-dir", type=Path, default=None, metavar="DIR",
                     help="directory in which to create the LUN disk images "
                          "under I/O test (default: the per-run directory "
                          f"under {SOAK_DIR})")
    ap.add_argument("--keep-all", action="store_true",
                     help="keep overlays/images even for a clean 'completed' run")
    args = ap.parse_args()
    err = apply_bsod(args)
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    if args.host_pressure_cores and not shutil.which("taskset"):
        print("Error: --host-pressure-cores given but 'taskset' not found in PATH.",
              file=sys.stderr)
        return 1

    # argparse's float() takes "nan" and "inf", which pass every range
    # check below and then never let a cycle (or the run) end.
    for flag in ("duration_hours", "recovery_deadline_s", "window_s",
                 "dead_target_s", "cooldown_s", "late_probability",
                 "heartbeat_seconds", "cached_read_file_gib"):
        value = getattr(args, flag)
        if value is not None and not math.isfinite(value):
            print(f"Error: --{flag.replace('_', '-')} must be a finite "
                  f"number.", file=sys.stderr)
            return 1
    if args.duration_hours <= 0 or args.heartbeat_seconds <= 0:
        print("Error: --duration-hours and --heartbeat-seconds must be > 0.",
              file=sys.stderr)
        return 1
    if not (0.0 <= args.late_probability <= 1.0):
        print("Error: --late-probability must be between 0.0 and 1.0.",
              file=sys.stderr)
        return 1
    names = [n.strip() for n in args.scenarios.split(",") if n.strip()]
    unknown = [n for n in names if n not in SCENARIOS_BY_NAME]
    if not names or unknown:
        print(f"Error: unknown scenario(s) {unknown}; choose from "
              f"{', '.join(SCENARIOS_BY_NAME)}.", file=sys.stderr)
        return 1
    scenarios = [SCENARIOS_BY_NAME[n] for n in names]
    for flag in ("recovery_deadline_s", "window_s", "dead_target_s"):
        if getattr(args, flag) <= 0:
            print(f"Error: --{flag.replace('_', '-')} must be > 0.",
                  file=sys.stderr)
            return 1
    if args.cooldown_s < 0:
        print("Error: --cooldown-s must be >= 0.", file=sys.stderr)
        return 1
    # QEMU's own limit (see ScsiFaultOptions in qapi/scsi.json).
    if not (0 <= args.tmf_hang_ms <= 86400000):
        print("Error: --tmf-hang-ms must be between 0 and 86400000.",
              file=sys.stderr)
        return 1
    settings = FaultSettings(
        recovery_deadline_s=args.recovery_deadline_s,
        window_s=args.window_s, dead_target_s=args.dead_target_s,
        cooldown_s=args.cooldown_s, tmf_hang_ms=args.tmf_hang_ms,
        late_probability=args.late_probability,
        late_dma_delay_s=args.late_dma_delay_s,
        late_dma_release_after=args.late_dma_release_after)

    if args.adapters < 1 or args.targets < 1 or args.luns_per_target < 1:
        print("Error: --adapters, --targets and --luns-per-target must all "
              "be >= 1.", file=sys.stderr)
        return 1
    # See IoProgress: with one target in the whole VM, an armed fault holds
    # every LUN, and "the guest has gone dark" would have nothing but the
    # screen and the guest agent to go on -- exactly the two a busy but
    # healthy guest can fail.
    if args.adapters * args.targets < 2:
        print("Error: need at least two targets in the VM (--adapters x "
              "--targets), so that some LUN is outside the faulted target "
              "and the I/O-stall check has something to watch.",
              file=sys.stderr)
        return 1
    if args.iothreads is not None and args.iothreads < 0:
        print("Error: --iothreads must be >= 0 (0 keeps adapter I/O in "
              "QEMU's main loop).", file=sys.stderr)
        return 1
    # virtio-scsi's own limits (VIRTIO_SCSI_MAX_TARGET / VIRTIO_SCSI_MAX_LUN
    # in include/hw/virtio/virtio-scsi.h) -- fail fast with a clear message
    # instead of QEMU rejecting the device partway through startup.
    if args.targets > 256:
        print("Error: --targets must be <= 256 (virtio-scsi's max target id "
              "is 255).", file=sys.stderr)
        return 1
    if args.luns_per_target > 16384:
        print("Error: --luns-per-target must be <= 16384 (virtio-scsi's max "
              "LUN is 16383).", file=sys.stderr)
        return 1

    cached_read_file_bytes = 0
    if args.io_driver == "cached-read":
        gib = args.cached_read_file_gib
        if gib is None:
            try:
                ram_gib = qemu_ram_bytes(args.ram) / 1024**3
            except ValueError:
                print(f"Error: can't size the cached-read file from --ram "
                      f"{args.ram!r}; give --cached-read-file-gib.",
                      file=sys.stderr)
                return 1
            gib = math.ceil(ram_gib * CACHED_READ_RAM_FACTOR)
        if gib <= 0:
            print("Error: --cached-read-file-gib must be > 0.",
                  file=sys.stderr)
            return 1
        # Whole chunks, which is what the guest writes.
        cached_read_file_bytes = (math.ceil(gib * 1024**3
                                            / CACHED_READ_CHUNK_BYTES)
                                  * CACHED_READ_CHUNK_BYTES)
    elif args.cached_read_file_gib is not None:
        print("Error: --cached-read-file-gib only applies to "
              "--io-driver=cached-read.", file=sys.stderr)
        return 1

    duration_s = args.duration_hours * 3600.0

    err = check_prereqs()
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    qmp_module = load_qmp_module()
    if qmp_module is None:
        return 1

    SOAK_DIR.mkdir(parents=True, exist_ok=True)

    total_luns = args.adapters * args.targets * args.luns_per_target
    print(f"Starting {args.duration_hours:.1f}h target-fault soak on "
          f"{total_luns} LUN(s) "
          f"({args.adapters} adapter(s) x {args.targets} target(s) x "
          f"{args.luns_per_target} lun(s)), scenarios: "
          f"{', '.join(names)}.")
    if args.bsod:
        print(bsod_banner(args))

    result = run_soak(args.adapters, args.targets, args.luns_per_target,
                       duration_s, args.ram, args.cpus,
                       args.host_pressure_cores, args.keep_all, qmp_module,
                       args.io_driver, args.diskspd_path, args.fio_path,
                       scenarios, settings,
                       args.seed, args.heartbeat_seconds,
                       args.vioscsi_telemetry_script,
                       args.disk_dir, args.iothreads, args.tmf_trace,
                       args.stop_on_broken, args.ring_diag,
                       args.dump_on_agent_stall, args.qga_trace,
                       args.hv_crash, cached_read_file_bytes,
                       args.bsod_cycles if args.bsod else None)

    results_path = SOAK_DIR / f"result-{int(time.time())}.json"
    results_path.write_text(json.dumps(result, indent=2))

    print()
    print(f"Outcome: {result['outcome']} ({result['elapsed_s']:.0f}s)")
    if "guest_panic" in result:
        print(f"Bugcheck: {result['guest_panic'].get('bugcheck')}")
    if "bsod_verdict" in result:
        print(f"--bsod: {result['bsod_verdict']}")
    print(f"Result written to {results_path}")
    if result["outcome"] in FAILURE_OUTCOMES:
        print(f"Artifacts in {result['run_dir']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
