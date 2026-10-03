#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Concurrent multi-LUN reset-race harness for the vioscsi (virtio-scsi)
# Windows guest driver, built on the inject-error latency-injection branch.
#
# Background
# ----------
# Reading vioscsi's current source (vioscsi.c / helper.c) shows that a
# storport request timeout on a LUN drives this path:
#
#   PreProcessRequest() SRB_FUNCTION_RESET_LOGICAL_UNIT
#     -> CompletePendingRequestsOnReset()
#          - sets a single *per-adapter* adaptExt->reset_in_progress flag
#          - fires an async VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET via
#            DeviceReset(), which reuses a single *per-adapter* scratch
#            buffer (adaptExt->tmf_cmd) and sets adaptExt->tmf_infly=TRUE
#            without waiting for the response
#          - synchronously force-completes every pending SRB on every
#            queue with SRB_STATUS_BUS_RESET
#          - clears reset_in_progress unconditionally (NOT gated on
#            tmf_infly clearing) and calls StorPortResume()
#
# adaptExt->tmf_cmd/tmf_infly/reset_in_progress are adapter-wide, not
# per-LUN. If a *second* LUN's own timeout fires SRB_FUNCTION_RESET_
# LOGICAL_UNIT while the first LUN's TMF response hasn't come back yet,
# DeviceReset() re-enters and reuses tmf_cmd while the device may still
# be acting on the first one -- guarded only by ASSERT(tmf_infly==FALSE),
# which compiles to nothing in a free/retail build. That is a plausible
# mechanism for the PFN_LIST_CORRUPT / PAGE_HASH_ERRORS_INPAGE / CRITICAL_
# PROCESS_DIED bugchecks reported against vioscsi under slow storage
# (kvm-guest-drivers-windows#1014, #877).
#
# The race window is *not* controlled by how long a stalled request is
# held, though: QEMU's virtio-scsi emulation processes the LUN-reset TMF
# by draining that LUN's block node (hw/scsi/virtio-scsi.c, device_cold_
# reset()), and inject-error wakes every held request the instant drain
# begins (block/inject-error.c, inject_error_drain_begin() ->
# inject_delay_wake()) rather than waiting out the injected delay. So a
# single LUN's own TMF round-trip resolves in however long QEMU takes to
# schedule and run that drain -- normally fast. The lever this harness
# pulls is therefore *concurrency*: stall multiple LUNs on the same
# adapter at once, so their independent storport timeouts (and the TMFs
# they trigger) land close enough together, repeated over many trials
# and under host scheduling pressure, to have a chance of overlapping
# vioscsi's brief per-adapter tmf_infly window.
#
# Confirming the theory is cheapest with a *checked* (debug) vioscsi.sys:
# ASSERT is compiled out of the retail driver every real-world reporter
# runs, so on retail the race (if hit) manifests as silent corruption;
# on checked it should bugcheck immediately and attributably the moment
# two resets overlap.
#
# What this harness does
# -----------------------
# Boots the existing golden Windows image from setup-windows-inject-vm.sh
# (unmodified -- this script only *reads* that image, via a throwaway
# overlay), attaches N fresh scratch SCSI LUNs to one virtio-scsi-pci
# adapter, each behind its own inject-error filter node, drives sustained
# raw writes to all N from inside the guest via qemu-guest-agent, then
# arms a 'stall' rule on every LUN's node with a small, swept host-side
# gap between each arm call. It watches for the guest going silent
# (guest-agent stops answering, screen stops changing) as a crash
# signal, and on a suspected crash attempts a win-dmp capture via
# '-device vmcoreinfo' + QMP 'dump-guest-memory' (requires the fwcfg
# driver installed in the guest for a fully symbolized dump; see
# docs/devel/storage-error-injection.rst and kvm-guest-drivers-windows
# issue #877 for that setup).
#
# Prerequisites (see scripts/setup-windows-inject-vm.sh's own usage()):
#   - Golden boot.qcow2 + OVMF_VARS.qcow2 already created and installed
#     ('setup-windows-inject-vm.sh create' then 'install')
#   - qemu-guest-agent installed and running in the golden image
#   - Automatic restart on bugcheck disabled in the golden image, so a
#     BSOD leaves the guest sitting at the blue/black screen instead of
#     silently rebooting into an unmonitored retry
#   - The vioscsi driver installed at least once in the golden image
#     (binds to any virtio-scsi-pci controller subsequently attached,
#     including the throwaway one this script adds -- it doesn't need to
#     be the same disks setup-windows-inject-vm.sh created)
#
# Path portability: this repo's other inject-error scripts hardcode a
# single machine's home directory. This one instead resolves QEMU_SRC
# from its own location on disk (robust regardless of $HOME or where the
# checkout lives) and VM_DIR from $HOME (matching the persistent VM
# state layout setup-windows-inject-vm.sh already uses under $HOME),
# both overridable by environment variable, so the same script runs
# unmodified across different machines.

import argparse
import base64
import dataclasses
import fcntl
import hashlib
import itertools
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

QEMU_SRC = Path(os.environ.get("QEMU_SRC", str(Path(__file__).resolve().parents[1])))
QEMU_BUILD = Path(os.environ.get("QEMU_BUILD", str(QEMU_SRC / "build")))
QEMU_BIN = QEMU_BUILD / "qemu-system-x86_64"
QEMU_IMG = QEMU_BUILD / "qemu-img"

HOME = Path(os.environ.get("HOME", str(Path.home())))
VM_DIR = Path(os.environ.get("VM_DIR", str(HOME / "VirtualMachines" / "qemu" / "windows_inject")))
FUZZ_DIR = VM_DIR / "fuzz-scsi-reset"

BOOT_DISK = VM_DIR / "boot.qcow2"
OVMF_CODE = Path(os.environ.get(
    "OVMF_CODE", "/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2"))
OVMF_VARS = VM_DIR / "OVMF_VARS.qcow2"
TPM_DIR = VM_DIR / "tpm"  # shared, persistent -- same TPM state the golden image was installed with

TRACE_EVENTS = QEMU_SRC / "scripts" / "windows-storage-trace-events"

PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
DEFAULT_DISKSPD_PATH = r"C:\Tools\diskspd.exe"

DEFAULT_RAM = "8G"
DEFAULT_CPUS = "4"
LUN_IMAGE_SIZE = "1G"

BOOT_TIMEOUT_S = 180
GUEST_EXEC_TIMEOUT_S = 30
DEFAULT_SETTLE_S = 2.0  # how long to let I/O run cleanly before arming a stall.
                        # Used both for the initial warmup (so the first arm
                        # catches an in-flight guest write rather than racing
                        # the very first one) and, on multi-cycle runs, as the
                        # gap between a confirmed recovery and re-arming the
                        # next --cycles stall.
# Ceiling on how long we wait, after releasing a stall, for the scsi disks to
# resume completing writes. Recovery is driven by the *guest's* storport reset
# escalation, not by our release: storport times out (~60s), freezes the LUN,
# and only issues its reset -- which is what actually unblocks I/O -- some time
# later, so recovery routinely lands well after release. Give it real room; the
# resume poll returns the instant I/O picks back up, so a large ceiling only
# costs wall-clock on trials that genuinely never recover.
DEFAULT_RECOVERY_TIMEOUT_S = 120
QMP_CMD_TIMEOUT_S = 15
QMP_CONNECT_TIMEOUT_S = 30  # generous: back-to-back trial launches can leave
                            # the host busy enough that a freshly-started
                            # QEMU's QMP monitor isn't ready to accept yet
DUMP_TIMEOUT_S = 900  # a win-dmp writes out all of guest RAM; minutes, not seconds
DUMP_START_TIMEOUT_S = 300  # dump-guest-memory stops the VM (drain + flush of
                            # every image) before detaching, which can outlast
                            # QMP_CMD_TIMEOUT_S on a busy host
DUMP_POLL_INTERVAL_S = 2
STACK_CAPTURE_TIMEOUT_S = 120  # gdb attaching to a large QEMU and loading its
                               # symbols takes a while
POLL_INTERVAL_S = 2
AGENT_SILENCE_THRESHOLD_S = 15  # guest-agent silence this long, post-boot, is
                                 # itself a strong crash signal (its service
                                 # dies with the rest of the guest at a BSOD)
STATIC_SCREEN_THRESHOLD_S = 20  # corroborating signal once agent has gone quiet

# Pre-flight I/O verification. Before arming any stall we sample completed
# write ops across the LUNs over this window and require the writers to be
# driving at least this many per second in total -- otherwise the trial can
# only ever "recover" trivially (nothing in flight to stall), which is exactly
# the silent no-op a broken --io-driver / --diskspd-path produces.
IO_PROBE_WINDOW_S = 3.0
MIN_WRITE_OPS_PER_S = 2.0

# Sequential writes past this offset wrap back to 0. Keeps every write
# sector-aligned and inside the 1G scratch LUN without ever hitting EOF,
# which would otherwise throw partway through a run and end the loop.
WRITER_WINDOW_BYTES = 32 * 1024 * 1024
WRITER_BLOCK_BYTES = 64 * 1024

# The reset race is about *many* commands in flight when a reset lands: the
# vioscsi bug is concurrent TMFs colliding on the adapter's shared
# tmf_cmd/reset_in_progress state. A single outstanding write (the old -t1 -o1)
# lets a stall pin at most ~1 request per LUN, so there is nothing to race.
# Drive a deep queue instead so an armed stall pins dozens of in-flight
# commands per LUN, and storport has a real pile to reset concurrently.
WRITER_THREADS = 4          # diskspd -t: worker threads per target
WRITER_QUEUE_DEPTH = 32     # diskspd -o: outstanding I/Os per thread


def usage_note() -> str:
    return f"""
Prerequisites (one-time, on the golden image):
  1. ./scripts/setup-windows-inject-vm.sh create
     WIN_ISO=/path/to/Win.iso ./scripts/setup-windows-inject-vm.sh install
  2. In the guest: install qemu-guest-agent from the virtio-win ISO, and
     install the vioscsi driver (Device Manager, once the SCSI data disks
     from that script are visible -- it doesn't matter that this harness
     attaches different scratch LUNs; the driver binds to the controller
     class).
  3. Disable automatic restart on bugcheck (elevated PowerShell):
       Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name AutoReboot -Value 0
  4. For symbolized crash dumps (optional but recommended): install the
     fwcfg driver from the virtio-win ISO. See docs/devel/storage-error-
     injection.rst and kvm-guest-drivers-windows issue #877.
  5. For --io-driver=diskspd (optional): copy diskspd.exe into the guest
     at the path given by --diskspd-path (default: {DEFAULT_DISKSPD_PATH}).
  6. Shut down cleanly.

Environment overrides for running on different machines:
  QEMU_SRC, QEMU_BUILD   default to this script's own checkout
  VM_DIR                 default to $HOME/VirtualMachines/qemu/windows_inject
  OVMF_CODE              default to {OVMF_CODE}
"""


# ------------------------------------------------------------------
# QEMU guest agent client (JSON lines over its own virtio-serial socket,
# separate from the main QMP protocol/socket)
# ------------------------------------------------------------------


def qga_call(sock_path: Path, execute: str, arguments: Optional[dict] = None,
             timeout: float = 5.0) -> Optional[dict]:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(sock_path))
            msg: dict = {"execute": execute}
            if arguments is not None:
                msg["arguments"] = arguments
            s.sendall((json.dumps(msg) + "\n").encode())
            buf = b""
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                for line in buf.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        resp = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(resp, dict) and ("return" in resp or "error" in resp):
                        return resp
    except (OSError, ConnectionError):
        return None
    return None


def qga_ping(sock_path: Path, timeout: float = 2.0) -> bool:
    resp = qga_call(sock_path, "guest-ping", timeout=timeout)
    return resp is not None and "return" in resp


def qga_exec(sock_path: Path, path: str, args: list, capture: bool,
             timeout: float = GUEST_EXEC_TIMEOUT_S) -> Optional[int]:
    resp = qga_call(sock_path, "guest-exec",
                     {"path": path, "arg": args, "capture-output": capture},
                     timeout=timeout)
    if resp and "return" in resp:
        return resp["return"].get("pid")
    return None


def qga_exec_wait(sock_path: Path, pid: int, timeout: float) -> Optional[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = qga_call(sock_path, "guest-exec-status", {"pid": pid}, timeout=5.0)
        if resp and "return" in resp and resp["return"].get("exited"):
            return resp["return"]
        time.sleep(0.3)
    return None


def b64_text(data: Optional[str]) -> str:
    if not data:
        return ""
    return base64.b64decode(data).decode("utf-8", errors="replace")


def encode_ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def ps_exec(sock_path: Path, script: str, capture: bool,
            timeout: float = GUEST_EXEC_TIMEOUT_S) -> Optional[int]:
    args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", encode_ps(script)]
    return qga_exec(sock_path, PS_EXE, args, capture=capture, timeout=timeout)


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


def build_writer_script(drive_number: int, duration_s: float) -> str:
    window_blocks = WRITER_WINDOW_BYTES // WRITER_BLOCK_BYTES
    return f"""
$path = "\\\\.\\PhysicalDrive{drive_number}"
$blockSize = {WRITER_BLOCK_BYTES}
$windowBlocks = {window_blocks}
$buf = New-Object byte[] $blockSize
(New-Object Random).NextBytes($buf)
$fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
$i = 0
$deadline = (Get-Date).AddSeconds({duration_s})
try {{
    while ((Get-Date) -lt $deadline) {{
        try {{
            $fs.Seek((($i % $windowBlocks) * $blockSize), [System.IO.SeekOrigin]::Begin) | Out-Null
            $fs.Write($buf, 0, $buf.Length)
            $fs.Flush()
            $i++
        }} catch {{
            Start-Sleep -Milliseconds 200
        }}
    }}
}} finally {{
    $fs.Close()
}}
"""


def build_diskspd_args(drive_number: int, duration_s: float) -> list:
    # Target a physical drive with diskspd's '#N' syntax, NOT the raw
    # \\.\PhysicalDriveN path: diskspd treats the latter as an ordinary file
    # path, so it fails before doing any I/O -- with '-c' it tries to *create*
    # that file ("Could not create the file (error code: 87)"), and without it
    # it tries to size a nonexistent file ("Error getting file size"). '#N'
    # (N = the PhysicalDrive number) is how diskspd names a raw drive.
    #
    # Also note: no '-c' -- that sizes/creates a *file*; a physical drive
    # already has a fixed extent, so diskspd just writes across it (wrapping
    # for the duration) with no size argument needed.
    return [
        f"-d{int(round(duration_s))}",
        "-w100",            # 100% writes
        f"-b{WRITER_BLOCK_BYTES}",
        "-s",                # sequential per-thread
        f"-t{WRITER_THREADS}",   # deep queue: many concurrent in-flight writes
        f"-o{WRITER_QUEUE_DEPTH}",  # so an armed stall has a real pile to reset
        "-Sh",                # disable software caching and hardware write
                              # caching, so writes are actually flushed like the
                              # PowerShell writer's explicit Flush()
        f"#{drive_number}",
    ]


def resolve_drive_numbers(qga_sock: Path, serials: list) -> dict:
    pid = ps_exec(qga_sock, build_resolve_script(serials), capture=True)
    if pid is None:
        raise RuntimeError("guest-exec (resolve disk numbers) failed to launch")
    status = qga_exec_wait(qga_sock, pid, timeout=GUEST_EXEC_TIMEOUT_S)
    if status is None:
        raise RuntimeError("guest-exec (resolve disk numbers) timed out")
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


def launch_writer(qga_sock: Path, drive_number: int, duration_s: float,
                   io_driver: str = "powershell",
                   diskspd_path: str = DEFAULT_DISKSPD_PATH) -> int:
    if io_driver == "diskspd":
        pid = qga_exec(qga_sock, diskspd_path,
                        build_diskspd_args(drive_number, duration_s),
                        capture=False)
    else:
        pid = ps_exec(qga_sock, build_writer_script(drive_number, duration_s), capture=False)
    if pid is None:
        raise RuntimeError(f"guest-exec (writer for PhysicalDrive{drive_number}) failed to launch")
    return pid


def diskspd_diagnostic(qga_sock: Path, diskspd_path: str, drive_number: int) -> str:
    """Run diskspd briefly with output captured, to surface *why* it drove no
    I/O -- e.g. a bad --diskspd-path, '-c' rejected on a raw physical drive, or
    access denied. Only called on the no-io abort path, where the real writers
    aren't producing I/O anyway, so a short extra run can't perturb a live test."""
    pid = qga_exec(qga_sock, diskspd_path, build_diskspd_args(drive_number, 1),
                   capture=True, timeout=GUEST_EXEC_TIMEOUT_S)
    if pid is None:
        return (f"diskspd failed to even launch at {diskspd_path!r} "
                f"(guest-exec returned no pid -- path wrong or not present?)")
    status = qga_exec_wait(qga_sock, pid, timeout=GUEST_EXEC_TIMEOUT_S)
    if status is None:
        return "diskspd diagnostic run timed out"
    out = b64_text(status.get("out-data")).strip()
    err = b64_text(status.get("err-data")).strip()
    return (f"diskspd exitcode={status.get('exitcode')}; "
            f"stdout={out[:400]!r}; stderr={err[:400]!r}")


# ------------------------------------------------------------------
# QEMU process / QMP plumbing
# ------------------------------------------------------------------


@dataclasses.dataclass
class LunSpec:
    index: int
    image: Path
    file_node: str
    fmt_node: str
    err_node: str
    dev_id: str
    serial: str


def make_blank_image(path: Path, size: str = LUN_IMAGE_SIZE) -> None:
    subprocess.run([str(QEMU_IMG), "create", "-f", "qcow2", str(path), size],
                   check=True, capture_output=True)


def make_overlay(golden: Path, dest: Path) -> None:
    subprocess.run([str(QEMU_IMG), "create", "-f", "qcow2", "-F", "qcow2",
                    "-b", str(golden), str(dest)],
                   check=True, capture_output=True)


def other_swtpm_pids(exclude_pid: int) -> list:
    try:
        out = subprocess.run(["pgrep", "-f", "swtpm socket"],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return []
    exclude = str(exclude_pid)
    return [pid for pid in out.stdout.split() if pid != exclude]


def check_tpm_dir_lockable() -> None:
    # TPM_DIR is shared and persistent, matching the golden image's real TPM
    # state. swtpm takes swtpm's exclusive '.lock' on that directory -- but it
    # does so *lazily*, only when QEMU sends CMD_INIT, not at startup. So a
    # second swtpm sharing this dir (e.g. an interactive
    # setup-windows-inject-vm.sh 'run' session, or an orphaned process from a
    # prior run) starts up and creates its own control socket perfectly
    # happily; the lock conflict only surfaces later as swtpm failing CMD_INIT
    # ("Could not lock access to lockfile") and QEMU dying with an opaque
    # "TPM result for CMD_INIT: 0x9 operation failed". Waiting for the control
    # socket to appear therefore proves nothing about the lock.
    #
    # Detect the contention up front instead: try to grab the same flock
    # non-blocking, then immediately drop it so swtpm can take it. There's a
    # tiny TOCTOU window between here and swtpm's own lock, but a shared
    # persistent TPM dir has no legitimate concurrent user anyway, so catching
    # the common "another VM is already running against this dir" case with a
    # clear message is well worth it.
    TPM_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = TPM_DIR / ".lock"
    try:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o640)
    except OSError:
        return  # can't pre-check (permissions); let swtpm report it instead
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holders = other_swtpm_pids(os.getpid())
            raise RuntimeError(
                f"the shared TPM state dir {TPM_DIR} is already locked by "
                f"another process -- swtpm here would fail CMD_INIT and QEMU "
                f"would die with 'TPM result for CMD_INIT: 0x9'. This is "
                f"almost always another VM sharing this dir (a running "
                f"setup-windows-inject-vm.sh session, or an orphaned swtpm). "
                f"swtpm process(es) currently running: "
                f"{holders if holders else 'none visible via pgrep'}. Shut "
                f"that VM down (or kill the stray swtpm) and retry.")
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def start_swtpm(tpm_sock: Path) -> subprocess.Popen:
    # A fresh swtpm process is required per VM launch (its unixio ctrl
    # channel doesn't survive a reconnect), but TPM_DIR itself is shared and
    # persistent. Confirm nothing else already holds the state-dir lock before
    # launching, since swtpm won't reveal that conflict until QEMU's CMD_INIT
    # (see check_tpm_dir_lockable). If swtpm instead blocks trying to *create*
    # its control socket, the timeout loop below still catches that.
    check_tpm_dir_lockable()
    TPM_DIR.mkdir(parents=True, exist_ok=True)
    if tpm_sock.exists():
        tpm_sock.unlink()
    log_path = tpm_sock.parent / "swtpm-startup.log"
    log_file = log_path.open("wb")
    proc = subprocess.Popen([
        "swtpm", "socket",
        "--tpmstate", f"dir={TPM_DIR}",
        "--ctrl", f"type=unixio,path={tpm_sock}",
        "--tpm2",
    ], stdout=log_file, stderr=subprocess.STDOUT)
    log_file.close()
    for _ in range(50):
        if tpm_sock.exists():
            return proc
        exit_code = proc.poll()
        if exit_code is not None:
            output = log_path.read_text(errors="replace").strip()
            raise RuntimeError(
                f"swtpm exited immediately (code {exit_code}) instead of "
                f"creating its control socket. swtpm output:\n{output}")
        time.sleep(0.1)
    proc.kill()
    other_swtpm = other_swtpm_pids(proc.pid)
    hint = (f" -- other swtpm process(es) currently running: {other_swtpm}; "
            f"one of them likely already holds the exclusive lock on "
            f"{TPM_DIR} (check for a leftover interactive "
            f"setup-windows-inject-vm.sh session or an orphaned swtpm from "
            f"a prior run, and kill it)" if other_swtpm else
            f" -- no other swtpm process is currently visible, so this "
            f"isn't the usual {TPM_DIR} lock contention; check the swtpm "
            f"install and permissions on that directory")
    raise RuntimeError(
        f"swtpm did not create its control socket within 5s -- it likely "
        f"blocked silently trying to lock {TPM_DIR} rather than erroring "
        f"out{hint}")


def build_qemu_argv(boot_overlay: Path, vars_overlay: Path, qmp_sock: Path,
                     qga_sock: Path, serial_log: Path, tpm_sock: Path,
                     trace_path: Optional[Path], lun_specs: list, seed: int,
                     ram: str, cpus: str, taskset_cores: Optional[str],
                     tmf_delay_ms: int = 0, tmf_delay_count: int = 0) -> list:
    argv: list = []
    if taskset_cores:
        argv += ["taskset", "-c", taskset_cores]

    argv += [
        str(QEMU_BIN),
        "-machine", "q35,accel=kvm,smm=on",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-cpu", "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,"
                "hv-synic,hv-stimer,hv-time,hv-ipi,hv-tlbflush",
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
        "-serial", f"file:{serial_log}",
        "-chardev", f"socket,path={qga_sock},server=on,wait=off,id=qga0",
        "-device", "virtio-serial",
        "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        # Boot disk stays a plain inject-error passthrough -- no rules are
        # ever armed on it. This harness targets the SCSI data LUNs only.
        "-blockdev", f"driver=file,filename={boot_overlay},node-name=file0",
        "-blockdev", "driver=qcow2,file=file0,node-name=raw0",
        "-blockdev", "driver=inject-error,image=raw0,node-name=err0",
        "-device", "virtio-blk-pci,drive=err0,bootindex=0,id=disk0",
        "-device", (f"virtio-scsi-pci,id=scsi0"
                    + (f",x-tmf-delay-ms={tmf_delay_ms},"
                       f"x-tmf-delay-count={tmf_delay_count}"
                       if tmf_delay_ms and tmf_delay_count else "")),
    ]

    if trace_path is not None:
        argv += ["-trace", f"events={TRACE_EVENTS},file={trace_path}"]

    for spec in lun_specs:
        argv += [
            "-blockdev", f"driver=file,filename={spec.image},node-name={spec.file_node}",
            "-blockdev", f"driver=qcow2,file={spec.file_node},node-name={spec.fmt_node}",
            "-blockdev", f"driver=inject-error,image={spec.fmt_node},"
                          f"node-name={spec.err_node},seed={seed}",
            "-device", f"scsi-hd,drive={spec.err_node},bus=scsi0.0,"
                       f"id={spec.dev_id},serial={spec.serial}",
        ]

    return argv


# The legacy QMP client sends commands without an "id" unless we supply
# one, and routes every ID-less reply to whichever ID-less command is
# currently pending. After a single timeout the late reply would then be
# handed to the *next* command, desynchronizing every reply after it for
# the rest of the run. Unique IDs make late replies unroutable, so the
# client drops them instead.
_qmp_ids = itertools.count()


def qmp_call(qmp, name: str, **kwargs) -> Any:
    args = {k.replace("_", "-"): v for k, v in kwargs.items()}
    msg = {"execute": name, "id": f"fuzz-{next(_qmp_ids)}"}
    if args:
        msg["arguments"] = args
    resp = qmp.cmd_obj(msg)
    if "error" in resp:
        raise RuntimeError(f"{name}: {resp['error']}")
    return resp.get("return")


def screendump_hash(qmp, path: Path) -> Optional[str]:
    try:
        qmp_call(qmp, "screendump", filename=str(path))
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def capture_qemu_stacks(pid: int, out: Path) -> None:
    """Record where every QEMU thread is, for a dump that has wedged.

    The per-thread kernel state and wait channel show I/O sleeps (state D),
    and a gdb backtrace shows what the main loop is stuck on. Best effort:
    a missing gdb or a refused ptrace still leaves the /proc part.
    """
    lines = []
    for task in sorted(Path(f"/proc/{pid}/task").glob("*"),
                       key=lambda t: int(t.name)):
        try:
            comm = (task / "comm").read_text().strip()
            state = (task / "stat").read_text().rsplit(")", 1)[1].split()[0]
            wchan = (task / "wchan").read_text().strip()
        except OSError:
            continue
        lines.append(f"tid={task.name} comm={comm} state={state} wchan={wchan}")
    text = "\n".join(lines) + "\n\n"

    if shutil.which("gdb"):
        # Keep gdb from stalling on debuginfod downloads mid-capture.
        env = dict(os.environ, DEBUGINFOD_URLS="")
        try:
            r = subprocess.run(
                ["gdb", "-batch", "-nx", "-p", str(pid),
                 "-ex", "set pagination off",
                 "-ex", "thread apply all bt"],
                capture_output=True, text=True, env=env,
                timeout=STACK_CAPTURE_TIMEOUT_S)
            text += r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            text += f"gdb timed out after {STACK_CAPTURE_TIMEOUT_S}s\n"
    else:
        text += "gdb not installed; no userspace backtrace\n"

    out.write_text(text)
    print(f"    QEMU thread stacks saved to {out}", file=sys.stderr)


def try_dump_guest_memory(qmp, path: Path, qemu_pid: int,
                          err_nodes: list) -> bool:
    # Disarm any stall rule still installed (the crash-suspected path dumps
    # mid-stall). Stopping the VM drains, which wakes held requests, but the
    # flush that follows the drain goes through inject-error like any other
    # request: a still-armed rule holds it forever and the dump never starts.
    # Remove without releasing, so held requests complete only once the
    # drain runs, with the vCPUs already paused.
    for node in err_nodes:
        try:
            qmp_call(qmp, "x-inject-error-delay-remove", node_name=node, id=node)
        except RuntimeError:
            pass  # already removed after the cycle's release

    # A stale dump from a prior run reusing this run dir can be left
    # read-only (observed mode 0400), which makes QEMU's open() for the
    # new dump fail with EACCES even though we own the file.
    path.unlink(missing_ok=True)

    # Detached, so QEMU writes the dump from its own thread and the monitor
    # stays responsive. A synchronous dump blocks the main loop for the whole
    # write, and if that outlasts the QMP timeout the subsequent 'quit' times
    # out too and the QEMU process gets killed mid-dump.
    #
    # Even detached, the command stops the VM before returning, and stopping
    # drains and flushes every image on the main loop. Give that its own
    # longer timeout, and treat a timeout as "outcome unknown" rather than a
    # refusal: QEMU may well go on to start the dump, and returning here would
    # send 'quit' into the middle of it. query-dump is queued behind the
    # dump command, so its first answer tells us which way it went.
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
            # Main loop still busy (the VM stop, or the dump command itself).
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
# Telemetry: is the test actually driving I/O, stalling it, and recovering?
# ------------------------------------------------------------------


def write_ops_by_node(qmp) -> dict:
    """identifier -> cumulative completed write operations.

    Block I/O accounting lives on the *BlockBackend* (the guest device), not on
    the per-node view: query-blockstats with query-nodes=True reports the graph's
    nodes but their wr_operations stay 0 for guest traffic, so keying on
    node-name alone reads zero even while writes flow. We merge both views and
    key each entry under every identifier it exposes ('device', 'qdev', and
    'node-name'), so a caller can look a LUN up by its scsi-hd id or by any of
    its block nodes and get the real count."""
    out: dict = {}
    for query_nodes in (False, True):
        try:
            stats = qmp_call(qmp, "query-blockstats",
                             query_nodes=query_nodes) or []
        except Exception:
            continue
        for entry in stats:
            wr = entry.get("stats", {}).get("wr_operations", 0)
            for key in ("device", "qdev", "node-name"):
                ident = entry.get(key)
                if ident:
                    out[ident] = max(out.get(ident, 0), wr)
    return out


def lun_write_delta(before: dict, after: dict, spec: "LunSpec") -> int:
    """Completed writes seen on a LUN over an interval. Take the max across every
    identifier the LUN is known by -- its scsi-hd device id (where guest write
    accounting actually lands) and its err/fmt/file nodes -- since which of these
    carries a nonzero wr_operations depends on the block-graph view."""
    return max(after.get(k, 0) - before.get(k, 0)
               for k in (spec.dev_id, spec.err_node, spec.fmt_node,
                         spec.file_node))


def wait_for_io_resume(qmp, lun_specs: list, deadline: float,
                       sample_s: float = 1.0,
                       min_ops_per_s: float = MIN_WRITE_OPS_PER_S):
    """Poll the block write counters until guest SCSI writes actually resume.

    This is the real recovery signal: after we release a stall, the interesting
    question is whether the *virtio-scsi disks* start completing writes again --
    not whether the guest agent responds. (qga rides virtio-serial and is
    unaffected by a scsi stall, so its liveness says nothing about disk
    recovery; that was the old, misleading measure.)

    Returns (resumed, seconds_to_resume | None, observed_ops_per_s)."""
    start = time.monotonic()
    prev = write_ops_by_node(qmp)
    while time.monotonic() < deadline:
        time.sleep(sample_s)
        cur = write_ops_by_node(qmp)
        wps = sum(lun_write_delta(prev, cur, s) for s in lun_specs) / sample_s
        if wps >= min_ops_per_s:
            return True, round(time.monotonic() - start, 1), round(wps, 1)
        prev = cur
    return False, None, 0.0


# virtio-scsi task-management function subtypes (see VIRTIO_SCSI_T_TMF_* in the
# virtio spec / include/standard-headers/linux/virtio_scsi.h).
TMF_SUBTYPE_NAMES = {
    0: "abort-task", 1: "abort-task-set", 2: "clear-aca",
    3: "clear-task-set", 4: "i-t-nexus-reset", 5: "lun-reset",
    6: "query-task", 7: "query-task-set",
}
# 'target=' is present only with the patched virtio-scsi tmf tracepoints; fall
# back to the LUN field for traces from an unpatched QEMU. Note the LUN-within-
# target is always 0 here (one LUN per target), so without 'target=' the resets
# cannot be told apart -- which is exactly why the tracepoint was extended.
_TMF_REQ_RE = re.compile(
    r"virtio_scsi_tmf_req (?:target=(\d+) )?lun=(\d+) tag=(0x[0-9a-f]+).*subtype=(\d+)")
_TMF_DELAY_RE = re.compile(
    r"virtio_scsi_tmf_delay target=(\d+) lun=(\d+) tag=(0x[0-9a-f]+) delay_ms=(\d+)")
_TMF_RESP_RE = re.compile(
    r"virtio_scsi_tmf_resp (?:target=(\d+) )?lun=(\d+) tag=(0x[0-9a-f]+).*response=(\d+)")


def scan_reset_events(trace_path: Optional[Path]) -> Optional[dict]:
    """Scan the trace for virtio-scsi task-management (reset) activity.

    Records, as a positive fact in the result, whether the guest actually issued
    the resets we are trying to race -- and which LUNs reset -- instead of
    leaving that to be grepped out of a multi-hundred-MB trace after the fact.
    The whole-trace scan is cheap: we skip the regex on any line without the
    'virtio_scsi_tmf' marker.

    Also answers the question the x-tmf-delay-* knob exists to ask: with one
    TMF response held open (see --tmf-delay-ms/--tmf-delay-count), does
    storport ever re-enter with a *second* TMF for the same target on its own,
    before the first one's response is released? That would mean its reset
    escalation path re-enters DeviceReset() off real storport timeouts, not
    just because we forced a second reset -- i.e. the race is naturally
    reachable, not a lab artifact requiring us to supply both resets.

    Returns a summary dict, or None if no trace is available."""
    if trace_path is None or not trace_path.exists():
        return None
    by_target: dict = {}
    resps_by_code: dict = {}
    total_reqs = 0
    held_tags_by_target: dict = {}  # target -> set of tags currently delayed
    escalations: list = []  # requests that arrived while another TMF on the
                            # same target was still being held
    try:
        with trace_path.open("r", errors="replace") as f:
            for line in f:
                if "virtio_scsi_tmf" not in line:
                    continue
                m = _TMF_REQ_RE.search(line)
                if m:
                    total_reqs += 1
                    target_s, lun_s, tag, subtype_s = m.groups()
                    subtype = int(subtype_s)
                    name = TMF_SUBTYPE_NAMES.get(subtype, f"subtype{subtype}")
                    # Prefer the target id (distinguishes the disks); fall back
                    # to the always-0 LUN field for unpatched traces.
                    where = f"target{target_s}" if target_s is not None else f"lun{lun_s}"
                    key = f"{where}/{name}"
                    by_target[key] = by_target.get(key, 0) + 1
                    held = held_tags_by_target.get(target_s) if target_s is not None else None
                    if held:
                        escalations.append({"target": target_s, "tag": tag,
                                            "subtype": name,
                                            "held_tags": sorted(held)})
                    continue
                m = _TMF_DELAY_RE.search(line)
                if m:
                    target_s, _lun_s, tag, _delay_ms = m.groups()
                    held_tags_by_target.setdefault(target_s, set()).add(tag)
                    continue
                m = _TMF_RESP_RE.search(line)
                if m:
                    target_s, _lun_s, tag, response = m.groups()
                    resps_by_code[response] = resps_by_code.get(response, 0) + 1
                    if target_s is not None:
                        held_tags_by_target.get(target_s, set()).discard(tag)
    except OSError:
        return None
    return {"tmf_reqs": total_reqs, "by_target": by_target,
            "resps_by_code": resps_by_code,
            "escalations_during_delay": escalations}


def held_counts(qmp, err_nodes: list) -> dict:
    """err-node -> number of requests the node is currently holding (stalled)."""
    out: dict = {}
    for n in err_nodes:
        try:
            held = qmp_call(qmp, "x-inject-error-delay-inflight", node_name=n) or []
            out[n] = len(held)
        except Exception:
            out[n] = 0
    return out


def rule_hits(qmp, err_nodes: list) -> dict:
    """err-node -> cumulative requests the node's rule(s) have delayed so far."""
    out: dict = {}
    for n in err_nodes:
        try:
            rules = qmp_call(qmp, "x-inject-error-delay-list", node_name=n) or []
            out[n] = sum(r.get("hits", 0) for r in rules)
        except Exception:
            out[n] = 0
    return out


def writer_states(qga_sock: Path, pids: list) -> list:
    """Per-writer {pid, exited, exitcode} from the guest agent, so a writer that
    failed to launch (bad path) or died immediately is visible rather than
    silently assumed to be running."""
    states = []
    for pid in pids:
        resp = qga_call(qga_sock, "guest-exec-status", {"pid": pid}, timeout=5.0)
        ret = resp.get("return", {}) if resp and "return" in resp else {}
        states.append({"pid": pid, "exited": ret.get("exited"),
                       "exitcode": ret.get("exitcode")})
    return states


# ------------------------------------------------------------------
# Grid definitions
# ------------------------------------------------------------------


@dataclasses.dataclass
class ResetRaceCase:
    label: str
    arm_gap_ms: float
    mode: str  # "stall" | "delay"
    delay_ms: int = 0
    delay_max_ms: int = 0
    seed: int = 1


def gen_cases(gaps_ms: list, mode: str, delay_ms: int, delay_max_ms: int,
              repeat: int, seed_base: int) -> list:
    cases = []
    for gap in gaps_ms:
        for r in range(repeat):
            seed = seed_base + len(cases)
            label = f"mode={mode},gap-ms={gap},rep={r}"
            cases.append(ResetRaceCase(label, gap, mode, delay_ms, delay_max_ms, seed))
    return cases


def rule_for(tc: ResetRaceCase, lun_id: str) -> dict:
    rule = {"id": lun_id}
    if tc.mode == "stall":
        rule["stall"] = True
    else:
        rule["delay-ms"] = tc.delay_ms
        if tc.delay_max_ms:
            rule["delay-max-ms"] = tc.delay_max_ms
    return rule


# ------------------------------------------------------------------
# Harness
# ------------------------------------------------------------------


def run_case(tc: ResetRaceCase, run_id: int, luns: int, run_timeout_s: int,
             ram: str, cpus: str, taskset_cores: Optional[str],
             keep_all: bool, qmp_module, cycles: int = 1,
             inter_cycle_settle_s: float = DEFAULT_SETTLE_S,
             io_driver: str = "powershell",
             diskspd_path: str = DEFAULT_DISKSPD_PATH,
             recovery_timeout_s: float = DEFAULT_RECOVERY_TIMEOUT_S,
             tmf_delay_ms: int = 0, tmf_delay_count: int = 0) -> dict:
    run_dir = FUZZ_DIR / f"run-{run_id:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)

    boot_overlay = run_dir / "boot.qcow2"
    vars_overlay = run_dir / "vars.qcow2"
    qmp_sock = run_dir / "qmp.sock"
    qga_sock = run_dir / "qga.sock"
    tpm_sock = run_dir / "swtpm.sock"
    serial_log = run_dir / "serial.log"
    screenshot = run_dir / "screen.ppm"
    trace_path = run_dir / "trace.log" if TRACE_EVENTS.exists() else None
    dump_path = run_dir / "crash.dmp"

    qemu_log_path = run_dir / "qemu.log"
    qmp = None
    proc = None
    swtpm = None
    lun_specs: list = []
    result: dict = {"label": tc.label, "outcome": "error", "elapsed_s": 0.0,
                     "run_dir": str(run_dir), "arm_times_s": []}
    start = time.monotonic()

    try:
        make_overlay(BOOT_DISK, boot_overlay)
        make_overlay(OVMF_VARS, vars_overlay)

        for i in range(luns):
            img = run_dir / f"lun{i}.qcow2"
            make_blank_image(img)
            lun_specs.append(LunSpec(
                index=i, image=img, file_node=f"lfile{i}", fmt_node=f"lraw{i}",
                err_node=f"lerr{i}", dev_id=f"lun{i}", serial=f"RRLUN{i}"))

        # Budget the writers to comfortably outlast every cycle -- including the
        # initial warmup, both I/O probe windows per cycle, and all inter-cycle
        # settles. Under-budgeting silently lets the writers exit before the
        # last cycles, so those cycles would arm a stall with nothing in flight
        # (a silent no-op the once-only pre-flight probe wouldn't catch).
        # Over-budgeting is harmless: QEMU is quit at end of trial regardless.
        per_cycle_s = (run_timeout_s + recovery_timeout_s + IO_PROBE_WINDOW_S
                       + inter_cycle_settle_s)
        writer_duration = (inter_cycle_settle_s + IO_PROBE_WINDOW_S
                           + per_cycle_s * cycles + 120)

        argv = build_qemu_argv(boot_overlay, vars_overlay, qmp_sock, qga_sock,
                                serial_log, tpm_sock, trace_path, lun_specs,
                                tc.seed, ram, cpus, taskset_cores,
                                tmf_delay_ms, tmf_delay_count)

        meta = {"label": tc.label, "mode": tc.mode, "arm_gap_ms": tc.arm_gap_ms,
                "delay_ms": tc.delay_ms, "delay_max_ms": tc.delay_max_ms,
                "luns": luns, "seed": tc.seed, "argv": argv}
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))

        swtpm = start_swtpm(tpm_sock)
        with qemu_log_path.open("wb") as qemu_log:
            proc = subprocess.Popen(argv, stdout=qemu_log, stderr=subprocess.STDOUT)

        def qemu_died_error(context: str) -> RuntimeError:
            output = qemu_log_path.read_text(errors="replace").strip()
            swtpm_log_path = run_dir / "swtpm-startup.log"
            swtpm_output = (swtpm_log_path.read_text(errors="replace").strip()
                            if swtpm_log_path.exists() else "")
            msg = (
                f"QEMU exited early (code {proc.returncode}) {context} -- a "
                f"common cause is another swtpm process (e.g. a leftover "
                f"interactive setup-windows-inject-vm.sh session, or an "
                f"orphan from a prior run) already holding the shared TPM "
                f"state in {TPM_DIR}. QEMU output:\n{output}")
            if swtpm_output:
                msg += f"\nswtpm output:\n{swtpm_output}"
            return RuntimeError(msg)

        qmp_connect_deadline = time.monotonic() + QMP_CONNECT_TIMEOUT_S
        qmp = qmp_module.QEMUMonitorProtocol(str(qmp_sock))
        connected = False
        last_connect_exc: Optional[Exception] = None
        while time.monotonic() < qmp_connect_deadline:
            if proc.poll() is not None:
                raise qemu_died_error("before the QMP connection succeeded")
            if not qmp_sock.exists():
                time.sleep(0.1)
                continue
            try:
                qmp.connect()
                connected = True
                break
            except Exception as exc:
                # QEUMonitorProtocol.connect() wraps the real cause (e.g. a
                # raw ConnectionRefusedError) in its own qemu.qmp ConnectError
                # rather than raising it directly, so unwrap via '.exc' (if
                # present) before deciding whether this is worth retrying.
                # Under back-to-back trial launches the host can be busy
                # enough that a freshly-listening QMP socket isn't actually
                # ready to accept yet -- retry instead of failing on the
                # first attempt, rather than mistaking host load for a real
                # QEMU crash. Anything that isn't a plain OSError (e.g. a
                # genuine protocol/negotiation error) is not a timing issue
                # and should fail immediately instead of being retried.
                root_cause = getattr(exc, "exc", exc)
                if not isinstance(root_cause, OSError):
                    raise
                last_connect_exc = exc
                time.sleep(0.2)
        if not connected:
            if proc.poll() is not None:
                raise qemu_died_error("right after opening the QMP socket")
            raise RuntimeError(
                f"could not connect to QMP within {QMP_CONNECT_TIMEOUT_S}s "
                f"(host may be overloaded from back-to-back trial launches)"
                + (f": {last_connect_exc}" if last_connect_exc else
                   " -- QMP socket never appeared"))
        qmp.settimeout(QMP_CMD_TIMEOUT_S)

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

        serials = [s.serial for s in lun_specs]
        drive_numbers = resolve_drive_numbers(qga_sock, serials)
        result["drive_numbers"] = drive_numbers

        writer_pids = []
        for spec in lun_specs:
            drive_no = drive_numbers[spec.serial]
            writer_pids.append(launch_writer(qga_sock, drive_no, writer_duration,
                                              io_driver, diskspd_path))
        result["writer_pids"] = writer_pids

        time.sleep(inter_cycle_settle_s)  # initial warmup, same knob as the
                                          # between-cycles settle below

        # Pre-flight: confirm the writers are actually driving I/O to the LUNs
        # before we stall anything. Without this, a broken --io-driver / bad
        # --diskspd-path yields trials that "recover" every time simply because
        # there was never any in-flight I/O to stall -- the test silently
        # exercises nothing. Fail loudly instead.
        err_nodes = [s.err_node for s in lun_specs]
        w_before = write_ops_by_node(qmp)
        time.sleep(IO_PROBE_WINDOW_S)
        w_after = write_ops_by_node(qmp)
        wps_per_lun = {s.serial: lun_write_delta(w_before, w_after, s) / IO_PROBE_WINDOW_S
                       for s in lun_specs}
        total_wps = sum(wps_per_lun.values())
        result["writer_states"] = writer_states(qga_sock, writer_pids)
        result["pre_arm_write_ops_per_s"] = wps_per_lun
        result["pre_arm_write_ops_per_s_total"] = round(total_wps, 1)
        if total_wps < MIN_WRITE_OPS_PER_S:
            result["outcome"] = "no-io"
            result["elapsed_s"] = time.monotonic() - start
            diag = ""
            if io_driver == "diskspd":
                # Turn "no I/O, unknown why" into diskspd's own error text.
                result["diskspd_diagnostic"] = diskspd_diagnostic(
                    qga_sock, diskspd_path, drive_numbers[lun_specs[0].serial])
                diag = f" diskspd diagnostic: {result['diskspd_diagnostic']}"
            result["error"] = (
                f"writers are not driving I/O: only {total_wps:.1f} write ops/s "
                f"across all {luns} LUN(s) (need >= {MIN_WRITE_OPS_PER_S}). "
                f"Nothing would be in flight to stall, so this trial would "
                f"'recover' without exercising the reset path. Check "
                f"--io-driver / --diskspd-path; writer states: "
                f"{result['writer_states']}.{diag}")
            return result

        result["cycles_completed"] = 0
        result["cycle_telemetry"] = []
        recovered = False

        for cycle in range(cycles):
            arm_start = time.monotonic()
            for spec in lun_specs:
                qmp_call(qmp, "x-inject-error-delay-add", node_name=spec.err_node,
                         rule=rule_for(tc, spec.err_node))
                result["arm_times_s"].append(time.monotonic() - arm_start)
                if tc.arm_gap_ms:
                    time.sleep(tc.arm_gap_ms / 1000.0)

            cyc: dict = {"cycle": cycle, "held_peak_per_node": {n: 0 for n in err_nodes}}
            agent_alive = True
            agent_lost_t: Optional[float] = None
            last_hash = None
            last_change_t = time.monotonic()
            monitor_deadline = time.monotonic() + run_timeout_s

            while time.monotonic() < monitor_deadline:
                now = time.monotonic()
                elapsed = now - start

                # QEMU itself dying (e.g. an assert in the virtio-scsi reset
                # path) also silences the agent and screen; don't mistake it
                # for a guest crash and try to dump a process that's gone.
                if proc.poll() is not None:
                    result["cycle_telemetry"].append(cyc)
                    result["outcome"] = "qemu-exited"
                    result["qemu_returncode"] = proc.returncode
                    result["elapsed_s"] = elapsed
                    result["crash_cycle"] = cycle
                    return result

                # Telemetry: track the peak number of requests actually held by
                # the stall, per node. A stall that never holds anything (peak 0)
                # means the guest wasn't blocked -- the race can't fire.
                for n, c in held_counts(qmp, err_nodes).items():
                    if c > cyc["held_peak_per_node"][n]:
                        cyc["held_peak_per_node"][n] = c

                if qga_ping(qga_sock):
                    agent_alive = True
                    agent_lost_t = None
                else:
                    if agent_alive:
                        agent_lost_t = now
                    agent_alive = False

                h = screendump_hash(qmp, screenshot)
                if h is not None:
                    if h != last_hash:
                        last_hash = h
                        last_change_t = now

                if (not agent_alive and agent_lost_t is not None
                        and now - agent_lost_t > AGENT_SILENCE_THRESHOLD_S
                        and now - last_change_t > STATIC_SCREEN_THRESHOLD_S):
                    cyc["hits_per_node"] = rule_hits(qmp, err_nodes)
                    result["cycle_telemetry"].append(cyc)
                    result["outcome"] = "crash-suspected"
                    result["elapsed_s"] = elapsed
                    result["crash_cycle"] = cycle
                    result["dump_ok"] = try_dump_guest_memory(
                        qmp, dump_path, proc.pid, err_nodes)
                    return result

                time.sleep(POLL_INTERVAL_S)

            # Capture cumulative hits before releasing/removing the rule.
            cyc["hits_per_node"] = rule_hits(qmp, err_nodes)

            for spec in lun_specs:
                try:
                    qmp_call(qmp, "x-inject-error-delay-release", node_name=spec.err_node,
                             disposition="complete")
                except Exception as exc:
                    print(f"    release on {spec.err_node} failed: {exc}", file=sys.stderr)
                # release only completes the requests currently *held*; the
                # named rule itself stays installed. Remove it too, so (a) the
                # writers' new I/O during recovery/settle isn't immediately
                # re-stalled by the still-armed rule, and (b) the next cycle's
                # re-arm doesn't fail with "a delay rule ... already exists".
                # Order matters: release first (wakes held requests), then
                # remove (delay-remove leaves already-held requests untouched).
                try:
                    qmp_call(qmp, "x-inject-error-delay-remove", node_name=spec.err_node,
                             id=spec.err_node)
                except Exception as exc:
                    print(f"    remove on {spec.err_node} failed: {exc}", file=sys.stderr)

            # Recovery = the virtio-scsi disks actually resume completing writes,
            # not the guest agent responding. Poll the write counters until I/O
            # picks back up (or the recovery window expires). The window must be
            # generous: recovery is driven by the guest's storport reset, which
            # can land well after our release (see DEFAULT_RECOVERY_TIMEOUT_S).
            release_t = time.monotonic()
            recovered, cyc["recovery_s"], resume_wps = wait_for_io_resume(
                qmp, lun_specs, release_t + recovery_timeout_s)
            cyc["post_release_write_ops_per_s"] = resume_wps
            # Coarse "is the guest even alive" signal, recorded alongside but not
            # used to define recovery: lets us tell "disks wedged but guest up"
            # apart from "guest gone".
            cyc["agent_alive_post_release"] = qga_ping(qga_sock)
            result["cycle_telemetry"].append(cyc)

            if not recovered:
                # I/O didn't come back within the grace window -- stop cycling
                # rather than re-arming stalls on top of disks that never
                # recovered from the last one.
                break

            result["cycles_completed"] = cycle + 1
            if cycle < cycles - 1:
                # Let a few writes actually land before the next cycle's stall,
                # so each cycle really starts from "I/O working" rather than
                # re-arming on top of requests still recovering from the last one.
                time.sleep(inter_cycle_settle_s)

        if proc.poll() is not None:
            result["outcome"] = "qemu-exited"
            result["qemu_returncode"] = proc.returncode
            result["elapsed_s"] = time.monotonic() - start
            return result
        if recovered:
            result["outcome"] = "recovered"
        elif qga_ping(qga_sock):
            # Guest is up but its scsi disks never resumed I/O after release --
            # the disks are wedged, which is itself an interesting failure.
            result["outcome"] = "io-stuck"
        else:
            result["outcome"] = "recovered-unresponsive"
        result["elapsed_s"] = time.monotonic() - start
        if not recovered:
            result["dump_ok"] = try_dump_guest_memory(
                qmp, dump_path, proc.pid, err_nodes)
        return result

    except Exception as exc:
        result["outcome"] = "error"
        result["error"] = str(exc)
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

        # QEMU has exited, so the trace is complete: mine it for the resets we
        # were trying to provoke before it is (possibly) deleted below.
        reset_events = scan_reset_events(trace_path)
        if reset_events is not None:
            result["reset_events"] = reset_events

        if result["outcome"] == "recovered" and not keep_all:
            for f in [boot_overlay, vars_overlay, screenshot] + [s.image for s in lun_specs]:
                f.unlink(missing_ok=True)
            if trace_path is not None:
                trace_path.unlink(missing_ok=True)
        else:
            result["screenshot"] = str(screenshot) if screenshot.exists() else None
            result["serial_log"] = str(serial_log)
            result["qemu_log"] = str(qemu_log_path)
            result["trace_log"] = str(trace_path) if trace_path and trace_path.exists() else None
            result["dump"] = str(dump_path) if dump_path.exists() else None


def telemetry_summary(result: dict) -> str:
    """One-line, human-readable check that the trial did what it's supposed to:
    drove I/O, the stall actually held it, and the guest recovered."""
    total = result.get("pre_arm_write_ops_per_s_total")
    if total is None:
        return "no telemetry (trial ended before I/O probe)"
    if result.get("outcome") == "no-io":
        return f"!! I/O NOT DRIVEN: {total} write ops/s across LUNs -- test exercised nothing"

    cycles = result.get("cycle_telemetry", [])
    peak_held = max((max(c.get("held_peak_per_node", {}).values(), default=0)
                     for c in cycles), default=0)
    total_hits = sum(sum(c.get("hits_per_node", {}).values()) for c in cycles)
    recoveries = [c.get("recovery_s") for c in cycles if c.get("recovery_s") is not None]
    resumed = [c.get("post_release_write_ops_per_s") for c in cycles
               if c.get("post_release_write_ops_per_s") is not None]

    parts = [f"io={total} wps",
             f"stall held peak={peak_held} req",
             f"rule hits={total_hits}",
             f"recovery={recoveries}s" if recoveries else "recovery=none"]
    if resumed:
        parts.append(f"post-release io={resumed} wps")

    # Whether the guest actually issued the resets we are racing -- the single
    # most important "did the test do its job" signal.
    reset_events = result.get("reset_events")
    if reset_events is not None:
        n = reset_events.get("tmf_reqs", 0)
        if n:
            parts.append(f"guest resets={n} {reset_events.get('by_target', {})}")
        else:
            parts.append("guest resets=0 (no reset was provoked!)")
        escalations = reset_events.get("escalations_during_delay") or []
        if escalations:
            parts.append(f"** STORPORT SELF-ESCALATED: {len(escalations)} TMF(s) "
                         f"arrived while an earlier one on the same target was "
                         f"still held -- reset re-entry happens on its own **")

    warn = "" if peak_held > 0 else "  <-- WARNING: stall never held any I/O"
    return " | ".join(parts) + warn


def check_prereqs() -> Optional[str]:
    for path, what in ((BOOT_DISK, "boot disk"), (OVMF_VARS, "OVMF NVRAM"),
                        (QEMU_BIN, "qemu binary")):
        if not path.exists():
            return (f"{what} not found: {path}\n"
                    "Run './scripts/setup-windows-inject-vm.sh create' and "
                    "'install' first (see --help for full prerequisites).")
    if not TRACE_EVENTS.exists():
        print(f"Note: {TRACE_EVENTS} not found, tracing disabled for this run.",
              file=sys.stderr)
    return None


def load_qmp_module():
    site_packages = QEMU_BUILD / "pyvenv" / "lib"
    for py_dir in site_packages.glob("python*/site-packages"):
        sys.path.insert(0, str(py_dir))
    try:
        from qemu.qmp import legacy as qmp_module  # type: ignore
        return qmp_module
    except ImportError:
        print("Error: could not import qemu.qmp from the build's pyvenv.\n"
              "Build QEMU first (ninja -C build) so build/pyvenv exists.",
              file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Race concurrent vioscsi LUN resets against the inject-error branch.",
        epilog=usage_note(), formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--luns", type=int, default=3,
                     help="number of SCSI LUNs on the shared virtio-scsi-pci "
                          "adapter to stall concurrently (default: 3, matching "
                          "the multi-controller shape in the real-world report "
                          "this targets)")
    ap.add_argument("--gaps-ms", default="0,5,20,50,100,250,500",
                     help="comma list of host-side gaps between arming each "
                          "LUN's stall, in milliseconds (default: %(default)s)")
    ap.add_argument("--mode", choices=["stall", "delay"], default="stall",
                     help="'stall' holds indefinitely until the guest's own "
                          "reset releases it (recommended: guarantees the "
                          "guest's timeout, not our delay, drives the race). "
                          "'delay' completes after a fixed time instead.")
    ap.add_argument("--delay-ms", type=int, default=70000,
                     help="for --mode delay: base hold time, chosen to land "
                          "past the ~60-90s storport timeouts seen in the "
                          "field (default: %(default)s)")
    ap.add_argument("--delay-max-ms", type=int, default=95000,
                     help="for --mode delay: upper bound of the hold range")
    ap.add_argument("--repeat", type=int, default=3,
                     help="trials per gap value (default: %(default)s); this "
                          "race is timing-sensitive, repetition matters more "
                          "than any single trial")
    ap.add_argument("--run-timeout", type=int, default=90,
                     help="seconds to hold the stall (and watch for a crash) "
                          "before releasing. Only needs to comfortably exceed "
                          "the guest's storport timeout (~60s) so every LUN "
                          "crosses it and fires its reset -- that co-timeout is "
                          "what makes the concurrent resets race. Holding much "
                          "longer just idles (default: %(default)s)")
    ap.add_argument("--recovery-timeout", type=float,
                     default=DEFAULT_RECOVERY_TIMEOUT_S,
                     help="seconds to wait, after releasing a stall, for the "
                          "scsi disks to resume completing writes before "
                          "declaring the trial 'io-stuck'. Recovery is driven "
                          "by the guest's storport reset, which can land well "
                          "after release, so this needs real headroom; the "
                          "poll returns as soon as I/O resumes (default: "
                          "%(default)s)")
    ap.add_argument("--cycles", type=int, default=1,
                     help="stall/reset/recover cycles to run per trial, in the "
                          "same guest boot, before giving up (default: "
                          "%(default)s); a single overlapping reset may only "
                          "corrupt memory silently without faulting anything, "
                          "so repeating the race after confirming the guest "
                          "recovered each time tests whether it takes several "
                          "hits to actually crash")
    ap.add_argument("--inter-cycle-settle", type=float,
                     default=DEFAULT_SETTLE_S,
                     help="seconds to let I/O run cleanly before arming a "
                          "stall (default: %(default)s) -- applies both to the "
                          "initial warmup before the first arm and, on "
                          "multi-cycle runs, to the gap after a confirmed "
                          "recovery before re-arming the next --cycles stall")
    ap.add_argument("--io-driver", choices=["powershell", "diskspd"],
                     default="powershell",
                     help="how to drive guest I/O: 'powershell' (default) runs "
                          "the built-in raw-write loop; 'diskspd' launches "
                          "Microsoft's diskspd.exe directly against each LUN's "
                          "PhysicalDriveN instead")
    ap.add_argument("--diskspd-path", default=DEFAULT_DISKSPD_PATH,
                     help="guest-side path to diskspd.exe, used when "
                          "--io-driver=diskspd (default: %(default)s); must "
                          "already be installed in the golden image")
    ap.add_argument("--tmf-delay-ms", type=int, default=0,
                     help="hold the control-queue response to each of the "
                          "adapter's first --tmf-delay-count TMFs (e.g. the "
                          "LUN reset storport issues on timeout) for this many "
                          "milliseconds before completing it, via virtio-scsi-"
                          "pci's x-tmf-delay-ms/-count properties. Pairs with "
                          "--tmf-delay-count to run the escalation experiment: "
                          "don't inject a second reset at all, just hold the "
                          "first TMF open and watch (via the trace scan's "
                          "'escalations_during_delay') whether storport "
                          "re-enters with a second TMF on the same target on "
                          "its own -- which is what would show the race is "
                          "reachable from a real storport timeout, not just "
                          "from us forcing both resets. 0 (default) disables.")
    ap.add_argument("--tmf-delay-count", type=int, default=0,
                     help="number of TMFs on the adapter to delay by "
                          "--tmf-delay-ms before completing (default: "
                          "%(default)s, i.e. none delayed; set to 1 to hold "
                          "only the first, so a second TMF "
                          "appearing in the trace can only be storport's own "
                          "doing). Ignored unless --tmf-delay-ms is set.")
    ap.add_argument("--ram", default=DEFAULT_RAM)
    ap.add_argument("--cpus", default=DEFAULT_CPUS)
    ap.add_argument("--host-pressure-cores", default=None, metavar="CPULIST",
                     help="restrict QEMU to these host cores via taskset "
                          "(e.g. '0-1'), to widen the race window with host "
                          "scheduling contention -- the real-world reports "
                          "all had a busy/slow host")
    ap.add_argument("--seed-base", type=int, default=1)
    ap.add_argument("--keep-all", action="store_true",
                     help="keep overlays/images even for clean 'recovered' trials")
    ap.add_argument("--stop-on-first-crash", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the grid, run nothing")
    args = ap.parse_args()

    if args.host_pressure_cores and not shutil.which("taskset"):
        print("Error: --host-pressure-cores given but 'taskset' not found in PATH.",
              file=sys.stderr)
        return 1

    gaps = [float(g) for g in args.gaps_ms.split(",")]
    cases = gen_cases(gaps, args.mode, args.delay_ms, args.delay_max_ms,
                       args.repeat, args.seed_base)

    print(f"{len(cases)} trial(s), {args.luns} LUN(s) each.")
    if args.dry_run:
        for tc in cases:
            print(f"  {tc.label}")
        return 0

    err = check_prereqs()
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    qmp_module = load_qmp_module()
    if qmp_module is None:
        return 1

    FUZZ_DIR.mkdir(parents=True, exist_ok=True)
    results_path = FUZZ_DIR / f"results-{int(time.time())}.jsonl"
    print(f"Results: {results_path}")

    crashes = []
    for i, tc in enumerate(cases):
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{started_at}] [{i + 1}/{len(cases)}] {tc.label} ... ",
              end="", flush=True)
        result = run_case(tc, i, args.luns, args.run_timeout, args.ram, args.cpus,
                           args.host_pressure_cores, args.keep_all, qmp_module,
                           args.cycles, args.inter_cycle_settle,
                           args.io_driver, args.diskspd_path,
                           args.recovery_timeout,
                           args.tmf_delay_ms, args.tmf_delay_count)
        finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{result['outcome']} ({result['elapsed_s']:.0f}s, done {finished_at})")
        print("    " + telemetry_summary(result))
        with results_path.open("a") as f:
            f.write(json.dumps(result) + "\n")
        if result["outcome"] in ("crash-suspected", "qemu-exited"):
            crashes.append(result)
            if args.stop_on_first_crash:
                break

    print()
    print(f"Done. {len(crashes)} crash candidate(s) out of {len(cases)}.")
    for c in crashes:
        print(f"  {c['label']} -> {c['run_dir']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
