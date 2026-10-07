#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Long-running tail-latency soak test for the vioscsi (virtio-scsi) Windows
# guest driver, built on the inject-error latency-injection branch.
#
# Unlike scripts/fuzz-windows-inject-scsi-reset.py (which races concurrent
# LUN resets over many short trials), this harness boots one VM and leaves
# it running for hours under a single, constant tail-latency rule: a small
# fraction of read/write requests on each data LUN complete late (default
# 5% of requests, held 61-65s -- past typical storport timeouts) while the
# rest complete normally. See docs/devel/storage-error-injection.rst,
# "Tail latency: small probability with a wide delay range".
#
# The rule is baked into each LUN's '-blockdev' at VM startup (the
# 'delays.0.*' properties), not armed/released over QMP, since it needs to
# stay live for the whole run rather than being cycled. Sustained raw
# writes are driven from inside the guest via qemu-guest-agent for the
# full test duration. The harness just watches for the guest going dark
# (guest-agent stops answering, screen stops changing) as a bugcheck
# signal, and on that signal captures a win-dmp crash dump via
# '-device vmcoreinfo' + QMP 'dump-guest-memory' (requires the fwcfg
# driver in the guest for a fully symbolized dump).
#
# Prerequisites: identical to fuzz-windows-inject-scsi-reset.py -- see that
# script's usage_note() / module docstring, or run this one with --help.
#
# Expect duty-cycle, not steady, throughput. The default writer keeps a deep
# queue of outstanding requests per LUN (WRITER_THREADS * WRITER_QUEUE_DEPTH),
# and at this setup's IOPS each one independently rolls the 5% dice many
# times within milliseconds of being issued -- so, counter-intuitively,
# *every* outstanding slot ends up trapped by the 61-65s delay at almost the
# same moment, not just 5% of them. Measured behavior: the whole queue
# free-runs for a few milliseconds, then goes fully dark for ~60s, then
# releases and re-traps itself in one multi-hundred-op burst, repeating on a
# ~61-65s duty cycle for as long as the writer runs. This is actually useful
# here: it means every cycle lands dozens of concurrent requests past a
# storport timeout at once, which is a good way to provoke the driver's
# timeout/reset path. But it means any I/O-rate check sampled over a window
# shorter than one cycle will unpredictably see either a burst or dead air --
# see IO_PROBE_MARGIN_S, which sizes the pre-flight probe to always span a
# full cycle.

import argparse
import base64
import dataclasses
import fcntl
import hashlib
import itertools
import json
import os
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
SOAK_DIR = VM_DIR / "soak-tail-latency"

BOOT_DISK = VM_DIR / "boot.qcow2"
OVMF_CODE = Path(os.environ.get(
    "OVMF_CODE", "/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2"))
OVMF_VARS = VM_DIR / "OVMF_VARS.qcow2"
TPM_DIR = VM_DIR / "tpm"  # shared, persistent -- same TPM state the golden image was installed with

PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
TASKKILL_EXE = r"C:\Windows\System32\taskkill.exe"
DEFAULT_DISKSPD_PATH = r"C:\Tools\diskspd.exe"
DEFAULT_FIO_PATH = r"C:\Program Files\fio\fio.exe"
DEFAULT_VIOSCSI_TELEMETRY_SCRIPT = r"C:\test\GetVioScsiTelemetry.ps1"
VIOSCSI_TELEMETRY_TIMEOUT_S = 60
WRITER_STOP_TIMEOUT_S = 30

DEFAULT_RAM = "8G"
DEFAULT_CPUS = "5"
LUN_IMAGE_SIZE = "4G"

BOOT_TIMEOUT_S = 180
GUEST_EXEC_TIMEOUT_S = 30
WARMUP_S = 5.0  # just long enough for guest-exec to actually launch the
                # writer before the pre-flight probe starts timing itself
QMP_CMD_TIMEOUT_S = 15
QMP_CONNECT_TIMEOUT_S = 30
DUMP_TIMEOUT_S = 900
DUMP_START_TIMEOUT_S = 300
DUMP_POLL_INTERVAL_S = 2
STACK_CAPTURE_TIMEOUT_S = 120
POLL_INTERVAL_S = 2
AGENT_SILENCE_THRESHOLD_S = 15
STATIC_SCREEN_THRESHOLD_S = 20
DEFAULT_HEARTBEAT_S = 300  # how often to log a progress line on an hours-long run

# The pre-flight I/O probe's window has to span at least one full duty cycle
# (see the module docstring) or it will unpredictably sample a dead patch and
# misdiagnose a perfectly healthy writer as "no-io" -- a single cycle is
# bounded above by roughly delay-max-ms, so the margin below just has to
# cover scheduling slop, not another whole cycle.
IO_PROBE_MARGIN_S = 10.0
IO_PROBE_ATTEMPTS = 2  # retries before declaring "no-io", in case the first
                       # window's timing was unlucky (e.g. a slow QMP round
                       # trip stretching it right to the edge of a cycle)
MIN_WRITE_OPS_PER_S = 2.0

WRITER_WINDOW_BYTES = 32 * 1024 * 1024
WRITER_BLOCK_BYTES = 64 * 1024
WRITER_THREADS = 4
WRITER_QUEUE_DEPTH = 32

# Writers are budgeted to outlast the configured test duration by this much,
# so a slow boot or heartbeat overhead can never let them exit early and
# leave the back half of a multi-hour run with no I/O to delay.
WRITER_DURATION_SLACK_S = 600


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
  7. For vioscsi telemetry collection (optional, on by default): have the
     script given by --vioscsi-telemetry-script (default:
     {DEFAULT_VIOSCSI_TELEMETRY_SCRIPT}) present in the guest.
  8. Shut down cleanly.

Environment overrides for running on different machines:
  QEMU_SRC, QEMU_BUILD   default to this script's own checkout
  VM_DIR                 default to $HOME/VirtualMachines/qemu/windows_inject
  OVMF_CODE              default to {OVMF_CODE}
"""


# ------------------------------------------------------------------
# QEMU guest agent client (same protocol/plumbing as the reset-race harness)
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
    # See fuzz-windows-inject-scsi-reset.py's build_diskspd_args for why this
    # is '#N' (raw physical drive), '-w100' + no '-c', and '-Sh'.
    return [
        f"-d{int(round(duration_s))}",
        "-w50",              # mixed read/write -- a pure-write workload
                              # wouldn't exercise the 'read' side of the rule
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
    # would make verify failures indistinguishable from the tail-latency
    # rule corrupting data. --serialize_overlap guards the same race within
    # the one job's own in-flight queue. Random read/write against a fixed
    # window lets fio verify previously-written blocks on every read for the
    # life of the run, rather than only checking data written-then-read in a
    # single pass.
    return [
        "--name=tail-latency-soak",
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
                   diskspd_path: str = DEFAULT_DISKSPD_PATH,
                   fio_path: str = DEFAULT_FIO_PATH) -> int:
    if io_driver == "diskspd":
        pid = qga_exec(qga_sock, diskspd_path,
                        build_diskspd_args(drive_number, duration_s),
                        capture=False)
    elif io_driver == "fio":
        pid = qga_exec(qga_sock, fio_path,
                        build_fio_args(drive_number, duration_s),
                        capture=False)
    else:
        pid = ps_exec(qga_sock, build_writer_script(drive_number, duration_s), capture=False)
    if pid is None:
        raise RuntimeError(f"guest-exec (writer for PhysicalDrive{drive_number}) failed to launch")
    return pid


def diskspd_diagnostic(qga_sock: Path, diskspd_path: str, drive_number: int,
                        delay_max_ms: int) -> str:
    # diskspd waits for every outstanding I/O to complete before it exits and
    # reports, even for a 1s '-d1' run -- including any that landed in the
    # rule's 61-65s hold. Give it room past delay_max_ms rather than the
    # ordinary GUEST_EXEC_TIMEOUT_S, or this diagnostic itself "times out"
    # on perfectly healthy I/O and reports nothing useful.
    diag_timeout = delay_max_ms / 1000.0 + GUEST_EXEC_TIMEOUT_S
    pid = qga_exec(qga_sock, diskspd_path, build_diskspd_args(drive_number, 1),
                   capture=True, timeout=diag_timeout)
    if pid is None:
        return (f"diskspd failed to even launch at {diskspd_path!r} "
                f"(guest-exec returned no pid -- path wrong or not present?)")
    status = qga_exec_wait(qga_sock, pid, timeout=diag_timeout)
    if status is None:
        return "diskspd diagnostic run timed out"
    out = b64_text(status.get("out-data")).strip()
    err = b64_text(status.get("err-data")).strip()
    return (f"diskspd exitcode={status.get('exitcode')}; "
            f"stdout={out[:400]!r}; stderr={err[:400]!r}")


def fio_diagnostic(qga_sock: Path, fio_path: str, drive_number: int,
                    delay_max_ms: int) -> str:
    # Same rationale as diskspd_diagnostic: fio with --verify waits for its
    # read-back/verify phase before exiting, so give it room past
    # delay_max_ms rather than the ordinary GUEST_EXEC_TIMEOUT_S.
    diag_timeout = delay_max_ms / 1000.0 + GUEST_EXEC_TIMEOUT_S
    pid = qga_exec(qga_sock, fio_path, build_fio_args(drive_number, 1),
                   capture=True, timeout=diag_timeout)
    if pid is None:
        return (f"fio failed to even launch at {fio_path!r} "
                f"(guest-exec returned no pid -- path wrong or not present?)")
    status = qga_exec_wait(qga_sock, pid, timeout=diag_timeout)
    if status is None:
        return "fio diagnostic run timed out"
    out = b64_text(status.get("out-data")).strip()
    err = b64_text(status.get("err-data")).strip()
    return (f"fio exitcode={status.get('exitcode')}; "
            f"stdout={out[:400]!r}; stderr={err[:400]!r}")


def capture_vioscsi_telemetry(qga_sock: Path, script_path: str, out_path: Path,
                               timeout: float = VIOSCSI_TELEMETRY_TIMEOUT_S) -> str:
    """Run the guest's vioscsi telemetry PowerShell script and save its
    output to out_path on the host. Never raises -- a telemetry capture
    failure (e.g. the guest going dark right as a crash is suspected)
    shouldn't abort the harness, just get recorded as a short status."""
    pid = qga_exec(qga_sock, PS_EXE,
                    ["-NoProfile", "-NonInteractive", "-File", script_path],
                    capture=True, timeout=timeout)
    if pid is None:
        msg = f"guest-exec failed to launch telemetry script {script_path!r}"
        out_path.write_text(msg + "\n")
        return msg
    status = qga_exec_wait(qga_sock, pid, timeout=timeout)
    if status is None:
        msg = f"telemetry script timed out after {timeout:.0f}s"
        out_path.write_text(msg + "\n")
        return msg
    out = b64_text(status.get("out-data"))
    err = b64_text(status.get("err-data"))
    text = out
    if err:
        text += f"\n--- stderr ---\n{err}"
    out_path.write_text(text)
    return f"exitcode={status.get('exitcode')}, saved to {out_path}"


def writer_states(qga_sock: Path, pids: list) -> list:
    states = []
    for pid in pids:
        resp = qga_call(qga_sock, "guest-exec-status", {"pid": pid}, timeout=5.0)
        ret = resp.get("return", {}) if resp and "return" in resp else {}
        states.append({"pid": pid, "exited": ret.get("exited"),
                       "exitcode": ret.get("exitcode")})
    return states


def wait_for_writers(qga_sock: Path, pids: list, timeout: float) -> list:
    deadline = time.monotonic() + timeout
    states = writer_states(qga_sock, pids)
    while time.monotonic() < deadline and any(not s["exited"] for s in states):
        time.sleep(1.0)
        states = writer_states(qga_sock, pids)
    return states


def stop_writers(qga_sock: Path, pids: list,
                  timeout: float = WRITER_STOP_TIMEOUT_S) -> list:
    """Force-stop any writer still running and wait for it to exit.

    Writers are launched with writer_duration, padded well past the
    monitored test window by WRITER_DURATION_SLACK_S so a slow boot or
    heartbeat can never starve the back half of a run -- see that constant.
    Left alone they'd keep hammering the guest with I/O for up to another
    ~10 minutes after the harness is done watching, which races vioscsi
    telemetry collection (and anything else run post-test) against a guest
    still under full write load."""
    for st in writer_states(qga_sock, pids):
        if not st["exited"]:
            qga_exec(qga_sock, TASKKILL_EXE, ["/F", "/PID", str(st["pid"])],
                      capture=False)
    return wait_for_writers(qga_sock, pids, timeout)


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
    # See fuzz-windows-inject-scsi-reset.py's check_tpm_dir_lockable for why
    # this pre-check matters: swtpm's own lock is lazy (taken at CMD_INIT,
    # not startup), so waiting for its control socket to appear proves
    # nothing about contention on the shared, persistent TPM_DIR.
    TPM_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = TPM_DIR / ".lock"
    try:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o640)
    except OSError:
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holders = other_swtpm_pids(os.getpid())
            raise RuntimeError(
                f"the shared TPM state dir {TPM_DIR} is already locked by "
                f"another process -- swtpm here would fail CMD_INIT and QEMU "
                f"would die with 'TPM result for CMD_INIT: 0x9'. swtpm "
                f"process(es) currently running: "
                f"{holders if holders else 'none visible via pgrep'}. Shut "
                f"that VM down (or kill the stray swtpm) and retry.")
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def start_swtpm(tpm_sock: Path) -> subprocess.Popen:
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
            f"{TPM_DIR}" if other_swtpm else
            f" -- no other swtpm process is currently visible, so this "
            f"isn't the usual {TPM_DIR} lock contention; check the swtpm "
            f"install and permissions on that directory")
    raise RuntimeError(
        f"swtpm did not create its control socket within 5s -- it likely "
        f"blocked silently trying to lock {TPM_DIR} rather than erroring "
        f"out{hint}")


def tail_rule_props(rule_id: str, probability: float, delay_ms: int,
                     delay_max_ms: int, ops: list, seed: int) -> str:
    """Render the tail-latency rule as '-blockdev' properties (delays.0.*),
    so it is live for the LUN's very first I/O rather than armed afterward
    over QMP -- this rule needs to stay in effect for the whole run, not be
    cycled, so there is no reason to arm it any other way."""
    props = [f"delays.0.id={rule_id}",
             f"delays.0.probability={probability}",
             f"delays.0.delay-ms={delay_ms}",
             f"delays.0.delay-max-ms={delay_max_ms}"]
    for i, op in enumerate(ops):
        props.append(f"delays.0.ops.{i}={op}")
    return ",".join(props)


def build_qemu_argv(boot_overlay: Path, vars_overlay: Path, qmp_sock: Path,
                     qga_sock: Path, serial_log: Path, tpm_sock: Path,
                     adapters: int, lun_specs: list, seed: int, ram: str,
                     cpus: str, taskset_cores: Optional[str], probability: float,
                     delay_ms: int, delay_max_ms: int, ops: list) -> list:
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
        # Boot disk is SATA/AHCI and stays a plain passthrough -- the
        # tail-latency rule only targets the SCSI data LUNs below, not the
        # virtio-blk boot path.
        "-device", "ahci,id=ahci0",
        "-blockdev", f"driver=file,filename={boot_overlay},node-name=file0",
        "-blockdev", "driver=qcow2,file=file0,node-name=raw0",
        "-blockdev", "driver=inject-error,image=raw0,node-name=err0",
        "-device", "ide-hd,bus=ahci0.0,drive=err0,bootindex=0,id=disk0",
    ]

    for a in range(adapters):
        argv += ["-device", f"virtio-scsi-pci,id=scsi{a}"]

    for spec in lun_specs:
        rule_props = tail_rule_props(spec.err_node, probability, delay_ms,
                                      delay_max_ms, ops, seed)
        argv += [
            "-blockdev", f"driver=file,filename={spec.image},node-name={spec.file_node}",
            "-blockdev", f"driver=qcow2,file={spec.file_node},node-name={spec.fmt_node}",
            "-blockdev", f"driver=inject-error,image={spec.fmt_node},"
                          f"node-name={spec.err_node},seed={seed},{rule_props}",
            "-device", f"scsi-hd,drive={spec.err_node},bus=scsi{spec.adapter}.0,"
                       f"scsi-id={spec.target},lun={spec.lun},"
                       f"id={spec.dev_id},serial={spec.serial}",
        ]

    return argv


_qmp_ids = itertools.count()


def qmp_call(qmp, name: str, **kwargs) -> Any:
    args = {k.replace("_", "-"): v for k, v in kwargs.items()}
    msg = {"execute": name, "id": f"soak-{next(_qmp_ids)}"}
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
    # Remove (not release) any still-live delay rule first: stopping the VM
    # to dump drains every block node, which wakes held requests on its own,
    # but leaves the rule installed to catch the flush that follows -- see
    # fuzz-windows-inject-scsi-reset.py's try_dump_guest_memory for the full
    # rationale.
    for node in err_nodes:
        try:
            qmp_call(qmp, "x-inject-error-delay-remove", node_name=node, id=node)
        except RuntimeError:
            pass

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


def write_ops_by_node(qmp) -> dict:
    """identifier -> cumulative completed write operations. See
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
            wr = entry.get("stats", {}).get("wr_operations", 0)
            for key in ("device", "qdev", "node-name"):
                ident = entry.get(key)
                if ident:
                    out[ident] = max(out.get(ident, 0), wr)
    return out


def lun_write_delta(before: dict, after: dict, spec: "LunSpec") -> int:
    return max(after.get(k, 0) - before.get(k, 0)
               for k in (spec.dev_id, spec.err_node, spec.fmt_node,
                         spec.file_node))


def rule_hits(qmp, err_nodes: list) -> dict:
    out: dict = {}
    for n in err_nodes:
        try:
            rules = qmp_call(qmp, "x-inject-error-delay-list", node_name=n) or []
            out[n] = sum(r.get("hits", 0) for r in rules)
        except Exception:
            out[n] = 0
    return out


def held_counts(qmp, err_nodes: list) -> dict:
    out: dict = {}
    for n in err_nodes:
        try:
            held = qmp_call(qmp, "x-inject-error-delay-inflight", node_name=n) or []
            out[n] = len(held)
        except Exception:
            out[n] = 0
    return out


# ------------------------------------------------------------------
# Harness
# ------------------------------------------------------------------


def run_soak(adapters: int, targets: int, luns_per_target: int, duration_s: float,
             ram: str, cpus: str, taskset_cores: Optional[str], keep_all: bool,
             qmp_module, io_driver: str, diskspd_path: str, fio_path: str,
             probability: float, delay_ms: int, delay_max_ms: int, ops: list,
             seed: int, heartbeat_s: float, vioscsi_telemetry_script: str) -> dict:
    run_dir = SOAK_DIR / f"run-{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    status_path = run_dir / "status.json"

    boot_overlay = run_dir / "boot.qcow2"
    vars_overlay = run_dir / "vars.qcow2"
    qmp_sock = run_dir / "qmp.sock"
    qga_sock = run_dir / "qga.sock"
    tpm_sock = run_dir / "swtpm.sock"
    serial_log = run_dir / "serial.log"
    vioscsi_telemetry_log = run_dir / "vioscsi-telemetry.log"
    screenshot = run_dir / "screen.ppm"
    dump_path = run_dir / "crash.dmp"
    qemu_log_path = run_dir / "qemu.log"

    qmp = None
    proc = None
    swtpm = None
    lun_specs: list = []
    result: dict = {"outcome": "error", "elapsed_s": 0.0, "run_dir": str(run_dir),
                    "duration_s": duration_s, "probability": probability,
                    "delay_ms": delay_ms, "delay_max_ms": delay_max_ms, "ops": ops}
    start = time.monotonic()

    def write_status(extra: dict) -> None:
        status_path.write_text(json.dumps({**result, **extra}, indent=2))

    def collect_vioscsi_telemetry() -> None:
        if not vioscsi_telemetry_script:
            return
        # Stop the writers first: they're still live (see stop_writers'
        # docstring), and leaving them running races the telemetry query
        # against a guest saturated with I/O.
        result["writer_states"] = stop_writers(qga_sock, writer_pids)
        print(f"    collecting vioscsi telemetry via {vioscsi_telemetry_script}",
              file=sys.stderr)
        msg = capture_vioscsi_telemetry(qga_sock, vioscsi_telemetry_script,
                                         vioscsi_telemetry_log)
        result["vioscsi_telemetry"] = msg
        result["vioscsi_telemetry_log"] = str(vioscsi_telemetry_log)
        if "timed out" in msg:
            print("    telemetry collection still timed out -- capturing a "
                  "screenshot and a guest memory dump for postmortem",
                  file=sys.stderr)
            result["telemetry_timeout_screenshot"] = (
                screendump_hash(qmp, screenshot) is not None)
            result["telemetry_timeout_dump"] = try_dump_guest_memory(
                qmp, dump_path, proc.pid, err_nodes)

    try:
        make_overlay(BOOT_DISK, boot_overlay)
        make_overlay(OVMF_VARS, vars_overlay)

        for a in range(adapters):
            for t in range(targets):
                for l in range(luns_per_target):
                    tag = f"{a}-{t}-{l}"
                    img = run_dir / f"lun{tag}.qcow2"
                    make_blank_image(img)
                    lun_specs.append(LunSpec(
                        adapter=a, target=t, lun=l, image=img,
                        file_node=f"lfile{tag}", fmt_node=f"lraw{tag}",
                        err_node=f"lerr{tag}", dev_id=f"lun{tag}",
                        serial=f"TL{tag}"))
        total_luns = len(lun_specs)

        # See IO_PROBE_MARGIN_S above: the probe window has to span a full
        # duty cycle, not just a few seconds, or it will unpredictably land
        # in a dead patch between bursts.
        io_probe_window_s = delay_max_ms / 1000.0 + IO_PROBE_MARGIN_S
        writer_duration = duration_s + WARMUP_S + io_probe_window_s + WRITER_DURATION_SLACK_S

        argv = build_qemu_argv(boot_overlay, vars_overlay, qmp_sock, qga_sock,
                                serial_log, tpm_sock, adapters, lun_specs, seed,
                                ram, cpus, taskset_cores, probability, delay_ms,
                                delay_max_ms, ops)

        meta = {"adapters": adapters, "targets": targets,
                "luns_per_target": luns_per_target, "total_luns": total_luns,
                "duration_s": duration_s, "probability": probability,
                "delay_ms": delay_ms, "delay_max_ms": delay_max_ms, "ops": ops,
                "seed": seed, "argv": argv}
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))

        swtpm = start_swtpm(tpm_sock)
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
                root_cause = getattr(exc, "exc", exc)
                if not isinstance(root_cause, OSError):
                    raise
                last_connect_exc = exc
                time.sleep(0.2)
        if not connected:
            if proc.poll() is not None:
                raise qemu_died_error("right after opening the QMP socket")
            raise RuntimeError(
                f"could not connect to QMP within {QMP_CONNECT_TIMEOUT_S}s"
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
                                              io_driver, diskspd_path, fio_path))
        result["writer_pids"] = writer_pids

        time.sleep(WARMUP_S)

        # See IO_PROBE_MARGIN_S / the module docstring: this workload runs in
        # bursts on a ~delay-max-ms duty cycle (the deep queue traps nearly
        # every outstanding request at once, then releases and re-traps them
        # together), so io_probe_window_s is sized to always span a full
        # cycle regardless of what phase it starts in. The retry is just a
        # safety net for scheduling slop, not the main defense -- getting
        # this wrong would abort an unattended multi-hour run before it even
        # starts, so don't rely on luck here.
        err_nodes = [s.err_node for s in lun_specs]
        total_wps = 0.0
        wps_per_lun: dict = {}
        for attempt in range(IO_PROBE_ATTEMPTS):
            w_before = write_ops_by_node(qmp)
            time.sleep(io_probe_window_s)
            w_after = write_ops_by_node(qmp)
            wps_per_lun = {s.serial: lun_write_delta(w_before, w_after, s) / io_probe_window_s
                           for s in lun_specs}
            total_wps = sum(wps_per_lun.values())
            if total_wps >= MIN_WRITE_OPS_PER_S:
                break
            if attempt + 1 < IO_PROBE_ATTEMPTS:
                print(f"    no write I/O seen yet (attempt {attempt + 1}/"
                      f"{IO_PROBE_ATTEMPTS}), retrying...", file=sys.stderr)
        result["writer_states"] = writer_states(qga_sock, writer_pids)
        result["pre_test_write_ops_per_s"] = wps_per_lun
        result["pre_test_write_ops_per_s_total"] = round(total_wps, 1)
        if total_wps < MIN_WRITE_OPS_PER_S:
            result["outcome"] = "no-io"
            result["elapsed_s"] = time.monotonic() - start
            diag = ""
            if io_driver == "diskspd":
                result["diskspd_diagnostic"] = diskspd_diagnostic(
                    qga_sock, diskspd_path, drive_numbers[lun_specs[0].serial],
                    delay_max_ms)
                diag = f" diskspd diagnostic: {result['diskspd_diagnostic']}"
            elif io_driver == "fio":
                result["fio_diagnostic"] = fio_diagnostic(
                    qga_sock, fio_path, drive_numbers[lun_specs[0].serial],
                    delay_max_ms)
                diag = f" fio diagnostic: {result['fio_diagnostic']}"
            result["error"] = (
                f"writers are not driving I/O: only {total_wps:.1f} write ops/s "
                f"across all {total_luns} LUN(s) (need >= {MIN_WRITE_OPS_PER_S}). "
                f"Check --io-driver / --diskspd-path / --fio-path; writer "
                f"states: {result['writer_states']}.{diag}")
            collect_vioscsi_telemetry()
            return result

        print(f"    soak running: {duration_s / 3600:.1f}h, {total_wps:.1f} wps "
              f"across {total_luns} LUN(s) ({adapters} adapter(s) x {targets} "
              f"target(s) x {luns_per_target} lun(s)), heartbeat every "
              f"{heartbeat_s:.0f}s")

        test_start = time.monotonic()
        monitor_deadline = test_start + duration_s
        last_heartbeat = test_start
        prev_wops = write_ops_by_node(qmp)

        agent_alive = True
        agent_lost_t: Optional[float] = None
        last_hash = None
        last_change_t = test_start

        while time.monotonic() < monitor_deadline:
            now = time.monotonic()
            elapsed = now - start

            if proc.poll() is not None:
                result["outcome"] = "qemu-exited"
                result["qemu_returncode"] = proc.returncode
                result["elapsed_s"] = elapsed
                write_status({"elapsed_s": elapsed})
                return result

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
                result["outcome"] = "crash-suspected"
                result["elapsed_s"] = elapsed
                result["rule_hits"] = rule_hits(qmp, err_nodes)
                print(f"    guest appears dark after {elapsed:.0f}s -- "
                      f"capturing crash dump", file=sys.stderr)
                result["dump_ok"] = try_dump_guest_memory(
                    qmp, dump_path, proc.pid, err_nodes)
                write_status({"elapsed_s": elapsed})
                return result

            if now - last_heartbeat >= heartbeat_s:
                cur_wops = write_ops_by_node(qmp)
                sample_s = now - last_heartbeat
                wps = sum(lun_write_delta(prev_wops, cur_wops, s) for s in lun_specs) / sample_s
                prev_wops = cur_wops
                last_heartbeat = now
                hits = rule_hits(qmp, err_nodes)
                held = held_counts(qmp, err_nodes)
                hb = {"elapsed_s": round(elapsed, 0), "write_ops_per_s": round(wps, 1),
                      "rule_hits": hits, "held_now": held,
                      "agent_alive": agent_alive}
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"{elapsed / 3600:.2f}h elapsed, {wps:.1f} wps, "
                      f"rule hits={sum(hits.values())}, held now={sum(held.values())}")
                write_status(hb)

            time.sleep(POLL_INTERVAL_S)

        result["outcome"] = "completed"
        result["elapsed_s"] = time.monotonic() - start
        result["rule_hits"] = rule_hits(qmp, err_nodes)
        collect_vioscsi_telemetry()
        write_status({"elapsed_s": result["elapsed_s"]})
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

        keep_debug_artifacts = (keep_all or result.get("telemetry_timeout_screenshot")
                                 or result.get("telemetry_timeout_dump"))
        if result["outcome"] == "completed" and not keep_debug_artifacts:
            for f in [boot_overlay, vars_overlay, screenshot] + [s.image for s in lun_specs]:
                f.unlink(missing_ok=True)
        else:
            result["screenshot"] = str(screenshot) if screenshot.exists() else None
            result["serial_log"] = str(serial_log)
            result["qemu_log"] = str(qemu_log_path)
            result["dump"] = str(dump_path) if dump_path.exists() else None


def check_prereqs() -> Optional[str]:
    for path, what in ((BOOT_DISK, "boot disk"), (OVMF_VARS, "OVMF NVRAM"),
                        (QEMU_BIN, "qemu binary")):
        if not path.exists():
            return (f"{what} not found: {path}\n"
                    "Run './scripts/setup-windows-inject-vm.sh create' and "
                    "'install' first (see --help for full prerequisites).")
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
        description="Hours-long tail-latency soak test for the vioscsi "
                     "Windows guest driver: a small fraction of read/write "
                     "requests on each data LUN complete late (default 5% "
                     "held 61-65s), the rest complete normally, and the "
                     "harness watches for a bugcheck over the full run.",
        epilog=usage_note(), formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adapters", type=int, default=1,
                     help="number of vioscsi (virtio-scsi-pci) adapters to "
                          "create (default: %(default)s); --targets and "
                          "--luns-per-target apply to each adapter")
    ap.add_argument("--targets", type=int, default=1,
                     help="number of SCSI targets per adapter (default: "
                          "%(default)s)")
    ap.add_argument("--luns-per-target", type=int, default=1,
                     help="number of LUNs per target, all subject to the "
                          "tail-latency rule (default: %(default)s)")
    ap.add_argument("--duration-hours", type=float, default=4.0,
                     help="how long to run the soak test (default: %(default)s)")
    ap.add_argument("--probability", type=float, default=0.05,
                     help="fraction of matching read/write requests to delay "
                          "(default: %(default)s, i.e. 5%%)")
    ap.add_argument("--delay-ms", type=int, default=61000,
                     help="minimum hold time for a delayed request, in ms "
                          "(default: %(default)s, i.e. 61s -- just past "
                          "typical ~60s storport timeouts)")
    ap.add_argument("--delay-max-ms", type=int, default=65000,
                     help="maximum hold time for a delayed request, in ms "
                          "(default: %(default)s, i.e. 65s); the actual hold "
                          "is drawn uniformly from [--delay-ms, --delay-max-ms]")
    ap.add_argument("--ops", default="read,write",
                     help="comma list of operation types the rule matches "
                          "(default: %(default)s)")
    ap.add_argument("--io-driver", choices=["powershell", "diskspd", "fio"],
                     default="powershell",
                     help="how to drive guest I/O: 'powershell' (default) runs "
                          "the built-in raw-write loop (writes only -- use "
                          "diskspd or fio to also exercise reads); 'diskspd' "
                          "launches Microsoft's diskspd.exe with a 50/50 "
                          "read/write mix against each LUN's PhysicalDriveN; "
                          "'fio' launches fio.exe with a 50/50 random "
                          "read/write mix and crc32c data-integrity "
                          "verification against each LUN's PhysicalDriveN")
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
                          "the run (default: %(default)s); keep this well "
                          "above --delay-max-ms or individual heartbeats will "
                          "alias the workload's own burst/dead duty cycle and "
                          "bounce between 0 and a high rate rather than "
                          "showing a stable average")
    ap.add_argument("--ram", default=DEFAULT_RAM)
    ap.add_argument("--cpus", default=DEFAULT_CPUS)
    ap.add_argument("--host-pressure-cores", default=None, metavar="CPULIST",
                     help="restrict QEMU to these host cores via taskset "
                          "(e.g. '0-1')")
    ap.add_argument("--seed", type=int, default=1,
                     help="inject-error PRNG seed, for reproducing a run")
    ap.add_argument("--keep-all", action="store_true",
                     help="keep overlays/images even for a clean 'completed' run")
    args = ap.parse_args()

    if args.host_pressure_cores and not shutil.which("taskset"):
        print("Error: --host-pressure-cores given but 'taskset' not found in PATH.",
              file=sys.stderr)
        return 1

    if not (0.0 <= args.probability <= 1.0):
        print("Error: --probability must be between 0.0 and 1.0.", file=sys.stderr)
        return 1

    if args.adapters < 1 or args.targets < 1 or args.luns_per_target < 1:
        print("Error: --adapters, --targets and --luns-per-target must all "
              "be >= 1.", file=sys.stderr)
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

    ops = [o.strip() for o in args.ops.split(",") if o.strip()]
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
    print(f"Starting {args.duration_hours:.1f}h tail-latency soak: "
          f"{args.probability * 100:.1f}% of {ops} ops on {total_luns} LUN(s) "
          f"({args.adapters} adapter(s) x {args.targets} target(s) x "
          f"{args.luns_per_target} lun(s)) held "
          f"{args.delay_ms}-{args.delay_max_ms}ms.")

    result = run_soak(args.adapters, args.targets, args.luns_per_target,
                       duration_s, args.ram, args.cpus,
                       args.host_pressure_cores, args.keep_all, qmp_module,
                       args.io_driver, args.diskspd_path, args.fio_path,
                       args.probability, args.delay_ms, args.delay_max_ms, ops,
                       args.seed, args.heartbeat_seconds,
                       args.vioscsi_telemetry_script)

    results_path = SOAK_DIR / f"result-{int(time.time())}.json"
    results_path.write_text(json.dumps(result, indent=2))

    print()
    print(f"Outcome: {result['outcome']} ({result['elapsed_s']:.0f}s)")
    print(f"Result written to {results_path}")
    if result["outcome"] in ("crash-suspected", "qemu-exited", "error"):
        print(f"Artifacts in {result['run_dir']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
