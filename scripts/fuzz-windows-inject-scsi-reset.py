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
import hashlib
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
FUZZ_DIR = VM_DIR / "fuzz-scsi-reset"

BOOT_DISK = VM_DIR / "boot.qcow2"
OVMF_CODE = Path(os.environ.get(
    "OVMF_CODE", "/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2"))
OVMF_VARS = VM_DIR / "OVMF_VARS.qcow2"
TPM_DIR = VM_DIR / "tpm"  # shared, persistent -- same TPM state the golden image was installed with

TRACE_EVENTS = QEMU_SRC / "scripts" / "windows-storage-trace-events"

PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

DEFAULT_RAM = "8G"
DEFAULT_CPUS = "4"
LUN_IMAGE_SIZE = "1G"

BOOT_TIMEOUT_S = 180
GUEST_EXEC_TIMEOUT_S = 30
WRITER_SETTLE_S = 2.0  # let writers issue a few requests before arming, so the
                       # arm actually catches an in-flight guest write rather
                       # than racing the very first one
RELEASE_GRACE_S = 20
QMP_CMD_TIMEOUT_S = 15
POLL_INTERVAL_S = 2
AGENT_SILENCE_THRESHOLD_S = 15  # guest-agent silence this long, post-boot, is
                                 # itself a strong crash signal (its service
                                 # dies with the rest of the guest at a BSOD)
STATIC_SCREEN_THRESHOLD_S = 20  # corroborating signal once agent has gone quiet

# Sequential writes past this offset wrap back to 0. Keeps every write
# sector-aligned and inside the 1G scratch LUN without ever hitting EOF,
# which would otherwise throw partway through a run and end the loop.
WRITER_WINDOW_BYTES = 32 * 1024 * 1024
WRITER_BLOCK_BYTES = 64 * 1024


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
  5. Shut down cleanly.

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


def launch_writer(qga_sock: Path, drive_number: int, duration_s: float) -> int:
    pid = ps_exec(qga_sock, build_writer_script(drive_number, duration_s), capture=False)
    if pid is None:
        raise RuntimeError(f"guest-exec (writer for PhysicalDrive{drive_number}) failed to launch")
    return pid


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


def start_swtpm(tpm_sock: Path) -> subprocess.Popen:
    # A fresh swtpm process is required per VM launch (its unixio ctrl
    # channel doesn't survive a reconnect), but TPM_DIR itself is shared
    # and persistent, matching the golden image's real TPM state.
    TPM_DIR.mkdir(parents=True, exist_ok=True)
    if tpm_sock.exists():
        tpm_sock.unlink()
    proc = subprocess.Popen([
        "swtpm", "socket",
        "--tpmstate", f"dir={TPM_DIR}",
        "--ctrl", f"type=unixio,path={tpm_sock}",
        "--tpm2",
    ])
    for _ in range(50):
        if tpm_sock.exists():
            return proc
        time.sleep(0.1)
    raise RuntimeError("swtpm did not create its control socket")


def build_qemu_argv(boot_overlay: Path, vars_overlay: Path, qmp_sock: Path,
                     qga_sock: Path, serial_log: Path, tpm_sock: Path,
                     trace_path: Optional[Path], lun_specs: list, seed: int,
                     ram: str, cpus: str, taskset_cores: Optional[str]) -> list:
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
        "-device", "virtio-scsi-pci,id=scsi0",
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


def qmp_call(qmp, name: str, **kwargs) -> Any:
    args = {k.replace("_", "-"): v for k, v in kwargs.items()}
    msg = {"execute": name}
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


def try_dump_guest_memory(qmp, path: Path) -> bool:
    try:
        qmp_call(qmp, "dump-guest-memory", paging=False,
                 protocol=f"file:{path}", format="win-dmp")
        return True
    except Exception as exc:
        print(f"    dump-guest-memory failed (fwcfg driver not installed?): {exc}",
              file=sys.stderr)
        return False


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
             keep_all: bool, qmp_module) -> dict:
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

    make_overlay(BOOT_DISK, boot_overlay)
    make_overlay(OVMF_VARS, vars_overlay)

    lun_specs = []
    for i in range(luns):
        img = run_dir / f"lun{i}.qcow2"
        make_blank_image(img)
        lun_specs.append(LunSpec(
            index=i, image=img, file_node=f"lfile{i}", fmt_node=f"lraw{i}",
            err_node=f"lerr{i}", dev_id=f"lun{i}", serial=f"RRLUN{i}"))

    writer_duration = run_timeout_s + RELEASE_GRACE_S + 60

    argv = build_qemu_argv(boot_overlay, vars_overlay, qmp_sock, qga_sock,
                            serial_log, tpm_sock, trace_path, lun_specs,
                            tc.seed, ram, cpus, taskset_cores)

    meta = {"label": tc.label, "mode": tc.mode, "arm_gap_ms": tc.arm_gap_ms,
            "delay_ms": tc.delay_ms, "delay_max_ms": tc.delay_max_ms,
            "luns": luns, "seed": tc.seed, "argv": argv}
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    swtpm = start_swtpm(tpm_sock)
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    qmp = None
    result: dict = {"label": tc.label, "outcome": "error", "elapsed_s": 0.0,
                     "run_dir": str(run_dir), "arm_times_s": []}
    start = time.monotonic()

    try:
        for _ in range(50):
            if qmp_sock.exists():
                break
            time.sleep(0.1)
        qmp = qmp_module.QEMUMonitorProtocol(str(qmp_sock))
        qmp.connect()
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
            writer_pids.append(launch_writer(qga_sock, drive_no, writer_duration))
        result["writer_pids"] = writer_pids

        time.sleep(WRITER_SETTLE_S)

        arm_start = time.monotonic()
        for spec in lun_specs:
            qmp_call(qmp, "x-inject-error-delay-add", node_name=spec.err_node,
                     rule=rule_for(tc, spec.err_node))
            result["arm_times_s"].append(time.monotonic() - arm_start)
            if tc.arm_gap_ms:
                time.sleep(tc.arm_gap_ms / 1000.0)

        agent_alive = True
        agent_lost_t: Optional[float] = None
        last_hash = None
        last_change_t = time.monotonic()
        monitor_deadline = time.monotonic() + run_timeout_s

        while time.monotonic() < monitor_deadline:
            now = time.monotonic()
            elapsed = now - start

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
                result["dump_ok"] = try_dump_guest_memory(qmp, dump_path)
                return result

            time.sleep(POLL_INTERVAL_S)

        for spec in lun_specs:
            try:
                qmp_call(qmp, "x-inject-error-delay-release", node_name=spec.err_node,
                         disposition="complete")
            except Exception as exc:
                print(f"    release on {spec.err_node} failed: {exc}", file=sys.stderr)

        recovered = False
        release_deadline = time.monotonic() + RELEASE_GRACE_S
        while time.monotonic() < release_deadline:
            if qga_ping(qga_sock):
                recovered = True
                break
            time.sleep(1.0)

        result["outcome"] = "recovered" if recovered else "recovered-unresponsive"
        result["elapsed_s"] = time.monotonic() - start
        if not recovered:
            result["dump_ok"] = try_dump_guest_memory(qmp, dump_path)
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
        swtpm.terminate()
        try:
            swtpm.wait(timeout=5)
        except subprocess.TimeoutExpired:
            swtpm.kill()
            swtpm.wait()

        if result["outcome"] == "recovered" and not keep_all:
            for f in [boot_overlay, vars_overlay, screenshot] + [s.image for s in lun_specs]:
                f.unlink(missing_ok=True)
            if trace_path is not None:
                trace_path.unlink(missing_ok=True)
        else:
            result["screenshot"] = str(screenshot) if screenshot.exists() else None
            result["serial_log"] = str(serial_log)
            result["trace_log"] = str(trace_path) if trace_path and trace_path.exists() else None
            result["dump"] = str(dump_path) if dump_path.exists() else None


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
    ap.add_argument("--run-timeout", type=int, default=240,
                     help="seconds to watch each trial for a crash before "
                          "releasing the stalls (default: %(default)s)")
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
                           args.host_pressure_cores, args.keep_all, qmp_module)
        finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{result['outcome']} ({result['elapsed_s']:.0f}s, done {finished_at})")
        with results_path.open("a") as f:
            f.write(json.dumps(result) + "\n")
        if result["outcome"] == "crash-suspected":
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
