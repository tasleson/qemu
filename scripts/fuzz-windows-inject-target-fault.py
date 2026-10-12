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

import argparse
import base64
import collections
import dataclasses
import fcntl
import hashlib
import itertools
import json
import math
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Optional

QEMU_SRC = Path(os.environ.get("QEMU_SRC", str(Path(__file__).resolve().parents[1])))
QEMU_BUILD = Path(os.environ.get("QEMU_BUILD", str(QEMU_SRC / "build")))
QEMU_BIN = QEMU_BUILD / "qemu-system-x86_64"
QEMU_IMG = QEMU_BUILD / "qemu-img"

HOME = Path(os.environ.get("HOME", str(Path.home())))
VM_DIR = Path(os.environ.get("VM_DIR", str(HOME / "VirtualMachines" / "qemu" / "windows_inject")))
SOAK_DIR = VM_DIR / "soak-target-fault"

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
# Before post-failure collection, how hard to try the guest agent. A busy
# main loop can delay a reply by seconds, so one short ping is not enough to
# call it dead; but a dead one makes everything after it wait out
# GUEST_EXEC_TIMEOUT_S per writer -- hours at 75 LUNs.
AGENT_CHECK_ATTEMPTS = 3
AGENT_CHECK_TIMEOUT_S = 5.0

DEFAULT_RAM = "8G"
DEFAULT_CPUS = "5"
LUN_IMAGE_SIZE = "4G"

BOOT_TIMEOUT_S = 180
# Generous on purpose: at high LUN counts the agent can take a long while to
# answer -- 30s was enough to abort a 75-LUN run during writer ramp-up --
# and a timeout here ends the run. Why it goes quiet is not settled; see
# NoReplyError and the launch-failure diagnostics. A sync that goes
# unechoed is resent within this (QGA_SYNC_RESEND_S). WRITER_LAUNCH_
# TIMEOUT_S, not this, is what bounds an unattended run: a genuinely dead
# guest must not cost 75 x this before the harness gives up.
GUEST_EXEC_TIMEOUT_S = 120
WRITER_LAUNCH_TIMEOUT_S = 600
WARMUP_S = 5.0  # just long enough for guest-exec to actually launch the
                # writer before the pre-flight probe starts timing itself
QMP_CMD_TIMEOUT_S = 15
QMP_CONNECT_TIMEOUT_S = 30
DUMP_TIMEOUT_S = 900
DUMP_START_TIMEOUT_S = 300
DUMP_POLL_INTERVAL_S = 2
# A dump the harness stopped the VM for can outlive DUMP_TIMEOUT_S, and
# QEMU refuses 'cont' while it runs. How much longer to wait for it to end
# before leaving the VM paused and saying so.
DUMP_RESUME_WAIT_S = 900
STACK_CAPTURE_TIMEOUT_S = 120
# x-stop-on-broken asks for the stop right after virtio_error() prints, but
# the main loop carries it out a moment later, so a poll that has just read
# the message can still find the VM running. Give it this long to pause.
STOP_ON_BROKEN_SETTLE_S = 2.0
POLL_INTERVAL_S = 2
AGENT_SILENCE_THRESHOLD_S = 15
# How many agent silences in the soak loop get an info qtree capture of
# the agent's port (see capture_qga_port); later ones get none, unless
# the guest is declared dark.
QGA_PORT_SILENCE_CAPTURES = 5
STATIC_SCREEN_THRESHOLD_S = 20
# How long LUN writes may stop before that counts towards "the guest has
# gone dark". Only LUNs no fault is holding are watched (see IoProgress
# and FaultCycler.unfaulted), but they can still sit out a while: the guest
# resetting the faulted target can pause the whole adapter, and a request
# it already timed out is retried only after the guest's own I/O timeout.
# So: that timeout, plus the longest hold any scenario puts on a command
# (late-completion's), plus slack.
GUEST_IO_TIMEOUT_S = 60  # storport's default per-request timeout
IO_STALL_MARGIN_S = 30
DEFAULT_HEARTBEAT_S = 300  # how often to log a progress line on an hours-long run

# The pre-flight I/O probe runs before the first fault is armed, so nothing
# is held and a healthy writer shows up within seconds. The retry covers a
# writer that was slow to get going.
IO_PROBE_WINDOW_S = 10.0
IO_PROBE_ATTEMPTS = 2
MIN_WRITE_OPS_PER_S = 2.0

# After an agent request before the soak (resolving drives, launching a
# writer) went unanswered, keep watching the agent and the LUNs this long
# before calling the agent gone. No fault is armed yet, so LUNs that stop
# are not being held; the time is for a guest too starved to schedule
# qemu-ga to come back.
LAUNCH_PROBE_S = 120.0
LAUNCH_PROBE_INTERVAL_S = 5.0  # between pings; each also samples the LUNs
WRITER_COUNT_TIMEOUT_S = 60  # counting writer processes once the agent is back

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
LATE_DELAY_MS = (61000, 65000)  # just past storport's ~60s timeout
SLOW_DELAY_MS = (5000, 15000)   # slow, but answering well within it
# How many of a cycle's TMFs are kept verbatim in its record; the rest
# are only counted.
CYCLE_TMF_LINES = 40
# Arming failures in a row before the run gives up: a QEMU without
# x-scsi-fault-*, or adapters the faults can't find, fail every time.
MAX_CONSECUTIVE_ARM_FAILURES = 3

WRITER_WINDOW_BYTES = 32 * 1024 * 1024
WRITER_BLOCK_BYTES = 64 * 1024
WRITER_THREADS = 4
WRITER_QUEUE_DEPTH = 32

# Writers are budgeted to outlast the configured test duration by this much,
# so a slow boot or heartbeat overhead can never let them exit early and
# leave the back half of a multi-hour run with no I/O to delay.
WRITER_DURATION_SLACK_S = 600


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
  7. For vioscsi telemetry collection (optional, on by default): have the
     script given by --vioscsi-telemetry-script (default:
     {DEFAULT_VIOSCSI_TELEMETRY_SCRIPT}) present in the guest.
  8. Shut down cleanly.

Fault scenarios (--scenarios), each armed on one whole target per cycle:
{scenario_list()}

Each cycle in the result records what ended it: recovered (with cleared_by,
the recovery that did it, and time_to_clear_s), not-recovered (the guest
never got there within --recovery-deadline-s), window-ended, replaced
(dead-target), removed (someone else removed it over QMP), interrupted (the
harness removed every fault: for a dump, a broken virtio ring, an error or
the end of the run) or arm-failed (the run ends after
{MAX_CONSECUTIVE_ARM_FAILURES} in a row); along with the commands it held,
the recovery attempts it saw and the TMFs the guest sent the target.
scenario_summary rolls those up per scenario.

Environment overrides for running on different machines:
  QEMU_SRC, QEMU_BUILD   default to this script's own checkout
  VM_DIR                 default to $HOME/VirtualMachines/qemu/windows_inject
  OVMF_CODE              default to {OVMF_CODE}
"""


# ------------------------------------------------------------------
# QEMU guest agent client (same protocol/plumbing as the reset-race harness)
# ------------------------------------------------------------------


# A guest-sync-delimited reply, and the request that resets the agent's
# parser, are both preceded by this byte; it never occurs in JSON text.
# The agent answers the request-side byte with a parse error of its own,
# which the sync skips like any other reply that isn't its echo.
QGA_SENTINEL = b"\xff"


def _qga_request(execute: str, arguments: Optional[dict] = None) -> bytes:
    msg: dict = {"execute": execute}
    if arguments is not None:
        msg["arguments"] = arguments
    return (json.dumps(msg) + "\n").encode()


# A sync the agent never saw -- run-1791557706 lost one about 10s after the
# boot ping had answered, with no load on the guest at all -- would
# otherwise cost the call its whole timeout. After this long without an
# echo, send another. Only ever the sync: the command that follows it may
# not be idempotent (guest-exec isn't).
QGA_SYNC_RESEND_S = 5.0


# The format of qemu.log's trace timestamps, to line up against them.
UTC_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime(UTC_FORMAT)


def wall_time(mono: float) -> str:
    """A time.monotonic() reading from the past, as utc_now() would have
    put it then."""
    then = time.time() - (time.monotonic() - mono)
    return datetime.fromtimestamp(then, timezone.utc).strftime(UTC_FORMAT)


@dataclasses.dataclass
class QgaSync:
    """How the guest-sync-delimited ahead of one agent command went."""
    syncs_sent: int = 0
    # From the first sync sent to the first echo of any of ours, or None.
    first_echo_s: Optional[float] = None
    # The first echo was for a sync we had already resent: that one was
    # slow, not lost.
    first_echo_stale: bool = False

    def slow(self) -> bool:
        return (self.syncs_sent > 1 or (self.first_echo_s is not None and
                                        self.first_echo_s > QGA_SYNC_RESEND_S))

    def describe(self) -> str:
        echo = ("no echo" if self.first_echo_s is None else
                f"first echo after {self.first_echo_s:.1f}s"
                + (" (for an earlier sync)" if self.first_echo_stale else ""))
        return f"{self.syncs_sent} sync(s) sent, {echo}"


class _QgaReplies:
    """The agent's replies on one connection, read up to a caller-chosen
    point in time, so the sync can give up waiting and resend."""

    def __init__(self, s: socket.socket):
        self.s = s
        self.buf = b""
        self.pending: collections.deque = collections.deque()
        self.eof = False

    def next(self, until: float) -> Optional[dict]:
        while not self.pending:
            remaining = until - time.monotonic()
            if self.eof or remaining <= 0:
                return None
            self.s.settimeout(remaining)
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                self.eof = True
                return None
            # The sentinel only marks where a reply starts, so treating it
            # as a line break also throws away any half-written stale reply.
            self.buf += chunk.replace(QGA_SENTINEL, b"\n")
            *lines, self.buf = self.buf.split(b"\n")
            for line in lines:
                try:
                    resp = json.loads(line)
                except ValueError:
                    continue
                if isinstance(resp, dict) and ("return" in resp or
                                               "error" in resp):
                    self.pending.append(resp)
        return self.pending.popleft()


def _qga_call(sock_path: Path, execute: str, arguments: Optional[dict],
              timeout: float
              ) -> tuple[Optional[dict], Optional[str], QgaSync]:
    """Run one guest agent command: (reply, None, sync), or (None, stage,
    sync) where stage is how far it got -- "connect" (the socket could not
    be reached), "sync" (no echo of any guest-sync-delimited we sent, so
    the command was never sent) or "command" (synced, but the command
    itself got no reply). sync says how the synchronization went.

    The agent's virtio-serial channel outlives our connection: a reply to
    a request whose client gave up -- timed out, or asked while the VM was
    paused -- is still delivered, to whoever connects next, and would be
    taken for the answer to the next command. So first synchronize with
    guest-sync-delimited, as the agent's protocol asks, and drop
    everything up to the echo of our own token. The agent answers in
    order, so the next reply after that is ours.

    A sync with no echo after QGA_SYNC_RESEND_S is resent with a fresh
    token, while the timeout leaves a resend the time to be answered. Only
    the echo of the latest token counts as synced: each earlier sync, and
    the parse error each sentinel draws, gets its own reply first, and any
    of those would be taken for the command's. Once an echo of ours shows
    how long the agent takes to answer, the latest sync is given that long
    on top before it counts as lost -- so an agent that is merely slow is
    waited on, not chased with ever more syncs, while one that dropped the
    latest sync after answering an earlier one still gets another.
    """
    deadline = time.monotonic() + timeout
    sync = QgaSync()
    tokens: list = []
    stage = "connect"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(sock_path))
            stage = "sync"
            replies = _QgaReplies(s)

            sent_at: dict = {}  # token -> when it was sent

            def send_sync() -> float:
                tokens.append(random.getrandbits(63))
                s.sendall(QGA_SENTINEL + _qga_request(
                    "guest-sync-delimited", {"id": tokens[-1]}))
                sync.syncs_sent += 1
                sent_at[tokens[-1]] = time.monotonic()
                return sent_at[tokens[-1]]

            first_sent = last_sent = send_sync()
            latency = 0.0  # of the most recent echo of ours, once there is one
            while True:
                resend_at = last_sent + latency + QGA_SYNC_RESEND_S
                resending = resend_at + QGA_SYNC_RESEND_S <= deadline
                resp = replies.next(resend_at if resending else deadline)
                if resp is None:
                    if replies.eof or time.monotonic() >= deadline:
                        return None, stage, sync
                    if resending:
                        last_sent = send_sync()
                    continue
                ret = resp.get("return")
                if isinstance(ret, int) and ret in sent_at:
                    now = time.monotonic()
                    latency = now - sent_at[ret]
                    if sync.first_echo_s is None:
                        sync.first_echo_s = round(now - first_sent, 1)
                        sync.first_echo_stale = ret != tokens[-1]
                    if ret == tokens[-1]:
                        break
            stage = "command"
            s.sendall(_qga_request(execute, arguments))
            resp = replies.next(deadline)
            return resp, (None if resp is not None else stage), sync
    except (OSError, ConnectionError):
        return None, stage, sync


def qga_call(sock_path: Path, execute: str, arguments: Optional[dict] = None,
             timeout: float = 5.0) -> Optional[dict]:
    """Run one guest agent command and return its reply, or None. See
    _qga_call for the protocol, and for which stage went unanswered."""
    return _qga_call(sock_path, execute, arguments, timeout)[0]


def qga_ping(sock_path: Path, timeout: float = 2.0) -> bool:
    resp = qga_call(sock_path, "guest-ping", timeout=timeout)
    return resp is not None and "return" in resp


class GuestExecError(RuntimeError):
    """A guest-exec request that did not come back with a pid.

    The message distinguishes which of two very different failures
    happened, because they call for opposite responses. If the agent
    refused the request, the command or the guest is wrong. If the agent
    never answered, the command may be fine and the process may even be
    running, with only the reply lost. Collapsing both into "failed to
    launch" sends you looking for a bug in the wrong place.
    """


class NoReplyError(GuestExecError):
    """The agent never answered: the second case above. stage says how far
    the request got (see _qga_call): at "sync" none of the syncs we sent
    was echoed, so nothing came back over the channel and the command
    never went out; at "command" the channel worked both ways and only
    the command went unanswered. sync is how the synchronization went, and
    command the agent command that went unanswered: the guest-exec itself,
    or a guest-exec-status poll while waiting for it."""

    def __init__(self, message: str, stage: str, sync: QgaSync,
                 command: str = "guest-exec"):
        super().__init__(message)
        self.stage = stage
        self.sync = sync
        self.command = command


def qga_exec(sock_path: Path, what: str, path: str, args: list, capture: bool,
             timeout: float = GUEST_EXEC_TIMEOUT_S,
             resyncs: Optional[list] = None) -> int:
    """Run path in the guest and return its pid. A sync that needed
    resending, or was slow to come back, is reported on stderr and
    appended to resyncs if given -- the call still worked, but that is
    the stall the resend exists for, and how long it lasted."""
    resp, stage, sync = _qga_call(sock_path, "guest-exec",
                                  {"path": path, "arg": args,
                                   "capture-output": capture}, timeout)
    if resp is None:
        if stage == "connect":
            why = (f"could not reach the guest agent's socket {sock_path}, "
                   f"so the request to run {path!r} was never sent")
        elif stage == "sync":
            why = (f"the guest agent never answered any of the "
                   f"{sync.syncs_sent} guest-sync-delimited sent ahead of it "
                   f"over {timeout:.0f}s, so the request to run {path!r} was "
                   f"never sent")
        else:
            why = (f"the guest agent answered the sync ({sync.describe()}) "
                   f"but not the request to run {path!r} within "
                   f"{timeout:.0f}s; it was sent, so the process may have "
                   f"started and only the reply been lost")
        raise NoReplyError(f"guest-exec ({what}): {why}", stage, sync)
    if sync.slow():
        print(f"    guest agent: {sync.describe()} ({what})", file=sys.stderr)
        if resyncs is not None:
            resyncs.append({"at": utc_now(), "request": what,
                            **dataclasses.asdict(sync)})
    if "error" in resp:
        err = resp["error"] if isinstance(resp["error"], dict) else {}
        raise GuestExecError(
            f"guest-exec ({what}): the guest agent refused to run {path!r}: "
            f"{err.get('class', '?')}: {err.get('desc', resp['error'])}")
    pid = resp.get("return", {}).get("pid")
    if pid is None:
        raise GuestExecError(
            f"guest-exec ({what}): the guest agent accepted {path!r} but "
            f"returned no pid: {resp!r}")
    return pid


def qga_exec_wait(sock_path: Path, pid: int, timeout: float,
                  silent_raises: Optional[str] = None) -> Optional[dict]:
    """Poll guest-exec-status until pid exits; its status, or None.

    None folds together a process still running and an agent that stopped
    answering the polls. With silent_raises -- the request's name, for the
    message -- a wait that ends on the second, the last poll unanswered and
    none answered for AGENT_SILENCE_THRESHOLD_S, raises NoReplyError
    instead, so it can be diagnosed like an unanswered guest-exec. An agent
    that kept saying "not exited" still gets None."""
    start = time.monotonic()
    deadline = start + timeout
    last_answer = start  # the guest-exec that started pid was answered
    stage: Optional[str] = None
    sync = QgaSync()
    while time.monotonic() < deadline:
        resp, stage, sync = _qga_call(sock_path, "guest-exec-status",
                                      {"pid": pid}, 5.0)
        if resp is not None:
            last_answer = time.monotonic()
            if "return" in resp and resp["return"].get("exited"):
                return resp["return"]
        time.sleep(0.3)
    silent_s = time.monotonic() - last_answer
    if (silent_raises is not None and stage is not None
            and silent_s >= AGENT_SILENCE_THRESHOLD_S):
        raise NoReplyError(
            f"guest-exec-status ({silent_raises}): the guest agent stopped "
            f"answering the status polls for pid {pid}: none answered in the "
            f"last {silent_s:.0f}s of the {timeout:.0f}s wait (last poll: no "
            f"reply at {stage}, {sync.describe()})", stage, sync,
            "guest-exec-status")
    return None


def b64_text(data: Optional[str]) -> str:
    if not data:
        return ""
    return base64.b64decode(data).decode("utf-8", errors="replace")


def encode_ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def ps_exec(sock_path: Path, what: str, script: str, capture: bool,
            timeout: float = GUEST_EXEC_TIMEOUT_S,
            resyncs: Optional[list] = None) -> int:
    args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", encode_ps(script)]
    return qga_exec(sock_path, what, PS_EXE, args, capture=capture,
                     timeout=timeout, resyncs=resyncs)


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


RESOLVE_REQUEST = "resolve disk numbers"


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


def launch_writer(qga_sock: Path, drive_number: int, duration_s: float,
                   io_driver: str = "powershell",
                   diskspd_path: str = DEFAULT_DISKSPD_PATH,
                   fio_path: str = DEFAULT_FIO_PATH,
                   resyncs: Optional[list] = None) -> int:
    what = f"writer for PhysicalDrive{drive_number}"
    if io_driver == "diskspd":
        return qga_exec(qga_sock, what, diskspd_path,
                         build_diskspd_args(drive_number, duration_s),
                         capture=False, resyncs=resyncs)
    if io_driver == "fio":
        return qga_exec(qga_sock, what, fio_path,
                         build_fio_args(drive_number, duration_s),
                         capture=False, resyncs=resyncs)
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


def capture_vioscsi_telemetry(qga_sock: Path, script_path: str, out_path: Path,
                               timeout: float = VIOSCSI_TELEMETRY_TIMEOUT_S
                               ) -> tuple[bool, str]:
    """Run the guest's vioscsi telemetry PowerShell script and save its
    output to out_path on the host. Returns (ok, status message). Never
    raises -- a telemetry capture failure (e.g. the guest going dark right
    as a crash is suspected) shouldn't abort the harness, just get
    recorded as a short status; the caller decides whether to grab a
    postmortem dump."""
    try:
        pid = qga_exec(qga_sock, "vioscsi telemetry", PS_EXE,
                        ["-NoProfile", "-NonInteractive", "-File", script_path],
                        capture=True, timeout=timeout)
    except GuestExecError as exc:
        msg = str(exc)
        out_path.write_text(msg + "\n")
        return False, msg
    status = qga_exec_wait(qga_sock, pid, timeout=timeout)
    if status is None:
        msg = f"telemetry script timed out after {timeout:.0f}s"
        out_path.write_text(msg + "\n")
        return False, msg
    out = b64_text(status.get("out-data"))
    err = b64_text(status.get("err-data"))
    text = out
    if err:
        text += f"\n--- stderr ---\n{err}"
    out_path.write_text(text)
    ok = status.get("exitcode") == 0 and bool(out.strip())
    return ok, f"exitcode={status.get('exitcode')}, saved to {out_path}"


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
            try:
                qga_exec(qga_sock, f"taskkill pid {st['pid']}", TASKKILL_EXE,
                          ["/F", "/PID", str(st["pid"])], capture=False)
            except GuestExecError:
                pass  # best-effort; wait_for_writers reports what survived
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


def build_qemu_argv(boot_overlay: Path, vars_overlay: Path, qmp_sock: Path,
                     qga_sock: Path, serial_log: Path, tpm_sock: Path,
                     adapters: int, lun_specs: list, ram: str,
                     cpus: str, taskset_cores: Optional[str],
                     iothreads: Optional[int] = None,
                     tmf_trace: bool = True,
                     stop_on_broken: bool = True,
                     ring_diag: bool = True,
                     qga_trace: bool = True) -> list:
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


# What HMP "info qtree" prints for each virtio-serial port
# (virtser_bus_dev_print) -- the only place QEMU reports a port throttled.
QTREE_PORT_RE = re.compile(r"port (\d+), guest (on|off), host (on|off), "
                           r"throttle (on|off)")
QTREE_NAME_RE = re.compile(r'^\s*name = "(.*)"$')


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


# virtio_error() in hw/virtio/virtio.c is how QEMU reacts to a guest that
# puts something impossible in a virtqueue. It does not just complain: it
# sets VIRTIO_CONFIG_S_NEEDS_RESET and vdev->broken, and virtqueue_pop()
# then refuses to touch that device's queues ever again (see the
# vdev->broken checks in virtio.c). So the device is dead for the rest of
# the run, and every LUN behind it silently stops doing I/O.
#
# There is no QMP way to ask for this. 'broken' is not a QOM property, and
# x-query-virtio-status -- the obvious candidate -- aborts QEMU outright on
# this tree (visit_start_struct assertion, reproducible on any virtio
# device on a bare -S VM), so it cannot be used here. What is left, and is
# in fact perfectly reliable, is QEMU's own stderr, which the harness
# already captures. These are virtio_error()'s messages from virtio.c (the
# generic ring handling) plus virtio-scsi.c, with the printf escapes
# loosened.
VIRTIO_BROKEN_PATTERNS = tuple(re.compile(p) for p in (
    r"virtio: zero sized buffers are not allowed",
    r"virtio: too many write descriptors in",
    r"virtio: bogus descriptor or out of resources",
    r"virtio: queue \d+ size \d+ exceeds max size",
    r"Desc next is \d+",
    r"Invalid size for indirect buffer table",
    r"Incorrect order for descriptors",
    r"Cannot map descriptor ring",
    r"Cannot map indirect buffer",
    r"Looped descriptor",
    r"Region caches not initialized",
    r"Virtqueue size exceeded",
    r"Guest moved used index from \d+ to \d+",
    r"Guest says index \d+ is available",
    r"VQ \d+ size 0x[0-9a-f]+ Guest index 0x[0-9a-f]+",
    r"wrong size for virtio-scsi headers",
))


# Tracepoints enabled with --tmf-trace (the default). Every one carries
# bus=scsiN.0, so each line can be pinned to an adapter. With the log
# trace backend they go to stderr -- the same stream, and with
# "-msg timestamp=on" the same clock, as virtio_error()'s messages -- so
# qemu.log reads as one ordered timeline of what each adapter was asked
# to do right up to the moment it broke.
#
# The rest explain a break when one happens, and are quiet otherwise: TMF
# and drain snapshots (a line or two per reset), the chain the device
# failed on and what it looked like when published (only at a break), and
# requests popped while the device still held one with the same command
# header or head (capped at 256 lines per adapter; the count keeps going in
# the snapshot and verdict lines). virtqueue_chain_* comes from the virtio
# core and names the adapter by proxy id (dev=scsi0) rather than bus.
TMF_TRACE_EVENTS = ("virtio_scsi_tmf_*", "virtio_scsi_reset",
                    "virtio_scsi_broken", "virtio_scsi_broken_*",
                    "virtio_scsi_drain_*", "virtio_scsi_req_overlap",
                    "virtio_scsi_stop_on_broken", "virtqueue_chain_*")
TRACE_LINE_RE = re.compile(r"^(?:(\S+Z) )?(virtio_scsi|virtqueue_chain)_(\w+) ")

# The target faults' tracepoints the harness always enables (see
# build_qemu_argv): the fault being armed, each recovery attempt on it and
# what the fault made of it, and the fault clearing. Not scsi_fault_hold
# and scsi_fault_release, which fire per command -- tens of thousands of
# lines in a late-completion window.
FAULT_TRACE_EVENTS = ("scsi_fault_add", "scsi_fault_recovery",
                      "scsi_fault_clear")
FAULT_TRACE_LINE_RE = re.compile(r"^(?:(\S+Z) )?scsi_fault_(\w+) ")
# Diagnostic lines: attached to the broken event they explain, or tallied
# separately, rather than counted with the TMFs or kept as TMF context.
DIAG_EVENTS = ("broken_verdict", "broken_before", "broken_before_detail",
               "broken_before_entry", "req_overlap", "tmf_snapshot",
               "drain_begin", "drain_snapshot", "stop_on_broken")

# Tracepoints enabled with --qga-trace (the default): the guest agent's
# virtio-serial port, seen from QEMU. In run-1791602155 qemu-ga sat 56
# minutes in one 81-byte write to that port, and vioser completes a write
# only once QEMU hands the buffer back. These say whether QEMU ever got it
# and what became of it: each guest write as it reaches the chardev
# (flush_buf; out_len < in_len means the socket refused some and the port
# is now throttled, holding the buffer), the port being throttled and
# released, and our client connecting and leaving (chr_event). A few lines
# per agent call, on the same clock as the TMFs.
#
# A client leaving releases a throttled port without a throttle line:
# virtio_serial_close() clears the flag itself and throws the held buffer
# away (discard_throttle_data detaches it, so the guest never gets it
# back). Hence QemuStderr's closed_while_throttled. chr_socket_poll_err
# marks the rarer order, where the write itself finds the socket dead with
# no read pending and disconnects inside flush_buf -- the close, and the
# discard, come before that write's own flush_buf line.
QGA_TRACE_EVENTS = ("virtio_console_flush_buf", "virtio_serial_throttle_port",
                    "virtio_console_chr_event", "chr_socket_poll_err")
QGA_TRACE_LINE_RE = re.compile(r"^(?:(\S+Z) )?(" + "|".join(QGA_TRACE_EVENTS)
                               + r") ")
QGA_TRACE_FIELD_RE = re.compile(r"(\w+) (-?\d+)")
CHR_SOCKET_LABEL_RE = re.compile(r"\((\S+)\)$")
# include/chardev/char.h, QEMUChrEvent
CHR_EVENTS = {0: "break", 1: "opened", 2: "mux_in", 3: "mux_out",
              4: "closed"}

# What virtio_scsi_broken_verdict says happened to the request the ring
# broke on, comparing its first sighting while pending (at a TMF or during a
# drain) with what the device read. See virtio_scsi_diag_broken() in
# hw/scsi/virtio-scsi.c.
VERDICT_MEANINGS = {
    "zeroed": "valid while pending, all zeros when the device read it: the "
              "guest rewrote a request it had already handed over (the "
              "signature of an early-completed SRB whose extension, and so "
              "its indirect table, BuildIo zeroed)",
    "rewritten": "valid while pending, different when the device read it: "
                 "the guest reused the request's memory while it was still "
                 "queued (check the entries for another request's shape, or "
                 "for garbage, which would mean a stray write)",
    "head-changed": "the avail slot named a different descriptor when read "
                    "than while pending: guest ring bookkeeping",
    "no-snapshot": "never seen pending, so there is nothing to compare: "
                   "published and consumed outside any TMF or drain",
    "no-chain": "broke on something other than a descriptor chain (e.g. "
                "request headers of the wrong size)",
    "not-request": "broke on the control or event queue, not a request queue",
    "unreadable": "part of the chain points at memory that isn't RAM (MMIO "
                  "or unmapped), so there was nothing to read or compare: a "
                  "garbage descriptor address -- see addr in the chain record",
    "diag-off": "run with --no-ring-diag, so nothing was recorded to compare; "
                "the chain record still shows what the device failed on",
}

# Where the "before" picture of the failing entry was taken. Only a kick
# seen during a drain is (to within microseconds) the moment the guest
# published it; the other two are taken at the reset, and the entry may have
# been published -- and changed -- any time before that.
FIRST_SIGHT = {
    "kick": "as the guest published it (a kick during the reset's drain)",
    "drain": "only when the reset's drain began",
    "tmf": "only when the TMF arrived",
}


def first_sight(before: dict) -> str:
    where = FIRST_SIGHT.get(before.get("source"), "at an unknown point")
    age_ms = int(before.get("age_us", 0)) / 1000
    return f"first seen {where}, {age_ms:.1f} ms before the device read it"


def explain_break(ev: dict) -> str:
    verdict = ev.get("verdict")
    if verdict is None:
        return "no verdict traced (QEMU without the diagnostics?)"
    before = ev.get("before", {})
    if verdict == "unchanged":
        zero = int(before.get("zero_len", 0))
        if not zero:
            meaning = ("failed exactly as first seen, with nothing "
                       "zero-length in it: look at QEMU")
        elif before.get("source") == "kick":
            meaning = (f"failed exactly as the guest published it, with {zero} "
                       "zero-length element(s) already in it: the driver "
                       "built the request that way")
        else:
            meaning = (f"failed exactly as first seen, with {zero} "
                       "zero-length element(s) already in it -- but it was "
                       "first seen at the reset, not as published, so it "
                       "could have been published intact and changed before "
                       "then; this does not rule out a rewrite")
    else:
        meaning = VERDICT_MEANINGS.get(verdict, "unknown verdict")
    if ev.get("verdict_detail", {}).get("head_inflight") == "1":
        meaning += ("; the failing head was also still in flight in QEMU, "
                    "so the guest re-published a descriptor it never got back")
    return meaning
TRACE_FIELD_RE = re.compile(r"(\w+)=(\S+)")
TRACE_CONTEXT_LINES = 20  # per-adapter history attached to a broken event

# include/standard-headers/linux/virtio_scsi.h
TMF_SUBTYPES = {0: "abort_task", 1: "abort_task_set", 2: "clear_aca",
                3: "clear_task_set", 4: "i_t_nexus_reset",
                5: "logical_unit_reset", 6: "query_task",
                7: "query_task_set"}
TMF_RESPONSES = {0: "ok", 2: "aborted", 3: "bad_target", 4: "reset",
                 5: "busy", 9: "failure", 10: "function_succeeded",
                 11: "function_rejected", 12: "incorrect_lun"}
VIRTIO_SCSI_QUEUE_KINDS = {0: "control", 1: "event"}  # 2+ are request queues
# TMF tracepoints that name a target, and so can be pinned to a fault cycle
CYCLE_TMF_EVENTS = ("tmf_req", "tmf_resp", "tmf_hang", "tmf_drop",
                    "tmf_delay")


class CycleTrace:
    """The trace lines that belong to one fault cycle: TMFs the guest sent
    to the faulted target, and what the fault made of each recovery
    attempt (scsi_fault_recovery's action). Fed by QemuStderr while the
    cycle is watched; lines stamped before the fault was armed are
    skipped, since QemuStderr only reads the log once per poll."""

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
                or fields.get("target") != str(self.target)
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


def lun_activity_by_adapter(qmp, lun_specs: list, window_s: float) -> dict:
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
    is not the test."""
    before = write_ops_by_node(qmp)
    time.sleep(window_s)
    after = write_ops_by_node(qmp)
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


def count_guest_processes(qga_sock: Path, exe_path: str,
                          timeout: float = WRITER_COUNT_TIMEOUT_S
                          ) -> Optional[int]:
    """How many processes the guest is running from exe_path's image name,
    or None if the agent could not say."""
    name = PureWindowsPath(exe_path).stem.replace("'", "''")
    script = f"@(Get-Process -Name '{name}' -ErrorAction SilentlyContinue).Count"
    try:
        pid = ps_exec(qga_sock, f"count of {name} processes", script,
                      capture=True, timeout=timeout)
    except GuestExecError:
        return None
    status = qga_exec_wait(qga_sock, pid, timeout)
    if status is None:
        return None
    try:
        return int(b64_text(status.get("out-data")).strip())
    except ValueError:
        return None


def _lun_writes_phrase(writes: dict, complete: bool) -> str:
    # "With writes", not "live": an adapter that stopped popping still
    # completes the requests it had already started.
    with_writes = sum(1 for n in writes.values() if n)
    phrase = (f"{sum(writes.values())} LUN writes completed meanwhile, with "
              f"writes on {with_writes}/{len(writes)} adapter(s)")
    if not complete:
        phrase += " (some query-blockstats samples failed)"
    return phrase


def _covers_luns(wops: dict, lun_specs: list) -> bool:
    """Whether a write_ops_by_node() sample can be trusted for a delta.

    It swallows QMP failures per view, and only the device view carries a
    LUN's accounting -- the node view's wr_operations is 0 -- so a sample
    whose device-view query failed comes back non-empty and all zero.
    That reads as "no I/O", and makes the next good sample look like
    every write since boot."""
    return all(s.dev_id in wops for s in lun_specs)


def no_faults_armed() -> None:
    """try_dump_guest_memory's disarm for dumps taken before the soak,
    which is when the first fault is armed."""


def diagnose_launch_failure(diag: dict, persist, qmp, qga_sock: Path,
                            qemu_pid: int, run_dir: Path, lun_specs: list,
                            launched: int, probe_s: float,
                            writer_exe: Optional[str], screenshot: Path,
                            dump_path: Path, dump_at_failure: bool = False
                            ) -> str:
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
    prev: Optional[dict] = write_ops_by_node(qmp)
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
        cur = write_ops_by_node(qmp)
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


@dataclasses.dataclass(frozen=True)
class Scenario:
    """One way of making a target misbehave.

    ends says what ends a cycle: "recovery" waits for the guest's recovery
    to clear the fault and gives up after --recovery-deadline-s; "window"
    and "dead" faults only clear when removed, which the harness does after
    --window-s or --dead-target-s."""
    name: str
    ends: str
    summary: str
    options: Callable[[FaultSettings], dict]

    def limit_s(self, settings: FaultSettings) -> float:
        return {"recovery": settings.recovery_deadline_s,
                "window": settings.window_s,
                "dead": settings.dead_target_s}[self.ends]

    def longest_hold_ms(self, settings: FaultSettings) -> int:
        """Longest a command can be held before it runs on its own: a
        delay fault's upper bound, 0 for a stall (the fault, not time,
        decides)."""
        return self.options(settings).get("delay-max-ms", 0)


# Each cycle arms one of these on a whole target (every LUN behind it).
# Outcomes per ends: "recovery" -> recovered (by the level in cleared_by)
# or not-recovered; "window" -> window-ended; "dead" -> replaced. Any
# cycle can also end removed (a manual clear the harness didn't make),
# interrupted (the harness removed every fault: for a dump, a broken
# virtio ring, an error or the end of the run) or arm-failed.
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
]
SCENARIOS_BY_NAME = {sc.name: sc for sc in SCENARIOS}

CYCLE_END_OUTCOMES = {"recovery": "not-recovered", "window": "window-ended",
                      "dead": "replaced"}

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
    on; the harness uses no others -- and either ends the current cycle
    (cleared, or out of time), refreshes its x-scsi-fault-list snapshot,
    or arms the next one once the cooldown is over. So cycle times are
    only as fine as the loop's period (a few seconds), except
    time_to_clear_s, which comes from the event's own timestamp."""

    def __init__(self, scenarios: list, settings: FaultSettings,
                 adapters: int, targets: int, seed: int, start: float,
                 stderr: "QemuStderr", tmf_trace: bool):
        self.scenarios = scenarios
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
        self._next = itertools.cycle(scenarios)
        self._cleared: dict = {}
        self._done: set = set()
        # (device, id) of faults a failed QMP call may have left armed;
        # removed before the next one is armed.
        self._orphans: dict = {}
        self._arm_failures = 0

    def begin(self, qmp, now: float) -> None:
        """Start cycling. Events queued since QMP connected -- boot's own
        resets among them -- are counted apart from the soak's."""
        try:
            events = qmp.get_events(wait=False)
        except Exception:
            events = []
        self.pre_soak_events.update(ev.get("event", "?") for ev in events)
        self.next_arm_t = now

    # -- event handling -------------------------------------------------

    def pump_events(self, qmp) -> None:
        try:
            events = qmp.get_events(wait=False)
        except Exception as exc:
            print(f"    reading QMP events failed: {exc!r}", file=sys.stderr)
            return
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
        cur = self.current
        if cur is not None:
            ev = self._cleared.pop((cur["device"], cur["fault_id"]), None)
            if ev is not None:
                self._finish(cur, ev, now)
            elif now >= cur["end_t"]:
                self._remove(qmp, cur, CYCLE_END_OUTCOMES[cur["ends"]], now)
            else:
                self._snapshot(qmp, cur)
        elif (self.disarmed is None and self.next_arm_t is not None
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
        target = self.rng.randrange(self.targets)
        fault = {"id": f"c{index}-{sc.name}", "target": target,
                 **sc.options(self.settings)}
        cur = {"index": index, "scenario": sc.name, "ends": sc.ends,
               "adapter": adapter, "target": target,
               "device": f"scsi{adapter}", "fault_id": fault["id"],
               "fault": fault, "armed_at": utc_now(),
               "armed_epoch": time.time(),
               "armed_s": round(now - self.start, 1),
               "armed_t": now, "end_t": now + sc.limit_s(self.settings)}
        trace = CycleTrace(f"scsi{adapter}.0", target, fault["id"],
                           cur["armed_at"])
        self.stderr.watch(trace)
        cur["trace"] = trace
        try:
            qmp_call(qmp, "x-scsi-fault-add", device=cur["device"],
                     fault=fault)
        except Exception as exc:
            self.stderr.unwatch(trace)
            del cur["trace"]
            cur["error"] = repr(exc)
            # Unanswered rather than refused, it may be armed after all.
            self._orphans[(cur["device"], fault["id"])] = repr(exc)
            self._remove_orphans(qmp)
            self._record(cur, "arm-failed", now)
            self._arm_failures += 1
            if self._arm_failures >= MAX_CONSECUTIVE_ARM_FAILURES:
                self.disarmed = (f"arming failed {self._arm_failures} times "
                                 f"in a row, last: {exc!r}")
                raise FaultArmError(f"target faults: {self.disarmed}")
            return
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
        cur.pop("armed_epoch", None)
        cur.pop("end_t", None)
        self._done.add((cur["device"], cur["fault_id"]))
        self.cycles.append(cur)
        self.current = None
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
        return {k: v for k, v in cur.items()
                if k not in ("trace", "armed_t", "armed_epoch", "end_t")}

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
        else:
            head += f"{outcome} after {cur['duration_s']:.0f}s"
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
        return (head + f"; {held}"
                + (f", recovery attempts {actions}" if actions else
                   ", no recovery attempts")
                + (f", TMFs {reqs}" if reqs else ""))

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
             qga_trace: bool = True) -> dict:
    run_dir = SOAK_DIR / f"run-{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    # LUN images (the disks under I/O test) may live on a different
    # filesystem than the rest of the run artifacts.
    lun_dir = disk_dir if disk_dir is not None else run_dir
    lun_dir.mkdir(parents=True, exist_ok=True)
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
    break_dump_path = run_dir / "break.dmp"
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
        # Stop the writers first: they're still live (see stop_writers'
        # docstring), and leaving them running races the telemetry query
        # against a guest saturated with I/O.
        result["writer_states"] = stop_writers(qga_sock, writer_pids)
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
            dump_now)
        diag["summary"] = summary
        print(f"    {summary}", file=sys.stderr)
        if diag.get("vm_paused"):
            dump_if_stopped_on_broken()

    try:
        make_overlay(BOOT_DISK, boot_overlay)
        make_overlay(OVMF_VARS, vars_overlay)

        for a in range(adapters):
            for t in range(targets):
                for l in range(luns_per_target):
                    tag = f"{a}-{t}-{l}"
                    img = lun_dir / f"lun{tag}-{run_dir.name}.qcow2"
                    make_blank_image(img)
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
                                stop_on_broken, ring_diag, qga_trace)

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
                "argv": argv}
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
                writer_pids.append(launch_writer(qga_sock, drive_no,
                                                  writer_duration, io_driver,
                                                  diskspd_path, fio_path,
                                                  qga_resyncs))
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
            w_before = write_ops_by_node(qmp)
            time.sleep(IO_PROBE_WINDOW_S)
            w_after = write_ops_by_node(qmp)
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
        result["writer_states"] = writer_states(qga_sock, writer_pids)
        result["pre_test_write_ops_per_s"] = wps_per_lun
        result["pre_test_write_ops_per_s_total"] = round(total_wps, 1)
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
                f"writers are not driving I/O: only {total_wps:.1f} write ops/s "
                f"across all {total_luns} LUN(s) (need >= {MIN_WRITE_OPS_PER_S}). "
                f"Check --io-driver / --diskspd-path / --fio-path; writer "
                f"states: {result['writer_states']}.{diag}")
            collect_vioscsi_telemetry()
            return result

        print(f"    soak running: {duration_s / 3600:.1f}h, {total_wps:.1f} wps "
              f"across {total_luns} LUN(s) ({adapters} adapter(s) x {targets} "
              f"target(s) x {luns_per_target} lun(s)), scenarios "
              f"{', '.join(sc.name for sc in scenarios)}, heartbeat every "
              f"{heartbeat_s:.0f}s")

        test_start = time.monotonic()
        monitor_deadline = test_start + duration_s
        last_heartbeat = test_start
        prev_wops = write_ops_by_node(qmp)

        qemu_stderr = QemuStderr(qemu_log_path)
        qemu_stderr.poll()
        # Firmware, driver init and the pre-flight probe all issue resets
        # and TMFs of their own (each adapter resets three times on a bare
        # boot). Keep those apart so the soak's tallies mean something.
        # Any virtio_error() already seen stays pending and is reported on
        # the first pass of the loop below -- an adapter that broke during
        # pre-flight is just as broken.
        result["tmf_trace_pre_soak"] = qemu_stderr.take_counts()

        cycler = FaultCycler(scenarios, settings, adapters, targets, seed,
                             start, qemu_stderr, tmf_trace)
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

        while time.monotonic() < monitor_deadline:
            now = time.monotonic()
            elapsed = now - start

            qemu_stderr.poll()
            broken_lines = qemu_stderr.take_broken()
            if broken_lines:
                result["outcome"] = "virtio-broken"
                result["elapsed_s"] = elapsed
                result["qemu_stderr"] = qemu_stderr.lines
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
                    act = lun_activity_by_adapter(qmp, lun_specs, window_s)
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

            cycler.tick(qmp, now)

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

            io_progress.update(now, write_ops_by_node(qmp),
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
                cur_wops = write_ops_by_node(qmp)
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
                      f"{elapsed / 3600:.2f}h elapsed, {wps:.1f} wps, "
                      f"{faults['cycles_done']} cycle(s) done, {now_phrase}, "
                      f"TMFs={qemu_stderr.tmf_requests()}")
                write_status(hb)

            time.sleep(POLL_INTERVAL_S)

        result["outcome"] = "completed"
        result["elapsed_s"] = time.monotonic() - start
        # Before telemetry, which stops the writers: they can't finish
        # while a target holds their I/O.
        disarm("end of run")
        record_trace()
        collect_vioscsi_telemetry()
        write_status({"elapsed_s": result["elapsed_s"]})
        return result

    except Exception as exc:
        result["outcome"] = "error"
        result["error"] = str(exc)
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
                     default=True,
                     help="pause the VM the moment a virtio-scsi ring breaks "
                          "(x-stop-on-broken), dump guest memory to break.dmp "
                          "while the failing request is still where the "
                          "driver left it, then resume. The dump removes "
                          "every target fault and no more are armed "
                          "(default: on)")
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
    ap.add_argument("--iothreads", type=int, default=None,
                     help="number of QEMU iothreads to create, assigned "
                          "round-robin to the adapters (default: one per "
                          "adapter). 0 leaves all adapter I/O in QEMU's main "
                          "loop, where it contends with the guest agent and "
                          "QMP -- useful only to reproduce an old run")
    ap.add_argument("--adapters", type=int, default=1,
                     help="number of vioscsi (virtio-scsi-pci) adapters to "
                          "create (default: %(default)s); --targets and "
                          "--luns-per-target apply to each adapter")
    ap.add_argument("--targets", type=int, default=2,
                     help="number of SCSI targets per adapter (default: "
                          "%(default)s). Faults are per target, and the "
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
    ap.add_argument("--scenarios", default=",".join(SCENARIOS_BY_NAME),
                     help="comma list of fault scenarios to rotate through, "
                          "in order (default: all of them; see the list "
                          "below)")
    ap.add_argument("--recovery-deadline-s", type=float,
                     default=DEFAULT_RECOVERY_DEADLINE_S,
                     help="how long a scenario that waits for the guest's "
                          "recovery gets before the harness removes the "
                          "fault itself and records not-recovered (default: "
                          "%(default)s). Allow for the guest's ~60s timeout "
                          "and a few rounds of escalation")
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
                          "the run (default: %(default)s). Its write rate is "
                          "the average since the last heartbeat across all "
                          "LUNs, so it swings with whatever fault happened to "
                          "be armed meanwhile; the per-cycle records, not "
                          "the heartbeats, say what each fault did")
    ap.add_argument("--ram", default=DEFAULT_RAM)
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

    if args.host_pressure_cores and not shutil.which("taskset"):
        print("Error: --host-pressure-cores given but 'taskset' not found in PATH.",
              file=sys.stderr)
        return 1

    # argparse's float() takes "nan" and "inf", which pass every range
    # check below and then never let a cycle (or the run) end.
    for flag in ("duration_hours", "recovery_deadline_s", "window_s",
                 "dead_target_s", "cooldown_s", "late_probability",
                 "heartbeat_seconds"):
        if not math.isfinite(getattr(args, flag)):
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
        late_probability=args.late_probability)

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

    result = run_soak(args.adapters, args.targets, args.luns_per_target,
                       duration_s, args.ram, args.cpus,
                       args.host_pressure_cores, args.keep_all, qmp_module,
                       args.io_driver, args.diskspd_path, args.fio_path,
                       scenarios, settings,
                       args.seed, args.heartbeat_seconds,
                       args.vioscsi_telemetry_script,
                       args.disk_dir, args.iothreads, args.tmf_trace,
                       args.stop_on_broken, args.ring_diag,
                       args.dump_on_agent_stall, args.qga_trace)

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
