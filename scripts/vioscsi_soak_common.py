# SPDX-License-Identifier: GPL-2.0-or-later
#
# Shared machinery for the vioscsi (virtio-scsi) Windows soak harnesses
# built on the inject-error block filter: the guest-agent client, the
# guest-side I/O writers, the QEMU/QMP plumbing, the stderr trace parser
# and the soak driver loop itself.
#
# This is a library: importing it must have no side effects beyond
# defining the constants below, and it has no main(). Each harness
# supplies its own module docstring, its own run directory (soak_dir) and
# a SoakStrategy saying which delay rules to inject and what to watch for.

import argparse
import base64
import collections
import dataclasses
import fcntl
import hashlib
import itertools
import json
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
from typing import Any, Optional

QEMU_SRC = Path(os.environ.get("QEMU_SRC", str(Path(__file__).resolve().parents[1])))
QEMU_BUILD = Path(os.environ.get("QEMU_BUILD", str(QEMU_SRC / "build")))
QEMU_BIN = QEMU_BUILD / "qemu-system-x86_64"
QEMU_IMG = QEMU_BUILD / "qemu-img"

HOME = Path(os.environ.get("HOME", str(Path.home())))
VM_DIR = Path(os.environ.get("VM_DIR", str(HOME / "VirtualMachines" / "qemu" / "windows_inject")))

BOOT_DISK = VM_DIR / "boot.qcow2"
OVMF_CODE = Path(os.environ.get(
    "OVMF_CODE", "/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2"))
OVMF_VARS = VM_DIR / "OVMF_VARS.qcow2"
TPM_DIR = VM_DIR / "tpm"  # shared, persistent -- same TPM state the golden image was installed with

PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
TASKKILL_EXE = r"C:\Windows\System32\taskkill.exe"
DEFAULT_DISKSPD_PATH = r"C:\Tools\diskspd.exe"
DEFAULT_FIO_PATH = r"C:\Program Files\fio\fio.exe"
DEFAULT_PARANOID_PATH = r"C:\test\paranoid.exe"
# Writers that check what they read back and exit non-zero on the first
# mismatch: paranoid.exe under '--stop-on-first-error', fio under
# '--verify_fatal=1'. Only for these does an early exit mean the data came
# back wrong rather than the writer merely dying, so only these are polled
# for it during the soak (see the heartbeat's writer_states check).
VERIFYING_IO_DRIVERS = ("paranoid", "fio")
# Why a verifying writer exited: because what it read back did not match
# what it wrote, or because the read itself failed. The two are different
# findings -- the first says the device handed over wrong data, the second
# says a command was failed to the application after the guest gave up on
# it -- so they get different outcomes and must not be reported as one.
#
# fio prints a "verify" line naming the mismatch and sets EILSEQ (err=84)
# on a verification failure; on a failed request it prints "io_u error"
# with the OS error, e.g.
#   fio: io_u error on file \\.\PhysicalDrive1: Input/output error: read
#   offset=17104896, buflen=65536
# paranoid.exe leaves a failure dump per LUN on a mismatch and none on an
# I/O error, so for it the dumps decide and stderr is only the fallback.
WRITER_CORRUPTION_SIGNATURES = ("verify: bad", "verify failed",
                                "verify type mismatch", "err=84")
WRITER_IO_ERROR_SIGNATURES = ("io_u error", "input/output error",
                              "i/o error")
# Outcomes the CLIs treat as a finding: they print the artifact directory
# and exit non-zero. Shared so the harnesses cannot drift apart over which
# outcomes matter.
FAILURE_OUTCOMES = ("crash-suspected", "qemu-exited", "error",
                    "guest-panicked", "data-corruption", "io-error",
                    "writer-exited", "fill-failed")
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

# paranoid.exe's '--initialize' writes every LUN end to end before its
# random mix starts. With the tail-latency rule live, that sequential pass
# crawls along one 61-65s hold at a time and the soak spends its hours
# filling disks instead of stressing the driver. So for that driver the
# rule is left out of '-blockdev' and armed over QMP only once every LUN's
# image on the host has grown to its full virtual size (see wait_for_fill).
DEFAULT_FILL_TIMEOUT_S = 2 * 3600
FILL_POLL_INTERVAL_S = 10.0
FILL_PROGRESS_INTERVAL_S = 60.0
# How often (in polls) to ask the guest whether a writer has exited -- one
# agent call per writer, so not every poll at high LUN counts.
FILL_WRITER_CHECK_POLLS = 6
# No image grew at all for this long: the fill has stalled.
FILL_STALL_S = 600.0

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
STACK_CAPTURE_TIMEOUT_S = 120
# x-stop-on-broken asks for the stop right after virtio_error() prints, but
# the main loop carries it out a moment later, so a poll that has just read
# the message can still find the VM running. Give it this long to pause.
STOP_ON_BROKEN_SETTLE_S = 2.0
# --watch-after-break: how often to look at the run state, and how often to
# keep a screenshot while waiting to see whether the guest bugchecks.
WATCH_POLL_S = 2.0
WATCH_SHOT_INTERVAL_S = 60.0
POLL_INTERVAL_S = 2
AGENT_SILENCE_THRESHOLD_S = 15
# How many agent silences in the soak loop get an info qtree capture of
# the agent's port (see capture_qga_port); later ones get none, unless
# the guest is declared dark.
QGA_PORT_SILENCE_CAPTURES = 5
STATIC_SCREEN_THRESHOLD_S = 20
# Slack on top of the longest injected hold before "no block I/O completing"
# counts as a stall rather than every writer waiting on a held request.
IO_STALL_MARGIN_S = 30
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

# After an agent request before the soak (resolving drives, launching a
# writer) went unanswered, keep watching for this many I/O probe windows
# (each one a full hold cycle, see IO_PROBE_MARGIN_S) before calling the
# agent gone. Shorter, and LUNs that happen to sit in a hold the whole time
# look exactly like a main loop that has stopped servicing them.
LAUNCH_PROBE_CYCLES = 2
LAUNCH_PROBE_INTERVAL_S = 5.0  # between pings; each also samples the LUNs
WRITER_COUNT_TIMEOUT_S = 60  # counting writer processes once the agent is back

WRITER_WINDOW_BYTES = 32 * 1024 * 1024
WRITER_BLOCK_BYTES = 64 * 1024
WRITER_THREADS = 4
WRITER_QUEUE_DEPTH = 32


def parse_size_bytes(size_str: str) -> int:
    units = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    s = size_str.strip()
    if s and s[-1].upper() in units:
        return int(float(s[:-1]) * units[s[-1].upper()])
    return int(s)


# paranoid.exe's own '--per-request-timeout-ms' is independent of (and
# would otherwise fight) the rule's hold: a single-queue op held past the
# rule's 61-65s would look like a stuck device and fail the run, when
# that hold is the whole point of the test. Set past delay-max-ms with
# this much slop, the same margin WRITER_DURATION_SLACK_S gives the
# writer's own lifetime.
PARANOID_TIMEOUT_MARGIN_MS = 5000

# Verify every write immediately (not some sampled fraction): this is a
# corruption-hunting soak, not a throughput benchmark, so catching a bad
# write the moment it happens -- rather than whenever that slot is later
# read back -- matters more than the extra read it costs.
PARANOID_VERIFY_EVERY = 1

# One paranoid.exe drives every LUN ('--disk a,b,c'), so the LUNs share one
# process and its stderr names a hung LUN next to the healthy ones (that
# output only comes back once the process exits; see writer_states).
# '--threads' is per disk: each LUN gets this many workers, each with its
# own handle, completion port and slice of the LUN, so the run has
# PARANOID_THREADS_PER_LUN * total_luns workers in all.
PARANOID_THREADS_PER_LUN = 2
PARANOID_QUEUE_DEPTH = 512
PARANOID_SLOT_BYTES = 16384
PARANOID_MAX_IO_SLOTS = 128

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
  7. For --io-driver=paranoid (optional): copy paranoid.exe into the guest
     at the path given by --paranoid-path (default: {DEFAULT_PARANOID_PATH}).
  8. For vioscsi telemetry collection (optional, on by default): have the
     script given by --vioscsi-telemetry-script (default:
     {DEFAULT_VIOSCSI_TELEMETRY_SCRIPT}) present in the guest.
  9. Shut down cleanly.

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
        Write-Output "MAP $s $($d.Number) $($d.Size)"
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


PARANOID_LOG_BASE = r"C:\test\paranoid.auditlog"


def paranoid_log_path(drive_number: int) -> str:
    """Guest-side path to one drive's binary audit log: the name
    paranoid.exe itself gives each disk's log ('<stem>-disk<N>.<ext>')
    when '--log-path PARANOID_LOG_BASE' covers several disks."""
    return fr"C:\test\paranoid-disk{drive_number}.auditlog"


def paranoid_failures_dir(log_path: str) -> str:
    """Where paranoid.exe itself drops a verification failure's raw debug
    data: a sibling directory of the audit log, named '<log-file>-failures'.
    The audit log's 'verification_failure' event records the file it wrote
    there in its error_detail, rather than embedding the dump itself."""
    return f"{log_path}-failures"


def build_paranoid_args(drive_numbers: list, duration_s: float,
                        delay_max_ms: int, initialize: bool = True,
                        log_path: Optional[str] = None) -> list:
    # 'run' against every LUN at once (paranoid.exe's '--disk' takes
    # PhysicalDriveN indexes, not paths), mixed read/write like
    # diskspd/fio's 50/50 mix. '--initialize' stamps each whole LUN first,
    # which is what fills the images (see wait_for_fill).
    # '--i-understand-this-erases-data' is required since this writes; the
    # LUNs are freshly-created blank images, never the boot disk, so there
    # is nothing on them to lose.
    #
    # '--log-path' turns on the binary audit logs (one per disk, see
    # paranoid_log_path; with a single disk paranoid.exe uses the path as
    # given, so hand it that disk's name directly) and so the sibling
    # failure-dump directories (see paranoid_failures_dir).
    # '--verify-every 1' catches a bad write immediately, and
    # '--stop-on-first-error' exits the process the moment that happens --
    # an early exit is how the harness notices corruption, since the
    # writer otherwise runs silently in the background for the whole soak.
    if log_path is None and len(drive_numbers) == 1:
        log_path = paranoid_log_path(drive_numbers[0])
    elif log_path is None:
        log_path = PARANOID_LOG_BASE
    return [
        "run",
        "--disk", ",".join(str(d) for d in drive_numbers),
        *(["--initialize"] if initialize else []),
        "--mode", "mixed",
        "--threads", str(PARANOID_THREADS_PER_LUN),
        "--read-percent", "50",
        "--queue-depth", str(PARANOID_QUEUE_DEPTH),
        "--slot-size", str(PARANOID_SLOT_BYTES),
        "--duration-secs", str(int(round(duration_s))),
        "--order", "random",
        "--write-through",
        "--per-request-timeout-ms",
        str(delay_max_ms + PARANOID_TIMEOUT_MARGIN_MS),
        "--log-path", log_path,
        "--verify-every", str(PARANOID_VERIFY_EVERY),
        "--stop-on-first-error",
        "--max-io-sectors", str(PARANOID_MAX_IO_SLOTS),
        "--i-understand-this-erases-data",
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
    sizes: dict = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] == "MAP":
            mapping[parts[1]] = int(parts[2])
            sizes[parts[1]] = int(parts[3])
    missing = [s for s in serials if s not in mapping]
    if missing:
        raise RuntimeError(f"guest could not find disk(s) with serial(s): {missing}\n"
                            f"guest-exec output was:\n{out}")
    # A LUN the guest sees at some other size would never fill to the
    # image's virtual size, so wait_for_fill would only time out on it.
    want = parse_size_bytes(LUN_IMAGE_SIZE)
    wrong = {s: n for s, n in sizes.items() if n != want}
    if wrong:
        raise RuntimeError(f"guest sees disk(s) at the wrong size (want {want} "
                            f"bytes): {wrong}")
    return mapping


def launch_writer(qga_sock: Path, drive_number: int, duration_s: float,
                   io_driver: str = "powershell",
                   diskspd_path: str = DEFAULT_DISKSPD_PATH,
                   fio_path: str = DEFAULT_FIO_PATH,
                   resyncs: Optional[list] = None) -> int:
    """Start the per-LUN writer for drivers other than paranoid, which runs
    one process over every LUN (see launch_paranoid_writer)."""
    if io_driver == "paranoid":
        raise ValueError("paranoid runs one writer over every LUN; "
                         "use launch_paranoid_writer")
    what = f"writer for PhysicalDrive{drive_number}"
    if io_driver == "diskspd":
        return qga_exec(qga_sock, what, diskspd_path,
                         build_diskspd_args(drive_number, duration_s),
                         capture=False, resyncs=resyncs)
    if io_driver == "fio":
        # Captured, like paranoid.exe's: fio writes "verify: bad magic
        # header ..." and the failing offset to stderr, and the agent only
        # hands that back for a process started with capture-output. The
        # exit code alone would say a verify failed but not where.
        return qga_exec(qga_sock, what, fio_path,
                         build_fio_args(drive_number, duration_s),
                         capture=True, resyncs=resyncs)
    return ps_exec(qga_sock, what,
                    build_writer_script(drive_number, duration_s),
                    capture=False, resyncs=resyncs)


def paranoid_writer_name(drive_numbers: list) -> str:
    return ("paranoid.exe writer for "
            + ", ".join(f"PhysicalDrive{d}" for d in drive_numbers))


def launch_paranoid_writer(qga_sock: Path, drive_numbers: list,
                           duration_s: float, paranoid_path: str,
                           delay_max_ms: int,
                           resyncs: Optional[list] = None) -> int:
    """The one paranoid.exe process that drives every LUN. Its output is
    captured, unlike the other writers', so its console warnings (e.g.
    requests a LUN never answered) come back with its exit status; see
    writer_states."""
    return qga_exec(qga_sock, paranoid_writer_name(drive_numbers),
                     paranoid_path,
                     build_paranoid_args(drive_numbers, duration_s,
                                         delay_max_ms),
                     capture=True, resyncs=resyncs)


def diskspd_diagnostic(qga_sock: Path, diskspd_path: str, drive_number: int,
                        delay_max_ms: int) -> str:
    # diskspd waits for every outstanding I/O to complete before it exits and
    # reports, even for a 1s '-d1' run -- including any that landed in the
    # rule's 61-65s hold. Give it room past delay_max_ms rather than the
    # ordinary GUEST_EXEC_TIMEOUT_S, or this diagnostic itself "times out"
    # on perfectly healthy I/O and reports nothing useful.
    diag_timeout = delay_max_ms / 1000.0 + GUEST_EXEC_TIMEOUT_S
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


def fio_diagnostic(qga_sock: Path, fio_path: str, drive_number: int,
                    delay_max_ms: int) -> str:
    # Same rationale as diskspd_diagnostic: fio with --verify waits for its
    # read-back/verify phase before exiting, so give it room past
    # delay_max_ms rather than the ordinary GUEST_EXEC_TIMEOUT_S.
    diag_timeout = delay_max_ms / 1000.0 + GUEST_EXEC_TIMEOUT_S
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


# The diagnostic's own audit log, so it never overwrites the live writer's.
PARANOID_DIAGNOSTIC_LOG = r"C:\test\paranoid-diagnostic.auditlog"


def paranoid_diagnostic(qga_sock: Path, paranoid_path: str, drive_number: int,
                        delay_max_ms: int) -> str:
    # Same rationale as diskspd_diagnostic/fio_diagnostic: a 1s run still
    # has to wait out any op it launched into the rule's hold before it
    # can exit and report, so give it room past delay_max_ms rather than
    # the ordinary GUEST_EXEC_TIMEOUT_S.
    diag_timeout = delay_max_ms / 1000.0 + GUEST_EXEC_TIMEOUT_S
    try:
        pid = qga_exec(qga_sock, "paranoid diagnostic", paranoid_path,
                        # The live writer still owns every LUN: no
                        # '--initialize' (a second whole-LUN stamp) and a
                        # log of its own.
                        build_paranoid_args([drive_number], 1, delay_max_ms,
                                            initialize=False,
                                            log_path=PARANOID_DIAGNOSTIC_LOG),
                        capture=True, timeout=diag_timeout)
    except GuestExecError as exc:
        return f"paranoid.exe failed to even launch at {paranoid_path!r}: {exc}"
    status = qga_exec_wait(qga_sock, pid, timeout=diag_timeout)
    if status is None:
        return "paranoid.exe diagnostic run timed out"
    out = b64_text(status.get("out-data")).strip()
    err = b64_text(status.get("err-data")).strip()
    return (f"paranoid.exe exitcode={status.get('exitcode')}; "
            f"stdout={out[:400]!r}; stderr={err[:400]!r}")


def list_guest_files(qga_sock: Path, dir_path: str,
                     timeout: float = GUEST_EXEC_TIMEOUT_S) -> list:
    """Full paths of files in a guest directory, or [] if it doesn't exist
    or the agent can't be reached."""
    script = (f"if (Test-Path -LiteralPath '{dir_path}') {{ "
              f"(Get-ChildItem -LiteralPath '{dir_path}' -File).FullName }}")
    try:
        pid = ps_exec(qga_sock, f"list {dir_path}", script, capture=True,
                      timeout=timeout)
    except GuestExecError:
        return []
    status = qga_exec_wait(qga_sock, pid, timeout)
    if status is None or status.get("exitcode") != 0:
        return []
    return [line.strip() for line in b64_text(status.get("out-data")).splitlines()
            if line.strip()]


def fetch_guest_text_file(qga_sock: Path, guest_path: str,
                          timeout: float = GUEST_EXEC_TIMEOUT_S) -> Optional[str]:
    """A guest text file's content, or None. Used for the decoded
    (JSON-Lines) audit log."""
    try:
        pid = ps_exec(qga_sock, f"fetch {guest_path}",
                      f"Get-Content -LiteralPath '{guest_path}' -Raw",
                      capture=True, timeout=timeout)
    except GuestExecError:
        return None
    status = qga_exec_wait(qga_sock, pid, timeout)
    if status is None or status.get("exitcode") != 0:
        return None
    return b64_text(status.get("out-data"))


def fetch_guest_binary_file(qga_sock: Path, guest_path: str,
                            timeout: float = GUEST_EXEC_TIMEOUT_S
                            ) -> Optional[bytes]:
    """A guest file's raw bytes, or None. paranoid.exe's failure dumps are
    binary, so they travel as base64 through guest-exec's own base64
    envelope rather than as text, which would mangle them."""
    script = (f"[Convert]::ToBase64String("
              f"[System.IO.File]::ReadAllBytes('{guest_path}'))")
    try:
        pid = ps_exec(qga_sock, f"fetch {guest_path}", script, capture=True,
                      timeout=timeout)
    except GuestExecError:
        return None
    status = qga_exec_wait(qga_sock, pid, timeout)
    if status is None or status.get("exitcode") != 0:
        return None
    try:
        return base64.b64decode(b64_text(status.get("out-data")).strip())
    except ValueError:
        return None


def collect_paranoid_corruption(qga_sock: Path, paranoid_path: str,
                                drive_number: int, run_dir: Path,
                                timeout: float = GUEST_EXEC_TIMEOUT_S) -> dict:
    """After a paranoid.exe writer exits early (--stop-on-first-error means
    that only happens on a verification failure or similar fatal error),
    decode its binary audit log to JSON-Lines on the guest and pull both it
    and any failure dumps paranoid.exe itself wrote (see
    paranoid_failures_dir) back to run_dir on the host, for analysis after
    the run. Never raises -- these diagnostics must not take down the
    corruption finding they explain."""
    artifacts: dict = {}
    log_path = paranoid_log_path(drive_number)
    decoded_guest_path = fr"C:\test\paranoid-disk{drive_number}.jsonl"
    try:
        pid = qga_exec(qga_sock,
                        f"decode paranoid audit log for PhysicalDrive{drive_number}",
                        paranoid_path,
                        ["log", "--log-path", log_path, "--start", "0",
                         "--slot-size", str(PARANOID_SLOT_BYTES),
                         "--out", decoded_guest_path],
                        capture=True, timeout=timeout)
        status = qga_exec_wait(qga_sock, pid, timeout)
    except GuestExecError as exc:
        status = None
        artifacts["decode_error"] = str(exc)
    if status is None and "decode_error" not in artifacts:
        artifacts["decode_error"] = "decode timed out"
    elif status is not None and status.get("exitcode") != 0:
        artifacts["decode_error"] = (
            f"exitcode={status.get('exitcode')}: "
            f"{b64_text(status.get('err-data')).strip()[:300]}")

    if "decode_error" not in artifacts:
        decoded = fetch_guest_text_file(qga_sock, decoded_guest_path, timeout)
        if decoded is None:
            artifacts["decoded_log_error"] = "could not fetch decoded audit log"
        else:
            host_path = run_dir / f"paranoid-disk{drive_number}.jsonl"
            host_path.write_text(decoded)
            artifacts["decoded_log"] = str(host_path)

    failures_dir = paranoid_failures_dir(log_path)
    dump_files = list_guest_files(qga_sock, failures_dir, timeout)
    fetched = []
    for guest_file in dump_files:
        data = fetch_guest_binary_file(qga_sock, guest_file, timeout)
        if data is None:
            continue
        host_file = run_dir / (f"paranoid-disk{drive_number}-"
                               f"{PureWindowsPath(guest_file).name}")
        host_file.write_bytes(data)
        fetched.append(str(host_file))
    artifacts["failure_dumps"] = fetched
    if dump_files and not fetched:
        artifacts["failure_dumps_error"] = (
            f"found {len(dump_files)} dump file(s) in {failures_dir} but "
            f"could not fetch any of them")
    return artifacts


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


# Enough of a writer's stderr to keep in the result: paranoid.exe's
# timeout warnings are rate-limited, so this covers many minutes of them.
WRITER_STDERR_TAIL_CHARS = 8000


def writer_states(qga_sock: Path, pids: list,
                   seen: Optional[dict] = None) -> list:
    """Each writer's exit state, newest poll first.

    The agent answers guest-exec-status for an exited process once: it
    hands back the exit code and whatever output was captured, then reaps
    the pid, and every later poll of it fails. So the first poll that says
    "exited" carries the only copy of that writer's stderr there will ever
    be, and re-polling would turn a known exit back into an unknown one.

    Pass @seen -- a pid -> state dict the caller keeps across calls -- to
    make that stick: a pid already known to have exited is answered from
    it instead of re-polled, and every fresh state is recorded in it.
    That also spares the agent a round trip per dead writer, which is the
    bulk of them once a run is failing.
    """
    states = []
    for pid in pids:
        if seen is not None and seen.get(pid, {}).get("exited"):
            states.append(seen[pid])
            continue
        resp = qga_call(qga_sock, "guest-exec-status", {"pid": pid}, timeout=5.0)
        ret = resp.get("return", {}) if resp and "return" in resp else {}
        state = {"pid": pid, "exited": ret.get("exited"),
                 "exitcode": ret.get("exitcode")}
        # Only writers launched with captured output (paranoid.exe, fio)
        # have any, and the agent hands it back only once the process
        # exits.
        err = b64_text(ret.get("err-data")).strip()
        if err:
            state["stderr_tail"] = err[-WRITER_STDERR_TAIL_CHARS:]
        if seen is not None:
            seen[pid] = state
        states.append(state)
    return states


def classify_writer_exit(states: list) -> tuple:
    """(outcome, why) for writers that exited on their own, read off the
    stderr they left: see WRITER_CORRUPTION_SIGNATURES.

    A verify line wins over an I/O error in the same stderr -- fio keeps
    going through failed requests until --verify_fatal stops it, so a
    mismatch anywhere in the tail is the reason it is gone. With neither
    signature there is nothing to stand behind, and the caller must say
    only that the writer exited; guessing "corruption" there is how a
    stalled command that storport eventually failed to the application
    gets filed as a data-integrity bug.
    """
    tails = [st.get("stderr_tail", "").lower() for st in states]
    for sig in WRITER_CORRUPTION_SIGNATURES:
        if any(sig in tail for tail in tails):
            return "data-corruption", f"verification failed ({sig!r} in stderr)"
    for sig in WRITER_IO_ERROR_SIGNATURES:
        if any(sig in tail for tail in tails):
            return "io-error", (f"a request was failed to the writer "
                                f"({sig!r} in stderr), with no verification "
                                f"mismatch reported")
    return "writer-exited", ("neither a verification mismatch nor an I/O "
                             "error in stderr" if any(tails)
                             else "no stderr captured")


def wait_for_writers(qga_sock: Path, pids: list, timeout: float,
                      seen: Optional[dict] = None) -> list:
    deadline = time.monotonic() + timeout
    states = writer_states(qga_sock, pids, seen)
    while time.monotonic() < deadline and any(not s["exited"] for s in states):
        time.sleep(1.0)
        states = writer_states(qga_sock, pids, seen)
    return states


def stop_writers(qga_sock: Path, pids: list,
                  timeout: float = WRITER_STOP_TIMEOUT_S,
                  seen: Optional[dict] = None) -> list:
    """Force-stop any writer still running and wait for it to exit.

    Writers are launched with writer_duration, padded well past the
    monitored test window by WRITER_DURATION_SLACK_S so a slow boot or
    heartbeat can never starve the back half of a run -- see that constant.
    Left alone they'd keep hammering the guest with I/O for up to another
    ~10 minutes after the harness is done watching, which races vioscsi
    telemetry collection (and anything else run post-test) against a guest
    Pass @seen through so a writer that already exited -- the one that
    failed verification, say -- keeps the state and stderr it exited with
    rather than having them replaced by a poll the agent can no longer
    answer. See writer_states()."""
    for st in writer_states(qga_sock, pids, seen):
        if not st["exited"]:
            try:
                qga_exec(qga_sock, f"taskkill pid {st['pid']}", TASKKILL_EXE,
                          ["/F", "/PID", str(st["pid"])], capture=False)
            except GuestExecError:
                pass  # best-effort; wait_for_writers reports what survived
    return wait_for_writers(qga_sock, pids, timeout, seen)


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


# A delay rule is a plain dict matching InjectDelayRuleOptions in
# qapi/block-core.json: 'id' plus any of 'ops', 'sector', 'count',
# 'probability', 'delay-ms', 'delay-max-ms', 'stall', 'errno' and
# 'max-hits'. Insertion order is the order the '-blockdev' properties are
# rendered in, so a harness that cares about the exact command line just
# builds the dict in the order it wants.
#
# A rule whose 'id' is absent or empty is named after the LUN's own
# inject-error node (see rule_for_node): every harness so far wants one
# rule per LUN named for that LUN, and this keeps the caller from having
# to template the id itself.


def rule_for_node(rule: dict, node_name: str) -> dict:
    """The rule as it applies to one LUN: a copy with an absent or empty
    'id' filled in with that LUN's inject-error node name."""
    out = dict(rule)
    if not out.get("id"):
        out["id"] = node_name
    return out


def _rule_prop_value(value: Any) -> str:
    # -blockdev's option parser spells booleans 'on'/'off', not Python's
    # 'True'/'False'.
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, (str, int, float)):
        return str(value)
    raise TypeError(f"delay rule values must be scalars or lists of them, "
                    f"not {type(value).__name__}")


def delay_rule_props(index: int, rule: dict) -> str:
    """Render one delay rule as '-blockdev' properties (delays.<index>.*),
    so it is live for the LUN's very first I/O rather than armed afterward
    over QMP -- a rule that needs to stay in effect for the whole run, not
    be cycled, has no reason to be armed any other way. The exception is
    --fill-wait: then it is armed over QMP once the LUNs have filled (see
    arm_delay_rules / wait_for_fill)."""
    props = []
    for key, value in rule.items():
        if isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                props.append(f"delays.{index}.{key}.{i}={_rule_prop_value(item)}")
        else:
            props.append(f"delays.{index}.{key}={_rule_prop_value(value)}")
    return ",".join(props)


def delay_rules_props(rules: list) -> str:
    """Render a list of delay rules as '-blockdev' properties."""
    return ",".join(delay_rule_props(i, rule) for i, rule in enumerate(rules))


def arm_delay_rules(qmp, lun_specs: list, rules: list) -> None:
    """Arm every rule on every LUN over QMP -- for arming after the fill
    (see wait_for_fill)."""
    for spec in lun_specs:
        for rule in rules:
            qmp_call(qmp, "x-inject-error-delay-add", node_name=spec.err_node,
                     rule=rule_for_node(rule, spec.err_node))


def image_bytes_on_disk(path: Path) -> int:
    """Host bytes actually allocated to an image file. A fresh qcow2 is
    sparse, so this only reaches the virtual size once the guest has
    written every cluster."""
    try:
        return path.stat().st_blocks * 512
    except FileNotFoundError:
        return 0


def image_data_bytes(qmp, path: Path, node: str) -> Optional[int]:
    """Guest-visible bytes the image actually has data for, per its own
    metadata. image_bytes_on_disk also counts qcow2 metadata, so it can
    reach the virtual size with a few clusters still unwritten; this is
    the exact check. '-U' since the running VM holds the image lock.
    None if the flush failed or qemu-img could not read it.

    The running QEMU keeps qcow2 L2 updates in its metadata cache until
    something flushes the node, and paranoid.exe's write-through I/O does
    not reliably do that, so without the flush below qemu-img reads stale
    L2 tables: the last ~100 MiB each writer thread laid down shows as
    unallocated indefinitely even though the host clusters (and their
    refcounts) are already on disk. 'node' is flushed recursively, so the
    LUN's top node is enough."""
    try:
        out = qmp_call(qmp, "human-monitor-command",
                       command_line=f'qemu-io {node} "flush"')
    except RuntimeError:
        return None
    if out and out.strip():
        # HMP reports qemu-io failures as text, not as a QMP error.
        return None
    try:
        out = subprocess.run([str(QEMU_IMG), "map", "-U", "--output=json",
                              str(path)],
                             check=True, capture_output=True, text=True,
                             timeout=60).stdout
        return sum(e["length"] for e in json.loads(out) if e.get("data"))
    except (subprocess.SubprocessError, ValueError, KeyError):
        return None


def wait_for_fill(qmp, lun_specs: list, target_bytes: int,
                  timeout_s: float, proc: subprocess.Popen, qga_sock: Path,
                  writer_pids: list, seen: Optional[dict] = None) -> dict:
    """Block until every LUN image has as many bytes allocated on the host
    as the disk's virtual size -- i.e. the writers' sequential initialize
    pass has touched every cluster -- or until that can no longer happen.

    Returns a summary whose 'status' is 'filled' on success, otherwise
    'qemu-exited', 'writer-exited', 'stalled' or 'timeout'."""
    t0 = time.monotonic()
    deadline = t0 + timeout_s
    last_report = t0
    last_growth = t0
    prev_total = -1
    polls = 0
    filled: set = set()
    while True:
        on_disk = {s.serial: image_bytes_on_disk(s.image) for s in lun_specs}
        total = sum(on_disk.values())
        for s in lun_specs:
            if s.serial in filled or on_disk[s.serial] < target_bytes:
                continue
            data = image_data_bytes(qmp, s.image, s.err_node)
            if data is not None and data >= target_bytes:
                filled.add(s.serial)
        short = sorted(s.serial for s in lun_specs if s.serial not in filled)
        now = time.monotonic()
        info: dict = {"elapsed_s": round(now - t0, 1),
                      "target_bytes": target_bytes,
                      "bytes_on_disk": on_disk,
                      "short": short}
        if not short:
            info["status"] = "filled"
            return info
        if total > prev_total:
            prev_total = total
            last_growth = now
        if proc.poll() is not None:
            info["status"] = "qemu-exited"
            return info
        if polls and polls % FILL_WRITER_CHECK_POLLS == 0:
            states = writer_states(qga_sock, writer_pids, seen)
            if any(st["exited"] for st in states):
                info["status"] = "writer-exited"
                info["writer_states"] = states
                return info
        if now - last_growth >= FILL_STALL_S:
            info["status"] = "stalled"
            return info
        if now >= deadline:
            info["status"] = "timeout"
            return info
        if now - last_report >= FILL_PROGRESS_INTERVAL_S:
            last_report = now
            want = target_bytes * len(lun_specs)
            print(f"    filling LUNs: {total / 1024**3:.1f} of "
                  f"{want / 1024**3:.1f} GiB on disk, {len(short)} of "
                  f"{len(lun_specs)} LUN(s) short, {now - t0:.0f}s elapsed",
                  file=sys.stderr)
        polls += 1
        time.sleep(FILL_POLL_INTERVAL_S)


def build_qemu_argv(boot_overlay: Path, vars_overlay: Path, qmp_sock: Path,
                     qga_sock: Path, serial_log: Path, tpm_sock: Path,
                     adapters: int, lun_specs: list, seed: int, ram: str,
                     cpus: str, taskset_cores: Optional[str],
                     delay_rules: list,
                     iothreads: Optional[int] = None,
                     tmf_trace: bool = True,
                     stop_on_broken: bool = True,
                     ring_diag: bool = True,
                     qga_trace: bool = True,
                     arm_at_start: bool = True,
                     hv_crash: bool = False) -> list:
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
        # Boot disk is SATA/AHCI and stays a plain passthrough -- the
        # delay rules only target the SCSI data LUNs below, not the
        # virtio-blk boot path.
        "-device", "ahci,id=ahci0",
        "-blockdev", f"driver=file,filename={boot_overlay},node-name=file0",
        "-blockdev", "driver=qcow2,file=file0,node-name=raw0",
        "-blockdev", "driver=inject-error,image=raw0,node-name=err0",
        "-device", "ide-hd,bus=ahci0.0,drive=err0,bootindex=0,id=disk0",
    ]

    if hv_crash:
        # QEMU's default panic action is shutdown, which would power the VM
        # off and take the crashed guest's memory with it.
        argv += ["-action", "panic=pause"]
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
        err_props = f"node-name={spec.err_node},seed={seed}"
        if arm_at_start:
            rule_props = delay_rules_props(
                [rule_for_node(r, spec.err_node) for r in delay_rules])
            if rule_props:
                err_props += "," + rule_props
        argv += [
            "-blockdev", f"driver=file,filename={spec.image},node-name={spec.file_node}",
            "-blockdev", f"driver=qcow2,file={spec.file_node},node-name={spec.fmt_node}",
            "-blockdev", f"driver=inject-error,image={spec.fmt_node},{err_props}",
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
    56-minute hang in run-1791602155 is suspected of."""

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
                    self._trace(m.group(3), line)
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

    def _trace(self, event: str, line: str) -> None:
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
               for k in (spec.dev_id, spec.err_node, spec.fmt_node,
                         spec.file_node))


def total_lun_writes(wops: dict, lun_specs: list) -> int:
    """Cumulative writes across the data LUNs only.

    Deliberately excludes the boot disk. It is SATA/AHCI and has no
    tail-latency rule on it, so Windows keeps writing to C: -- pagefile,
    event log, registry -- long after every LUN under test has stopped
    dead. Counting it made the I/O-stall detector permanently think the
    guest was making progress. Same max-across-aliases trick as
    lun_write_delta: query-blockstats reports one LUN's writes under
    several identifiers and they must not be added together."""
    return sum(max(wops.get(k, 0)
                   for k in (s.dev_id, s.err_node, s.fmt_node, s.file_node))
               for s in lun_specs)


def lun_activity_by_adapter(qmp, lun_specs: list, window_s: float) -> dict:
    """Per-adapter liveness, sampled over window_s.

    QEMU's virtio_error() messages don't say which device went broken,
    and x-query-virtio-status -- the command that would -- aborts QEMU on
    this tree. But LUNs are grouped by adapter, so watching which ones
    still complete writes identifies the dead adapter(s) by elimination:
    a broken virtio device stops servicing its queues, so all its LUNs go
    quiet together while the other adapters carry on.

    window_s has no default on purpose. It must span a full hold cycle --
    the same reasoning as io_probe_window_s -- or healthy LUNs that
    happen to be sitting in a 61-65s hold are counted as quiet. A first
    cut used a flat 3s and reported live adapters as 4/15 and 5/15, which
    reads like partial failure and is really just a window far shorter
    than the thing it is sampling. Deciding which adapters are dead from
    these counts is adapters_without_io()'s job -- "zero writes" is not
    the test."""
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


def adapters_without_io(activity: dict, held: dict, lun_specs: list) -> list:
    """Adapters whose writes over the window don't exceed what they held.

    A broken device still finishes requests it had already popped: they
    sit in the inject-error hold and complete when it expires. A window
    long enough to be fair to healthy LUNs -- a full hold cycle -- sees
    every one of them, so "no writes at all" misses a dead adapter. It
    did once, reporting none dead while scsi0 sat at 7 writes against
    ~28000 on each of its neighbours. What a dead adapter can still
    complete is bounded by what it was holding when it broke, held being
    the per-node held_counts() taken at that moment."""
    held_by_adapter: collections.Counter = collections.Counter()
    for spec in lun_specs:
        held_by_adapter[f"scsi{spec.adapter}"] += held.get(spec.err_node, 0)
    return [a for a, v in sorted(activity.items())
            if v["writes"] <= held_by_adapter[a]]


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
    # completes the requests it had in the inject-error hold.
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


def diagnose_launch_failure(diag: dict, persist, qmp, qga_sock: Path,
                            qemu_pid: int, run_dir: Path, lun_specs: list,
                            err_nodes: list, launched: int, probe_s: float,
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
    then follows a VM stop with the delay rules removed, so it no longer
    watches the same workload. There is no second dump unless that one
    failed and the agent then stays silent.

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
        # Set first: the dump removes the rules before it can fail.
        diag["delay_rules_removed"] = True
        diag["dump_at"] = "failure"
        persist()
        # So that a file found afterwards is this dump's (it would replace
        # it anyway, but only once past removing the rules).
        dump_path.unlink(missing_ok=True)
        try:
            diag["dump"] = try_dump_guest_memory(qmp, dump_path, qemu_pid,
                                                 err_nodes)
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
                           f"{dump_path}, so the probe followed a VM stop "
                           f"without the delay rules")
        elif stopped:
            dump_phrase = ("; guest memory dump at the failure started but "
                           "failed, so the probe followed a VM stop without "
                           "the delay rules")
        else:
            why = diag.get("dump_error", "refused or never started")
            dump_phrase = (f"; guest memory dump at the failure failed "
                           f"({why}); the delay rules may still have been "
                           f"removed")

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
    # Set first: the dump removes the rules before it can fail.
    diag["delay_rules_removed"] = True
    diag["dump_at"] = "end"
    persist()
    diag["dump"] = try_dump_guest_memory(qmp, dump_path, qemu_pid, err_nodes)
    persist()
    return (f"guest agent silent for the whole {probe_s:.0f}s probe; "
            f"{writes_phrase}; guest memory dump "
            f"{'saved to ' + str(dump_path) if diag['dump'] else 'failed'}")


# ------------------------------------------------------------------
# Harness
# ------------------------------------------------------------------


# Keys run_soak writes into the result and meta.json itself. A strategy's
# meta() may not reuse them -- see SoakStrategy.meta.
SOAK_RESERVED_KEYS = frozenset((
    "outcome", "elapsed_s", "run_dir", "duration_s", "error",
    "adapters", "targets", "luns_per_target", "total_luns", "seed",
    "iothreads", "tmf_trace", "stop_on_broken", "ring_diag",
    "dump_on_agent_stall", "qga_trace", "fill_wait", "fill_timeout_s",
    "watch_after_break_s", "argv",
))


@dataclasses.dataclass
class SoakContext:
    """What run_soak hands a strategy on every callback. Deliberately
    small: the live QMP monitor, the guest agent socket, the QEMU process,
    the run directory, the LUNs and their inject-error node names, the
    result dict being built, the QEMU stderr/trace reader (None until the
    soak loop starts), the write_status helper that persists the result so
    far, the monotonic time the run started, and run_soak's own capture
    helpers for a strategy that needs them outside the normal exit paths.

    qemu_stderr is the only field that changes after the object is built,
    so a strategy must read it when called rather than caching it. Its
    trace_counts are {bus: {event: count}} -- bus as QEMU names it
    ('scsi0.0'), and the event shorn of its 'virtio_scsi_' prefix, so a
    device reset is counted under 'reset'. virtio_scsi_tmf_req is split by
    subtype into 'tmf_req:<subtype>' keys (TMF_SUBTYPES names them) and
    there is no bare 'tmf_req'; see tmf_requests() for summing them. The
    counts accumulate from the start of the soak -- they are taken and
    cleared exactly once, into tmf_trace_pre_soak -- so a strategy spots a
    new event by diffing against what it saw last, not by expecting zero."""
    qmp: Any
    qga_sock: Path
    proc: Any
    run_dir: Path
    lun_specs: list
    err_nodes: list
    result: dict
    qemu_stderr: Any
    write_status: Any
    start: float
    record_trace: Any
    collect_vioscsi_telemetry: Any
    capture_postmortem: Any
    capture_qga_port: Any


class SoakStrategy:
    """What differs between the harnesses built on run_soak: which delay
    rules to inject, and what else to watch for while the soak runs.

    The defaults implement the tail-latency harness's behavior with an
    empty rule list, so a subclass only has to override what it changes."""

    def delay_rules(self) -> list:
        """Rules to bake into '-blockdev', or to arm after the fill."""
        return []

    def max_hold_ms(self) -> int:
        """The longest a request can be held by any of these rules. Sizes
        the I/O probe window and the stall threshold below, and the guest
        writer's own per-request timeout, which has to stay clear of a
        hold that is the whole point of the test."""
        return max((int(r.get("delay-max-ms", 0) or 0)
                    for r in self.delay_rules()), default=0)

    def io_probe_window_s(self) -> float:
        """How long the pre-flight I/O probe samples for. See
        IO_PROBE_MARGIN_S: it has to span a full duty cycle."""
        return self.max_hold_ms() / 1000.0 + IO_PROBE_MARGIN_S

    def io_stall_threshold_s(self) -> float:
        """How long block I/O may make no progress before the guest counts
        as stalled rather than merely waiting on a held request."""
        return self.max_hold_ms() / 1000.0 + IO_STALL_MARGIN_S

    def rule_label(self) -> str:
        """What to call this harness's rules in progress messages."""
        return "the delay rules"

    def arm_after_fill(self, ctx: SoakContext) -> None:
        """Arm the rules over QMP once --fill-wait's fill has completed."""
        arm_delay_rules(ctx.qmp, ctx.lun_specs, self.delay_rules())

    def on_tick(self, ctx: SoakContext) -> Optional[dict]:
        """Called once per pass of the soak's monitor loop, after its own
        checks and before it sleeps -- so not during the --fill-wait fill,
        the pre-flight probe or --watch-after-break. Return None to keep
        going, or mutate and return ctx.result to end the run.

        It has to be ctx.result itself, not a fresh dict: that is the
        object run_soak folds the trace, the telemetry and the artifact
        paths into, and the one the caller reads outcome and run_dir from.
        Set outcome and whatever the run found; run_soak does the rest."""
        return None

    def meta(self) -> dict:
        """Extra key/values folded into meta.json and into the result.
        Must not use any of SOAK_RESERVED_KEYS; run_soak rejects that
        rather than let one name mean two things."""
        return {}

    def heartbeat(self, ctx: SoakContext) -> dict:
        """Extra key/values folded into each heartbeat line."""
        return {}


def run_soak(soak_dir: Path,
             adapters: int, targets: int, luns_per_target: int, duration_s: float,
             ram: str, cpus: str, taskset_cores: Optional[str], keep_all: bool,
             qmp_module, io_driver: str, diskspd_path: str, fio_path: str,
             paranoid_path: str,
             strategy: SoakStrategy,
             seed: int, heartbeat_s: float, vioscsi_telemetry_script: str,
             disk_dir: Optional[Path] = None,
             iothreads: Optional[int] = None,
             tmf_trace: bool = True,
             stop_on_broken: bool = True,
             ring_diag: bool = True,
             dump_on_agent_stall: bool = False,
             qga_trace: bool = True,
             fill_wait: bool = False,
             fill_timeout_s: float = DEFAULT_FILL_TIMEOUT_S,
             watch_after_break_s: float = 0.0) -> dict:
    run_dir = soak_dir / f"run-{int(time.time())}"
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
    panic_dump_path = run_dir / "panic.dmp"
    qemu_log_path = run_dir / "qemu.log"

    qmp = None
    proc = None
    swtpm = None
    lun_specs: list = []
    # A strategy that named one of run_soak's own keys would quietly take
    # over the result's outcome or the run directory here, and lose to the
    # real value in meta.json below -- the same name meaning two things.
    # Cheaper to refuse it than to debug it.
    clash = SOAK_RESERVED_KEYS & strategy.meta().keys()
    if clash:
        raise ValueError(f"strategy meta() must not use run_soak's own "
                         f"key(s): {sorted(clash)}")
    result: dict = {"outcome": "error", "elapsed_s": 0.0, "run_dir": str(run_dir),
                    "duration_s": duration_s, **strategy.meta()}
    start = time.monotonic()

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

        Note try_dump_guest_memory removes the delay rules first (see
        there), so holds stop for the rest of the run."""
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
            qmp, break_dump_path, proc.pid, err_nodes)
        result["break_dump_path"] = str(break_dump_path)
        result["delay_rules_removed"] = True
        try:
            qmp_call(qmp, "cont")
        except Exception as exc:
            result["break_resume_error"] = repr(exc)
            print(f"    cont after the break dump failed: {exc!r}",
                  file=sys.stderr)
        write_status({"elapsed_s": time.monotonic() - start})
        return True

    def capture_guest_panic() -> dict:
        """Screenshot and Windows-format dump of a guest that bugchecked
        (hv-crash left the VM in guest-panicked)."""
        shot = run_dir / "watch-panic.ppm"
        screendump_hash(qmp, shot)
        print(f"    guest bugchecked; dumping guest memory to "
              f"{panic_dump_path}", file=sys.stderr)
        return {"screenshot": str(shot),
                "dump": try_dump_guest_memory(qmp, panic_dump_path, proc.pid,
                                              err_nodes),
                "dump_path": str(panic_dump_path)}

    def watch_after_break() -> None:
        """Leave the guest running after a break and see whether it
        bugchecks. The guest reports a bugcheck through the Hyper-V crash
        MSRs (hv-crash), which parks the VM in guest-panicked; that gets a
        Windows-format dump with the real bugcheck code. Screenshots are
        kept along the way either way."""
        watch: dict = {"minutes": watch_after_break_s / 60.0}
        result["watch_after_break"] = watch
        print(f"    watching the guest for {watch_after_break_s / 60.0:.0f} "
              f"min for a bugcheck", file=sys.stderr)
        t0 = time.monotonic()
        next_shot = t0
        shots = 0
        while True:
            now = time.monotonic()
            watch["elapsed_s"] = round(now - t0, 1)
            if proc.poll() is not None:
                watch["outcome"] = "qemu-exited"
                break
            try:
                status = qmp_call(qmp, "query-status").get("status")
            except Exception as exc:
                watch["outcome"] = f"query-status failed: {exc!r}"
                break
            if status == "guest-panicked":
                watch["outcome"] = "guest-panicked"
                watch.update(capture_guest_panic())
                break
            if now >= t0 + watch_after_break_s:
                watch["outcome"] = f"no bugcheck (status {status})"
                break
            if now >= next_shot:
                next_shot = now + WATCH_SHOT_INTERVAL_S
                shots += 1
                screendump_hash(qmp, run_dir / f"watch-{shots:03d}.ppm")
            time.sleep(WATCH_POLL_S)
        watch["agent_alive"] = qga_ping(qga_sock)
        print(f"    after the break: {watch['outcome']} "
              f"({watch['elapsed_s']:.0f}s watched, guest agent "
              f"{'answering' if watch['agent_alive'] else 'silent'})",
              file=sys.stderr)
        write_status({"elapsed_s": time.monotonic() - start})

    def capture_postmortem() -> None:
        result["telemetry_failure_screenshot"] = (
            screendump_hash(qmp, screenshot) is not None)
        if result.get("break_dump"):
            return  # the one taken at the break is the one that matters
        result["telemetry_failure_dump"] = try_dump_guest_memory(
            qmp, dump_path, proc.pid, err_nodes)

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
        result["writer_states"] = stop_writers(qga_sock, writer_pids,
                                                seen=writer_seen)
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
        Fills in the whole result -- outcome, error and the evidence each
        driver leaves -- and returns True, so the caller only has to
        return it.

        The outcome is not assumed: a writer can exit because it read
        back data that did not match what it wrote, or because a request
        was failed to it, and classify_writer_exit() decides which from
        the evidence. Both end the run; only the first is a
        data-integrity finding.

        Not called on every 2s poll: a writer's exit status is its own
        guest-agent round trip per LUN, and the module docstring flags that
        as too costly at high LUN counts. Only the heartbeat and the end of
        the run ask. An exit is always a failure for these drivers, never a
        clean finish, since writer_duration outlasts duration_s.
        """
        if io_driver not in VERIFYING_IO_DRIVERS:
            return False
        exited = [st for st in writer_states(qga_sock, writer_pids,
                                             writer_seen)
                  if st["exited"]]
        if not exited:
            return False
        st = exited[0]
        outcome, why = classify_writer_exit(exited)
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
        if io_driver == "paranoid":
            print(f"    paranoid.exe writer exited early "
                  f"(exitcode={st['exitcode']}) after "
                  f"{elapsed:.0f}s -- {why}; "
                  f"retrieving the audit log and failure dumps "
                  f"of each LUN that left any", file=sys.stderr)
            # One process drives every LUN, so its exit alone doesn't say
            # which LUN failed: the one(s) with failure dumps do. Only
            # those are collected -- a full sweep is several guest round
            # trips per LUN, far too slow at high LUN counts.
            failures = []
            for spec in lun_specs:
                drive_no = drive_numbers[spec.serial]
                if not list_guest_files(
                        qga_sock, paranoid_failures_dir(
                            paranoid_log_path(drive_no))):
                    continue
                artifacts = collect_paranoid_corruption(
                    qga_sock, paranoid_path, drive_no, run_dir)
                failures.append({"lun": spec.dev_id,
                                 "drive": drive_no,
                                 "exitcode": st["exitcode"],
                                 **artifacts})
            result["paranoid_failures"] = failures
            if failures:
                # A failure dump is a mismatch paranoid.exe captured, so
                # it outranks whatever its stderr happened to say.
                result["outcome"] = "data-corruption"
                where = (f"data corruption on: "
                         f"{[f['lun'] for f in failures]}; audit "
                         f"log(s) and failure dump(s) retrieved "
                         f"to the run directory for analysis")
            else:
                where = (f"no LUN left a failure dump, and {why}; see "
                         f"writer_states' stderr_tail for why it exited")
            result["error"] = (
                "paranoid.exe writer exited early under "
                f"--stop-on-first-error -- {where}")
        else:
            # One writer per LUN, so the pids that exited name the LUNs
            # that failed. The verify message or the OS error and its
            # offset are in each one's stderr_tail; there are no separate
            # dump files to fetch.
            lost = sorted(writer_luns.get(s["pid"], f"pid {s['pid']}")
                          for s in exited)
            codes = sorted({s["exitcode"] for s in exited},
                           key=lambda c: (c is None, c))
            print(f"    {io_driver} writer(s) exited early "
                  f"(exitcode={codes}) after {elapsed:.0f}s on {lost} "
                  f"-- {why}", file=sys.stderr)
            result["error"] = (
                f"{io_driver} writer(s) exited early on {lost}: {why}; "
                f"see writer_states' stderr_tail for the failing "
                f"offset(s)")
        # Same postmortem the clean path records, and for more reason: the
        # trace fold and the rule tallies are how many commands the run had
        # held, and how the guest answered, when the data went wrong. Taken
        # over QMP before collect_vioscsi_telemetry(), which stops the
        # writers and may find the agent gone.
        record_trace()
        result["rule_hits"] = rule_hits(qmp, err_nodes)
        write_status({"elapsed_s": elapsed})
        collect_vioscsi_telemetry()
        write_status({"elapsed_s": elapsed})
        return True

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
        probe_s = LAUNCH_PROBE_CYCLES * io_probe_window_s
        how = f"{reason} at {no_reply.stage}" if no_reply else reason
        # Only for an agent that went quiet: a deadline that ran out on a
        # slow but answering agent has nothing stuck to catch.
        dump_now = dump_on_agent_stall and reason == "no-reply"
        print(f"    {request or 'writer launch'} failed ({how}) at "
              f"{failed_at}; capturing "
              f"QEMU stacks{', dumping guest memory' if dump_now else ''} "
              f"and watching the guest agent and LUNs for {probe_s:.0f}s",
              file=sys.stderr)
        writer_exe = {"diskspd": diskspd_path, "fio": fio_path,
                      "paranoid": paranoid_path}.get(io_driver)
        try:
            summary = diagnose_launch_failure(
                diag,
                lambda: write_status({"elapsed_s": time.monotonic() - start}),
                qmp, qga_sock, proc.pid, run_dir, lun_specs, err_nodes,
                len(writer_pids), probe_s, writer_exe, screenshot, dump_path,
                dump_now)
        finally:
            # Even if the dump failed part way: it removes the rules first.
            if diag.get("delay_rules_removed"):
                result["delay_rules_removed"] = True
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
                        err_node=f"lerr{tag}", dev_id=f"lun{tag}",
                        serial=f"TL{tag}"))
        total_luns = len(lun_specs)
        err_nodes = [s.err_node for s in lun_specs]

        # See IO_PROBE_MARGIN_S above: the probe window has to span a full
        # duty cycle, not just a few seconds, or it will unpredictably land
        # in a dead patch between bursts.
        io_probe_window_s = strategy.io_probe_window_s()
        writer_duration = duration_s + WARMUP_S + io_probe_window_s + WRITER_DURATION_SLACK_S
        # The fill runs inside the writer's own lifetime, before the soak
        # starts counting: budget for the longest it is allowed to take.
        # stop_writers ends them at the close of the run either way.
        if fill_wait:
            writer_duration += fill_timeout_s

        argv = build_qemu_argv(boot_overlay, vars_overlay, qmp_sock, qga_sock,
                                serial_log, tpm_sock, adapters, lun_specs, seed,
                                ram, cpus, taskset_cores,
                                strategy.delay_rules(), iothreads, tmf_trace,
                                stop_on_broken, ring_diag, qga_trace,
                                arm_at_start=not fill_wait,
                                hv_crash=watch_after_break_s > 0)

        meta = {"adapters": adapters, "targets": targets,
                "luns_per_target": luns_per_target, "total_luns": total_luns,
                "duration_s": duration_s, **strategy.meta(),
                "seed": seed,
                "iothreads": adapters if iothreads is None else iothreads,
                "tmf_trace": tmf_trace,
                "stop_on_broken": stop_on_broken,
                "ring_diag": ring_diag,
                "dump_on_agent_stall": dump_on_agent_stall,
                "qga_trace": qga_trace,
                "fill_wait": fill_wait,
                "fill_timeout_s": fill_timeout_s,
                "watch_after_break_s": watch_after_break_s,
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

        # Handed to the strategy's callbacks from here on. qemu_stderr is
        # the one field that changes after this point: it stays None until
        # the soak loop builds the reader.
        ctx = SoakContext(qmp=qmp, qga_sock=qga_sock, proc=proc,
                          run_dir=run_dir, lun_specs=lun_specs,
                          err_nodes=err_nodes, result=result,
                          qemu_stderr=None, write_status=write_status,
                          start=start, record_trace=record_trace,
                          collect_vioscsi_telemetry=collect_vioscsi_telemetry,
                          capture_postmortem=capture_postmortem,
                          capture_qga_port=capture_qga_port)

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
        # pid -> LUN, for the per-LUN writers: which LUN a writer that
        # exited was driving. paranoid.exe drives every LUN from one
        # process and names the failing ones by its own dumps instead, so
        # it leaves this empty.
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
        launch_deadline = time.monotonic() + WRITER_LAUNCH_TIMEOUT_S
        if io_driver == "paranoid":
            all_drives = [drive_numbers[s.serial] for s in lun_specs]
            request_sent_at = utc_now()
            try:
                writer_pids.append(launch_paranoid_writer(
                    qga_sock, all_drives, writer_duration, paranoid_path,
                    strategy.max_hold_ms(), qga_resyncs))
            except NoReplyError as exc:
                diagnose_failed_launch("no-reply",
                                       paranoid_writer_name(all_drives),
                                       request_sent_at, exc)
                raise
        else:
            for spec in lun_specs:
                drive_no = drive_numbers[spec.serial]
                if time.monotonic() > launch_deadline:
                    diagnose_failed_launch("deadline")
                    raise RuntimeError(
                        f"only got {len(writer_pids)} of {total_luns} "
                        f"writer(s) started within {WRITER_LAUNCH_TIMEOUT_S}s")
                # A refused guest-exec answered, so it fails as before: the
                # diagnostics are for an agent that went quiet.
                request_sent_at = utc_now()
                try:
                    pid = launch_writer(
                        qga_sock, drive_no, writer_duration, io_driver,
                        diskspd_path, fio_path, qga_resyncs)
                    writer_pids.append(pid)
                    writer_luns[pid] = spec.dev_id
                except NoReplyError as exc:
                    diagnose_failed_launch(
                        "no-reply", f"writer for PhysicalDrive{drive_no}",
                        request_sent_at, exc, drive_no)
                    raise

        if fill_wait:
            target_bytes = parse_size_bytes(LUN_IMAGE_SIZE)
            print(f"    waiting up to {fill_timeout_s:.0f}s for all "
                  f"{total_luns} LUN image(s) to reach {LUN_IMAGE_SIZE} on "
                  f"disk before arming {strategy.rule_label()}",
                  file=sys.stderr)
            fill = wait_for_fill(qmp, lun_specs, target_bytes,
                                 fill_timeout_s, proc, qga_sock,
                                 writer_pids, writer_seen)
            result["fill"] = fill
            if fill["status"] == "qemu-exited":
                raise qemu_died_error("while waiting for the LUNs to fill")
            if fill["status"] != "filled":
                # A ring break pauses the VM, which stops the fill cold.
                dump_if_stopped_on_broken()
                short = {k: fill["bytes_on_disk"][k] for k in fill["short"]}
                result["outcome"] = "fill-failed"
                result["elapsed_s"] = time.monotonic() - start
                result["error"] = (
                    f"LUN images did not fill to {target_bytes} bytes on "
                    f"disk ({fill['status']} after {fill['elapsed_s']:.0f}s); "
                    f"short: {short}")
                collect_vioscsi_telemetry()
                return result
            print(f"    all LUNs filled in {fill['elapsed_s']:.0f}s; arming "
                  f"{strategy.rule_label()}", file=sys.stderr)
            strategy.arm_after_fill(ctx)
            result["rule_armed_after_fill_s"] = fill["elapsed_s"]

        time.sleep(WARMUP_S)

        # See IO_PROBE_MARGIN_S / the module docstring: this workload runs in
        # bursts on a ~delay-max-ms duty cycle (the deep queue traps nearly
        # every outstanding request at once, then releases and re-traps them
        # together), so io_probe_window_s is sized to always span a full
        # cycle regardless of what phase it starts in. The retry is just a
        # safety net for scheduling slop, not the main defense -- getting
        # this wrong would abort an unattended multi-hour run before it even
        # starts, so don't rely on luck here.
        total_wps = 0.0
        wps_per_lun: dict = {}
        broke_in_preflight = False
        for attempt in range(IO_PROBE_ATTEMPTS):
            w_before = write_ops_by_node(qmp)
            time.sleep(io_probe_window_s)
            w_after = write_ops_by_node(qmp)
            wps_per_lun = {s.serial: lun_write_delta(w_before, w_after, s) / io_probe_window_s
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
        if total_wps < MIN_WRITE_OPS_PER_S and not broke_in_preflight:
            result["outcome"] = "no-io"
            result["elapsed_s"] = time.monotonic() - start
            diag = ""
            if io_driver == "diskspd":
                result["diskspd_diagnostic"] = diskspd_diagnostic(
                    qga_sock, diskspd_path, drive_numbers[lun_specs[0].serial],
                    strategy.max_hold_ms())
                diag = f" diskspd diagnostic: {result['diskspd_diagnostic']}"
            elif io_driver == "fio":
                result["fio_diagnostic"] = fio_diagnostic(
                    qga_sock, fio_path, drive_numbers[lun_specs[0].serial],
                    strategy.max_hold_ms())
                diag = f" fio diagnostic: {result['fio_diagnostic']}"
            elif io_driver == "paranoid":
                result["paranoid_diagnostic"] = paranoid_diagnostic(
                    qga_sock, paranoid_path, drive_numbers[lun_specs[0].serial],
                    strategy.max_hold_ms())
                diag = f" paranoid diagnostic: {result['paranoid_diagnostic']}"
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

        qemu_stderr = QemuStderr(qemu_log_path)
        ctx.qemu_stderr = qemu_stderr
        qemu_stderr.poll()
        # Firmware, driver init and the pre-flight probe all issue resets
        # and TMFs of their own (each adapter resets three times on a bare
        # boot). Keep those apart so the soak's tallies mean something.
        # Any virtio_error() already seen stays pending and is reported on
        # the first pass of the loop below -- an adapter that broke during
        # pre-flight is just as broken.
        result["tmf_trace_pre_soak"] = qemu_stderr.take_counts()

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
        # (static) screen or a starved guest agent look like. Held requests
        # legitimately stall completions, so only call it a stall once it has
        # outlasted the longest hold.
        io_stall_threshold_s = strategy.io_stall_threshold_s()
        last_io_progress_t = test_start
        prev_total_wr = total_lun_writes(prev_wops, lun_specs)

        while time.monotonic() < monitor_deadline:
            now = time.monotonic()
            elapsed = now - start

            qemu_stderr.poll()
            broken_lines = qemu_stderr.take_broken()
            if broken_lines:
                result["outcome"] = "virtio-broken"
                result["elapsed_s"] = elapsed
                result["qemu_stderr"] = qemu_stderr.lines
                result["rule_hits"] = rule_hits(qmp, err_nodes)
                result["held_now"] = held_counts(qmp, err_nodes)
                # Before anything that needs the guest: it may be paused.
                dump_if_stopped_on_broken()
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
                # window below takes a full hold cycle, and telemetry talks
                # to a guest that has just lost its disks. Neither must be
                # able to take the finding down with it.
                write_status({"elapsed_s": elapsed})

                act = lun_activity_by_adapter(qmp, lun_specs,
                                               io_probe_window_s)
                dead = adapters_without_io(act, result["held_now"], lun_specs)
                result["adapter_activity"] = act
                result["activity_window_s"] = round(io_probe_window_s, 1)
                result["dead_adapters"] = dead
                result["write_ops_per_s"] = round(
                    sum(v["writes"] for v in act.values()) / io_probe_window_s, 1)
                result["error"] += f". Adapters no longer doing I/O: {dead or 'none'}"
                print(f"    adapters no longer doing I/O: {dead or 'none'} "
                      f"(of {len(act)}, over a {io_probe_window_s:.0f}s window)",
                      file=sys.stderr)
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
                if watch_after_break_s > 0 and result.get("break_dump"):
                    watch_after_break()
                return result

            if proc.poll() is not None:
                result["outcome"] = "qemu-exited"
                result["qemu_returncode"] = proc.returncode
                result["elapsed_s"] = elapsed
                write_status({"elapsed_s": elapsed})
                return result

            if watch_after_break_s > 0:
                try:
                    panicked = (qmp_call(qmp, "query-status").get("status")
                                == "guest-panicked")
                except Exception:
                    panicked = False
                if panicked:
                    result["outcome"] = "guest-panicked"
                    result["elapsed_s"] = elapsed
                    result["guest_panic"] = capture_guest_panic()
                    write_status({"elapsed_s": elapsed})
                    return result

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

            total_wr = total_lun_writes(write_ops_by_node(qmp), lun_specs)
            if total_wr > prev_total_wr:
                last_io_progress_t = now
            prev_total_wr = total_wr

            if (not agent_alive and agent_lost_t is not None
                    and now - agent_lost_t > AGENT_SILENCE_THRESHOLD_S
                    and now - last_change_t > STATIC_SCREEN_THRESHOLD_S
                    and now - last_io_progress_t > io_stall_threshold_s):
                result["outcome"] = "crash-suspected"
                result["elapsed_s"] = elapsed
                result["rule_hits"] = rule_hits(qmp, err_nodes)
                print(f"    guest appears dark after {elapsed:.0f}s -- "
                      f"capturing crash dump", file=sys.stderr)
                # Not subject to the silence cap: this one ends the run.
                capture_qga_port("guest dark", agent_silent_s=round(
                    now - agent_lost_t, 1))
                result["dump_ok"] = try_dump_guest_memory(
                    qmp, dump_path, proc.pid, err_nodes)
                write_status({"elapsed_s": elapsed})
                return result

            if now - last_heartbeat >= heartbeat_s:
                if writers_failed(elapsed):
                    return result
                cur_wops = write_ops_by_node(qmp)
                sample_s = now - last_heartbeat
                wps = sum(lun_write_delta(prev_wops, cur_wops, s) for s in lun_specs) / sample_s
                prev_wops = cur_wops
                last_heartbeat = now
                hits = rule_hits(qmp, err_nodes)
                held = held_counts(qmp, err_nodes)
                hb = {"elapsed_s": round(elapsed, 0), "write_ops_per_s": round(wps, 1),
                      "rule_hits": hits, "held_now": held,
                      "agent_alive": agent_alive,
                      "tmf_trace": qemu_stderr.trace_counts,
                      **strategy.heartbeat(ctx)}
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                      f"{elapsed / 3600:.2f}h elapsed, {wps:.1f} wps, "
                      f"rule hits={sum(hits.values())}, held now={sum(held.values())}, "
                      f"TMFs={qemu_stderr.tmf_requests()}")
                write_status(hb)

            # A strategy that wants to end the run mutates and returns
            # ctx.result (see SoakStrategy.on_tick). The housekeeping every
            # other exit path does is done here rather than left to the
            # strategy: a result that skipped it would have no trace fold,
            # no telemetry and no final status.json, and the finally block
            # below decides what to keep from this same dict.
            tick = strategy.on_tick(ctx)
            if tick is not None:
                result["elapsed_s"] = time.monotonic() - start
                record_trace()
                result["rule_hits"] = rule_hits(qmp, err_nodes)
                collect_vioscsi_telemetry()
                write_status({"elapsed_s": result["elapsed_s"]})
                return result

            time.sleep(POLL_INTERVAL_S)

        # The soak ran its duration, but the last heartbeat can be up to
        # heartbeat_s old: a writer that died since then would otherwise
        # be reported as a clean run.
        if writers_failed(time.monotonic() - start):
            return result

        result["outcome"] = "completed"
        result["elapsed_s"] = time.monotonic() - start
        record_trace()
        result["rule_hits"] = rule_hits(qmp, err_nodes)
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


def add_common_args(ap: argparse.ArgumentParser, soak_dir: Path,
                    rule_args=None,
                    rule_label: str = "the tail-latency rule",
                    max_hold_opt: str = "--delay-max-ms") -> None:
    """Add the options every soak harness shares.

    'rule_args', if given, is called to add the harness's own delay-rule
    options at the point in the list where they belong, so each harness
    keeps a sensible --help ordering rather than having its own options
    tacked on at the end. 'rule_label' and 'max_hold_opt' name the
    harness's rule and its longest-hold option in the help text of the
    shared options that refer to them; 'soak_dir' is the harness's own run
    directory, named in --disk-dir's help."""
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
                          "driver left it, then resume. The dump removes the "
                          "delay rules (default: on)")
    ap.add_argument("--watch-after-break", type=float, default=0.0,
                     metavar="MINUTES",
                     help="after a ring break has been dumped and the VM "
                          "resumed, keep it running this long and see "
                          "whether Windows bugchecks (hv-crash, so no guest "
                          "driver is needed). A bugcheck pauses the VM and "
                          "writes panic.dmp with the real bugcheck code; "
                          "screenshots go to watch-NNN.ppm (default: 0, "
                          "stop at the break)")
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
                          "dir) and the dump removes the delay rules, so the "
                          "probe that follows no longer sees the same "
                          "workload (default: off)")
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
    ap.add_argument("--targets", type=int, default=1,
                     help="number of SCSI targets per adapter (default: "
                          "%(default)s)")
    ap.add_argument("--luns-per-target", type=int, default=1,
                     help=f"number of LUNs per target, all subject to "
                          f"{rule_label} (default: %(default)s)")
    ap.add_argument("--duration-hours", type=float, default=4.0,
                     help="how long to run the soak test (default: %(default)s)")
    if rule_args is not None:
        rule_args(ap)
    ap.add_argument("--io-driver",
                     choices=["powershell", "diskspd", "fio", "paranoid"],
                     default="powershell",
                     help=f"how to drive guest I/O: 'powershell' (default) runs "
                          f"the built-in raw-write loop (writes only -- use "
                          f"diskspd, fio or paranoid to also exercise reads); "
                          f"'diskspd' launches Microsoft's diskspd.exe with a "
                          f"50/50 read/write mix against each LUN's "
                          f"PhysicalDriveN; 'fio' launches fio.exe with a 50/50 "
                          f"random read/write mix and crc32c data-integrity "
                          f"verification against each LUN's PhysicalDriveN; "
                          f"'paranoid' launches one paranoid.exe with a 50/50 "
                          f"mixed random I/O workload over every LUN's "
                          f"PhysicalDriveN at once, with its per-request "
                          f"timeout raised past {max_hold_opt} so the rule's "
                          f"hold is not mistaken for a stuck device")
    ap.add_argument("--diskspd-path", default=DEFAULT_DISKSPD_PATH,
                     help="guest-side path to diskspd.exe, used when "
                          "--io-driver=diskspd (default: %(default)s)")
    ap.add_argument("--fio-path", default=DEFAULT_FIO_PATH,
                     help="guest-side path to fio.exe, used when "
                          "--io-driver=fio (default: %(default)s)")
    ap.add_argument("--paranoid-path", default=DEFAULT_PARANOID_PATH,
                     help="guest-side path to paranoid.exe, used when "
                          "--io-driver=paranoid (default: %(default)s)")
    ap.add_argument("--fill-wait", action=argparse.BooleanOptionalAction,
                     default=None,
                     help=f"hold off arming {rule_label} until every "
                          f"LUN image is fully allocated on the host (all "
                          f"{LUN_IMAGE_SIZE} written), so the writer's "
                          f"sequential initialize pass runs at full speed. "
                          f"Default: on for --io-driver=paranoid (whose "
                          f"--initialize fills the disk), off otherwise -- the "
                          f"other drivers only touch a small window and would "
                          f"never fill it")
    ap.add_argument("--fill-timeout-minutes", type=float,
                     default=DEFAULT_FILL_TIMEOUT_S / 60,
                     help="give up if the LUNs have not filled within this "
                          "long (default: %(default)s)")
    ap.add_argument("--vioscsi-telemetry-script",
                     default=DEFAULT_VIOSCSI_TELEMETRY_SCRIPT,
                     help="guest-side PowerShell script to run and collect "
                          "vioscsi telemetry from after the run finishes "
                          "(default: %(default)s); its combined stdout/"
                          "stderr is saved to vioscsi-telemetry.log in the "
                          "run directory. Pass an empty string to disable")
    ap.add_argument("--heartbeat-seconds", type=float, default=DEFAULT_HEARTBEAT_S,
                     help=f"how often to print/record a progress line during "
                          f"the run (default: %(default)s); keep this well "
                          f"above {max_hold_opt} or individual heartbeats will "
                          f"alias the workload's own burst/dead duty cycle and "
                          f"bounce between 0 and a high rate rather than "
                          f"showing a stable average")
    ap.add_argument("--ram", default=DEFAULT_RAM)
    ap.add_argument("--cpus", default=DEFAULT_CPUS)
    ap.add_argument("--host-pressure-cores", default=None, metavar="CPULIST",
                     help="restrict QEMU to these host cores via taskset "
                          "(e.g. '0-1')")
    ap.add_argument("--seed", type=int, default=1,
                     help="inject-error PRNG seed, for reproducing a run")
    ap.add_argument("--disk-dir", type=Path, default=None, metavar="DIR",
                     help=f"directory in which to create the LUN disk images "
                          f"under I/O test (default: the per-run directory "
                          f"under {soak_dir})")
    ap.add_argument("--keep-all", action="store_true",
                     help="keep overlays/images even for a clean 'completed' run")
