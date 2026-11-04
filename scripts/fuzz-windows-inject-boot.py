#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Grid-sweep fuzz harness for the viostor (virtio-blk) boot path, driving
# scripts/setup-windows-inject-vm.sh's inject-error boot disk (err0)
# through a matrix of latency-injection scenarios until the guest either
# boots successfully or bugchecks/hangs.
#
# Design notes (see also docs/devel/storage-error-injection.rst and the
# InjectDelayRuleOptions schema in qapi/block-core.json):
#
#  - Each grid point gets a throwaway qcow2 overlay backed by the golden,
#    already-installed BOOT_DISK (and a throwaway overlay of OVMF_VARS),
#    so a crash or a dirty kill never mutates the golden image. The
#    overlay is discarded on a clean boot and kept for later inspection
#    on a suspected crash.
#  - The injected rule for each grid point is armed at '-blockdev'
#    creation time (delays.0.*), so it is active for the guest's very
#    first I/O, i.e. during boot -- not applied after the fact.
#  - Boot-complete detection uses qemu-guest-agent's 'guest-ping' over
#    its own virtserialport channel (a separate socket from the main QMP
#    socket). This requires a one-time setup step inside the guest: see
#    the usage() text below.
#  - Crash/hang detection does *not* try to parse the Windows kernel
#    debugger wire protocol (binary, needs a real handshake). Instead it
#    takes periodic QMP 'screendump' snapshots and flags a run as a
#    crash candidate once the framebuffer has stopped changing for
#    STATIC_SCREEN_THRESHOLD_S while guest-ping still isn't answering.
#    This requires automatic-restart-on-BSOD to be disabled in the guest
#    (see usage()) so the guest sits at the blue/black screen instead of
#    silently rebooting into a fresh, unmonitored attempt.
#  - A hard per-run wall-clock timeout (RUN_TIMEOUT_S) is the backstop:
#    nobody is going to wait around for a slow boot in real life, and it
#    guarantees one bad grid point can't stall the whole sweep.

import argparse
import dataclasses
import hashlib
import json
import random
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# The shared machinery lives next to this script, which is not necessarily
# the directory the harness is run from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# pylint: disable=wrong-import-position
from vioscsi_soak_common import (BOOT_DISK, OVMF_CODE, OVMF_VARS, QEMU_BIN,
                                 QEMU_BUILD, QEMU_IMG, VM_DIR, connect_qmp,
                                 describe_vioscsi_identity, qga_ping,
                                 qmp_call, read_vioscsi_identity,
                                 start_swtpm)

FUZZ_DIR = VM_DIR / "fuzz"
# The outcomes at which the guest agent has just answered: the only point
# a run can ask the guest anything.
AGENT_UP_OUTCOMES = ("boot-ok", "not-injected")

RAM = "8G"
CPUS = "4"

# How much *added* latency a single rule is allowed to contribute in the
# worst case (max-hits * delay), independent of how many requests the
# guest actually issues. Keeps any one grid point from running away.
RULE_BUDGET_MS = 180_000  # 3 minutes

RUN_TIMEOUT_S = 600  # hard per-run wall-clock cap (10 minutes)

# OVMF's own VirtioBlkDxe UEFI driver initializes and reads the boot disk
# long before ntoskrnl.exe/viostor.sys ever run. A 'stall' or 'reset-race'
# action scheduled off wall-clock time alone can land on that firmware
# traffic (or, worse, on QEMU's own pre-realize CHS geometry probe -- see
# the run-0037 deadlock this harness hit) instead of on the Windows driver
# it's meant to be exercising. VIRTIO_STATUS_TRACE captures every write to
# the virtio status register (-trace virtio_set_status) so the harness can
# detect the real OVMF -> Windows driver handoff: any virtio driver must
# reset the device (status=0) before it starts using it, so viostor.sys
# attaching produces a *second* reset+renegotiate cycle on the same device
# that OVMF already brought up once. See VirtioHandoffTracker below.
VIRTIO_STATUS_TRACE = "virtio-status.trace"
VIRTIO_CONFIG_S_DRIVER_OK = 0x04

# Both deliberately override the shared defaults: a boot sweep watches a
# screen that firmware legitimately leaves static for minutes, so it needs
# a far longer staleness threshold and no reason to poll as often.
#
# Must comfortably exceed RULE_BUDGET_MS: a single rule can legitimately
# keep one boot screen (e.g. the OVMF/TianoCore "loading Windows Boot
# Manager" splash, which doesn't animate while firmware slowly reads
# boot files) static for up to that long without anything being wrong.
# A threshold close to RULE_BUDGET_MS turns intentional injection into
# false "crash" verdicts.
STATIC_SCREEN_THRESHOLD_S = RULE_BUDGET_MS // 1000 + 90  # 270s
POLL_INTERVAL_S = 3
BOOT_GRACE_S = 20  # ignore framebuffer staleness before this point (firmware splash)

# The OVMF -> Windows handoff can land well under a second into a boot
# that completes in ~5s total, so POLL_INTERVAL_S's 3s cadence would burn
# most of that window just deciding whether it happened yet. Poll the
# handoff tracker (a cheap local file read, no QMP round trip) on this
# much tighter cadence until it fires; fall back to POLL_INTERVAL_S
# afterward, since guest-ping/screendump checks aren't as time-critical.
HANDOFF_POLL_INTERVAL_S = 0.05


def safety_max_hits(delay_ms: float, budget_ms: int = RULE_BUDGET_MS) -> int:
    return max(1, int(budget_ms // max(delay_ms, 1)))


def usage_note() -> str:
    return """
One-time guest setup (do this once, on the currently-installed boot.qcow2,
before running any sweep):

  1. Boot normally:
       ./scripts/setup-windows-inject-vm.sh run
  2. Install qemu-guest-agent from the virtio-win ISO (guest-agent\\
     qemu-ga-x86_64.msi) -- this is how the harness knows boot completed.
  3. Disable automatic restart on a bugcheck, so the guest sits at the
     blue/black screen instead of rebooting into an unmonitored retry
     (elevated PowerShell):
       Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name AutoReboot -Value 0
  4. Shut down cleanly. That boot.qcow2 is now the golden image every
     grid point's overlay is backed by.

Note: kernel debugging over serial (bcdedit /debug on) is *not* set up
here -- Secure Boot policy blocks enabling it from within the guest, and
the harness doesn't need it anyway (crash detection is guest-ping +
screendump staleness, not the KD wire protocol). A serial capture is
still recorded per run for whatever plain-text output the guest happens
to emit, but treat it as best-effort, not a KD log.
"""


# ------------------------------------------------------------------
# Grid definitions
# ------------------------------------------------------------------


@dataclasses.dataclass
class Action:
    at_s: float
    kind: str  # "release" | "remove" | "reset"
    kwargs: dict = dataclasses.field(default_factory=dict)
    # "start": at_s seconds after the VM process launched (the old
    # behavior). "handoff": at_s seconds after the boot disk's virtio
    # device is observed being reset and re-initialized by the guest's
    # own driver (see VirtioHandoffTracker) -- use this for actions meant
    # to race or stall the Windows driver specifically, not firmware I/O.
    relative_to: str = "start"


@dataclasses.dataclass
class TestCase:
    category: str
    label: str
    rule: dict  # InjectDelayRuleOptions fields (ops as a list)
    actions: list = dataclasses.field(default_factory=list)  # list[Action]
    seed: int = 1
    # "handoff" (the default): the disk boots as a plain passthrough and
    # 'rule' is only added, via x-inject-error-delay-add, once the boot
    # disk's virtio device shows the OVMF -> Windows driver handoff (see
    # VirtioHandoffTracker). Every category here is meant to exercise
    # viostor.sys, not OVMF's VirtioBlkDxe or QEMU's own pre-realize CHS
    # geometry probe -- both of which sit in front of the guest's real
    # driver and would otherwise silently eat a rule's max-hits budget
    # (or, for an unbounded 'stall', deadlock QEMU outright before the
    # monitor is even usable enough to release it; see the run-0037
    # incident this harness hit). "start": 'rule' is embedded in the
    # '-blockdev' options and armed at blockdev-creation time, active for
    # literally the first matching op on the node -- only useful for
    # deliberately targeting firmware/pre-boot I/O, which no generator
    # below currently wants.
    arm_rule_at: str = "handoff"


def _rule(id_, ops=None, **fields) -> dict:
    r = {"id": id_}
    if ops is not None:
        r["ops"] = ops
    r.update(fields)
    return r


def gen_baseline() -> list:
    # No 'delays' entries at all: the inject-error node is a transparent
    # pass-through. Use this to confirm the overlay/QMP/QGA/screendump
    # plumbing works end-to-end before trusting a "crash" verdict from
    # any of the actual injection categories.
    return [TestCase("baseline", "no-injection", {})]


def gen_fixed_latency() -> list:
    cases = []
    for ops in (["read"], ["write"], ["flush"]):
        for delay_ms in (50, 100, 250, 500, 1000, 2000, 5000, 10000):
            mh = safety_max_hits(delay_ms)
            cases.append(TestCase(
                "fixed-latency", f"ops={ops[0]},delay-ms={delay_ms},max-hits={mh}",
                _rule("fixed", ops=ops, **{"delay-ms": delay_ms, "max-hits": mh})))
    return cases


def gen_tail_latency() -> list:
    cases = []
    for delay_ms, delay_max_ms in ((20, 500), (50, 2000), (100, 10000), (200, 30000)):
        for probability in (0.001, 0.005, 0.02):
            # Budget against delay-max-ms, not the average: hits aren't
            # guaranteed to spread evenly, and a run of bad luck landing
            # every hit at the high end of the range must still stay
            # within budget.
            mh = safety_max_hits(delay_max_ms)
            cases.append(TestCase(
                "tail-latency",
                f"delay-ms={delay_ms},delay-max-ms={delay_max_ms},probability={probability},max-hits={mh}",
                _rule("tail", ops=["read"], probability=probability,
                      **{"delay-ms": delay_ms, "delay-max-ms": delay_max_ms, "max-hits": mh})))
    return cases


def gen_stall() -> list:
    # max-hits=1 stalls the very first matching op -- at blockdev-creation
    # time that's reliably OVMF/firmware I/O, not viostor.sys. Defer
    # arming the rule until the OVMF -> Windows driver handoff (see
    # VirtioHandoffTracker) so it's the Windows driver's first matching
    # op that actually gets stalled; hold_s then counts from that point.
    cases = []
    for ops in (["read"], ["write"], ["flush"]):
        for hold_s in (2, 10, 30, 60):
            for ended_by in ("release", "reset"):
                rule = _rule("stall", ops=ops, stall=True, **{"max-hits": 1})
                actions = [Action(hold_s, ended_by,
                                   {"disposition": "complete"} if ended_by == "release" else {},
                                   relative_to="handoff")]
                cases.append(TestCase(
                    "stall", f"ops={ops[0]},hold-s={hold_s},ended-by={ended_by}",
                    rule, actions, arm_rule_at="handoff"))
    return cases


def gen_timeout_success() -> list:
    cases = []
    for ops in (["read"], ["write"]):
        for delay_ms in (35000, 45000, 60000, 90000):
            cases.append(TestCase(
                "timeout-success", f"ops={ops[0]},delay-ms={delay_ms}",
                _rule("timeout-ok", ops=ops, **{"delay-ms": delay_ms, "max-hits": 2})))
    return cases


def gen_timeout_failure() -> list:
    cases = []
    for ops in (["read"], ["write"]):
        for delay_ms in (35000, 45000, 60000, 90000):
            for errno in (5, 110):  # EIO, ETIMEDOUT
                cases.append(TestCase(
                    "timeout-failure", f"ops={ops[0]},delay-ms={delay_ms},errno={errno}",
                    _rule("timeout-fail", ops=ops, errno=errno,
                          **{"delay-ms": delay_ms, "max-hits": 2})))
    return cases


def gen_backend_disconnect() -> list:
    # stall=True with no 'ops' filter catches every op on the whole
    # device, unlimited hits -- at blockdev-creation time that's the very
    # first firmware read. Defer arming until the OVMF -> Windows driver
    # handoff so this actually exercises viostor.sys's disconnect/
    # reconnect handling rather than wedging OVMF.
    cases = []
    for hold_before_release_s in (5, 15, 30):
        for reconnect_delay_s in (10, 30):
            rule = _rule("disconnect", stall=True)  # all ops, whole device, unlimited hits
            actions = [
                Action(hold_before_release_s, "release", {"disposition": "error", "errno": 5},
                       relative_to="handoff"),
                Action(hold_before_release_s + reconnect_delay_s, "remove", {},
                       relative_to="handoff"),
                Action(hold_before_release_s + reconnect_delay_s + 0.5, "release",
                       {"disposition": "complete"}, relative_to="handoff"),
            ]
            cases.append(TestCase(
                "backend-disconnect",
                f"fail-at-s={hold_before_release_s},reconnect-after-s={reconnect_delay_s}",
                rule, actions, arm_rule_at="handoff"))
    return cases


def gen_flush_latency() -> list:
    cases = []
    for delay_ms in (500, 1000, 2000, 5000, 10000, 20000, 30000):
        mh = safety_max_hits(delay_ms)
        cases.append(TestCase(
            "flush-latency", f"delay-ms={delay_ms},max-hits={mh}",
            _rule("flush", ops=["flush"], **{"delay-ms": delay_ms, "max-hits": mh})))
    return cases


def gen_queue_saturation() -> list:
    # 'stall=True' with no per-op release scheduled other than the one
    # Action below is the same unbounded-stall shape as gen_stall(): armed
    # at blockdev-creation time it would catch (and never release) OVMF's
    # or QEMU's own pre-realize I/O, deadlocking the whole VM before the
    # monitor can even deliver the release. Handoff-gated by default.
    cases = []
    for ops in (["read"], None):
        for max_hits in (4, 16, 64, 128, 256):
            rule = _rule("saturate", ops=ops, stall=True, **{"max-hits": max_hits})
            actions = [Action(20, "release", {"disposition": "complete"}, relative_to="handoff")]
            label_ops = ops[0] if ops else "all"
            cases.append(TestCase(
                "queue-saturation", f"ops={label_ops},max-hits={max_hits}",
                rule, actions))
    return cases


def gen_out_of_order() -> list:
    cases = []
    for delay_ms, delay_max_ms in ((20, 300), (50, 1000), (100, 3000), (200, 8000)):
        mh = safety_max_hits(delay_max_ms)  # budget against the worst case, not the average
        cases.append(TestCase(
            "out-of-order", f"delay-ms={delay_ms},delay-max-ms={delay_max_ms},max-hits={mh}",
            _rule("reorder", ops=["read"],
                  **{"delay-ms": delay_ms, "delay-max-ms": delay_max_ms, "max-hits": mh})))
    return cases


def gen_reset_race() -> list:
    # max-hits=1 again means the un-gated rule would stall firmware's
    # first matching op, not viostor.sys's -- arm at the OVMF -> Windows
    # handoff and count release_at_s from there instead of from process
    # start.
    cases = []
    for ops in (["read"], ["write"]):
        for release_at_s in (25, 30, 35, 55, 60, 65):
            rule = _rule("reset-race", ops=ops, stall=True, **{"max-hits": 1})
            actions = [Action(release_at_s, "release", {"disposition": "complete"},
                               relative_to="handoff")]
            cases.append(TestCase(
                "reset-race", f"ops={ops[0]},release-at-s={release_at_s}",
                rule, actions, arm_rule_at="handoff"))
    return cases


GENERATORS: dict = {
    "baseline": gen_baseline,
    "fixed-latency": gen_fixed_latency,
    "tail-latency": gen_tail_latency,
    "stall": gen_stall,
    "timeout-success": gen_timeout_success,
    "timeout-failure": gen_timeout_failure,
    "backend-disconnect": gen_backend_disconnect,
    "flush-latency": gen_flush_latency,
    "queue-saturation": gen_queue_saturation,
    "out-of-order": gen_out_of_order,
    "reset-race": gen_reset_race,
}


class VirtioHandoffTracker:
    """Watches a '-trace virtio_set_status,file=...' log to detect the
    moment the boot disk's virtio device is taken over by the guest's own
    driver (viostor.sys), as distinct from OVMF's VirtioBlkDxe.

    Every virtio driver must reset a device (status=0) before it starts
    using it, so the first device to reach DRIVER_OK is assumed to be the
    boot disk (OVMF never touches virtio-serial). A second reset+
    renegotiate cycle on that same device is the guest's real driver
    attaching.
    """

    _LINE_RE = re.compile(r"virtio_set_status vdev (0x[0-9a-fA-F]+) val (\d+)")

    def __init__(self, trace_path: Path):
        self._trace_path = trace_path
        self._pos = 0
        self._target_vdev: Optional[str] = None
        self._reset_after_driver_ok = False
        self.handoff_done = False

    def poll(self) -> bool:
        if self.handoff_done:
            return True
        if not self._trace_path.exists():
            return False
        with self._trace_path.open("r") as f:
            f.seek(self._pos)
            lines = f.readlines()
            self._pos = f.tell()
        for line in lines:
            m = self._LINE_RE.search(line)
            if not m:
                continue
            vdev, val = m.group(1), int(m.group(2))
            if self._target_vdev is None:
                if val & VIRTIO_CONFIG_S_DRIVER_OK:
                    self._target_vdev = vdev
                continue
            if vdev != self._target_vdev:
                continue
            if val == 0:
                self._reset_after_driver_ok = True
            elif val & VIRTIO_CONFIG_S_DRIVER_OK and self._reset_after_driver_ok:
                self.handoff_done = True
                return True
        return False


# ------------------------------------------------------------------
# Harness
# ------------------------------------------------------------------


def rule_props(rule: dict, idx: int = 0) -> list:
    props = []
    for key, val in rule.items():
        if key == "ops" and val is not None:
            for i, op in enumerate(val):
                props.append(f"delays.{idx}.ops.{i}={op}")
        elif isinstance(val, bool):
            props.append(f"delays.{idx}.{key}={'true' if val else 'false'}")
        else:
            props.append(f"delays.{idx}.{key}={val}")
    return props


def make_overlay(golden: Path, dest: Path) -> None:
    subprocess.run([str(QEMU_IMG), "create", "-f", "qcow2", "-F", "qcow2",
                    "-b", str(golden), str(dest)],
                   check=True, capture_output=True)


def build_qemu_argv(boot_overlay: Path, vars_overlay: Path,
                     qmp_sock: Path, qga_sock: Path, serial_log: Path,
                     tpm_sock: Path, trace_path: Path, rule: dict, seed: int) -> list:
    props = ",".join(rule_props(rule))
    inject_opts = f"driver=inject-error,image=raw0,node-name=err0,seed={seed}"
    if props:
        inject_opts += "," + props

    return [
        str(QEMU_BIN),
        "-machine", "q35,accel=kvm,smm=on",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-cpu", "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,hv-synic,hv-stimer,hv-time,hv-ipi,hv-tlbflush",
        "-smp", CPUS,
        "-m", RAM,
        "-drive", f"if=pflash,format=qcow2,unit=0,file={OVMF_CODE},readonly=on",
        "-drive", f"if=pflash,format=qcow2,unit=1,file={vars_overlay}",
        "-chardev", f"socket,id=chrtpm,path={tpm_sock}",
        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
        "-device", "tpm-crb,tpmdev=tpm0",
        "-display", "none",
        "-vga", "std",
        "-trace", f"virtio_set_status,file={trace_path}",
        "-qmp", f"unix:{qmp_sock},server=on,wait=off",
        "-serial", f"file:{serial_log}",
        "-chardev", f"socket,path={qga_sock},server=on,wait=off,id=qga0",
        "-device", "virtio-serial",
        "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        "-blockdev", f"driver=file,filename={boot_overlay},node-name=file0",
        "-blockdev", "driver=qcow2,file=file0,node-name=raw0",
        "-blockdev", inject_opts,
        "-device", "virtio-blk-pci,drive=err0,bootindex=0,id=disk0",
    ]


def screendump_hash(qmp, path: Path) -> Optional[str]:
    try:
        qmp_call(qmp, "screendump", filename=str(path))
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def dispatch_action(qmp, action: Action) -> None:
    if action.kind == "release":
        qmp_call(qmp, "x-inject-error-delay-release", node_name="err0", **action.kwargs)
    elif action.kind == "remove":
        qmp_call(qmp, "x-inject-error-delay-remove", node_name="err0", **action.kwargs)
    elif action.kind == "reset":
        qmp_call(qmp, "system_reset")


def disarm_boot_disk(qmp) -> list:
    """Remove every delay rule on err0, then complete whatever it still
    holds, so the identity read that follows a verdict runs off a plain
    disk instead of sitting out the rest of a rule's budget or taking
    its errno. Remove first: releasing first would let the guest's next
    I/O be held again by the still-armed rule, with nothing left to
    release it (the same order scsi-reset uses). Best effort: the
    failures come back as text for the record, never raised."""
    errors = []
    for command, args in (("x-inject-error-delay-remove", {}),
                          ("x-inject-error-delay-release",
                           {"disposition": "complete"})):
        try:
            qmp_call(qmp, command, node_name="err0", **args)
        except Exception as exc:  # pylint: disable=broad-except
            errors.append(f"{command}: {exc}")
    return errors


def read_driver_identity(qga_sock: Path) -> dict:
    """The golden image's vioscsi identity, VioscsiActionOnReset included,
    as the soak harnesses record it. This guest boots from virtio-blk, so
    usually no vioscsi device is present; that is recorded, not an error.
    Asked after the verdict, and any failure, even an agent that stopped
    answering, is only recorded: the boot outcome stands."""
    try:
        return read_vioscsi_identity(qga_sock)
    except Exception as exc:  # pylint: disable=broad-except
        return {"error": str(exc) or repr(exc)}


def run_case(tc: TestCase, run_id: int, qmp_module) -> dict:
    run_dir = FUZZ_DIR / f"run-{run_id:04d}-{tc.category}"
    run_dir.mkdir(parents=True, exist_ok=True)

    boot_overlay = run_dir / "boot.qcow2"
    vars_overlay = run_dir / "vars.qcow2"
    qmp_sock = run_dir / "qmp.sock"
    qga_sock = run_dir / "qga.sock"
    tpm_sock = run_dir / "swtpm.sock"
    serial_log = run_dir / "serial.log"
    screenshot = run_dir / "screen.ppm"
    trace_path = run_dir / VIRTIO_STATUS_TRACE

    # A rule armed 'at handoff' must not be embedded in the initial
    # '-blockdev' options -- the disk boots as a plain passthrough and the
    # rule is added dynamically via QMP once VirtioHandoffTracker fires.
    initial_rule = {} if tc.arm_rule_at == "handoff" else tc.rule
    argv = build_qemu_argv(boot_overlay, vars_overlay, qmp_sock,
                            qga_sock, serial_log, tpm_sock, trace_path,
                            initial_rule, tc.seed)

    meta = {"category": tc.category, "label": tc.label, "rule": tc.rule,
            "arm_rule_at": tc.arm_rule_at,
            "actions": [dataclasses.asdict(a) for a in tc.actions], "argv": argv}
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    swtpm: Optional[subprocess.Popen] = None
    proc: Optional[subprocess.Popen] = None
    qmp = None
    result = {"category": tc.category, "label": tc.label, "outcome": "error",
              "elapsed_s": 0.0, "run_dir": str(run_dir)}
    start = time.monotonic()
    pending_actions = list(tc.actions)
    last_hash = None
    last_change_t = start
    handoff_tracker = VirtioHandoffTracker(trace_path)
    handoff_t: Optional[float] = None
    rule_armed = tc.arm_rule_at != "handoff"
    # The injection waits on the handoff if its rule is armed there or any
    # action is timed from it; without a handoff nothing was injected.
    needs_handoff = ((tc.arm_rule_at == "handoff" and bool(tc.rule))
                     or any(a.relative_to == "handoff" for a in tc.actions))
    inject_errors: list = []
    kernel_confirmed_t: Optional[float] = None

    try:
        try:
            make_overlay(BOOT_DISK, boot_overlay)
            make_overlay(OVMF_VARS, vars_overlay)
            swtpm = start_swtpm(run_dir, tpm_sock)
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            qmp = connect_qmp(
                qmp_module, qmp_sock, proc,
                lambda context: RuntimeError(
                    f"QEMU exited early (code {proc.returncode}) {context}"))
        except Exception as exc:  # pylint: disable=broad-except
            # One case that never got going is not worth the whole grid.
            result["error"] = str(exc) or repr(exc)
            result["elapsed_s"] = time.monotonic() - start

        while qmp is not None:
            now = time.monotonic()
            elapsed = now - start

            if handoff_t is None and handoff_tracker.poll():
                handoff_t = now
                result["handoff_elapsed_s"] = elapsed

            if handoff_t is not None and not rule_armed:
                if tc.rule:  # baseline's {} has nothing to add
                    try:
                        qmp_call(qmp, "x-inject-error-delay-add", node_name="err0", rule=tc.rule)
                    except Exception as exc:
                        print(f"    delay-add failed: {exc}", file=sys.stderr)
                        inject_errors.append(f"delay-add: {exc}")
                rule_armed = True

            ready, still_pending = [], []
            for action in pending_actions:
                if action.relative_to == "handoff":
                    due = handoff_t is not None and (now - handoff_t) >= action.at_s
                else:
                    due = elapsed >= action.at_s
                (ready if due else still_pending).append(action)
            pending_actions = still_pending
            for action in sorted(ready, key=lambda a: a.at_s):
                try:
                    dispatch_action(qmp, action)
                except Exception as exc:
                    print(f"    action {action.kind} failed: {exc}", file=sys.stderr)
                    inject_errors.append(f"{action.kind}: {exc}")

            # A boot that never saw the injection it was meant to survive
            # is not a pass: report it rather than deleting its artifacts.
            if inject_errors:
                result["outcome"] = "inject-failed"
                result["inject_errors"] = inject_errors
                result["elapsed_s"] = elapsed
                break

            # Hold the verdict until every scheduled action has run: one
            # stalled write need not block boot, so the agent can answer
            # before the release/reset race the case exists to test. A boot
            # that answers before any handoff was seen can never arm, so
            # settle that one at once rather than running out the clock.
            missed_handoff = needs_handoff and handoff_t is None
            if (not pending_actions or missed_handoff) and qga_ping(qga_sock):
                result["outcome"] = "not-injected" if missed_handoff else "boot-ok"
                result["elapsed_s"] = elapsed
                break

            if elapsed > BOOT_GRACE_S:
                h = screendump_hash(qmp, screenshot)
                if h is not None:
                    if h != last_hash:
                        last_hash = h
                        last_change_t = now
                        if (handoff_t is not None and kernel_confirmed_t is None
                                and now > handoff_t):
                            kernel_confirmed_t = now
                            result["kernel_confirmed_elapsed_s"] = elapsed
                    elif now - last_change_t > STATIC_SCREEN_THRESHOLD_S:
                        result["outcome"] = "crash-suspected"
                        result["elapsed_s"] = elapsed
                        break

            if elapsed > RUN_TIMEOUT_S:
                result["outcome"] = "timeout"
                result["elapsed_s"] = elapsed
                break

            time.sleep(POLL_INTERVAL_S if handoff_t is not None else HANDOFF_POLL_INTERVAL_S)

        if result["outcome"] in AGENT_UP_OUTCOMES:
            disarm_errors = (disarm_boot_disk(qmp) if rule_armed and tc.rule
                             else [])
            result["vioscsi_driver"] = read_driver_identity(qga_sock)
            if disarm_errors:
                result["vioscsi_driver"]["disarm_error"] = "; ".join(disarm_errors)
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

    if result["outcome"] == "boot-ok":
        for f in (boot_overlay, vars_overlay, screenshot, trace_path):
            f.unlink(missing_ok=True)
    else:
        result["screenshot"] = str(screenshot) if screenshot.exists() else None
        result["serial_log"] = str(serial_log)
        result["virtio_status_trace"] = str(trace_path) if trace_path.exists() else None

    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Grid-sweep the viostor boot path against inject-error latency scenarios.",
        epilog=usage_note(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--categories", default="all",
                     help=f"comma list of {{{','.join(GENERATORS)}}} or 'all'")
    ap.add_argument("--limit", type=int, default=None, help="cap cases per category")
    ap.add_argument("--shuffle", action="store_true", help="randomize case order")
    ap.add_argument("--stop-on-first-crash", action="store_true",
                     help="stop the sweep at the first grid point that ends "
                          "crash-suspected")
    ap.add_argument("--dry-run", action="store_true", help="print the grid, run nothing")
    args = ap.parse_args()

    if not args.dry_run:
        for path, what in ((BOOT_DISK, "boot disk"), (OVMF_VARS, "OVMF NVRAM"),
                           (QEMU_BIN, "qemu binary")):
            if not path.exists():
                print(f"Error: {what} not found: {path}", file=sys.stderr)
                print("Run './scripts/setup-windows-inject-vm.sh create' and "
                      "'install' first, and see --help for one-time guest setup.",
                      file=sys.stderr)
                return 1

    site_packages = QEMU_BUILD / "pyvenv" / "lib"
    qmp_module = None
    if not args.dry_run:
        for py_dir in site_packages.glob("python*/site-packages"):
            sys.path.insert(0, str(py_dir))
        try:
            from qemu.qmp import legacy as qmp_module  # type: ignore
        except ImportError:
            print("Error: could not import qemu.qmp from the build's pyvenv.\n"
                  "Build QEMU first (ninja -C build) so build/pyvenv exists.",
                  file=sys.stderr)
            return 1

    categories = list(GENERATORS) if args.categories == "all" else args.categories.split(",")
    cases = []
    for cat in categories:
        if cat not in GENERATORS:
            print(f"Error: unknown category {cat!r}. Known: {', '.join(GENERATORS)}",
                  file=sys.stderr)
            return 1
        c = GENERATORS[cat]()
        if args.shuffle:
            random.shuffle(c)
        if args.limit:
            c = c[: args.limit]
        cases.extend(c)

    print(f"{len(cases)} grid points across {len(categories)} categories.")
    if args.dry_run:
        for tc in cases:
            print(f"  [{tc.category}] {tc.label}")
        return 0

    FUZZ_DIR.mkdir(parents=True, exist_ok=True)
    results_path = FUZZ_DIR / f"results-{int(time.time())}.jsonl"
    print(f"Results: {results_path}")

    crashes = []
    failed = []
    # Every grid point boots the same golden image, so the driver line is
    # printed only when it changes.
    last_driver = None
    for i, tc in enumerate(cases):
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{started_at}] [{i + 1}/{len(cases)}] {tc.category}: {tc.label} ... ",
              end="", flush=True)
        result = run_case(tc, i, qmp_module)
        finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{result['outcome']} ({result['elapsed_s']:.0f}s, done {finished_at})")
        if "vioscsi_driver" in result:
            driver = describe_vioscsi_identity(result["vioscsi_driver"])
            if driver != last_driver:
                print(f"    vioscsi driver: {driver}")
                last_driver = driver
        with results_path.open("a") as f:
            f.write(json.dumps(result) + "\n")
        if result["outcome"] == "crash-suspected":
            crashes.append(result)
            if args.stop_on_first_crash:
                break
        elif result["outcome"] != "boot-ok":
            failed.append(result)

    print()
    print(f"Done. {len(crashes)} crash candidate(s) and {len(failed)} "
          f"failed grid point(s) out of {len(cases)}.")
    for c in crashes:
        print(f"  [{c['category']}] {c['label']} -> {c['run_dir']}")
    for c in failed:
        print(f"  {c['outcome']}: [{c['category']}] {c['label']} -> "
              f"{c['run_dir']}")
    return 1 if crashes or failed else 0


if __name__ == "__main__":
    sys.exit(main())
