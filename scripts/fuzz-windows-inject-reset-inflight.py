#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Long-running soak test that drives the vioscsi (virtio-scsi) Windows
# guest driver through adapter resets with a large, *known* number of
# commands outstanding, built on the inject-error latency-injection
# branch.
#
# How this differs from its siblings:
#
#   scripts/fuzz-windows-inject-scsi-reset.py races concurrent LUN resets
#   over many short trials, driving recovery from the host side.
#
#   scripts/fuzz-windows-inject-tail-latency.py holds a small fraction of
#   requests for 61-65s each. It reaches "reset with commands
#   outstanding" only incidentally: as its docstring explains, the deep
#   queue plus a 5% chance per request means nearly every outstanding
#   slot gets trapped by the same hold, so the whole queue goes dark
#   together and the guest times it out. That is a measured, useful
#   effect, but the host never learns how deep the queue was when the
#   reset fired, and a timed hold can just as easily expire *before* the
#   reset as during it.
#
# This harness makes the same state deliberate and measured. Two rules
# are armed per LUN, and their order matters, because
# inject_delay_match() walks the rule list in insertion order and the
# first match wins (block/inject-error.c):
#
#   0. the stall rule: 'stall: true' with --stall-probability. A stalled
#      request is held indefinitely -- no deadline, no timer. The host
#      can count exactly how many there are at any moment with
#      x-inject-error-delay-inflight.
#
#   1. the baseline rule: probability 1.0, --baseline-delay-ms /
#      --baseline-delay-max-ms. Every request the stall rule did not take
#      gets ordinary slowness, so the guest keeps issuing I/O and the
#      queue keeps filling instead of the device looking idle and the
#      workload throttling itself.
#
# What that produces, reading block/inject-error.c rather than guessing:
# stalled requests sit in s->inflight with req->stalled set and
# qemu_co_sleep() with no deadline (inject_delay(), around line 416), so
# nothing in QEMU ever completes them on its own. Windows storport times
# the oldest one out and escalates -- abort_task, then
# logical_unit_reset, then i_t_nexus_reset, then an adapter reset. The
# virtio device reset drains the BlockBackend, and
# inject_error_drain_begin() (line ~443) sets s->draining and calls
# inject_delay_wake(s, all=true), waking *every* held request on that
# node, so the stalled commands complete into an adapter that is
# mid-reset. While s->draining is set, inject_delay() skips matching
# entirely (line ~384), so requests issued during the drain pass
# straight through; inject_error_drain_end() (line ~454) clears it and
# the rules -- which were never removed -- start matching again. The
# cycle therefore repeats with no host intervention.
#
# Expected throughput shape, and note this is *predicted*, unlike the
# tail-latency harness's duty cycle which is measured: the queue fills
# with stalled commands at roughly (stall probability x IOPS) per
# second, while the rest of the queue grinds along at the baseline
# delay, so the visible write rate decays as the outstanding slots are
# consumed by stalls, bottoms out when storport gives up and stops
# issuing, spikes at the reset as the whole held set completes at once,
# and recovers to full rate for the length of the drain. Cycle length is
# set by the guest's own timeout/escalation chain, not by any number on
# this command line -- which is exactly what the test is measuring.
#
# Each reset is recorded as a cycle: when it happened, on which adapter,
# how deep the in-flight hold was in the sample immediately before it,
# which TMF subtypes led up to it, and how long after the stall rule was
# armed. --cycles N ends the run once N of them have been seen.
#
# Prerequisites: identical to fuzz-windows-inject-scsi-reset.py -- see
# that script's usage_note() / module docstring, or run this one with
# --help.


import argparse
import collections
import json
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Optional

# The shared machinery lives next to this script, which is not necessarily
# the directory the harness is run from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# pylint: disable=wrong-import-position
from vioscsi_soak_common import (TMF_SUBTYPES, VM_DIR, SoakContext,
                                 SoakStrategy, add_common_args, arm_delay_rules,
                                 check_prereqs, load_qmp_module, qmp_call,
                                 run_soak, usage_note, utc_now)

SOAK_DIR = VM_DIR / "soak-reset-inflight"

# What the shared harness calls these rules in its progress messages.
RULE_LABEL = "the stall and baseline rules"

# Rule ids. Unlike the single-rule harnesses, which let rule_for_node name
# the rule after the LUN's own inject-error node, this one has two rules
# per node and they cannot share a name -- inject_delay_rule_add rejects a
# duplicate id within a node. Ids only have to be unique per node, so
# fixed names are enough and they read better in
# x-inject-error-delay-list and in a held request's rule-id.
STALL_RULE_ID = "stall"
BASELINE_RULE_ID = "baseline"

# Trace buses are named "scsi<N>.0" (see LunSpec.adapter); the adapter
# number is all this harness reports.
BUS_RE = re.compile(r"scsi(\d+)")

# How long the stalled set may sit before the guest is expected to have
# reset the adapter, and the floor under max_hold_ms(). Storport's
# per-command timeout is ~60s and it escalates through abort_task,
# logical_unit_reset, i_t_nexus_reset and finally an adapter reset, each
# step getting its own timeout, so the whole chain can legitimately run
# to a few minutes before anything completes. Everything max_hold_ms()
# feeds -- the pre-flight I/O probe window, the I/O-stall threshold and
# paranoid.exe's --per-request-timeout-ms -- has to sit above that or it
# will fire while the test is working exactly as intended.
DEFAULT_STALL_BUDGET_MS = 300000


def _tmf_name(subtype: str) -> str:
    """A TMF subtype as a name, whether the trace tally already resolved
    it or left the raw number."""
    if subtype.isdigit():
        return TMF_SUBTYPES.get(int(subtype), subtype)
    return subtype


class ResetInflightStrategy(SoakStrategy):
    """Two rules per LUN: an indefinite stall on a fraction of requests,
    and ordinary slowness on the rest. The stalls accumulate until the
    guest resets the adapter out from under them; the harness counts how
    deep the hold was each time that happens."""

    def __init__(self, stall_probability: float, baseline_delay_ms: int,
                 baseline_delay_max_ms: int, ops: list, stall_budget_ms: int,
                 cycles: int, release_after_reset_ms: Optional[int]):
        self.stall_probability = stall_probability
        self.baseline_delay_ms = baseline_delay_ms
        self.baseline_delay_max_ms = baseline_delay_max_ms
        self.ops = ops
        self.stall_budget_ms = stall_budget_ms
        self.cycles = cycles
        self.release_after_reset_ms = release_after_reset_ms

        self.armed_at: Optional[float] = None
        # Per-adapter view of the hold, refreshed every tick. prev_depth is
        # what makes the measurement worth anything: by the time a reset
        # shows up in the trace the drain has already emptied the hold, so
        # the depth that matters is the last one sampled before it.
        self.depth: dict = {}
        self.prev_depth: dict = {}
        self.max_depth: dict = {}
        self.resets: collections.Counter = collections.Counter()
        self.seen_resets: dict = {}
        self.seen_tmfs: dict = {}
        self.cycle_log: list = []
        self.releases = 0
        # Ticks where a hold query failed; a nonzero count means the
        # recorded depths are floors, not measurements.
        self.sample_errors = 0
        # (due_monotonic, adapter) for --release-after-reset-ms.
        self.pending_releases: list = []

    def delay_rules(self) -> list:
        # Insertion order is the matching order (inject_delay_match walks
        # the list and the first match wins), so the stall rule has to
        # come first or the probability-1.0 baseline would swallow every
        # request and nothing would ever stall.
        return [{"id": STALL_RULE_ID, "probability": self.stall_probability,
                 "stall": True, "ops": self.ops},
                {"id": BASELINE_RULE_ID, "probability": 1.0,
                 "delay-ms": self.baseline_delay_ms,
                 "delay-max-ms": self.baseline_delay_max_ms,
                 "ops": self.ops}]

    def max_hold_ms(self) -> int:
        # The inherited default takes the largest delay-max-ms, which here
        # is the baseline rule's -- meaningless for the stall rule, whose
        # hold has no bound at all and ends only when the guest resets.
        # The baseline maximum is the floor (nothing may misfire while a
        # merely-slow request is outstanding), but the pre-flight probe,
        # the stall threshold and paranoid.exe's per-request timeout also
        # have to survive a stalled command waiting out the guest's whole
        # timeout/escalation chain, so take the stall budget when it is
        # larger. See DEFAULT_STALL_BUDGET_MS.
        return max(self.baseline_delay_max_ms, self.stall_budget_ms)

    def rule_label(self) -> str:
        return RULE_LABEL

    def arm_after_fill(self, ctx: SoakContext) -> None:
        arm_delay_rules(ctx.qmp, ctx.lun_specs, self.delay_rules())
        # Every cycle is timed from here, so the first one is not credited
        # with however long the fill took.
        self.armed_at = time.monotonic()

    def on_tick(self, ctx: SoakContext) -> Optional[dict]:
        if self.armed_at is None:
            # Without --fill-wait the rules were baked into '-blockdev'
            # and have been live since the VM started.
            self.armed_at = ctx.start

        self._sample_inflight(ctx)
        self._do_pending_releases(ctx)
        for adapter, tmfs in self._new_resets(ctx):
            self._record_cycle(ctx, adapter, tmfs)

        ctx.result["reset_cycles"] = self.cycle_log
        ctx.result["max_inflight_by_adapter"] = dict(self.max_depth)
        ctx.result["resets_by_adapter"] = dict(self.resets)
        if self.releases:
            ctx.result["timed_releases"] = self.releases
        if self.sample_errors:
            ctx.result["inflight_sample_errors"] = self.sample_errors

        if self.cycles and len(self.cycle_log) >= self.cycles:
            # Mutate and return run_soak's own result, never a fresh dict:
            # it carries run_dir, qemu_log and the rest of the run's
            # bookkeeping, and run_soak does the trace/telemetry/status
            # capture itself on a non-None tick.
            ctx.result["outcome"] = "cycles-complete"
            ctx.result["elapsed_s"] = time.monotonic() - ctx.start
            return ctx.result
        return None

    def _sample_inflight(self, ctx: SoakContext) -> None:
        """Per-adapter count of requests the filters are holding right
        now, split out by whether they are stalled or merely slow: the
        stalled ones are the population the reset is supposed to catch,
        and a baseline hold inflates the total without being interesting.
        """
        depth: dict = {}
        for spec in ctx.lun_specs:
            try:
                held = qmp_call(ctx.qmp, "x-inject-error-delay-inflight",
                                node_name=spec.err_node) or []
            except Exception as exc:  # pylint: disable=broad-except
                # A node can be momentarily unavailable (a dump removes the
                # rules, the VM is paused at a break); losing one sample is
                # not worth ending a multi-hour run over. But a query that
                # fails every tick reads exactly like an empty hold, and
                # then every cycle records a depth of zero and the run
                # still looks healthy -- so say so the first time, and
                # keep the tally in the result.
                self.sample_errors += 1
                if self.sample_errors == 1:
                    print(f"    cannot sample the hold on {spec.err_node}: "
                          f"{exc!r} -- in-flight depths will read low until "
                          f"it recovers", file=sys.stderr)
                continue
            cur = depth.setdefault(spec.adapter, {"held": 0, "stalled": 0})
            cur["held"] += len(held)
            cur["stalled"] += sum(1 for r in held if r.get("stalled"))
        self.prev_depth, self.depth = self.depth, depth
        for adapter, cur in depth.items():
            prev = self.max_depth.get(adapter, {"held": 0, "stalled": 0})
            self.max_depth[adapter] = {
                "held": max(prev["held"], cur["held"]),
                "stalled": max(prev["stalled"], cur["stalled"])}

    def _new_resets(self, ctx: SoakContext):
        """Adapters that have reset since the last tick, each with the
        TMF subtypes seen on that adapter in the same interval.

        QemuStderr tallies trace lines per bus cumulatively for the whole
        soak (take_counts() is only called before the soak starts), so a
        new reset is a rise in that adapter's 'reset' count."""
        stderr = ctx.qemu_stderr
        if stderr is None:
            return
        for bus, counts in sorted(stderr.trace_counts.items()):
            m = BUS_RE.match(bus)
            adapter = int(m.group(1)) if m else -1
            # QemuStderr already names the subtype via TMF_SUBTYPES; a
            # subtype it does not know about comes through as the raw
            # number, which is worth keeping rather than dropping.
            tmfs = {_tmf_name(k.split(":", 1)[1]): v
                    for k, v in counts.items() if k.startswith("tmf_req:")}
            seen = self.seen_tmfs.get(bus, {})
            delta = {k: v - seen.get(k, 0) for k, v in tmfs.items()
                     if v > seen.get(k, 0)}
            resets = counts.get("reset", 0)
            new = resets - self.seen_resets.get(bus, 0)
            self.seen_resets[bus] = resets
            if new <= 0:
                continue
            # Only claim the TMFs once they have been attributed to a
            # cycle, so an adapter that escalates over several ticks
            # before resetting still reports the whole chain.
            self.seen_tmfs[bus] = tmfs
            for _ in range(new):
                yield adapter, delta

    def _record_cycle(self, ctx: SoakContext, adapter: int, tmfs: dict) -> None:
        before = self.prev_depth.get(adapter, {"held": 0, "stalled": 0})
        now = time.monotonic()
        self.resets[adapter] += 1
        cycle = {"n": len(self.cycle_log) + 1,
                 "time": utc_now(),
                 "elapsed_s": round(now - ctx.start, 1),
                 "adapter": adapter,
                 "held_before_reset": before["held"],
                 "stalled_before_reset": before["stalled"],
                 "tmfs_before_reset": tmfs,
                 "since_armed_s": round(now - (self.armed_at or ctx.start), 1)}
        self.cycle_log.append(cycle)
        print(f"[{cycle['time']}] reset #{cycle['n']} on scsi{adapter}: "
              f"{before['stalled']} stalled of {before['held']} held, "
              f"TMFs {tmfs or '{}'}, "
              f"{cycle['since_armed_s']:.0f}s since armed")
        if self.release_after_reset_ms is not None:
            self.pending_releases.append(
                (now + self.release_after_reset_ms / 1000.0, adapter))

    def _do_pending_releases(self, ctx: SoakContext) -> None:
        """--release-after-reset-ms: release whatever the adapter's nodes
        are holding a fixed time after a reset was seen.

        The drain at the reset has already woken the set that was stalled
        *before* it (inject_error_drain_begin), so what this catches is
        the commands the guest issued after drain_end and which stalled
        again. Releasing them on the harness's own clock puts their
        completions at a chosen point in the recovery -- while the driver
        is still rebuilding its queues, say -- instead of wherever the
        next drain happens to put them."""
        if not self.pending_releases:
            return
        now = time.monotonic()
        due = [a for t, a in self.pending_releases if t <= now]
        self.pending_releases = [(t, a) for t, a in self.pending_releases
                                 if t > now]
        for adapter in due:
            for spec in ctx.lun_specs:
                if spec.adapter != adapter:
                    continue
                try:
                    out = qmp_call(ctx.qmp, "x-inject-error-delay-release",
                                   node_name=spec.err_node) or {}
                except Exception:  # pylint: disable=broad-except
                    continue
                self.releases += out.get("count", 0)

    def heartbeat(self, ctx: SoakContext) -> dict:
        return {"inflight_by_adapter": dict(self.depth),
                "max_inflight_by_adapter": dict(self.max_depth),
                "reset_cycles_done": len(self.cycle_log),
                "resets_by_adapter": dict(self.resets)}

    def meta(self) -> dict:
        return {"stall_probability": self.stall_probability,
                "baseline_delay_ms": self.baseline_delay_ms,
                "baseline_delay_max_ms": self.baseline_delay_max_ms,
                "ops": self.ops,
                "stall_budget_ms": self.stall_budget_ms,
                "max_hold_ms": self.max_hold_ms(),
                "cycles": self.cycles,
                "release_after_reset_ms": self.release_after_reset_ms}


def add_rule_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--stall-probability", type=float, default=0.02,
                     help="fraction of matching requests held indefinitely, "
                          "until the guest resets the adapter (default: "
                          "%(default)s, i.e. 2%%). Higher fills the guest's "
                          "queue -- and so reaches a reset -- faster, but "
                          "leaves fewer requests moving in the meantime")
    ap.add_argument("--baseline-delay-ms", type=int, default=5,
                     help="minimum hold for the requests the stall rule did "
                          "not take, in ms (default: %(default)s). This is "
                          "what keeps the guest issuing I/O while the stalled "
                          "set accumulates")
    ap.add_argument("--baseline-delay-max-ms", type=int, default=50,
                     help="maximum hold for a non-stalled request, in ms "
                          "(default: %(default)s); the actual hold is drawn "
                          "uniformly from [--baseline-delay-ms, "
                          "--baseline-delay-max-ms)")
    ap.add_argument("--ops", default="read,write",
                     help="comma list of operation types both rules match "
                          "(default: %(default)s)")
    ap.add_argument("--stall-budget-ms", type=int,
                     default=DEFAULT_STALL_BUDGET_MS,
                     help="how long a stalled command may legitimately sit "
                          "before the guest has reset the adapter (default: "
                          "%(default)s). A stall has no hold time of its own, "
                          "so this is what sizes the pre-flight I/O probe, the "
                          "I/O-stall threshold and paranoid.exe's "
                          "per-request timeout; too low and they fire while "
                          "the test is working as intended")
    ap.add_argument("--cycles", type=int, default=0,
                     help="stop once this many adapter resets have been "
                          "observed (default: %(default)s, i.e. run for the "
                          "full --duration-hours)")
    ap.add_argument("--release-after-reset-ms", type=int, default=None,
                     metavar="MS",
                     help="instead of leaving every completion to the reset's "
                          "own drain, release the adapter's held requests this "
                          "long after a reset is seen, landing them at a "
                          "chosen point in the driver's recovery (default: "
                          "off)")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Hours-long soak test that drives the vioscsi Windows "
                     "guest driver through adapter resets with a large, "
                     "known number of commands outstanding: a fraction of "
                     "requests on each data LUN is stalled indefinitely "
                     "until the guest's timeout/escalation chain resets the "
                     "adapter and the drain completes them, while the rest "
                     "are merely slowed so the queue keeps filling.",
        epilog=usage_note(), formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap, SOAK_DIR, rule_args=add_rule_args,
                    rule_label=RULE_LABEL,
                    max_hold_opt="--stall-budget-ms")
    args = ap.parse_args()

    if args.host_pressure_cores and not shutil.which("taskset"):
        print("Error: --host-pressure-cores given but 'taskset' not found in PATH.",
              file=sys.stderr)
        return 1

    if not (0.0 < args.stall_probability <= 1.0):
        print("Error: --stall-probability must be above 0.0 and at most 1.0; "
              "at 0.0 nothing would ever stall and no reset would be "
              "provoked.", file=sys.stderr)
        return 1
    if args.baseline_delay_ms < 0 or args.baseline_delay_max_ms < 0:
        print("Error: --baseline-delay-ms and --baseline-delay-max-ms must "
              "be >= 0.", file=sys.stderr)
        return 1
    if args.baseline_delay_max_ms < args.baseline_delay_ms:
        print("Error: --baseline-delay-max-ms must be >= --baseline-delay-ms.",
              file=sys.stderr)
        return 1
    if args.stall_budget_ms <= 0:
        print("Error: --stall-budget-ms must be > 0.", file=sys.stderr)
        return 1
    if args.cycles < 0:
        print("Error: --cycles must be >= 0 (0 runs for the full duration).",
              file=sys.stderr)
        return 1
    if args.release_after_reset_ms is not None and args.release_after_reset_ms < 0:
        print("Error: --release-after-reset-ms must be >= 0.", file=sys.stderr)
        return 1

    if args.adapters < 1 or args.targets < 1 or args.luns_per_target < 1:
        print("Error: --adapters, --targets and --luns-per-target must all "
              "be >= 1.", file=sys.stderr)
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

    ops = [o.strip() for o in args.ops.split(",") if o.strip()]
    duration_s = args.duration_hours * 3600.0
    fill_wait = (args.io_driver == "paranoid" if args.fill_wait is None
                 else args.fill_wait)
    if args.fill_timeout_minutes <= 0:
        print("Error: --fill-timeout-minutes must be > 0.", file=sys.stderr)
        return 1

    err = check_prereqs()
    if err:
        print(f"Error: {err}", file=sys.stderr)
        return 1

    qmp_module = load_qmp_module()
    if qmp_module is None:
        return 1

    SOAK_DIR.mkdir(parents=True, exist_ok=True)

    total_luns = args.adapters * args.targets * args.luns_per_target
    stop = (f"{args.cycles} reset cycle(s)" if args.cycles
            else f"{args.duration_hours:.1f}h")
    print(f"Starting reset-with-inflight soak (stops after {stop}): "
          f"{args.stall_probability * 100:.1f}% of {ops} ops on {total_luns} "
          f"LUN(s) ({args.adapters} adapter(s) x {args.targets} target(s) x "
          f"{args.luns_per_target} lun(s)) stalled indefinitely, the rest "
          f"held {args.baseline_delay_ms}-{args.baseline_delay_max_ms}ms.")

    strategy = ResetInflightStrategy(args.stall_probability,
                                      args.baseline_delay_ms,
                                      args.baseline_delay_max_ms, ops,
                                      args.stall_budget_ms, args.cycles,
                                      args.release_after_reset_ms)
    result = run_soak(SOAK_DIR, args.adapters, args.targets,
                       args.luns_per_target,
                       duration_s, args.ram, args.cpus,
                       args.host_pressure_cores, args.keep_all, qmp_module,
                       args.io_driver, args.diskspd_path, args.fio_path,
                       args.paranoid_path, strategy,
                       args.seed, args.heartbeat_seconds,
                       args.vioscsi_telemetry_script,
                       args.disk_dir, args.iothreads, args.tmf_trace,
                       args.stop_on_broken, args.ring_diag,
                       args.dump_on_agent_stall, args.qga_trace,
                       fill_wait, args.fill_timeout_minutes * 60.0,
                       args.watch_after_break * 60.0)

    results_path = SOAK_DIR / f"result-{int(time.time())}.json"
    results_path.write_text(json.dumps(result, indent=2))

    cycles = result.get("reset_cycles", [])
    print()
    print(f"Outcome: {result['outcome']} ({result['elapsed_s']:.0f}s), "
          f"{len(cycles)} reset cycle(s)")
    if cycles:
        deepest = max(cycles, key=lambda c: c["stalled_before_reset"])
        print(f"Deepest hold at a reset: {deepest['stalled_before_reset']} "
              f"stalled of {deepest['held_before_reset']} held on "
              f"scsi{deepest['adapter']}")
    print(f"Result written to {results_path}")
    if result["outcome"] in ("crash-suspected", "qemu-exited", "error",
                             "guest-panicked", "data-corruption",
                             "fill-failed"):
        print(f"Artifacts in {result['run_dir']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
