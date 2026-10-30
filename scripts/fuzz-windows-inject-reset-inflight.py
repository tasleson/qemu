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
# Each reset is recorded as a cycle: what kind it was, when it happened,
# on which adapter, how deep the in-flight hold was in the sample
# immediately before it, which TMF subtypes led up to it, and how long
# after the stall rule was armed. --cycles N ends the run once N of them
# have been seen.
#
# A cycle is not only the adapter reset. A logical unit or I_T nexus
# reset ends the hold the same way: it reaches scsi_device_purge_requests()
# (hw/scsi/scsi-bus.c), which ends in blk_drain() on the LUN's
# BlockBackend, which trips inject_error_drain_begin() on that LUN's
# inject-error node and wakes everything it holds -- for one LUN rather
# than for the whole adapter, but woken all the same. Counting only the
# adapter reset reports zero cycles for a guest that recovers at the LUN
# level and never escalates, which is the common case: storport will
# retry a logical_unit_reset against the same LUN every timeout for as
# long as the application keeps asking.
#
# Prerequisites: identical to fuzz-windows-inject-scsi-reset.py -- see
# that script's usage_note() / module docstring, or run this one with
# --help.


import argparse
import collections
import re
import sys
import time
from pathlib import Path
from typing import Optional

# The shared machinery lives next to this script, which is not necessarily
# the directory the harness is run from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# pylint: disable=wrong-import-position
from vioscsi_soak_common import (TMF_SUBTYPES, VM_DIR, SoakContext,
                                 SoakStrategy, add_common_args,
                                 arm_delay_rules, qmp_call, run_soak_main,
                                 usage_note, utc_now)

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

# The recovery events that count as a cycle, each with the key QemuStderr
# tallies it under, in the order storport escalates through them. See the
# module docstring for why the two TMFs count and not just the adapter
# reset. Narrower kinds come first so that a tick which caught a whole
# escalation chain numbers its cycles in the order they happened.
CYCLE_KINDS = (("logical_unit_reset", "tmf_req:logical_unit_reset"),
               ("i_t_nexus_reset", "tmf_req:i_t_nexus_reset"),
               ("adapter_reset", "reset"))


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
        # adapter -> kind -> count, and bus -> kind -> count already
        # attributed to a cycle.
        self.resets: dict = {}
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
        for adapter, kind, tmfs in self._new_resets(ctx):
            self._record_cycle(ctx, adapter, kind, tmfs)

        ctx.result["reset_cycles"] = self.cycle_log
        ctx.result["max_inflight_by_adapter"] = dict(self.max_depth)
        ctx.result["resets_by_adapter"] = self._resets_snapshot()
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

    def _resets_snapshot(self) -> dict:
        """A copy deep enough to hand to the result and the heartbeat:
        both are serialised later, and the per-kind dicts keep being
        counted up in the meantime."""
        return {adapter: dict(kinds)
                for adapter, kinds in self.resets.items()}

    def _new_resets(self, ctx: SoakContext):
        """Recovery events seen since the last tick, each as (adapter,
        kind, tmfs): the kind is one of CYCLE_KINDS, and tmfs is the TMF
        subtypes seen on that adapter in the same interval.

        QemuStderr tallies trace lines per bus cumulatively for the whole
        soak (take_counts() is only called before the soak starts), so a
        new event is a rise in that adapter's count for its kind."""
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
            seen_kinds = self.seen_resets.setdefault(bus, {})
            new = []
            for kind, key in CYCLE_KINDS:
                total = counts.get(key, 0)
                new += [kind] * max(0, total - seen_kinds.get(kind, 0))
                seen_kinds[kind] = total
            if not new:
                continue
            # Only claim the TMFs once they have been attributed to a
            # cycle, so an adapter that escalates over several ticks
            # before resetting still reports the whole chain.
            self.seen_tmfs[bus] = tmfs
            # The chain belongs to the tick, not to each event in it, so
            # it goes on the first cycle only. Handing the same delta to
            # every cycle a tick yields would make the field impossible
            # to sum across cycles.
            for i, kind in enumerate(new):
                yield adapter, kind, delta if i == 0 else {}

    def _record_cycle(self, ctx: SoakContext, adapter: int, kind: str,
                      tmfs: dict) -> None:
        # The hold is sampled per adapter, so for a LUN or target reset
        # these depths cover more LUNs than the reset itself drained.
        # They are still the right number to report -- how deep the
        # adapter was when the guest gave up -- but they are not a count
        # of what this one event woke.
        before = self.prev_depth.get(adapter, {"held": 0, "stalled": 0})
        now = time.monotonic()
        self.resets.setdefault(adapter, {})
        self.resets[adapter][kind] = self.resets[adapter].get(kind, 0) + 1
        cycle = {"n": len(self.cycle_log) + 1,
                 "kind": kind,
                 "time": utc_now(),
                 "elapsed_s": round(now - ctx.start, 1),
                 "adapter": adapter,
                 "held_before_reset": before["held"],
                 "stalled_before_reset": before["stalled"],
                 # For a TMF-derived cycle this includes the TMF that is
                 # the cycle, not only what led up to it.
                 "tmfs_before_reset": tmfs,
                 "since_armed_s": round(now - (self.armed_at or ctx.start), 1)}
        self.cycle_log.append(cycle)
        print(f"[{cycle['time']}] {kind} #{cycle['n']} on scsi{adapter}: "
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
                "resets_by_adapter": self._resets_snapshot()}

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
                     help="stop once this many resets have been observed, of "
                          "any kind the guest recovers with -- logical unit, "
                          "I_T nexus or adapter (default: %(default)s, i.e. "
                          "run for the full --duration-hours)")
    ap.add_argument("--release-after-reset-ms", type=int, default=None,
                     metavar="MS",
                     help="instead of leaving every completion to the reset's "
                          "own drain, release the adapter's held requests this "
                          "long after a reset is seen, landing them at a "
                          "chosen point in the driver's recovery (default: "
                          "off)")


def cycle_summary(result: dict) -> list:
    """What the outcome line does not say: how many cycles the run saw,
    of which kinds, and the deepest hold any of them caught."""
    cycles = result.get("reset_cycles", [])
    by_kind = collections.Counter(c["kind"] for c in cycles)
    lines = [f"{len(cycles)} reset cycle(s)"
             + (": " + ", ".join(f"{n} {kind}" for kind, n
                                 in sorted(by_kind.items())) if cycles
                else "")]
    if cycles:
        deepest = max(cycles, key=lambda c: c["stalled_before_reset"])
        lines.append(f"Deepest hold at a reset: "
                     f"{deepest['stalled_before_reset']} stalled of "
                     f"{deepest['held_before_reset']} held on "
                     f"scsi{deepest['adapter']} at a {deepest['kind']}")
    return lines


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

    ops = [o.strip() for o in args.ops.split(",") if o.strip()]
    total_luns = args.adapters * args.targets * args.luns_per_target
    stop = (f"{args.cycles} reset cycle(s)" if args.cycles
            else f"{args.duration_hours:.1f}h")
    banner = (f"Starting reset-with-inflight soak (stops after {stop}): "
              f"{args.stall_probability * 100:.1f}% of {ops} ops on "
              f"{total_luns} LUN(s) ({args.adapters} adapter(s) x "
              f"{args.targets} target(s) x {args.luns_per_target} lun(s)) "
              f"stalled indefinitely, the rest held "
              f"{args.baseline_delay_ms}-{args.baseline_delay_max_ms}ms.")

    strategy = ResetInflightStrategy(args.stall_probability,
                                      args.baseline_delay_ms,
                                      args.baseline_delay_max_ms, ops,
                                      args.stall_budget_ms, args.cycles,
                                      args.release_after_reset_ms)
    return run_soak_main(SOAK_DIR, args, strategy, banner, cycle_summary)


if __name__ == "__main__":
    sys.exit(main())
