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
# stay live for the whole run rather than being cycled. (With --fill-wait,
# the default for --io-driver=paranoid, it is instead armed over QMP once
# every LUN image is fully allocated, so the writer's sequential initialize
# pass is not crawling through holds.) Sustained raw
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
import json
import shutil
import sys
import time
from pathlib import Path

# The shared machinery lives next to this script, which is not necessarily
# the directory the harness is run from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# pylint: disable=wrong-import-position
from vioscsi_soak_common import (FAILURE_OUTCOMES, VM_DIR, SoakStrategy,
                                 add_common_args, check_prereqs,
                                 load_qmp_module, run_soak, usage_note)

SOAK_DIR = VM_DIR / "soak-tail-latency"


class TailLatencyStrategy(SoakStrategy):
    """One constant rule per LUN: a small fraction of read/write requests
    held past typical storport timeouts for the whole run."""

    def __init__(self, probability: float, delay_ms: int, delay_max_ms: int,
                 ops: list):
        self.probability = probability
        self.delay_ms = delay_ms
        self.delay_max_ms = delay_max_ms
        self.ops = ops

    def delay_rules(self) -> list:
        # An empty id is filled in with the LUN's own inject-error node
        # name; see rule_for_node.
        return [{"id": "", "probability": self.probability,
                 "delay-ms": self.delay_ms,
                 "delay-max-ms": self.delay_max_ms, "ops": self.ops}]

    def rule_label(self) -> str:
        return "the tail-latency rule"

    def meta(self) -> dict:
        return {"probability": self.probability, "delay_ms": self.delay_ms,
                "delay_max_ms": self.delay_max_ms, "ops": self.ops}


def add_rule_args(ap: argparse.ArgumentParser) -> None:
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


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Hours-long tail-latency soak test for the vioscsi "
                     "Windows guest driver: a small fraction of read/write "
                     "requests on each data LUN complete late (default 5% "
                     "held 61-65s), the rest complete normally, and the "
                     "harness watches for a bugcheck over the full run.",
        epilog=usage_note(), formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_args(ap, SOAK_DIR, rule_args=add_rule_args)
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
    print(f"Starting {args.duration_hours:.1f}h tail-latency soak: "
          f"{args.probability * 100:.1f}% of {ops} ops on {total_luns} LUN(s) "
          f"({args.adapters} adapter(s) x {args.targets} target(s) x "
          f"{args.luns_per_target} lun(s)) held "
          f"{args.delay_ms}-{args.delay_max_ms}ms.")

    strategy = TailLatencyStrategy(args.probability, args.delay_ms,
                                   args.delay_max_ms, ops)
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

    print()
    print(f"Outcome: {result['outcome']} ({result['elapsed_s']:.0f}s)")
    print(f"Result written to {results_path}")
    if result["outcome"] in FAILURE_OUTCOMES:
        print(f"Artifacts in {result['run_dir']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
