#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Block I/O error and latency injection tool for QEMU
#
# Manages bad sector regions and latency rules on inject-error filter
# nodes via QMP.  Simulates media errors and slow, stalled or timing-out
# storage to test guest OS error handling.
#
# Usage: $builddir/run scripts/inject-error.py [options] <command> [args]

import argparse
import json
import sys

try:
    from qemu.qmp.legacy import QEMUMonitorProtocol
except ModuleNotFoundError as exc:
    print(f"Module '{exc.name}' not found.", file=sys.stderr)
    print(f"Try $builddir/run {' '.join(sys.argv)}", file=sys.stderr)
    sys.exit(1)

ERRNO_NAMES = {
    1: "EPERM", 5: "EIO", 12: "ENOMEM", 19: "ENODEV",
    22: "EINVAL", 28: "ENOSPC", 61: "ENODATA",
}

BEHAVIOR_HELP = {
    "persistent": "error fires on every matching I/O",
    "fix-on-write": "reads fail; a successful write clears the entry",
    "transient": "error fires once then auto-removes",
}


def qmp_connect(args):
    if args.socket:
        qmp = QEMUMonitorProtocol(args.socket)
    else:
        qmp = QEMUMonitorProtocol(address=(args.host, args.port))
    try:
        qmp.connect(negotiate=True)
    except Exception as exc:
        target = args.socket or f"{args.host}:{args.port}"
        sys.exit(f"Cannot connect to QMP at {target}: {exc}")
    return qmp


def qmp_execute(qmp, command, cmd_args):
    msg = {"execute": command, "arguments": cmd_args}
    try:
        obj = qmp.cmd_obj(msg)
    except Exception as exc:
        sys.exit(f"QMP command failed: {exc}")

    if "error" in obj:
        err = obj["error"]
        sys.exit(f"Error: {err.get('desc', err)}")

    return obj.get("return")


def errno_str(num):
    name = ERRNO_NAMES.get(num)
    return f"{num}/{name}" if name else str(num)


def format_sectors(sector, count):
    end = sector + count - 1
    if count == 1:
        return f"sector {sector}"
    return f"sectors {sector}-{end} ({count} sectors)"


def cmd_list(args):
    qmp = qmp_connect(args)
    entries = qmp_execute(qmp, "x-inject-error-list",
                          {"node-name": args.node})
    qmp.close()

    if not entries:
        print(f"{args.node}: no active error entries")
        return

    print(f"{args.node}: {len(entries)} active error "
          f"{'entry' if len(entries) == 1 else 'entries'}")
    print()

    for i, e in enumerate(entries):
        sector = e["sector"]
        count = e["count"]
        errno = e["errno"]
        behavior = e["behavior"]
        reads = e["reads"]
        writes = e["writes"]

        direction = []
        if reads:
            direction.append("reads")
        if writes:
            direction.append("writes")
        direction_str = "+".join(direction) if direction else "none"

        print(f"  [{i}] {format_sectors(sector, count)}  "
              f"errno={errno_str(errno)}  "
              f"behavior={behavior}  "
              f"affects={direction_str}")

    if args.json:
        print()
        print(json.dumps(entries, indent=2))


def cmd_add(args):
    qmp = qmp_connect(args)
    cmd_args = {
        "node-name": args.node,
        "sector": args.sector,
    }
    if args.count != 1:
        cmd_args["count"] = args.count
    if args.errno != 5:
        cmd_args["errno"] = args.errno
    if args.behavior != "persistent":
        cmd_args["behavior"] = args.behavior
    if not args.reads:
        cmd_args["reads"] = False
    if args.writes:
        cmd_args["writes"] = True

    qmp_execute(qmp, "x-inject-error-add", cmd_args)
    qmp.close()

    direction = []
    if args.reads:
        direction.append("reads")
    if args.writes:
        direction.append("writes")

    print(f"Added: {format_sectors(args.sector, args.count)}  "
          f"errno={errno_str(args.errno)}  "
          f"behavior={args.behavior}  "
          f"affects={'+'.join(direction)}")


def cmd_remove(args):
    qmp = qmp_connect(args)
    cmd_args = {
        "node-name": args.node,
        "sector": args.sector,
    }
    if args.count != 1:
        cmd_args["count"] = args.count

    qmp_execute(qmp, "x-inject-error-remove", cmd_args)
    qmp.close()
    print(f"Removed entries overlapping {format_sectors(args.sector, args.count)}")


def cmd_clear(args):
    """Remove all entries by listing then removing each one."""
    qmp = qmp_connect(args)
    entries = qmp_execute(qmp, "x-inject-error-list",
                          {"node-name": args.node})

    if not entries:
        print(f"{args.node}: no entries to clear")
        qmp.close()
        return

    # Find the bounding range that covers all entries
    min_sector = min(e["sector"] for e in entries)
    max_end = max(e["sector"] + e["count"] for e in entries)

    qmp_execute(qmp, "x-inject-error-remove", {
        "node-name": args.node,
        "sector": min_sector,
        "count": max_end - min_sector,
    })
    qmp.close()
    print(f"Cleared {len(entries)} entries from {args.node}")


def parse_sector(val):
    return int(val, 0)


def parse_ops(val):
    ops = [op.strip() for op in val.split(",") if op.strip()]
    for op in ops:
        if op not in OPS:
            raise argparse.ArgumentTypeError(
                f"unknown op '{op}', pick from {', '.join(OPS)}")
    return ops


def add_rule_arguments(parser, with_id=True):
    if with_id:
        parser.add_argument("id", help="name for the rule")
    parser.add_argument("--ops", type=parse_ops,
                        help="comma separated list of "
                             f"{{{','.join(OPS)}}} (default: all)")
    parser.add_argument("--sector", type=parse_sector,
                        help="first sector the rule covers (default: 0)")
    parser.add_argument("-c", "--count", type=int,
                        help="sectors covered (default: the whole device)")
    parser.add_argument("-p", "--probability", type=float,
                        help="fraction of matching requests to delay, "
                             "0.0-1.0 (default: 1.0)")
    parser.add_argument("-d", "--delay-ms", type=int,
                        help="how long to hold a request, in milliseconds")
    parser.add_argument("-D", "--delay-max-ms", type=int,
                        help="upper bound of a randomised hold time")
    parser.add_argument("--stall", action="store_true",
                        help="hold requests until released or reset")
    parser.add_argument("-e", "--errno", type=parse_errno,
                        help="fail the request with this errno once the "
                             "hold expires (default: complete normally)")
    parser.add_argument("--max-hits", type=int,
                        help="drop the rule after this many requests")


def parse_errno(val):
    val_upper = val.upper()
    for num, name in ERRNO_NAMES.items():
        if val_upper == name:
            return num
    return int(val, 0)

OPS = ["read", "write", "flush", "discard", "write-zeroes"]

# Ready-made rules for the failure modes worth exercising in a guest
# driver.  Every field can still be overridden on the command line.
SCENARIOS = {
    "fixed-latency": (
        "delay every request by a fixed amount",
        {"delay-ms": 50},
    ),
    "tail-latency": (
        "delay one request in a thousand by 10-60 seconds",
        {"probability": 0.001, "delay-ms": 10000, "delay-max-ms": 60000},
    ),
    "stall": (
        "hold requests until released or the device is reset",
        {"stall": True},
    ),
    "timeout-then-success": (
        "complete normally long after the guest has given up",
        {"delay-ms": 45000},
    ),
    "timeout-then-failure": (
        "fail long after the guest has given up",
        {"delay-ms": 45000, "errno": 5},
    ),
    "backend-disconnect": (
        "hold everything as if the backend went away; 'release --error' "
        "fails the outstanding requests, 'delay-remove' reconnects",
        {"stall": True},
    ),
    "flush-latency": (
        "delay only cache flushes, as seen during boot and fsck",
        {"ops": ["flush"], "delay-ms": 30000},
    ),
    "queue-saturation": (
        "stall the first requests so the queue fills up behind them",
        {"stall": True, "max-hits": 32},
    ),
    "out-of-order": (
        "spread hold times so completions overtake each other",
        {"probability": 0.25, "delay-ms": 100, "delay-max-ms": 5000},
    ),
    "reset-race": (
        "hold requests just past a typical guest timeout, so completions "
        "land while the guest is resetting the device",
        {"delay-ms": 30000, "delay-max-ms": 90000},
    ),
}


def describe_rule(rule):
    parts = []
    if rule.get("stall"):
        parts.append("stall")
    else:
        delay = rule.get("delay-ms", 0)
        delay_max = rule.get("delay-max-ms", delay)
        parts.append(f"delay={delay}ms" if delay_max == delay
                     else f"delay={delay}-{delay_max}ms")
    if rule.get("errno"):
        parts.append(f"then errno={errno_str(rule['errno'])}")
    ops = rule.get("ops", OPS)
    if list(ops) != OPS:
        parts.append("ops=" + ",".join(ops))
    if "count" in rule:
        parts.append(format_sectors(rule.get("sector", 0), rule["count"]))
    if rule.get("probability", 1.0) != 1.0:
        parts.append(f"probability={rule['probability']}")
    if "max-hits" in rule:
        parts.append(f"max-hits={rule['max-hits']}")
    return "  ".join(parts)


def rule_from_args(args, base=None):
    """Build a rule from @base, overridden by whatever was given on the
    command line."""
    rule = dict(base or {})
    rule["id"] = args.id
    if args.ops is not None:
        rule["ops"] = args.ops
    if args.sector is not None:
        rule["sector"] = args.sector
    if args.count is not None:
        rule["count"] = args.count
    if args.probability is not None:
        rule["probability"] = args.probability
    if args.delay_ms is not None:
        rule["delay-ms"] = args.delay_ms
    if args.delay_max_ms is not None:
        rule["delay-max-ms"] = args.delay_max_ms
    if args.stall:
        rule["stall"] = True
    if args.errno is not None:
        rule["errno"] = args.errno
    if args.max_hits is not None:
        rule["max-hits"] = args.max_hits
    return rule


def add_rule(args, base=None):
    rule = rule_from_args(args, base)
    qmp = qmp_connect(args)
    qmp_execute(qmp, "x-inject-error-delay-add",
                {"node-name": args.node, "rule": rule})
    qmp.close()
    print(f"Added rule '{rule['id']}': {describe_rule(rule)}")


def cmd_delay_add(args):
    add_rule(args)


def cmd_scenario(args):
    add_rule(args, SCENARIOS[args.scenario][1])


def cmd_delay_list(args):
    qmp = qmp_connect(args)
    rules = qmp_execute(qmp, "x-inject-error-delay-list",
                        {"node-name": args.node})
    qmp.close()

    if not rules:
        print(f"{args.node}: no latency rules")
        return

    print(f"{args.node}: {len(rules)} latency "
          f"{'rule' if len(rules) == 1 else 'rules'}")
    print()
    for rule in rules:
        print(f"  {rule['id']}: {describe_rule(rule)}  hits={rule['hits']}")

    if args.json:
        print()
        print(json.dumps(rules, indent=2))


def cmd_delay_remove(args):
    qmp = qmp_connect(args)
    cmd_args = {"node-name": args.node}
    if args.id:
        cmd_args["id"] = args.id
    ret = qmp_execute(qmp, "x-inject-error-delay-remove", cmd_args)
    qmp.close()
    print(f"Removed {ret['count']} rule(s) from {args.node}")


def cmd_inflight(args):
    qmp = qmp_connect(args)
    reqs = qmp_execute(qmp, "x-inject-error-delay-inflight",
                       {"node-name": args.node})
    qmp.close()

    if not reqs:
        print(f"{args.node}: no held requests")
        return

    print(f"{args.node}: {len(reqs)} held "
          f"{'request' if len(reqs) == 1 else 'requests'}")
    print()
    for req in reqs:
        where = ("whole device" if "sector" not in req
                 else format_sectors(req["sector"], req["count"]))
        when = ("stalled" if req["stalled"]
                else f"{req['remaining-ms']}ms left")
        outcome = f"errno={errno_str(req['errno'])}" if req["errno"] else "ok"
        print(f"  [{req['id']}] {req['op']}  {where}  {when}  "
              f"rule={req.get('rule-id', '-')}  on release: {outcome}")

    if args.json:
        print()
        print(json.dumps(reqs, indent=2))


def cmd_release(args):
    qmp = qmp_connect(args)
    cmd_args = {"node-name": args.node}
    if args.request_id is not None:
        cmd_args["request-id"] = args.request_id
    if args.error:
        cmd_args["disposition"] = "error"
        cmd_args["errno"] = args.errno if args.errno is not None else 5
    elif args.complete:
        cmd_args["disposition"] = "complete"
    ret = qmp_execute(qmp, "x-inject-error-delay-release", cmd_args)
    qmp.close()
    print(f"Released {ret['count']} request(s) from {args.node}")


def main():
    parser = argparse.ArgumentParser(
        description="Block I/O error and latency injection tool for QEMU",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
error behaviors:
  persistent    error fires on every matching I/O (default)
  fix-on-write  reads fail; a successful write clears the entry
  transient     error fires once then auto-removes

common errno values:
  5/EIO         generic I/O error (default)
  28/ENOSPC     no space left on device
  61/ENODATA    medium error (maps to SCSI MEDIUM_ERROR on Linux)

examples:
  %(prog)s -s /tmp/qmp.sock list err0
  %(prog)s -s /tmp/qmp.sock add err0 1024 --count 8
  %(prog)s -s /tmp/qmp.sock add err0 2048 --count 16 --errno ENOSPC --writes
  %(prog)s -s /tmp/qmp.sock add err0 0 --behavior fix-on-write --writes
  %(prog)s -s /tmp/qmp.sock remove err0 1024 --count 8
  %(prog)s -s /tmp/qmp.sock clear err0
  %(prog)s -s /tmp/qmp.sock scenario err0 tail-latency slow
  %(prog)s -s /tmp/qmp.sock delay-add err0 boot --ops flush --delay-ms 30000
  %(prog)s -s /tmp/qmp.sock inflight err0
  %(prog)s -s /tmp/qmp.sock release err0 --error
  %(prog)s -s /tmp/qmp.sock delay-remove err0
""",
    )

    conn = parser.add_argument_group("QMP connection")
    conn.add_argument("-s", "--socket", type=str,
                      help="QMP Unix socket path")
    conn.add_argument("-H", "--host", type=str, default="localhost",
                      help="QMP TCP host (default: localhost)")
    conn.add_argument("-P", "--port", type=int, default=4445,
                      help="QMP TCP port (default: 4445)")

    sub = parser.add_subparsers(dest="command", required=True)

    # -- list --
    p = sub.add_parser("list", help="list active error entries")
    p.add_argument("node", help="inject-error node name (e.g. err0)")
    p.add_argument("--json", action="store_true",
                   help="also print raw JSON output")
    p.set_defaults(func=cmd_list)

    # -- add --
    p = sub.add_parser("add", help="add a bad sector region")
    p.add_argument("node", help="inject-error node name")
    p.add_argument("sector", type=parse_sector,
                   help="first bad sector (512-byte sectors, supports 0x hex)")
    p.add_argument("-c", "--count", type=int, default=1,
                   help="number of consecutive bad sectors (default: 1)")
    p.add_argument("-e", "--errno", type=parse_errno, default=5,
                   help="error number or name (default: 5/EIO)")
    p.add_argument("-b", "--behavior", default="persistent",
                   choices=["persistent", "fix-on-write", "transient"],
                   help="error behavior (default: persistent)")
    p.add_argument("-r", "--reads", action="store_true", default=True,
                   help="fail read operations (default: true)")
    p.add_argument("-R", "--no-reads", action="store_false", dest="reads",
                   help="do not fail read operations")
    p.add_argument("-w", "--writes", action="store_true", default=False,
                   help="fail write operations (default: false)")
    p.set_defaults(func=cmd_add)

    # -- remove --
    p = sub.add_parser("remove",
                       help="remove entries overlapping a sector range")
    p.add_argument("node", help="inject-error node name")
    p.add_argument("sector", type=parse_sector,
                   help="first sector of range to clear")
    p.add_argument("-c", "--count", type=int, default=1,
                   help="number of sectors in the range (default: 1)")
    p.set_defaults(func=cmd_remove)

    # -- clear --
    p = sub.add_parser("clear", help="remove all error entries")
    p.add_argument("node", help="inject-error node name")
    p.set_defaults(func=cmd_clear)

    # -- scenario --
    p = sub.add_parser(
        "scenario", help="add a rule for a named failure mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="scenarios:\n" + "".join(
            f"  {name:<22}{help_}\n"
            for name, (help_, _) in SCENARIOS.items()))
    p.add_argument("node", help="inject-error node name")
    p.add_argument("scenario", choices=list(SCENARIOS),
                   metavar="scenario", help="failure mode to set up")
    add_rule_arguments(p)
    p.set_defaults(func=cmd_scenario)

    # -- delay-add --
    p = sub.add_parser("delay-add", help="add a latency rule")
    p.add_argument("node", help="inject-error node name")
    add_rule_arguments(p)
    p.set_defaults(func=cmd_delay_add)

    # -- delay-list --
    p = sub.add_parser("delay-list", help="list latency rules")
    p.add_argument("node", help="inject-error node name")
    p.add_argument("--json", action="store_true",
                   help="also print raw JSON output")
    p.set_defaults(func=cmd_delay_list)

    # -- delay-remove --
    p = sub.add_parser("delay-remove", help="remove latency rules")
    p.add_argument("node", help="inject-error node name")
    p.add_argument("id", nargs="?",
                   help="rule to remove (default: all of them)")
    p.set_defaults(func=cmd_delay_remove)

    # -- inflight --
    p = sub.add_parser("inflight", help="list currently held requests")
    p.add_argument("node", help="inject-error node name")
    p.add_argument("--json", action="store_true",
                   help="also print raw JSON output")
    p.set_defaults(func=cmd_inflight)

    # -- release --
    p = sub.add_parser("release", help="release held requests")
    p.add_argument("node", help="inject-error node name")
    p.add_argument("-i", "--request-id", type=int,
                   help="request to release (default: all of them)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--complete", action="store_true",
                       help="let the requests complete normally")
    group.add_argument("--error", action="store_true",
                       help="fail the requests")
    p.add_argument("-e", "--errno", type=parse_errno,
                   help="errno to fail with (default: 5/EIO)")
    p.set_defaults(func=cmd_release)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
