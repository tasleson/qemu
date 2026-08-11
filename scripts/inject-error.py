#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Block I/O error injection tool for QEMU
#
# Manages bad sector regions on inject-error filter nodes via QMP.
# Simulates media errors to test guest OS error handling.
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
    except ConnectionError:
        target = args.socket or f"{args.host}:{args.port}"
        sys.exit(f"Cannot connect to QMP at {target}")
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


def parse_errno(val):
    val_upper = val.upper()
    for num, name in ERRNO_NAMES.items():
        if val_upper == name:
            return num
    return int(val, 0)


def main():
    parser = argparse.ArgumentParser(
        description="Block I/O error injection tool for QEMU",
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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
