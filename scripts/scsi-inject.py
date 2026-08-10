#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# SCSI response injection tool for QEMU
#
# Sets SCSI command response overrides on scsi-hd/scsi-cd devices via QMP,
# useful for fuzzing guest storage management software.
#
# Usage: $builddir/run scripts/scsi-inject.py [options] <command> [args]

import argparse
import struct
import sys
from base64 import b64encode

try:
    from qemu.qmp.legacy import QEMUMonitorProtocol
except ModuleNotFoundError as exc:
    print(f"Module '{exc.name}' not found.", file=sys.stderr)
    print(f"Try $builddir/run {' '.join(sys.argv)}", file=sys.stderr)
    sys.exit(1)


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


def inject_set(qmp, device, resp_type, data, page=None):
    cmd_args = {
        "id": device,
        "type": resp_type,
        "data": b64encode(data).decode("ascii"),
    }
    if page is not None:
        cmd_args["page"] = page
    qmp_execute(qmp, "x-scsi-disk-inject-response-set", cmd_args)


def inject_clear(qmp, device, resp_type=None, page=None):
    cmd_args = {"id": device}
    if resp_type is not None:
        cmd_args["type"] = resp_type
    if page is not None:
        cmd_args["page"] = page
    qmp_execute(qmp, "x-scsi-disk-inject-response-clear", cmd_args)


def build_vpd_page(page_code, dev_type, page_data):
    """Build a complete VPD page response with 4-byte header."""
    buf = bytearray()
    buf.append(dev_type & 0x1F)
    buf.append(page_code)
    length = len(page_data)
    buf.append((length >> 8) & 0xFF)
    buf.append(length & 0xFF)
    buf.extend(page_data)
    return bytes(buf)


def build_inquiry_standard(dev_type, vendor, product, version,
                           removable=False, scsi_version=5):
    """Build a standard INQUIRY response."""
    buf = bytearray(96)
    buf[0] = dev_type & 0x1F
    buf[1] = 0x80 if removable else 0x00
    buf[2] = scsi_version
    buf[3] = 0x12  # Response Data Format 2, HiSup

    vendor_b = vendor.encode("ascii", errors="replace")[:8]
    product_b = product.encode("ascii", errors="replace")[:16]
    version_b = version.encode("ascii", errors="replace")[:4]

    for i in range(8, 16):
        buf[i] = 0x20
    buf[8:8 + len(vendor_b)] = vendor_b

    for i in range(16, 32):
        buf[i] = 0x20
    buf[16:16 + len(product_b)] = product_b

    for i in range(32, 36):
        buf[i] = 0x20
    buf[32:32 + len(version_b)] = version_b

    buf[4] = len(buf) - 5  # additional length
    buf[7] = 0x12  # Sync, CmdQue
    return bytes(buf)


def cmd_serial(args):
    qmp = qmp_connect(args)
    serial = args.serial.encode("ascii", errors="replace")
    data = build_vpd_page(0x80, args.dev_type, serial)
    inject_set(qmp, args.device, "inquiry-vpd", data, page=0x80)
    qmp.close()
    print(f"Set serial number on {args.device}: {args.serial}")


def cmd_device_id(args):
    qmp = qmp_connect(args)
    # VPD page 0x83 device identification
    # Identifier descriptor: code set=ASCII, association=device, type=vendor
    id_bytes = args.device_id.encode("ascii", errors="replace")
    desc = bytearray()
    desc.append(0x02)           # code set: ASCII
    desc.append(0x01)           # association: target device, type: T10 vendor
    desc.append(0x00)           # reserved
    desc.append(len(id_bytes))  # identifier length
    desc.extend(id_bytes)
    data = build_vpd_page(0x83, args.dev_type, bytes(desc))
    inject_set(qmp, args.device, "inquiry-vpd", data, page=0x83)
    qmp.close()
    print(f"Set device ID on {args.device}: {args.device_id}")


def cmd_inquiry(args):
    qmp = qmp_connect(args)
    data = build_inquiry_standard(
        dev_type=args.dev_type,
        vendor=args.vendor,
        product=args.product,
        version=args.version,
        removable=args.removable,
    )
    inject_set(qmp, args.device, "inquiry-standard", data)
    qmp.close()
    print(f"Set INQUIRY on {args.device}: "
          f"vendor={args.vendor!r} product={args.product!r}")


def cmd_vpd_raw(args):
    qmp = qmp_connect(args)
    data = bytes.fromhex(args.hex_data)
    inject_set(qmp, args.device, "inquiry-vpd", data, page=args.page)
    qmp.close()
    print(f"Set raw VPD page 0x{args.page:02x} on {args.device} "
          f"({len(data)} bytes)")


def cmd_mode_sense_raw(args):
    qmp = qmp_connect(args)
    data = bytes.fromhex(args.hex_data)
    inject_set(qmp, args.device, "mode-sense-page", data, page=args.page)
    qmp.close()
    print(f"Set raw MODE SENSE page 0x{args.page:02x} on {args.device} "
          f"({len(data)} bytes)")


def cmd_clear(args):
    qmp = qmp_connect(args)
    resp_type = getattr(args, "type", None)
    page = getattr(args, "page", None)
    inject_clear(qmp, args.device, resp_type=resp_type, page=page)
    qmp.close()
    what = "all overrides"
    if resp_type:
        what = resp_type
        if page is not None:
            what += f" page 0x{page:02x}"
    print(f"Cleared {what} on {args.device}")


def parse_page(val):
    return int(val, 0)


def main():
    parser = argparse.ArgumentParser(
        description="SCSI response injection tool for QEMU",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s serial disk0 "LONGSERIAL0123456789ABCDEF0123456789"
  %(prog)s device-id disk0 "MY_CUSTOM_DEVICE_ID_STRING"
  %(prog)s inquiry disk0 --vendor "ACME" --product "FuzzyDisk 9000"
  %(prog)s vpd-raw disk0 0x80 00800100FF
  %(prog)s clear disk0
  %(prog)s clear disk0 --type inquiry-vpd --page 0x80
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

    # -- serial --
    p = sub.add_parser("serial",
                       help="set VPD page 0x80 (unit serial number)")
    p.add_argument("device", help="QEMU device ID (e.g. disk0)")
    p.add_argument("serial", help="serial number string (any length)")
    p.add_argument("--dev-type", type=int, default=0,
                   help="peripheral device type (default: 0 = disk)")
    p.set_defaults(func=cmd_serial)

    # -- device-id --
    p = sub.add_parser("device-id",
                       help="set VPD page 0x83 (device identification)")
    p.add_argument("device", help="QEMU device ID")
    p.add_argument("device_id", help="device identification string")
    p.add_argument("--dev-type", type=int, default=0,
                   help="peripheral device type (default: 0 = disk)")
    p.set_defaults(func=cmd_device_id)

    # -- inquiry --
    p = sub.add_parser("inquiry",
                       help="set standard INQUIRY response")
    p.add_argument("device", help="QEMU device ID")
    p.add_argument("--vendor", default="QEMU",
                   help="vendor string, up to 8 chars (default: QEMU)")
    p.add_argument("--product", default="QEMU HARDDISK",
                   help="product string, up to 16 chars")
    p.add_argument("--version", default="1.0",
                   help="version string, up to 4 chars")
    p.add_argument("--removable", action="store_true",
                   help="set removable media bit")
    p.add_argument("--dev-type", type=int, default=0,
                   help="peripheral device type (default: 0 = disk)")
    p.set_defaults(func=cmd_inquiry)

    # -- vpd-raw --
    p = sub.add_parser("vpd-raw",
                       help="set raw VPD page (hex bytes)")
    p.add_argument("device", help="QEMU device ID")
    p.add_argument("page", type=parse_page,
                   help="VPD page code (e.g. 0x80)")
    p.add_argument("hex_data",
                   help="hex-encoded page data (complete response)")
    p.set_defaults(func=cmd_vpd_raw)

    # -- mode-sense-raw --
    p = sub.add_parser("mode-sense-raw",
                       help="set raw MODE SENSE response (hex bytes)")
    p.add_argument("device", help="QEMU device ID")
    p.add_argument("page", type=parse_page,
                   help="MODE SENSE page code (e.g. 0x08)")
    p.add_argument("hex_data",
                   help="hex-encoded response data (complete response)")
    p.set_defaults(func=cmd_mode_sense_raw)

    # -- clear --
    p = sub.add_parser("clear",
                       help="clear response overrides")
    p.add_argument("device", help="QEMU device ID")
    p.add_argument("--type", dest="type", choices=[
        "inquiry-standard", "inquiry-vpd", "mode-sense-page",
    ], help="clear only this override type (default: clear all)")
    p.add_argument("--page", type=parse_page,
                   help="page code (required with --type inquiry-vpd "
                        "or mode-sense-page)")
    p.set_defaults(func=cmd_clear)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
