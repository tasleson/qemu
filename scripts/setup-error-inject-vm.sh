#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Set up and run a QEMU VM for SCSI error injection testing.
#
# Creates:
#   - A boot disk for Fedora installation, behind an inject-error filter
#   - 3 additional sparse SCSI disks with inject-error filters
#   - QMP socket for runtime error/response injection
#
# Usage:
#   ./scripts/setup-error-inject-vm.sh create   - create disk images
#   ./scripts/setup-error-inject-vm.sh install   - boot from ISO for installation
#   ./scripts/setup-error-inject-vm.sh run       - boot installed system
#   ./scripts/setup-error-inject-vm.sh build-run - rebuild QEMU then boot

set -euo pipefail

QEMU_SRC="/home/tasleson/projects/qemu"
QEMU_BUILD="${QEMU_SRC}/build"
QEMU="${QEMU_BUILD}/qemu-system-x86_64"
VM_DIR="/home/tasleson/VirtualMachines/qemu/error_inject"
QMP_SOCK="${VM_DIR}/qmp.sock"

BOOT_DISK="${VM_DIR}/boot.qcow2"
BOOT_SIZE="40G"

SCSI_DISK_SIZE="10G"
SCSI_DISK1="${VM_DIR}/scsi-disk1.qcow2"
SCSI_DISK2="${VM_DIR}/scsi-disk2.qcow2"
SCSI_DISK3="${VM_DIR}/scsi-disk3.qcow2"

RAM="4G"
CPUS="4"

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  create      Create VM directory and sparse disk images
  install     Boot from Fedora ISO for installation (set FEDORA_ISO)
  run         Boot the installed system
  build-run   Rebuild QEMU from source, then boot
  status      Show VM directory and disk status

Environment variables:
  FEDORA_ISO  Path to Fedora installation ISO (required for 'install')
  RAM         VM memory (default: ${RAM})
  CPUS        VM CPU count (default: ${CPUS})

QMP socket: ${QMP_SOCK}

Block nodes for injection:
  err0        boot disk (virtio-blk) -- the running system's disk
  err1..err3  data disks (virtio-scsi)

After booting, inject errors/responses via QMP:
  # Add a bad sector on scsi-disk1
  $QEMU_BUILD/run scripts/scsi-inject.py -s ${QMP_SOCK} serial disk1 "FUZZ_SERIAL_123"

  # Or use qmp-shell directly
  $QEMU_BUILD/run qmp-shell ${QMP_SOCK}
EOF
    exit 1
}

cmd_create() {
    if [ -d "${VM_DIR}" ]; then
        echo "VM directory already exists: ${VM_DIR}"
        echo "Checking for missing disks..."
    else
        echo "Creating VM directory: ${VM_DIR}"
        mkdir -p "${VM_DIR}"
    fi

    for disk_info in \
        "${BOOT_DISK}:${BOOT_SIZE}:boot disk" \
        "${SCSI_DISK1}:${SCSI_DISK_SIZE}:SCSI disk 1" \
        "${SCSI_DISK2}:${SCSI_DISK_SIZE}:SCSI disk 2" \
        "${SCSI_DISK3}:${SCSI_DISK_SIZE}:SCSI disk 3"; do

        disk="${disk_info%%:*}"
        rest="${disk_info#*:}"
        size="${rest%%:*}"
        label="${rest#*:}"

        if [ -f "${disk}" ]; then
            echo "  ${label}: already exists ($(du -h "${disk}" | cut -f1) on disk)"
        else
            echo "  ${label}: creating ${size} sparse qcow2 at ${disk}"
            "${QEMU_BUILD}/qemu-img" create -f qcow2 "${disk}" "${size}"
        fi
    done

    echo ""
    echo "Done. Next steps:"
    echo "  Install: FEDORA_ISO=/path/to/Fedora.iso $0 install"
    echo "  Run:     $0 run"
}

run_vm() {
    local extra_args=("$@")

    if [ ! -x "${QEMU}" ]; then
        echo "Error: QEMU binary not found at ${QEMU}"
        echo "Run 'ninja -C ${QEMU_BUILD}' first, or use '$0 build-run'"
        exit 1
    fi

    for disk in "${BOOT_DISK}" "${SCSI_DISK1}" "${SCSI_DISK2}" "${SCSI_DISK3}"; do
        if [ ! -f "${disk}" ]; then
            echo "Error: disk image not found: ${disk}"
            echo "Run '$0 create' first"
            exit 1
        fi
    done

    # Clean up stale QMP socket
    rm -f "${QMP_SOCK}"

    echo "Starting VM..."
    echo "  QMP socket: ${QMP_SOCK}"
    echo "  Boot disk:  ${BOOT_DISK} (virtio-blk, inject-error filter)"
    echo "  SCSI disks: scsi-disk[1-3] with inject-error filters"
    echo "  Nodes:      err0 (boot), err1, err2, err3"
    echo "  Devices:    disk1, disk2, disk3 (for x-scsi-disk-inject-response-set)"
    echo ""
    echo "  Note: err0 is the running system's disk.  Injecting there can"
    echo "        bugcheck or corrupt the guest, and a stall on it will hold"
    echo "        up VM shutdown until released.  Back the image up first."
    echo ""

    exec "${QEMU}" \
        -machine q35,accel=kvm \
        -cpu host \
        -smp "${CPUS}" \
        -m "${RAM}" \
        \
        -display gtk \
        -vga virtio \
        \
        -qmp "unix:${QMP_SOCK},server=on,wait=off" \
        -monitor stdio \
        \
        -net nic,model=virtio-net-pci \
        -net passt,tcp-ports=2222:22 \
        \
        -blockdev driver=file,filename="${BOOT_DISK}",node-name=file0 \
        -blockdev driver=qcow2,file=file0,node-name=raw0 \
        -blockdev driver=inject-error,image=raw0,node-name=err0 \
        -device virtio-blk-pci,drive=err0,bootindex=0,id=disk0 \
        \
        -device virtio-scsi-pci,id=scsi0 \
        \
        -blockdev driver=file,filename="${SCSI_DISK1}",node-name=file1 \
        -blockdev driver=qcow2,file=file1,node-name=raw1 \
        -blockdev driver=inject-error,image=raw1,node-name=err1 \
        -device scsi-hd,drive=err1,bus=scsi0.0,id=disk1,serial=DISK1_SERIAL \
        \
        -blockdev driver=file,filename="${SCSI_DISK2}",node-name=file2 \
        -blockdev driver=qcow2,file=file2,node-name=raw2 \
        -blockdev driver=inject-error,image=raw2,node-name=err2 \
        -device scsi-hd,drive=err2,bus=scsi0.0,id=disk2,serial=DISK2_SERIAL \
        \
        -blockdev driver=file,filename="${SCSI_DISK3}",node-name=file3 \
        -blockdev driver=qcow2,file=file3,node-name=raw3 \
        -blockdev driver=inject-error,image=raw3,node-name=err3 \
        -device scsi-hd,drive=err3,bus=scsi0.0,id=disk3,serial=DISK3_SERIAL \
        \
        "${extra_args[@]}"
}

cmd_install() {
    if [ -z "${FEDORA_ISO:-}" ]; then
        echo "Error: FEDORA_ISO not set"
        echo "Usage: FEDORA_ISO=/path/to/Fedora-*.iso $0 install"
        exit 1
    fi

    if [ ! -f "${FEDORA_ISO}" ]; then
        echo "Error: ISO not found: ${FEDORA_ISO}"
        exit 1
    fi

    echo "Installing from: ${FEDORA_ISO}"
    echo "Install Fedora to the virtio boot disk, NOT the SCSI disks."
    echo ""

    run_vm -cdrom "${FEDORA_ISO}" -boot d
}

cmd_run() {
    run_vm
}

cmd_build_run() {
    echo "Building QEMU..."
    ninja -C "${QEMU_BUILD}" -j"$(nproc)"
    echo ""
    cmd_run
}

cmd_status() {
    echo "VM directory: ${VM_DIR}"
    echo ""

    if [ ! -d "${VM_DIR}" ]; then
        echo "  Not created yet. Run '$0 create' first."
        exit 0
    fi

    for disk_info in \
        "${BOOT_DISK}:boot disk (disk0/err0)" \
        "${SCSI_DISK1}:SCSI disk 1 (disk1/err1)" \
        "${SCSI_DISK2}:SCSI disk 2 (disk2/err2)" \
        "${SCSI_DISK3}:SCSI disk 3 (disk3/err3)"; do

        disk="${disk_info%%:*}"
        label="${disk_info#*:}"

        if [ -f "${disk}" ]; then
            actual=$(du -h "${disk}" | cut -f1)
            virtual=$("${QEMU_BUILD}/qemu-img" info --output=json "${disk}" 2>/dev/null \
                | python3 -c "import sys,json; print(json.load(sys.stdin).get('virtual-size',0) // (1<<30))" 2>/dev/null || echo "?")
            echo "  ${label}: ${actual} on disk / ${virtual}G virtual"
        else
            echo "  ${label}: not created"
        fi
    done

    echo ""
    if [ -S "${QMP_SOCK}" ]; then
        echo "  QMP socket: active"
    else
        echo "  QMP socket: not running"
    fi
}

case "${1:-}" in
    create)    cmd_create ;;
    install)   cmd_install ;;
    run)       cmd_run ;;
    build-run) cmd_build_run ;;
    status)    cmd_status ;;
    *)         usage ;;
esac
