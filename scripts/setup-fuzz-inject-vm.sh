#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Set up and run a QEMU VM with every storage device type for error injection testing.
#
# Storage types included:
#   - virtio-blk (boot)
#   - virtio-scsi (3 disks)
#   - NVMe
#   - SATA (ich9-ahci)
#   - IDE/PATA (piix4-ide)
#   - Floppy (ISA FDC, 1.44 MB)
#   - USB Mass Storage (xhci)
#   - SD card (sdhci-pci)
#   - LSI 53C895A SCSI
#   - MegaRAID SAS
#   - VMware PVSCSI
#   - UFS
#
# Every disk (except boot) has an inject-error filter for runtime error injection
# via QMP.  The inject-error node name is listed in the status/run output so you
# can target it with x-inject-error-add.
#
# Usage:
#   ./scripts/setup-error-inject-vm.sh create   - create disk images
#   ./scripts/setup-error-inject-vm.sh install   - boot from ISO for installation
#   ./scripts/setup-error-inject-vm.sh run       - boot installed system
#   ./scripts/setup-error-inject-vm.sh build-run - rebuild QEMU then boot
#   ./scripts/setup-error-inject-vm.sh status    - show disk status

set -euo pipefail

QEMU_SRC="/home/tasleson/projects/qemu"
QEMU_BUILD="${QEMU_SRC}/build"
QEMU="${QEMU_BUILD}/qemu-system-x86_64"
VM_DIR="/home/tasleson/VirtualMachines/qemu/error_inject"
QMP_SOCK="${VM_DIR}/qmp.sock"

RAM="4G"
CPUS="4"

# --- Disk paths and sizes ---

BOOT_DISK="${VM_DIR}/boot.qcow2"
BOOT_SIZE="40G"

DISK_SIZE="10G"

# virtio-scsi (existing)
SCSI_DISK1="${VM_DIR}/scsi-disk1.qcow2"
SCSI_DISK2="${VM_DIR}/scsi-disk2.qcow2"
SCSI_DISK3="${VM_DIR}/scsi-disk3.qcow2"

# Additional storage types
NVME_DISK="${VM_DIR}/nvme-disk1.qcow2"
SATA_DISK="${VM_DIR}/sata-disk1.qcow2"
IDE_DISK="${VM_DIR}/ide-disk1.qcow2"
FLOPPY_DISK="${VM_DIR}/floppy.img"
USB_DISK="${VM_DIR}/usb-disk1.qcow2"
SD_DISK="${VM_DIR}/sd-disk1.qcow2"
LSI_DISK="${VM_DIR}/lsi-disk1.qcow2"
MEGASAS_DISK="${VM_DIR}/megasas-disk1.qcow2"
PVSCSI_DISK="${VM_DIR}/pvscsi-disk1.qcow2"
UFS_DISK="${VM_DIR}/ufs-disk1.qcow2"

# Master list: "path:size:format:label"
ALL_DISKS=(
    "${BOOT_DISK}:${BOOT_SIZE}:qcow2:Boot disk (virtio-blk)"
    "${SCSI_DISK1}:${DISK_SIZE}:qcow2:SCSI disk 1 (virtio-scsi) [err1]"
    "${SCSI_DISK2}:${DISK_SIZE}:qcow2:SCSI disk 2 (virtio-scsi) [err2]"
    "${SCSI_DISK3}:${DISK_SIZE}:qcow2:SCSI disk 3 (virtio-scsi) [err3]"
    "${NVME_DISK}:${DISK_SIZE}:qcow2:NVMe disk [nvme1-err]"
    "${SATA_DISK}:${DISK_SIZE}:qcow2:SATA disk (ich9-ahci) [sata1-err]"
    "${IDE_DISK}:${DISK_SIZE}:qcow2:IDE/PATA disk (piix4) [ide1-err]"
    "${FLOPPY_DISK}:1440K:raw:Floppy disk (ISA FDC) [floppy-err]"
    "${USB_DISK}:${DISK_SIZE}:qcow2:USB disk (xhci) [usb1-err]"
    "${SD_DISK}:1G:qcow2:SD card (sdhci-pci) [sd1-err]"
    "${LSI_DISK}:${DISK_SIZE}:qcow2:LSI 53C895A SCSI disk [lsi1-err]"
    "${MEGASAS_DISK}:${DISK_SIZE}:qcow2:MegaRAID SAS disk [megasas1-err]"
    "${PVSCSI_DISK}:${DISK_SIZE}:qcow2:VMware PVSCSI disk [pvscsi1-err]"
    "${UFS_DISK}:${DISK_SIZE}:qcow2:UFS disk [ufs1-err]"
)

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  create      Create VM directory and sparse disk images
  install     Boot from Fedora ISO for installation (set FEDORA_ISO)
  run         Boot the installed system
  build-run   Rebuild QEMU from source, then boot
  status      Show VM directory and disk status

Storage types attached to the VM:
  virtio-blk      Boot disk
  virtio-scsi     3 SCSI disks (err1, err2, err3)
  NVMe            nvme-disk1 (nvme1-err)
  SATA (AHCI)     sata-disk1 (sata1-err)
  IDE/PATA        ide-disk1 (ide1-err)
  Floppy          floppy (floppy-err)
  USB Storage     usb-disk1 (usb1-err)
  SD card         sd-disk1 (sd1-err)
  LSI SCSI        lsi-disk1 (lsi1-err)
  MegaRAID SAS    megasas-disk1 (megasas1-err)
  VMware PVSCSI   pvscsi-disk1 (pvscsi1-err)
  UFS             ufs-disk1 (ufs1-err)

Environment variables:
  FEDORA_ISO  Path to Fedora installation ISO (required for 'install')
  RAM         VM memory (default: ${RAM})
  CPUS        VM CPU count (default: ${CPUS})

QMP socket: ${QMP_SOCK}

After booting, inject errors via QMP:
  $QEMU_BUILD/run scripts/scsi-inject.py -s ${QMP_SOCK} serial disk1 "FUZZ_SERIAL_123"
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

    for disk_info in "${ALL_DISKS[@]}"; do
        IFS=: read -r disk size fmt label <<< "${disk_info}"

        if [ -f "${disk}" ]; then
            echo "  ${label}: already exists ($(du -h "${disk}" | cut -f1) on disk)"
        else
            echo "  ${label}: creating ${size} ${fmt} at ${disk}"
            "${QEMU_BUILD}/qemu-img" create -f "${fmt}" "${disk}" "${size}"
        fi
    done

    echo ""
    echo "Done.  ${#ALL_DISKS[@]} disk images ready."
    echo "  Install: FEDORA_ISO=/path/to/Fedora.iso $0 install"
    echo "  Run:     $0 run"
}

# --- Blockdev helpers (append to the 'args' array) ---

# file -> qcow2 -> inject-error
# Creates node-names: ${name}-file, ${name}-raw, ${name}-err
add_qcow2_blockdev() {
    local name=$1 path=$2
    args+=(
        -blockdev "driver=file,filename=${path},node-name=${name}-file"
        -blockdev "driver=qcow2,file=${name}-file,node-name=${name}-raw"
        -blockdev "driver=inject-error,image=${name}-raw,node-name=${name}-err"
    )
}

# file -> raw -> inject-error
add_raw_blockdev() {
    local name=$1 path=$2
    args+=(
        -blockdev "driver=file,filename=${path},node-name=${name}-file"
        -blockdev "driver=raw,file=${name}-file,node-name=${name}-raw"
        -blockdev "driver=inject-error,image=${name}-raw,node-name=${name}-err"
    )
}

run_vm() {
    local extra_args=("$@")

    if [ ! -x "${QEMU}" ]; then
        echo "Error: QEMU binary not found at ${QEMU}"
        echo "Run 'ninja -C ${QEMU_BUILD}' first, or use '$0 build-run'"
        exit 1
    fi

    for disk_info in "${ALL_DISKS[@]}"; do
        local disk="${disk_info%%:*}"
        if [ ! -f "${disk}" ]; then
            echo "Error: disk image not found: ${disk}"
            echo "Run '$0 create' first"
            exit 1
        fi
    done

    rm -f "${QMP_SOCK}"

    echo "Starting VM with all storage types..."
    echo "  QMP socket: ${QMP_SOCK}"
    echo ""
    echo "  Inject-error nodes (use with x-inject-error-add):"
    echo "    virtio-scsi : err1, err2, err3"
    echo "    NVMe        : nvme1-err"
    echo "    SATA        : sata1-err"
    echo "    IDE/PATA    : ide1-err"
    echo "    Floppy      : floppy-err"
    echo "    USB         : usb1-err"
    echo "    SD          : sd1-err"
    echo "    LSI SCSI    : lsi1-err"
    echo "    MegaRAID    : megasas1-err"
    echo "    PVSCSI      : pvscsi1-err"
    echo "    UFS         : ufs1-err"
    echo ""
    echo "  SCSI response injection (use with scsi-inject.py):"
    echo "    virtio-scsi : disk1, disk2, disk3"
    echo "    USB         : usb-disk1"
    echo "    LSI SCSI    : lsi-disk1"
    echo "    MegaRAID    : megasas-disk1"
    echo "    PVSCSI      : pvscsi-disk1"
    echo ""

    local args=()

    # --- Machine ---
    args+=(
        -machine q35,accel=kvm
        -cpu host
        -smp "${CPUS}"
        -m "${RAM}"
    )

    # --- Display ---
    args+=(
        -display gtk
        -vga virtio
    )

    # --- Management ---
    args+=(
        -qmp "unix:${QMP_SOCK},server=on,wait=off"
        -monitor stdio
    )

    # --- Network ---
    args+=(
        -net nic,model=virtio-net-pci
        -net passt,tcp-ports=2222:22
    )

    # =====================================================================
    # Boot disk (virtio-blk, no inject-error)
    # =====================================================================
    args+=(
        -blockdev "driver=file,filename=${BOOT_DISK},node-name=boot-file"
        -blockdev driver=qcow2,file=boot-file,node-name=boot
        -device virtio-blk-pci,drive=boot,bootindex=0
    )

    # =====================================================================
    # virtio-scsi (3 disks, existing)
    # =====================================================================
    args+=(-device virtio-scsi-pci,id=scsi0)

    # Keep the original node-name scheme (file1/raw1/err1) for compatibility
    args+=(
        -blockdev "driver=file,filename=${SCSI_DISK1},node-name=file1"
        -blockdev driver=qcow2,file=file1,node-name=raw1
        -blockdev driver=inject-error,image=raw1,node-name=err1
        -device scsi-hd,drive=err1,bus=scsi0.0,id=disk1,serial=DISK1_SERIAL
    )
    args+=(
        -blockdev "driver=file,filename=${SCSI_DISK2},node-name=file2"
        -blockdev driver=qcow2,file=file2,node-name=raw2
        -blockdev driver=inject-error,image=raw2,node-name=err2
        -device scsi-hd,drive=err2,bus=scsi0.0,id=disk2,serial=DISK2_SERIAL
    )
    args+=(
        -blockdev "driver=file,filename=${SCSI_DISK3},node-name=file3"
        -blockdev driver=qcow2,file=file3,node-name=raw3
        -blockdev driver=inject-error,image=raw3,node-name=err3
        -device scsi-hd,drive=err3,bus=scsi0.0,id=disk3,serial=DISK3_SERIAL
    )

    # =====================================================================
    # NVMe
    # =====================================================================
    add_qcow2_blockdev nvme1 "${NVME_DISK}"
    args+=(-device nvme,serial=NVME1_SERIAL,drive=nvme1-err,id=nvme-disk1)

    # =====================================================================
    # SATA (ich9-ahci)
    # =====================================================================
    args+=(-device ich9-ahci,id=ahci0)
    add_qcow2_blockdev sata1 "${SATA_DISK}"
    args+=(-device ide-hd,drive=sata1-err,bus=ahci0.0,id=sata-disk1,serial=SATA1_SERIAL)

    # =====================================================================
    # IDE / PATA (piix4-ide — Intel PIIX4 PCI IDE controller)
    # =====================================================================
    args+=(-device piix4-ide,id=pata0)
    add_qcow2_blockdev ide1 "${IDE_DISK}"
    args+=(-device ide-hd,drive=ide1-err,bus=pata0.0,id=ide-disk1,serial=IDE1_SERIAL)

    # =====================================================================
    # Floppy (ISA FDC, 1.44 MB raw image)
    # =====================================================================
    add_raw_blockdev floppy "${FLOPPY_DISK}"
    args+=(-device isa-fdc,id=fdc0 -device floppy,drive=floppy-err,bus=fdc0.0)

    # =====================================================================
    # USB Mass Storage (xhci host controller)
    # =====================================================================
    args+=(-device qemu-xhci,id=xhci0)
    add_qcow2_blockdev usb1 "${USB_DISK}"
    args+=(-device usb-storage,drive=usb1-err,bus=xhci0.0,id=usb-disk1,serial=USB1_SERIAL,removable=on)

    # =====================================================================
    # SD card (sdhci-pci)
    # =====================================================================
    args+=(-device sdhci-pci,id=sdhci0)
    add_qcow2_blockdev sd1 "${SD_DISK}"
    args+=(-device sd-card,drive=sd1-err,bus=sd-bus)

    # =====================================================================
    # LSI 53C895A SCSI
    # =====================================================================
    args+=(-device lsi53c895a,id=lsi0)
    add_qcow2_blockdev lsi1 "${LSI_DISK}"
    args+=(-device scsi-hd,drive=lsi1-err,bus=lsi0.0,id=lsi-disk1,serial=LSI1_SERIAL)

    # =====================================================================
    # MegaRAID SAS
    # =====================================================================
    args+=(-device megasas,id=megasas0)
    add_qcow2_blockdev megasas1 "${MEGASAS_DISK}"
    args+=(-device scsi-hd,drive=megasas1-err,bus=megasas0.0,id=megasas-disk1,serial=MEGASAS1_SERIAL)

    # NOTE: mptsas1068 (Fusion-MPT SAS) excluded — prevents SeaBIOS from
    # booting the correct disk (corrupt initramfs decompression).

    # =====================================================================
    # VMware PVSCSI
    # =====================================================================
    args+=(-device pvscsi,id=pvscsi0)
    add_qcow2_blockdev pvscsi1 "${PVSCSI_DISK}"
    args+=(-device scsi-hd,drive=pvscsi1-err,bus=pvscsi0.0,id=pvscsi-disk1,serial=PVSCSI1_SERIAL)

    # =====================================================================
    # UFS (Universal Flash Storage)
    # =====================================================================
    args+=(-device ufs,id=ufs0)
    add_qcow2_blockdev ufs1 "${UFS_DISK}"
    args+=(-device ufs-lu,drive=ufs1-err,bus=ufs0)

    # =====================================================================

    exec "${QEMU}" "${args[@]}" "${extra_args[@]}"
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
    echo "Install Fedora to the virtio boot disk, NOT any of the data disks."
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

    for disk_info in "${ALL_DISKS[@]}"; do
        IFS=: read -r disk size fmt label <<< "${disk_info}"

        if [ -f "${disk}" ]; then
            actual=$(du -h "${disk}" | cut -f1)
            if [ "${fmt}" = "qcow2" ]; then
                virtual=$("${QEMU_BUILD}/qemu-img" info --output=json "${disk}" 2>/dev/null \
                    | python3 -c "import sys,json; print(json.load(sys.stdin).get('virtual-size',0) // (1<<30))" 2>/dev/null || echo "?")
                echo "  ${label}: ${actual} on disk / ${virtual}G virtual"
            else
                echo "  ${label}: ${actual} on disk / ${size} virtual"
            fi
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
