#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Set up and run a Windows QEMU VM for stress-testing the virtio-blk
# (viostor) and virtio-scsi (vioscsi) Windows guest drivers against the
# inject-error / SCSI response injection branch.
#
# Creates:
#   - A virtio-blk boot disk (Windows install target), behind an
#     inject-error filter
#   - A second virtio-blk data disk, behind an inject-error filter
#   - Two virtio-scsi data disks, behind inject-error filters
#   - UEFI (OVMF, Secure Boot capable) firmware + per-VM NVRAM
#   - An emulated TPM 2.0 (swtpm), required by Windows 11 setup
#   - QMP socket for runtime error/response injection
#
# Usage:
#   ./scripts/setup-windows-inject-vm.sh create   - create disks + NVRAM
#   ./scripts/setup-windows-inject-vm.sh install  - boot from Windows ISO for installation
#   ./scripts/setup-windows-inject-vm.sh run      - boot the installed system
#   ./scripts/setup-windows-inject-vm.sh build-run - rebuild QEMU then boot
#   ./scripts/setup-windows-inject-vm.sh status   - show VM/disk/firmware status

set -euo pipefail

QEMU_SRC="/home/tasleson/projects/qemu"
QEMU_BUILD="${QEMU_SRC}/build"
QEMU="${QEMU_BUILD}/qemu-system-x86_64"
VM_DIR="/home/tasleson/VirtualMachines/qemu/windows_inject"
QMP_SOCK="${VM_DIR}/qmp.sock"
QGA_SOCK="${VM_DIR}/qga.sock"
TPM_DIR="${VM_DIR}/tpm"
TPM_SOCK="${VM_DIR}/swtpm.sock"

BOOT_DISK="${VM_DIR}/boot.qcow2"
BOOT_SIZE="80G"

BLK_DATA_DISK="${VM_DIR}/blk-data1.qcow2"
BLK_DATA_SIZE="20G"

SCSI_DISK_SIZE="20G"
SCSI_DISK1="${VM_DIR}/scsi-disk1.qcow2"
SCSI_DISK2="${VM_DIR}/scsi-disk2.qcow2"

OVMF_CODE="/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2"
OVMF_VARS_TEMPLATE="/usr/share/edk2/ovmf/OVMF_VARS_4M.secboot.qcow2"
OVMF_VARS="${VM_DIR}/OVMF_VARS.qcow2"

VIRTIO_ISO="${VM_DIR}/virtio-win.iso"
WIN_ISO_DEFAULT="/home/tasleson/Downloads/Win11_25H2_English_x64_v2.iso"

TRACE_EVENTS_DEFAULT="${QEMU_SRC}/scripts/windows-storage-trace-events"
TRACE_LOG="${VM_DIR}/trace.log"

RAM="8G"
CPUS="4"

# parse_delay_rules SPEC
#
# Translate a compact rule spec into '-blockdev' inject-error 'delays.N.*'
# properties, so latency injection is armed at device-creation time and
# is therefore in effect for the very first I/O the guest issues (i.e.
# during boot), not just after a QMP command is sent post-boot.
#
# SPEC is one or more rules separated by ';'. Each rule is a
# comma-separated list of "field=value" pairs, where field is any
# InjectDelayRuleOptions field (id, ops, sector, count, probability,
# delay-ms, delay-max-ms, stall, errno, max-hits). The 'ops' value may
# list multiple operations joined with '+' (e.g. ops=read+write).
#
# Examples:
#   Constant latency on every read:
#     id=bootread,ops=read,delay-ms=200
#   Tail latency (1% of requests delayed 20-2000ms):
#     id=tail,probability=0.01,delay-ms=20,delay-max-ms=2000
#   Indefinite stall on the first write, to test guest timeout handling:
#     id=stall1,ops=write,stall=true,max-hits=1
parse_delay_rules() {
    local spec="$1"
    local out="" rule field key val idx=0 oi op
    local -a rules fields ops

    IFS=';' read -ra rules <<< "${spec}"
    for rule in "${rules[@]}"; do
        IFS=',' read -ra fields <<< "${rule}"
        for field in "${fields[@]}"; do
            key="${field%%=*}"
            val="${field#*=}"
            if [ "${key}" = "ops" ]; then
                oi=0
                IFS='+' read -ra ops <<< "${val}"
                for op in "${ops[@]}"; do
                    out+=",delays.${idx}.ops.${oi}=${op}"
                    oi=$((oi + 1))
                done
            else
                out+=",delays.${idx}.${key}=${val}"
            fi
        done
        idx=$((idx + 1))
    done

    echo "${out}"
}

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  create      Create VM directory, disk images, and per-VM UEFI NVRAM
  install     Boot from a Windows ISO + virtio-win driver ISO for installation
  run         Boot the installed system
  build-run   Rebuild QEMU from source, then boot
  status      Show VM directory, disk, and firmware status

The virtio-win driver ISO (${VIRTIO_ISO}) is attached as a CD-ROM on
every boot -- install, run, and build-run alike -- so drivers are
available to load/reinstall/update from Windows at any time, not just
during initial setup.

Environment variables:
  WIN_ISO       Path to Windows installer ISO (default: ${WIN_ISO_DEFAULT})
  RAM           VM memory (default: ${RAM})
  CPUS          VM CPU count (default: ${CPUS})
  TRACE_EVENTS  Trace events pattern file passed to '-trace events=' (default:
                ${TRACE_EVENTS_DEFAULT}, if present)
  NO_TRACE      Set to disable tracing even if a default events file exists

  BOOT_DELAY_ERR0/1/2/3  Latency injection rule(s) armed at VM startup for
                that disk (err0=boot, err1=blk data, err2/err3=scsi data),
                so they are in effect for the guest's very first I/O,
                including during OS boot. One or more rules separated by
                ';', each a comma-separated list of
                InjectDelayRuleOptions fields (id, ops, sector, count,
                probability, delay-ms, delay-max-ms, stall, errno,
                max-hits); 'ops' may combine values with '+'. Examples:
                  Constant latency on every read:
                    BOOT_DELAY_ERR0="id=bootread,ops=read,delay-ms=200"
                  Tail latency (1% of requests delayed 20-2000ms):
                    BOOT_DELAY_ERR0="id=tail,probability=0.01,delay-ms=20,delay-max-ms=2000"
                  Indefinite stall on the first write:
                    BOOT_DELAY_ERR1="id=stall1,ops=write,stall=true,max-hits=1"
  BOOT_DELAY_SEED  Seed for the inject-error PRNG used by 'probability'
                and 'delay-max-ms', shared by all BOOT_DELAY_ERR* rules on
                a given disk. Fix it to make a run reproducible.

QMP socket: ${QMP_SOCK}
QGA socket: ${QGA_SOCK} (virtio-serial channel for qemu-guest-agent;
            install the vioserial driver + qemu-ga in the guest from the
            virtio-win drivers CD for this to answer 'guest-ping')
Trace log:  ${TRACE_LOG} (plain text; tracing is on by default whenever
            ${TRACE_EVENTS_DEFAULT} exists)

Block nodes for injection:
  err0   boot disk       (virtio-blk, disk0)  -- the running system's disk
  err1   blk data disk   (virtio-blk, diskblk1)
  err2   scsi data disk1 (virtio-scsi, disk1)
  err3   scsi data disk2 (virtio-scsi, disk2)

  Note: err0 is the running system's disk.  Injecting there can bugcheck
        the guest, and a stall on it will hold up VM shutdown until
        released.  Prefer err1/err2/err3 for sustained fault injection;
        use err0 only for boot-disk-specific viostor scenarios.

After booting, inject errors/responses via QMP, e.g.:
  $QEMU_BUILD/run qmp-shell ${QMP_SOCK}

Windows setup notes:
  - At "Where do you want to install Windows?", click "Load driver" and
    browse the virtio-win CD (E:) to load viostor (virtio-blk) so the
    boot disk is visible, and NetKVM for networking.
  - vioscsi (virtio-scsi) driver only needs installing after first boot,
    once Windows enumerates the two SCSI data disks (Device Manager will
    show them as unknown storage controllers until then).
  - Windows 11 requires Secure Boot + TPM 2.0; both are already wired up
    (OVMF secure-boot template with default keys enrolled, and swtpm).
EOF
    exit 1
}

cmd_create() {
    if [ -d "${VM_DIR}" ]; then
        echo "VM directory already exists: ${VM_DIR}"
        echo "Checking for missing disks/firmware..."
    else
        echo "Creating VM directory: ${VM_DIR}"
        mkdir -p "${VM_DIR}"
    fi

    mkdir -p "${TPM_DIR}"

    for disk_info in \
        "${BOOT_DISK}:${BOOT_SIZE}:boot disk" \
        "${BLK_DATA_DISK}:${BLK_DATA_SIZE}:virtio-blk data disk" \
        "${SCSI_DISK1}:${SCSI_DISK_SIZE}:virtio-scsi disk 1" \
        "${SCSI_DISK2}:${SCSI_DISK_SIZE}:virtio-scsi disk 2"; do

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

    if [ -f "${OVMF_VARS}" ]; then
        echo "  UEFI NVRAM: already exists"
    else
        echo "  UEFI NVRAM: copying secure-boot template"
        cp "${OVMF_VARS_TEMPLATE}" "${OVMF_VARS}"
    fi

    if [ ! -f "${VIRTIO_ISO}" ]; then
        echo ""
        echo "Warning: virtio-win driver ISO not found at ${VIRTIO_ISO}"
        echo "  Download it from:"
        echo "  https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
    fi

    echo ""
    echo "Done. Next steps:"
    echo "  Install: WIN_ISO=/path/to/Win11.iso $0 install"
    echo "  Run:     $0 run"
}

run_vm() {
    local extra_args=("$@")

    if [ ! -x "${QEMU}" ]; then
        echo "Error: QEMU binary not found at ${QEMU}"
        echo "Run 'ninja -C ${QEMU_BUILD}' first, or use '$0 build-run'"
        exit 1
    fi

    for disk in "${BOOT_DISK}" "${BLK_DATA_DISK}" "${SCSI_DISK1}" "${SCSI_DISK2}" "${OVMF_VARS}"; do
        if [ ! -f "${disk}" ]; then
            echo "Error: file not found: ${disk}"
            echo "Run '$0 create' first"
            exit 1
        fi
    done

    # Clean up stale sockets
    rm -f "${QMP_SOCK}" "${QGA_SOCK}" "${TPM_SOCK}"

    echo "Starting swtpm..."
    swtpm socket \
        --tpmstate dir="${TPM_DIR}" \
        --ctrl type=unixio,path="${TPM_SOCK}" \
        --tpm2 --terminate &

    for _ in $(seq 1 50); do
        [ -S "${TPM_SOCK}" ] && break
        sleep 0.1
    done
    if [ ! -S "${TPM_SOCK}" ]; then
        echo "Error: swtpm did not create its control socket"
        exit 1
    fi

    local trace_args=()
    local events_file="${TRACE_EVENTS:-${TRACE_EVENTS_DEFAULT}}"
    if [ -n "${NO_TRACE:-}" ]; then
        events_file=""
    elif [ ! -f "${events_file}" ]; then
        echo "Warning: trace events file not found: ${events_file} (tracing disabled)"
        events_file=""
    fi
    if [ -n "${events_file}" ]; then
        trace_args=(-trace "events=${events_file},file=${TRACE_LOG}")
    fi

    local delay0 delay1 delay2 delay3
    delay0="$(parse_delay_rules "${BOOT_DELAY_ERR0:-}")"
    delay1="$(parse_delay_rules "${BOOT_DELAY_ERR1:-}")"
    delay2="$(parse_delay_rules "${BOOT_DELAY_ERR2:-}")"
    delay3="$(parse_delay_rules "${BOOT_DELAY_ERR3:-}")"
    if [ -n "${BOOT_DELAY_SEED:-}" ]; then
        [ -n "${delay0}" ] && delay0=",seed=${BOOT_DELAY_SEED}${delay0}"
        [ -n "${delay1}" ] && delay1=",seed=${BOOT_DELAY_SEED}${delay1}"
        [ -n "${delay2}" ] && delay2=",seed=${BOOT_DELAY_SEED}${delay2}"
        [ -n "${delay3}" ] && delay3=",seed=${BOOT_DELAY_SEED}${delay3}"
    fi

    local drivers_cd_args=()
    if [ -f "${VIRTIO_ISO}" ]; then
        drivers_cd_args=(
            -device ahci,id=ahci0
            -drive "id=cdrom_drivers,if=none,format=raw,media=cdrom,file=${VIRTIO_ISO},readonly=on"
            -device ide-cd,bus=ahci0.0,drive=cdrom_drivers
        )
    else
        echo "Warning: virtio-win driver ISO not found at ${VIRTIO_ISO} (drivers CD not attached)"
    fi

    echo "Starting VM..."
    echo "  QMP socket: ${QMP_SOCK}"
    echo "  QGA socket: ${QGA_SOCK} (guest-agent virtio-serial channel)"
    echo "  Boot disk:  ${BOOT_DISK} (virtio-blk, inject-error filter, err0)"
    echo "  Data disks: err1 (virtio-blk), err2/err3 (virtio-scsi)"
    if [ ${#drivers_cd_args[@]} -gt 0 ]; then
        echo "  Drivers CD: ${VIRTIO_ISO} (ahci0.0)"
    fi
    for pair in "err0:${delay0}" "err1:${delay1}" "err2:${delay2}" "err3:${delay3}"; do
        node="${pair%%:*}"
        rule="${pair#*:}"
        [ -n "${rule}" ] && echo "  Boot-time latency armed on ${node}: ${rule#,}"
    done
    if [ -n "${events_file}" ]; then
        echo "  Trace log:  ${TRACE_LOG} (events: ${events_file})"
    fi
    echo ""

    "${QEMU}" \
        -machine q35,accel=kvm,smm=on \
        -global driver=cfi.pflash01,property=secure,value=on \
        -cpu host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,hv-synic,hv-stimer,hv-time,hv-ipi,hv-tlbflush \
        -smp "${CPUS}" \
        -m "${RAM}" \
        \
        -drive if=pflash,format=qcow2,unit=0,file="${OVMF_CODE}",readonly=on \
        -drive if=pflash,format=qcow2,unit=1,file="${OVMF_VARS}" \
        \
        -chardev socket,id=chrtpm,path="${TPM_SOCK}" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-crb,tpmdev=tpm0 \
        \
        -display gtk \
        -vga std \
        -device qemu-xhci,id=usb \
        -device usb-tablet,bus=usb.0 \
        \
        -qmp "unix:${QMP_SOCK},server=on,wait=off" \
        -monitor stdio \
        \
        -chardev "socket,path=${QGA_SOCK},server=on,wait=off,id=qga0" \
        -device virtio-serial \
        -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
        \
        -net nic,model=virtio-net-pci \
        -net passt,tcp-ports=3389:3389 \
        \
        -blockdev driver=file,filename="${BOOT_DISK}",node-name=file0 \
        -blockdev driver=qcow2,file=file0,node-name=raw0 \
        -blockdev driver=inject-error,image=raw0,node-name=err0"${delay0}" \
        -device virtio-blk-pci,drive=err0,bootindex=0,id=disk0 \
        \
        -blockdev driver=file,filename="${BLK_DATA_DISK}",node-name=file1 \
        -blockdev driver=qcow2,file=file1,node-name=raw1 \
        -blockdev driver=inject-error,image=raw1,node-name=err1"${delay1}" \
        -device virtio-blk-pci,drive=err1,id=diskblk1 \
        \
        -device virtio-scsi-pci,id=scsi0 \
        \
        -blockdev driver=file,filename="${SCSI_DISK1}",node-name=file2 \
        -blockdev driver=qcow2,file=file2,node-name=raw2 \
        -blockdev driver=inject-error,image=raw2,node-name=err2"${delay2}" \
        -device scsi-hd,drive=err2,bus=scsi0.0,id=disk1,serial=SCSI_DISK1_SERIAL \
        \
        -blockdev driver=file,filename="${SCSI_DISK2}",node-name=file3 \
        -blockdev driver=qcow2,file=file3,node-name=raw3 \
        -blockdev driver=inject-error,image=raw3,node-name=err3"${delay3}" \
        -device scsi-hd,drive=err3,bus=scsi0.0,id=disk2,serial=SCSI_DISK2_SERIAL \
        \
        "${drivers_cd_args[@]}" \
        "${trace_args[@]}" \
        "${extra_args[@]}"
}

cmd_install() {
    local win_iso="${WIN_ISO:-${WIN_ISO_DEFAULT}}"

    if [ ! -f "${win_iso}" ]; then
        echo "Error: Windows ISO not found: ${win_iso}"
        echo "Usage: WIN_ISO=/path/to/Win11.iso $0 install"
        exit 1
    fi

    if [ ! -f "${VIRTIO_ISO}" ]; then
        echo "Error: virtio-win driver ISO not found: ${VIRTIO_ISO}"
        echo "Download it to that path first (see '$0 create' output)."
        exit 1
    fi

    echo "Installing from: ${win_iso}"
    echo "Drivers CD:       ${VIRTIO_ISO}"
    echo "Install Windows to the boot disk (virtio-blk, 'Load driver' -> viostor)."
    echo ""

    # The drivers CD (ahci0.0) is attached by run_vm itself; the Windows
    # installer ISO just needs another port on that same controller.
    run_vm \
        -drive id=cdrom_win,if=none,format=raw,media=cdrom,file="${win_iso}",readonly=on \
        -device ide-cd,bus=ahci0.1,drive=cdrom_win,bootindex=1
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
        "${BLK_DATA_DISK}:virtio-blk data disk (diskblk1/err1)" \
        "${SCSI_DISK1}:virtio-scsi disk 1 (disk1/err2)" \
        "${SCSI_DISK2}:virtio-scsi disk 2 (disk2/err3)"; do

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
    echo "  UEFI NVRAM:      $([ -f "${OVMF_VARS}" ] && echo "present" || echo "not created")"
    echo "  virtio-win ISO:  $([ -f "${VIRTIO_ISO}" ] && echo "present ($(du -h "${VIRTIO_ISO}" | cut -f1))" || echo "missing")"

    echo ""
    if [ -S "${QMP_SOCK}" ]; then
        echo "  QMP socket: active"
    else
        echo "  QMP socket: not running"
    fi
    if [ -S "${QGA_SOCK}" ]; then
        echo "  QGA socket: active"
    else
        echo "  QGA socket: not running"
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
