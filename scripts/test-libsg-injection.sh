#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test libstoragemgmt libsg.c SCSI response parsing via QEMU error injection.
#
# Runs from the host.  Injects crafted VPD and MODE SENSE responses into the
# running QEMU VM, then verifies lsmcli on the guest returns the right error
# codes and does not crash or misinterpret the data.
#
# Prerequisites:
#   - VM booted via setup-error-inject-vm.sh with SCSI disks disk1/disk2/disk3
#   - libstoragemgmt built and installed on the guest
#   - SSH access: ssh -p 2222 root@localhost

set -euo pipefail

QEMU_SRC="${QEMU_SRC:-/home/tasleson/projects/qemu}"
QMP="${QMP:-/home/tasleson/VirtualMachines/qemu/error_inject/qmp.sock}"
SSH="ssh -p 2222 -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost"
INJECT="${QEMU_SRC}/build/run ${QEMU_SRC}/scripts/scsi-inject.py -s ${QMP}"

PASS=0
FAIL=0
SKIP=0

# --- helpers ---

pass() {
    PASS=$((PASS + 1))
    printf "  PASS: %s\n" "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    printf "  FAIL: %s -- %s\n" "$1" "$2"
}

skip() {
    SKIP=$((SKIP + 1))
    printf "  SKIP: %s -- %s\n" "$1" "$2"
}

inject_vpd() {
    local device="$1" page="$2" hex="$3"
    $INJECT vpd-raw "$device" "$page" "$hex" >/dev/null
}

inject_mode() {
    local device="$1" page="$2" hex="$3"
    $INJECT mode-sense-raw "$device" "$page" "$hex" >/dev/null
}

clear_all() {
    for d in disk1 disk2 disk3; do
        $INJECT clear "$d" >/dev/null 2>&1 || true
    done
    $SSH "for d in sdc sdd sde; do echo 1 > /sys/block/\$d/device/rescan 2>/dev/null; done" 2>/dev/null || true
}

rescan() {
    local sd="$1"
    $SSH "echo 1 > /sys/block/${sd}/device/rescan" 2>/dev/null
}

# Run lsmcli on the guest and capture stdout and stderr separately.
# Sets LDL_OUT and LDL_ERR.
run_lsmcli() {
    LDL_ERR=$($SSH "lsmcli local-disk-list 2>&1 1>/tmp/lsm_out; cat /tmp/lsm_out >&2" 2>/tmp/lsm_host_out) || true
    LDL_OUT=$(cat /tmp/lsm_host_out)
    rm -f /tmp/lsm_host_out
}

# Check that stderr contains a WARN for the given function and disk with the
# given error code.
expect_warn() {
    local test_name="$1" func="$2" disk="$3" code="$4"
    local pattern="WARN: ${func}('${disk}'): ${code} "
    if echo "$LDL_ERR" | grep -qF "$pattern"; then
        pass "$test_name"
    else
        fail "$test_name" "expected WARN matching '$pattern' in stderr"
        echo "    stderr was: $LDL_ERR" | head -5
    fi
}

# Check that stderr does NOT contain a WARN for the given disk.
expect_no_warn_for_disk() {
    local test_name="$1" disk="$2"
    if echo "$LDL_ERR" | grep -qF "'${disk}'"; then
        fail "$test_name" "unexpected WARN for $disk in stderr"
        echo "    stderr was: $(echo "$LDL_ERR" | grep "$disk")"
    else
        pass "$test_name"
    fi
}

# Check that stdout contains a specific value in the line for a disk.
expect_output_contains() {
    local test_name="$1" disk="$2" value="$3"
    if echo "$LDL_OUT" | grep -F "$disk" | grep -qF "$value"; then
        pass "$test_name"
    else
        fail "$test_name" "expected '$value' in output for $disk"
        echo "    output line: $(echo "$LDL_OUT" | grep -F "$disk")"
    fi
}

# Check that stdout does NOT contain a specific value for a disk.
expect_output_not_contains() {
    local test_name="$1" disk="$2" value="$3"
    if echo "$LDL_OUT" | grep -F "$disk" | grep -qF "$value"; then
        fail "$test_name" "did not expect '$value' in output for $disk"
        echo "    output line: $(echo "$LDL_OUT" | grep -F "$disk")"
    else
        pass "$test_name"
    fi
}

# Build a hex string of N zero bytes.
zeros() {
    printf '%0*x' $(($1 * 2)) 0
}

# VPD 0x83 page with both a LUN designator (for vpd83_get) and a SAS target
# port designator (for link_type_get to identify the disk as SAS).
#
# Descriptor 1 (LUN, NAA): 01 03 00 08 <8 bytes NAA id>
# Descriptor 2 (target port, SAS, piv=1, NAA): 61 93 00 08 <8 bytes SAS addr>
# Total descriptors = 24 bytes -> page_len = 0x0018
SAS_VPD83="00830018010300085000c5000badf00d619300085000c5000badf00d"

# VPD 0x00 page listing pages 0x00 and 0x83 (but not 0x89, so not ATA).
VPD00_NO_ATA="000000020083"

# Set up disk1 as a SAS disk for tests that need health_status_get to reach
# the MODE SENSE path.  Injects VPD 0x00 (no ATA) + VPD 0x83 (SAS target port).
setup_sas_identity() {
    local device="${1:-disk1}"
    inject_vpd "$device" 0x00 "$VPD00_NO_ATA"
    inject_vpd "$device" 0x83 "$SAS_VPD83"
}

# --- Phase 0: Unit tests ---

phase0_unit_tests() {
    echo "=== Phase 0: Unit Tests ==="
    local result
    result=$($SSH "/libstoragemgmt/test/libsg_test 2>&1") || true
    if echo "$result" | grep -q "100%.*Failures: 0.*Errors: 0"; then
        local count
        count=$(echo "$result" | grep -oP 'Checks: \K[0-9]+')
        pass "libsg_test (${count} checks)"
    else
        fail "libsg_test" "$result"
    fi
}

# --- Phase 1: VPD 0x83 (Device Identification) ---

phase1_vpd83() {
    echo ""
    echo "=== Phase 1: VPD 0x83 (Device Identification) ==="

    # Test 1.1: Valid single NAA-5 designator
    clear_all
    inject_vpd disk1 0x83 "0083000c610300085000c5000badf00d"
    rescan sdc
    run_lsmcli
    expect_no_warn_for_disk "1.1 valid NAA designator (no warn)" "/dev/sdc"

    # Test 1.2: page_len > transfer size
    clear_all
    inject_vpd disk1 0x83 "00831000610300085000c5000badf00d"
    rescan sdc
    run_lsmcli
    expect_warn "1.2 page_len > transfer" "vpd83_get" "/dev/sdc" "3"

    # Test 1.3: Empty page (page_len=0)
    clear_all
    inject_vpd disk1 0x83 "00830000"
    rescan sdc
    run_lsmcli
    expect_no_warn_for_disk "1.3 empty page (absorbed)" "/dev/sdc"

    # Test 1.4: Truncated descriptor (desig_len=8, only 2 data bytes)
    clear_all
    inject_vpd disk1 0x83 "0083000661030008dead"
    rescan sdc
    run_lsmcli
    expect_warn "1.4 truncated descriptor" "vpd83_get" "/dev/sdc" "3"

    # Test 1.5: Wrong page code (0x00 instead of 0x83)
    clear_all
    inject_vpd disk1 0x83 "00000008610300085000c5000badf00d"
    rescan sdc
    run_lsmcli
    expect_no_warn_for_disk "1.5 wrong page code (absorbed)" "/dev/sdc"
}

# --- Phase 2: VPD 0x80 (Unit Serial Number) ---

phase2_vpd80() {
    echo ""
    echo "=== Phase 2: VPD 0x80 (Unit Serial Number) ==="

    # Test 2.1: Valid serial "TEST1234"
    clear_all
    inject_vpd disk1 0x80 "008000085445535431323334"
    rescan sdc
    run_lsmcli
    expect_no_warn_for_disk "2.1 valid serial (no warn)" "/dev/sdc"
    expect_output_contains "2.1 valid serial (output)" "/dev/sdc" "TEST1234"

    # Test 2.2: page_len > transfer (0x1000)
    clear_all
    inject_vpd disk1 0x80 "008010005445535431323334"
    rescan sdc
    run_lsmcli
    expect_warn "2.2 page_len > transfer" "serial_num_get" "/dev/sdc" "3"

    # Test 2.3: Wrong page code (0x83 instead of 0x80)
    clear_all
    inject_vpd disk1 0x80 "008300085445535431323334"
    rescan sdc
    run_lsmcli
    expect_no_warn_for_disk "2.3 wrong page code (absorbed)" "/dev/sdc"

    # Test 2.4: Only 3 bytes (too short for header)
    clear_all
    inject_vpd disk1 0x80 "008000"
    rescan sdc
    run_lsmcli
    expect_no_warn_for_disk "2.4 short header (absorbed)" "/dev/sdc"
}

# --- Phase 3: VPD 0x00 (Supported VPD Pages) ---

phase3_vpd00() {
    echo ""
    echo "=== Phase 3: VPD 0x00 (Supported VPD Pages) ==="

    # Test 3.1: Lists page 0x89 -> link_type should be ATA
    clear_all
    inject_vpd disk1 0x00 "00000003008089"
    run_lsmcli
    expect_output_contains "3.1 page 0x89 listed -> ATA" "/dev/sdc" "ATA"

    # Test 3.2: page_len=0xFFFF but 0x89 planted past 252-byte boundary
    # The device only returns alloc_len=252 bytes, so 0x89 at offset 300
    # should be invisible to _sg_is_vpd_page_supported().
    clear_all
    local hex_3_2="0000ffff008083"
    # Offsets 7..299 = 293 zero bytes, then 0x89 at offset 300
    hex_3_2+="$(zeros 293)89"
    inject_vpd disk1 0x00 "$hex_3_2"
    run_lsmcli
    expect_output_not_contains "3.2 page 0x89 past boundary -> not ATA" "/dev/sdc" "ATA"

    # Test 3.3: Only pages 0x00 and 0x83 (no 0x89)
    clear_all
    inject_vpd disk1 0x00 "000000020083"
    run_lsmcli
    expect_output_not_contains "3.3 no page 0x89 -> not ATA" "/dev/sdc" "ATA"
}

# --- Phase 4: VPD 0xb1 (Block Device Characteristics) ---

phase4_vpd_b1() {
    echo ""
    echo "=== Phase 4: VPD 0xb1 (Block Device Characteristics) ==="

    # Test 4.1: SSD (medium_rotation_rate = 0x0001)
    # page_len=0x003c (60), total 64 bytes
    clear_all
    inject_vpd disk1 0xb1 "00b1003c0001$(zeros 58)"
    local rpm
    # medium_rotation_rate=1 (SSD) is mapped to LSM_DISK_RPM_NON_ROTATING_MEDIUM=0
    rpm=$($SSH "timeout 15 python3 -c 'from lsm import LocalDisk; print(LocalDisk.rpm_get(\"/dev/sdc\"))'") || true
    if [ "$rpm" = "0" ]; then
        pass "4.1 SSD rotation (rpm=0, non-rotating)"
    else
        fail "4.1 SSD rotation" "expected rpm=0 (non-rotating), got '$rpm'"
    fi

    # Test 4.2: 7200 RPM (0x1c20)
    clear_all
    inject_vpd disk1 0xb1 "00b1003c1c20$(zeros 58)"
    rpm=$($SSH "timeout 15 python3 -c 'from lsm import LocalDisk; print(LocalDisk.rpm_get(\"/dev/sdc\"))'") || true
    if [ "$rpm" = "7200" ]; then
        pass "4.2 7200 RPM"
    else
        fail "4.2 7200 RPM" "expected rpm=7200, got '$rpm'"
    fi
}

# --- Phase 5: MODE SENSE 0x1c (Informational Exceptions) ---

phase5_mode_sense() {
    echo ""
    echo "=== Phase 5: MODE SENSE 0x1c (Informational Exceptions Control) ==="

    # health_status_get calls link_type_get first, and only proceeds to
    # MODE SENSE 0x1c if the disk is identified as SAS.  We inject VPD 0x00
    # (no ATA) and VPD 0x83 (SAS target port) alongside each MODE SENSE
    # override so the health path reaches the mode page parsing.

    # Test 5.1: Valid MODE SENSE, MRIE=6
    # mode_data_len=0x0012 (18), no block descriptors, page 0x1c, MRIE=6
    clear_all
    setup_sas_identity disk1
    inject_mode disk1 0x1c "00120000000000001c0a00060000000000000000"
    run_lsmcli
    # MODE SENSE validation must not fire.  The health path may still fail
    # later at REQUEST SENSE, but that is not a DEVICE_BUG from MODE SENSE.
    if echo "$LDL_ERR" | grep -F "/dev/sdc" | grep -qiE "MODE DATA LENGTH|BLOCK DESCRIPTOR"; then
        fail "5.1 valid MODE SENSE" "unexpected MODE SENSE validation error"
    else
        pass "5.1 valid MODE SENSE"
    fi

    # Test 5.2: mode_data_len = 0
    clear_all
    setup_sas_identity disk1
    inject_mode disk1 0x1c "00000000000000001c0a00060000000000000000"
    run_lsmcli
    expect_warn "5.2 mode_data_len=0" "health_status_get" "/dev/sdc" "3"

    # Test 5.3: mode_data_len = 0xFFFE (too large)
    clear_all
    setup_sas_identity disk1
    inject_mode disk1 0x1c "fffe0000000000001c0a00060000000000000000"
    run_lsmcli
    expect_warn "5.3 mode_data_len too large" "health_status_get" "/dev/sdc" "3"

    # Test 5.4: block_desc_len = 0xFFF0 (way too large)
    clear_all
    setup_sas_identity disk1
    inject_mode disk1 0x1c "001200000000fff01c0a00060000000000000000"
    run_lsmcli
    expect_warn "5.4 block_desc_len too large" "health_status_get" "/dev/sdc" "3"

    # Test 5.5: mode_data_len too small for block_desc_len
    # mode_data_len=8, block_desc_len=4 -> need mode_data_len >= 6+4=10
    clear_all
    setup_sas_identity disk1
    inject_mode disk1 0x1c "00080000000000041c0a00060000000000000000"
    run_lsmcli
    expect_warn "5.5 mode_data_len < block_desc" "health_status_get" "/dev/sdc" "3"
}

# --- Phase 6: Multi-Disk Isolation ---

phase6_multi_disk() {
    echo ""
    echo "=== Phase 6: Multi-Disk Isolation ==="

    # Test 6.1: Different valid VPD 0x83 on each disk
    clear_all
    inject_vpd disk1 0x83 "0083000c610300085000c5000badf001"
    inject_vpd disk2 0x83 "0083000c610300085000c5000badf002"
    inject_vpd disk3 0x83 "0083000c610300085000c5000badf003"
    $SSH "for d in sdc sdd sde; do echo 1 > /sys/block/\$d/device/rescan; done"
    run_lsmcli
    expect_no_warn_for_disk "6.1a disk1 no warn" "/dev/sdc"
    expect_no_warn_for_disk "6.1b disk2 no warn" "/dev/sdd"
    expect_no_warn_for_disk "6.1c disk3 no warn" "/dev/sde"

    # Test 6.2: Malformed on disk1, valid on disk2/disk3
    clear_all
    inject_vpd disk1 0x83 "00831000deadbeef"
    inject_vpd disk2 0x83 "0083000c610300085000c5000badf002"
    inject_vpd disk3 0x83 "0083000c610300085000c5000badf003"
    $SSH "for d in sdc sdd sde; do echo 1 > /sys/block/\$d/device/rescan; done"
    run_lsmcli
    expect_warn "6.2a disk1 malformed" "vpd83_get" "/dev/sdc" "3"
    expect_no_warn_for_disk "6.2b disk2 valid" "/dev/sdd"
    expect_no_warn_for_disk "6.2c disk3 valid" "/dev/sde"
}

# --- Main ---

echo "libsg.c SCSI response injection tests"
echo "======================================"
echo ""

# Check connectivity
if ! $SSH "true" 2>/dev/null; then
    echo "ERROR: cannot connect to guest via SSH"
    exit 1
fi

# Check QMP socket
if [ ! -S "$QMP" ]; then
    echo "ERROR: QMP socket not found at $QMP"
    exit 1
fi

phase0_unit_tests
phase1_vpd83
phase2_vpd80
phase3_vpd00
phase4_vpd_b1
phase5_mode_sense
phase6_multi_disk

# Restore
clear_all

echo ""
echo "======================================"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "======================================"

exit $FAIL
