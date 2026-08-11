Storage Error and Response Injection
=====================================

QEMU provides two complementary mechanisms for testing how guest software
handles storage errors and unusual hardware responses:

- **inject-error** block filter driver -- injects I/O errors (bad sectors)
  at the block layer
- **SCSI response injection** -- overrides INQUIRY and MODE SENSE responses
  at the SCSI emulation layer

Both are controlled at runtime via QMP and are intended for fuzzing and
testing guest storage management software.

Block-Layer Error Injection (inject-error)
------------------------------------------

The ``inject-error`` filter driver sits between a SCSI (or other) device and
its backing image.  When an I/O request touches a configured sector range, the
filter returns an error instead of forwarding the request.  The device
emulator (SCSI, NVMe, AHCI) translates the block-layer error into the
appropriate protocol-specific error response automatically.

Command-line setup
^^^^^^^^^^^^^^^^^^

Each SCSI disk needs three ``-blockdev`` layers: the file backend, the format
driver (qcow2/raw), and the inject-error filter on top::

    # File backend
    -blockdev driver=file,filename=/path/to/disk.qcow2,node-name=file0

    # Format layer
    -blockdev driver=qcow2,file=file0,node-name=fmt0

    # Inject-error filter (topmost -- this is what the SCSI device sees)
    -blockdev driver=inject-error,image=fmt0,node-name=err0

    # SCSI device referencing the filter node
    -device scsi-hd,drive=err0,bus=scsi0.0,id=disk0

Errors can also be configured at startup::

    -blockdev driver=inject-error,image=fmt0,node-name=err0,\
             errors.0.sector=1024,errors.0.count=8,errors.0.behavior=persistent

QMP commands
^^^^^^^^^^^^

**x-inject-error-add** -- add a bad sector region at runtime.

Arguments:

- ``node-name`` (string, required): the inject-error node name
- ``sector`` (int, required): first bad sector (512-byte sectors)
- ``count`` (int, default 1): number of consecutive bad sectors
- ``errno`` (int, default 5/EIO): error number to return
- ``behavior`` (string, default "persistent"): one of ``persistent``,
  ``fix-on-write``, ``transient``
- ``reads`` (bool, default true): fail read operations
- ``writes`` (bool, default false): fail write operations

Example::

    { "execute": "x-inject-error-add",
      "arguments": { "node-name": "err0",
                     "sector": 1024,
                     "count": 8 } }

**x-inject-error-remove** -- remove all entries overlapping a sector range.

Arguments:

- ``node-name`` (string, required): the inject-error node name
- ``sector`` (int, required): first sector of the range to clear
- ``count`` (int, default 1): number of consecutive sectors

Example::

    { "execute": "x-inject-error-remove",
      "arguments": { "node-name": "err0",
                     "sector": 1024,
                     "count": 8 } }

**x-inject-error-list** -- list all active error entries on a node.

Arguments:

- ``node-name`` (string, required): the inject-error node name

Returns an array of objects, each with: ``sector``, ``count``, ``errno``,
``behavior``, ``reads``, ``writes``.

Example::

    { "execute": "x-inject-error-list",
      "arguments": { "node-name": "err0" } }

Error behaviors
^^^^^^^^^^^^^^^

``persistent``
    The error fires on every matching I/O request indefinitely.

``fix-on-write``
    Reads to the affected range fail, but a successful write removes the
    entry (simulating sector reallocation on real hardware).

``transient``
    The error fires once, then the entry is automatically removed.


SCSI Response Injection
-----------------------

While inject-error operates at the block I/O layer, SCSI response injection
operates at the SCSI command emulation layer.  It replaces the data returned
by INQUIRY (standard and VPD pages) and MODE SENSE commands with arbitrary
bytes, allowing you to test how guest software handles malformed, oversized,
truncated, or unexpected SCSI responses.

This is useful for fuzzing software like ``sg_inq``, ``lsscsi``,
``udev`` rules, ``multipathd``, ``libstoragemgmt``, and any other tool
that queries SCSI device properties.

Supported override types
^^^^^^^^^^^^^^^^^^^^^^^^

``inquiry-standard``
    Replaces the standard (non-VPD) INQUIRY response.  Controls the
    vendor, product, version, device type, and all other fields that
    guest software reads to identify a device.

``inquiry-vpd``
    Replaces a specific VPD (Vital Product Data) page.  Each VPD page
    is identified by a page code (0x00--0xFF).  Common pages:

    - 0x00 -- Supported VPD Pages
    - 0x80 -- Unit Serial Number
    - 0x83 -- Device Identification
    - 0xB0 -- Block Limits
    - 0xB1 -- Block Device Characteristics

``mode-sense-page``
    Replaces the entire MODE SENSE response for a specific page code.
    The override applies regardless of whether MODE SENSE(6) or MODE
    SENSE(10) was used.  For "all pages" (page 0x3F), register an
    override with page=0x3F.

QMP commands
^^^^^^^^^^^^

**x-scsi-disk-inject-response-set** -- set a response override.

Arguments:

- ``id`` (string, required): device ID of the scsi-hd or scsi-cd device
- ``type`` (string, required): ``inquiry-standard``, ``inquiry-vpd``, or
  ``mode-sense-page``
- ``page`` (int, 0--255): page code; required for ``inquiry-vpd`` and
  ``mode-sense-page``, must not be present for ``inquiry-standard``
- ``data`` (string, required): base64-encoded response bytes; replaces
  the entire response verbatim with no validation

Example -- inject a long serial number (VPD page 0x80)::

    { "execute": "x-scsi-disk-inject-response-set",
      "arguments": { "id": "disk0",
                     "type": "inquiry-vpd",
                     "page": 128,
                     "data": "AIA/VEVTVFNFU0VSSUFMMDEyMzQ1Njc4OQ==" } }

**x-scsi-disk-inject-response-clear** -- clear response overrides.

Arguments:

- ``id`` (string, required): device ID
- ``type`` (string, optional): which override type to clear; omit to
  clear all overrides on the device
- ``page`` (int, optional): specific page to clear; required when
  ``type`` is ``inquiry-vpd`` or ``mode-sense-page``

Example -- clear all overrides::

    { "execute": "x-scsi-disk-inject-response-clear",
      "arguments": { "id": "disk0" } }

Example -- clear just VPD page 0x80::

    { "execute": "x-scsi-disk-inject-response-clear",
      "arguments": { "id": "disk0",
                     "type": "inquiry-vpd",
                     "page": 128 } }

Notes
^^^^^

- Override data replaces the **entire** response including any headers.
  For VPD pages this means the 4-byte header (device type, page code,
  page length) is part of the injected data.  The ``scsi-inject.py``
  helper constructs these headers automatically.

- Overrides apply only to ``scsi-hd`` and ``scsi-cd`` devices (emulated
  SCSI).  They have no effect on ``scsi-block`` (passthrough) devices,
  which route INQUIRY and MODE SENSE directly to the host via SG_IO.

- Overrides are not migrated.  After live migration, the fuzzer harness
  must re-inject any desired overrides.

- Overrides persist across guest reboots (they are not cleared on device
  reset).  Use the clear command to remove them.


Command-Line Tools
------------------

scsi-inject.py
^^^^^^^^^^^^^^

A high-level CLI for SCSI response injection.  Handles binary SCSI response
construction and base64 encoding internally.  Run via the build venv::

    build/run scripts/scsi-inject.py [options] <command> [args]

Connection options (choose one)::

    -s /path/to/qmp.sock        # Unix socket (preferred)
    -H localhost -P 4445         # TCP

Commands:

``serial <device> <string>``
    Set VPD page 0x80 (unit serial number).  No length limit -- the
    normal 36-character QEMU cap is bypassed entirely::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            serial disk0 "VERY_LONG_SERIAL_0123456789ABCDEF0123456789"

``device-id <device> <string>``
    Set VPD page 0x83 (device identification)::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            device-id disk0 "MY_CUSTOM_DEVICE_ID_STRING"

``inquiry <device> [--vendor V] [--product P] [--version V] [--removable]``
    Set the standard INQUIRY response::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            inquiry disk0 --vendor "ACME" --product "FuzzyDisk 9000"

``vpd-raw <device> <page> <hex>``
    Set a raw VPD page from hex-encoded bytes (complete response
    including the 4-byte VPD header)::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            vpd-raw disk0 0x80 00800024564552594c4f4e47

``mode-sense-raw <device> <page> <hex>``
    Set a raw MODE SENSE response from hex-encoded bytes::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            mode-sense-raw disk0 0x08 0300000008120400000000000000000000000000

``clear <device> [--type TYPE] [--page PAGE]``
    Clear overrides.  With no flags, clears everything on the device::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock clear disk0

    Clear a specific override::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            clear disk0 --type inquiry-vpd --page 0x80


inject-error.py
^^^^^^^^^^^^^^^^

A CLI for block-layer I/O error injection.  Manages bad sector regions on
inject-error filter nodes.  Run via the build venv::

    build/run scripts/inject-error.py [options] <command> [args]

Connection options (same as scsi-inject.py)::

    -s /path/to/qmp.sock        # Unix socket (preferred)
    -H localhost -P 4445         # TCP

Commands:

``list <node>``
    List all active error entries on a node::

        build/run scripts/inject-error.py -s /tmp/qmp.sock list err0

``add <node> <sector> [options]``
    Add a bad sector region.  Accepts errno by name (EIO, ENOSPC, ENODATA)
    or number::

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            add err0 1024 --count 8

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            add err0 2048 --count 16 --errno ENOSPC --writes

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            add err0 0 --behavior fix-on-write --writes

``remove <node> <sector> [--count N]``
    Remove entries overlapping a sector range::

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            remove err0 1024 --count 8

``clear <node>``
    Remove all error entries from a node::

        build/run scripts/inject-error.py -s /tmp/qmp.sock clear err0


setup-error-inject-vm.sh
^^^^^^^^^^^^^^^^^^^^^^^^^

Creates and manages a test VM with a Fedora boot disk and three SCSI
disks behind inject-error filters::

    scripts/setup-error-inject-vm.sh create       # create disk images
    FEDORA_ISO=/path/to/Fedora.iso \
        scripts/setup-error-inject-vm.sh install   # install from ISO
    scripts/setup-error-inject-vm.sh run           # boot installed system
    scripts/setup-error-inject-vm.sh build-run     # rebuild QEMU then boot
    scripts/setup-error-inject-vm.sh status        # show disk/VM status

The VM is configured with:

- A 40G boot disk on virtio-blk (install Fedora here)
- Three 10G SCSI disks on a virtio-scsi bus, each behind an
  inject-error filter
- A QMP Unix socket for runtime control
- GTK display, QEMU monitor on stdio

Device and node names:

====== ========= =========== ==================
Disk   Device ID Block Node  Description
====== ========= =========== ==================
1      disk1     err1        SCSI disk with inject-error filter
2      disk2     err2        SCSI disk with inject-error filter
3      disk3     err3        SCSI disk with inject-error filter
====== ========= =========== ==================

Use ``disk1``/``disk2``/``disk3`` with ``x-scsi-disk-inject-response-set``
and ``scsi-inject.py``.  Use ``err1``/``err2``/``err3`` with
``x-inject-error-add``.


Walkthrough: End-to-End Example
-------------------------------

This walks through setting up a VM, injecting both I/O errors and SCSI
response overrides, and observing the results from inside the guest.

1. Create disk images and install Fedora
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    scripts/setup-error-inject-vm.sh create
    FEDORA_ISO=~/Downloads/Fedora-Server-dvd-x86_64-42-1.1.iso \
        scripts/setup-error-inject-vm.sh install

During installation, install Fedora to the virtio boot disk (it will
appear as ``/dev/vda``).  Leave the three SCSI disks (``/dev/sda``,
``/dev/sdb``, ``/dev/sdc``) alone.

2. Boot the installed system
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    scripts/setup-error-inject-vm.sh run

3. Verify the SCSI disks are visible (inside the guest)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    $ lsblk -S
    NAME HCTL       TYPE VENDOR   MODEL            REV TRAN
    sda  0:0:0:0    disk QEMU     QEMU HARDDISK    2.5  spi
    sdb  0:0:1:0    disk QEMU     QEMU HARDDISK    2.5  spi
    sdc  0:0:2:0    disk QEMU     QEMU HARDDISK    2.5  spi

    $ sg_inq --page=0x80 /dev/sda
    Unit serial number: DISK1_SERIAL

4. Inject a long serial number (from the host)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    QMP=~/VirtualMachines/qemu/error_inject/qmp.sock

    build/run scripts/scsi-inject.py -s $QMP \
        serial disk1 "FUZZING_SERIAL_0123456789ABCDEF0123456789ABCDEF"

5. Verify in the guest
^^^^^^^^^^^^^^^^^^^^^^

::

    $ sg_inq --page=0x80 /dev/sda
    Unit serial number: FUZZING_SERIAL_0123456789ABCDEF0123456789ABCDEF

The serial number now exceeds the normal 36-character QEMU limit.

6. Inject a bad sector
^^^^^^^^^^^^^^^^^^^^^^

From the host::

    build/run scripts/inject-error.py -s $QMP add err1 0 --count 16

7. Observe the error in the guest
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    $ dd if=/dev/sda of=/dev/null bs=512 count=1
    dd: error reading '/dev/sda': Input/output error

8. List and clear the bad sector
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    build/run scripts/inject-error.py -s $QMP list err1
    build/run scripts/inject-error.py -s $QMP clear err1

The read succeeds again::

    $ dd if=/dev/sda of=/dev/null bs=512 count=1
    1+0 records in
    1+0 records out

9. Override the standard INQUIRY response
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    build/run scripts/scsi-inject.py -s $QMP \
        inquiry disk1 --vendor "ACME" --product "FuzzyDisk 9000"

In the guest::

    $ sg_inq /dev/sda
    ...
      Vendor identification: ACME
      Product identification: FuzzyDisk 9000

10. Clear all overrides and restore normal behavior
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    build/run scripts/scsi-inject.py -s $QMP clear disk1
