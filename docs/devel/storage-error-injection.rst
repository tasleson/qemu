Storage Error and Response Injection
=====================================

QEMU provides three complementary mechanisms for testing how guest software
handles storage errors and unusual hardware responses:

- **inject-error** block filter driver -- injects I/O errors (bad sectors)
  and latency (slow, stalled and timing-out requests) at the block layer
- **SCSI response injection** -- overrides INQUIRY and MODE SENSE responses
  at the SCSI emulation layer
- **NVMe response injection** -- overrides Identify Controller and Identify
  Namespace responses at the NVMe emulation layer

All are controlled at runtime via QMP and are intended for fuzzing and
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

Latency Injection
-----------------

Bad sectors cover the case where the disk answers quickly with an error.
Guest drivers are usually much weaker at the other case: a disk that
answers slowly, late, or not at all.  ``inject-error`` covers that with
*latency rules*, which hold a matching request for a while before passing
it on to the image or failing it.

A held request only yields its own coroutine.  The QEMU event loop and the
vCPU threads keep running, so the guest continues to execute, keeps
queueing I/O, and can time the request out or reset the device while it is
outstanding.  This is the difference between simulating a slow disk and
simulating a frozen VMM, and it is what makes the Windows VirtIO storage
driver take its recovery paths rather than simply stop.

Rules are matched in the order they were added and the first match wins.
A matching rule is applied before the bad sector entries, so a rule that
carries an ``errno`` short-circuits the request without the image ever
seeing it.

Rule options
^^^^^^^^^^^^

- ``id`` (string, required): name of the rule, used to remove it and
  reported on held requests
- ``ops`` (array, default all): any of ``read``, ``write``, ``flush``,
  ``discard``, ``write-zeroes``
- ``sector`` / ``count``: sector range the rule covers.  Without ``count``
  the rule covers the whole device; with it, flushes never match because a
  flush has no sector range.
- ``probability`` (0.0--1.0, default 1.0): fraction of matching requests to
  hold.  This is what tail latency is made of.
- ``delay-ms`` (default 0) and ``delay-max-ms``: how long to hold the
  request.  If ``delay-max-ms`` is larger, the hold time is drawn
  uniformly from the range, which makes held requests complete out of
  order with respect to later, undelayed ones.
- ``stall`` (default false): hold the request indefinitely instead.
- ``errno`` (default 0): fail the request with this error once the hold
  expires.  Zero means the request is passed on to the image and completes
  normally.
- ``max-hits``: drop the rule after it has held this many requests.

The upper bound on ``delay-ms`` is 24 hours; use ``stall`` for anything
longer.  Randomised hold times come from a per-node PRNG that can be
seeded at startup with the ``seed`` option, so a run can be reproduced.

Rules can be configured on the command line the same way bad sectors
are::

    -blockdev driver=inject-error,image=fmt0,node-name=err0,seed=1,\
             delays.0.id=bootflush,delays.0.ops.0=flush,\
             delays.0.delay-ms=30000

QMP commands
^^^^^^^^^^^^

**x-inject-error-delay-add** -- add a rule::

    { "execute": "x-inject-error-delay-add",
      "arguments": { "node-name": "err0",
                     "rule": { "id": "tail",
                               "probability": 0.001,
                               "delay-ms": 10000,
                               "delay-max-ms": 60000 } } }

**x-inject-error-delay-remove** -- remove the rule named ``id``, or every
rule if ``id`` is omitted.  Requests already held are unaffected.

**x-inject-error-delay-list** -- list the rules along with how many
requests each has held so far.

**x-inject-error-delay-inflight** -- list the requests currently being
held: request id, rule, operation, sector range, whether the request is
stalled or has a deadline, and the error it will fail with.

**x-inject-error-delay-release** -- release held requests.  Without
``request-id`` every held request is released.  ``disposition`` overrides
what the rule asked for: ``complete`` passes the request on to the image,
``error`` fails it with ``errno`` (default EIO)::

    { "execute": "x-inject-error-delay-release",
      "arguments": { "node-name": "err0", "disposition": "error" } }

Drain and device reset
^^^^^^^^^^^^^^^^^^^^^^

Draining a block node has to make progress, and a guest-initiated device
reset drains.  A stall therefore ends when the guest resets the device,
with each request keeping the disposition its rule asked for.  This is
both a practical necessity -- otherwise a reset would wedge QEMU rather
than the guest -- and a reasonable model of recovery: the point of the
test is what the driver does on the way there.

Nothing else releases a stall on its own, so a request left held will
hold up shutdown of whatever is using the node, in the same way a
suspended ``blkdebug`` request does.  Release the held requests, or drop
the rule and let the guest reset the device, before tearing a setup
down.

Failure modes worth testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^

``scripts/inject-error.py scenario`` sets up a rule for each of these; the
rule column shows what it configures.

=========================== ================================================
Scenario                    Rule
=========================== ================================================
Fixed latency               ``delay-ms``
Tail latency                small ``probability`` with a wide delay range
Complete stall              ``stall``, ended with a release or a reset
Timeout then success        ``delay-ms`` past the guest's own timeout
Timeout then failure        the same, plus ``errno``
Backend disconnect          ``stall`` everything, then release the
                            outstanding requests with ``--error`` while new
                            ones keep stalling; remove the rule to reconnect
Flush latency               ``ops=flush``, which is what bites during boot
                            and filesystem recovery
Queue saturation            ``stall`` with ``max-hits``, so the queue fills
                            up behind the held requests
Out-of-order completion     ``delay-max-ms`` above ``delay-ms``
Reset race                  a hold that straddles the guest's timeout, so
                            the completion lands during recovery
=========================== ================================================


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

- ``id`` (string, required): device ID of the scsi-hd, scsi-cd,
  usb-storage, or ufs-lu device (USB mass storage and UFS logical unit
  devices are resolved to their internal SCSI disk automatically)
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

- The maximum injected response size is 65536 bytes.  For VPD page 0x80
  (serial number), this means a maximum serial string of 65532 bytes
  (65536 minus the 4-byte VPD header).

- Overrides apply to ``scsi-hd`` and ``scsi-cd`` devices (emulated
  SCSI), including the internal SCSI disk inside ``usb-storage`` and
  ``ufs-lu`` devices.  When targeting a ``usb-storage`` or ``ufs-lu``
  device, pass its device ID and the injection commands will
  automatically resolve to the internal SCSI disk.  Overrides have no
  effect on ``scsi-block`` (passthrough) devices, which route INQUIRY
  and MODE SENSE directly to the host via SG_IO.

- Overrides are not migrated.  After live migration, the fuzzer harness
  must re-inject any desired overrides.

- Overrides persist across guest reboots (they are not cleared on device
  reset).  Use the clear command to remove them.

- The Linux kernel caches INQUIRY responses.  After injecting a new
  override, rescan the device in the guest to pick up the change::

      echo 1 > /sys/block/sda/device/rescan

  The rescan updates both direct queries (``sg_inq``) and the kernel's
  sysfs VPD cache (``/sys/block/sda/device/vpd_pg80``), which is what
  tools like ``lsmcli local-disk-list`` read.

  Note: ``sg_inq`` queries the device directly via SG_IO and will
  reflect overrides immediately without a rescan.  A rescan is only
  needed to update the kernel's cached copy in sysfs.


NVMe Response Injection
-----------------------

NVMe response injection operates at the NVMe admin command emulation layer.
It replaces the data returned by Identify Controller (CNS 01h) and Identify
Namespace (CNS 00h) commands with arbitrary bytes, and can also inject NVMe
status codes to simulate command failures.

This is useful for fuzzing software like ``nvme-cli``, ``udev`` rules, and
any other tool that queries NVMe device properties via Identify commands.

Supported override types
^^^^^^^^^^^^^^^^^^^^^^^^

``identify-ctrl``
    Replaces the Identify Controller response (4096 bytes).  Controls the
    vendor ID, serial number, model number, firmware revision, and all
    other controller-level fields that guest software reads.

``identify-ns``
    Replaces the Identify Namespace response (4096 bytes) for a specific
    namespace ID.  Controls the namespace size, capacity, LBA format,
    and other namespace-level properties.

QMP commands
^^^^^^^^^^^^

**x-nvme-inject-response-set** -- set a response override.

Arguments:

- ``id`` (string, required): device ID of the NVMe controller
- ``type`` (string, required): ``identify-ctrl`` or ``identify-ns``
- ``nsid`` (int, 1-based): namespace ID; required for ``identify-ns``,
  must not be present for ``identify-ctrl``
- ``data`` (string, optional): base64-encoded response bytes; replaces
  the entire response verbatim with no validation.  At least one of
  ``data`` or ``status`` must be specified.
- ``status`` (int, optional): NVMe status code to return in the
  completion queue entry.  At least one of ``data`` or ``status`` must
  be specified.  If only ``status`` is given, the command fails with
  this status and no data is transferred.

Example -- inject Identify Controller data::

    { "execute": "x-nvme-inject-response-set",
      "arguments": { "id": "nvme0",
                     "type": "identify-ctrl",
                     "data": "AQIDBA..." } }

Example -- inject an NVMe error status for Identify Namespace::

    { "execute": "x-nvme-inject-response-set",
      "arguments": { "id": "nvme0",
                     "type": "identify-ns",
                     "nsid": 1,
                     "status": 6 } }

The status value ``6`` corresponds to ``NVME_INTERNAL_DEV_ERROR``.

**x-nvme-inject-response-clear** -- clear response overrides.

Arguments:

- ``id`` (string, required): device ID of the NVMe controller
- ``type`` (string, optional): which override type to clear; omit to
  clear all overrides on the controller
- ``nsid`` (int, optional): namespace ID to clear; required when
  ``type`` is ``identify-ns``

Example -- clear all overrides::

    { "execute": "x-nvme-inject-response-clear",
      "arguments": { "id": "nvme0" } }

Example -- clear just Identify Namespace for NSID 1::

    { "execute": "x-nvme-inject-response-clear",
      "arguments": { "id": "nvme0",
                     "type": "identify-ns",
                     "nsid": 1 } }

Notes
^^^^^

- Override data replaces the **entire** 4096-byte identify response
  buffer.  The injected data is sent as-is with no validation.

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

``scenario <node> <scenario> <id> [options]``
    Add a latency rule for one of the named failure modes.  ``--help``
    lists them; every field of the rule can still be overridden::

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            scenario err0 tail-latency slow

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            scenario err0 fixed-latency lag --delay-ms 200

``delay-add <node> <id> [options]``
    Add a latency rule from scratch::

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            delay-add err0 bootflush --ops flush --delay-ms 30000

``delay-list <node>`` / ``delay-remove <node> [id]``
    List the latency rules, or remove one of them (all of them if no id is
    given)::

        build/run scripts/inject-error.py -s /tmp/qmp.sock delay-list err0
        build/run scripts/inject-error.py -s /tmp/qmp.sock delay-remove err0

``inflight <node>``
    List the requests currently being held::

        build/run scripts/inject-error.py -s /tmp/qmp.sock inflight err0

``release <node> [--request-id N] [--complete|--error]``
    Release held requests, optionally overriding how they complete::

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            release err0 --error --errno EIO


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

- A 40G boot disk on virtio-blk behind an inject-error filter (install
  Fedora here)
- Three 10G SCSI disks on a virtio-scsi bus, each behind an
  inject-error filter
- A QMP Unix socket for runtime control
- GTK display, QEMU monitor on stdio

Device and node names:

====== ========= =========== ===========================================
Disk   Device ID Block Node  Description
====== ========= =========== ===========================================
boot   disk0     err0        virtio-blk system disk, inject-error filter
1      disk1     err1        SCSI disk with inject-error filter
2      disk2     err2        SCSI disk with inject-error filter
3      disk3     err3        SCSI disk with inject-error filter
====== ========= =========== ===========================================

Use ``disk1``/``disk2``/``disk3`` with ``x-scsi-disk-inject-response-set``
and ``scsi-inject.py``; SCSI response injection does not apply to the boot
disk, which is virtio-blk.  Use ``err0`` through ``err3`` with
``x-inject-error-add`` and the latency commands.

Injecting on the system disk
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``err0`` is the disk the guest is running from, which makes it the most
realistic target and the most awkward one.  Three things to plan for.

The guest usually cannot report what happened, because the log it would
write lives on the disk that is failing.  Arrange an observable that does
not touch storage -- a serial console, or the QEMU-side trace events --
before injecting anything there.

Failures on the system disk tend to end the experiment rather than
produce a result: an error on the paging path is a guest crash, and on
some guests the crash dump is written by a separate driver instance that
will hit the same injected failure.

The image can be left inconsistent, and a stall on ``err0`` holds up VM
shutdown until it is released.  Work from a copy, or from an overlay
created with ``qemu-img create -f qcow2 -b boot.qcow2 -F qcow2``, so each
run starts from a known state.

The data disks are the better instrument for everything that does not
specifically require the boot path: the guest stays alive and able to
report, and a run costs seconds rather than a reinstall.


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

8a. Hold a request and watch the guest recover
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

From the host, stall every request to the disk::

    build/run scripts/inject-error.py -s $QMP scenario err1 stall gone

In the guest, a read now hangs instead of failing::

    $ dd if=/dev/sda of=/dev/null bs=512 count=1

Back on the host, the held request is visible, and can be failed or
completed at will::

    build/run scripts/inject-error.py -s $QMP inflight err1
    build/run scripts/inject-error.py -s $QMP release err1 --error
    build/run scripts/inject-error.py -s $QMP delay-remove err1

Leaving it held long enough instead lets the guest's own timeout and
device reset run, which is the interesting part for driver testing.

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
