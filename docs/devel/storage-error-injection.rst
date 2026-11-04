Storage Error and Response Injection
=====================================

This branch adds several complementary mechanisms for testing how guest
software handles storage errors, slow or unresponsive storage, and unusual
hardware responses:

- **inject-error** block filter driver -- injects I/O errors (bad sectors)
  and latency (slow, stalled and timing-out requests) at the block layer,
  under any emulated disk
- **SCSI response injection** -- overrides INQUIRY and MODE SENSE responses
  at the SCSI emulation layer
- **NVMe response injection** -- overrides Identify Controller and Identify
  Namespace responses at the NVMe emulation layer
- **ATA response injection** -- overrides IDENTIFY DEVICE and SMART data, or
  fails those commands, on IDE and SATA (AHCI) hard disks

They are controlled at runtime via QMP.  They are meant for fuzzing
and for testing guest drivers and storage management software, not
for production use: every command is marked ``unstable`` and carries
an ``x-`` prefix, and none of the injected state is migrated.

.. contents:: Contents
   :local:
   :depth: 2

Block-Layer Error Injection (inject-error)
------------------------------------------

The ``inject-error`` filter driver sits between a device and its backing
image.  When an I/O request touches a configured sector range, the filter
returns an error instead of forwarding the request.  The device emulator
(virtio-blk, SCSI, NVMe, AHCI and so on) translates the block-layer error
into the appropriate protocol-specific error response, subject to the
device's ``rerror``/``werror`` policy where it has one.

Sector numbers are always in 512-byte units, whatever the device's logical
block size.  A request fails if any part of it overlaps a bad region.
Reads are checked against the entries' ``reads`` flag; writes,
write-zeroes and discards are all checked against ``writes``.  Flushes are
never failed by a bad sector entry.

Command-line setup
^^^^^^^^^^^^^^^^^^

Each disk needs three ``-blockdev`` layers: the file backend, the format
driver (qcow2/raw), and the inject-error filter on top.  The example
attaches it to a SCSI adapter, but any disk device can use the filter
node as its ``drive``.  A QMP socket is needed for runtime control::

    # QMP socket for the runtime commands below
    -qmp unix:/path/to/qmp.sock,server=on,wait=off


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

- ``node-name`` (string, required): the inject-error node name.  Naming a
  node of another driver fails with "Node '...' is not an inject-error
  node".
- ``sector`` (int, required): first bad sector (512-byte sectors, must be
  non-negative)
- ``count`` (int, default 1): number of consecutive bad sectors (must be
  positive)
- ``errno`` (int, default 5/EIO): error number to return, a positive
  32-bit integer.  It is a host errno value; the device decides how to
  report it.
- ``behavior`` (string, default "persistent"): one of ``persistent``,
  ``fix-on-write``, ``transient``
- ``reads`` (bool, default true): fail read operations
- ``writes`` (bool, default false): fail write operations (including
  write-zeroes and discard)

Entries may overlap.  When several match a request, the most recently
added one that fails that kind of request decides the error returned.

Example::

    -> { "execute": "x-inject-error-add",
         "arguments": { "node-name": "err0",
                        "sector": 1024,
                        "count": 8 } }
    <- { "return": {} }

**x-inject-error-remove** -- remove all entries overlapping a sector range.

Arguments:

- ``node-name`` (string, required): the inject-error node name
- ``sector`` (int, required): first sector of the range to clear
- ``count`` (int, default 1): number of consecutive sectors

Example::

    -> { "execute": "x-inject-error-remove",
         "arguments": { "node-name": "err0",
                        "sector": 1024,
                        "count": 8 } }
    <- { "return": {} }

**x-inject-error-list** -- list all active error entries on a node.

Arguments:

- ``node-name`` (string, required): the inject-error node name

Returns an array of objects, each with: ``sector``, ``count``, ``errno``,
``behavior``, ``reads``, ``writes``.

Example::

    -> { "execute": "x-inject-error-list",
         "arguments": { "node-name": "err0" } }
    <- { "return": [ { "sector": 1024, "count": 8, "errno": 5,
                       "behavior": "persistent",
                       "reads": true, "writes": false } ] }

Error behaviors
^^^^^^^^^^^^^^^

``persistent``
    The error fires on every matching I/O request indefinitely.

``fix-on-write``
    Reads to the affected range fail.  Any write, write-zeroes or discard
    that overlaps the entry removes the whole entry and is passed on to
    the image, simulating sector reallocation on real hardware.  The
    entry is removed before the write reaches the image, so it is gone
    even if the write then fails for some other reason, and even if the
    write covered only part of it.  The ``writes`` flag has no effect on
    such an entry.

``transient``
    The error fires once, on the first request it fails, and the entry is
    then removed.

Neither bad sector entries nor latency rules are migrated.

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
seeing it.  A request held by a rule without an ``errno`` is checked
against the bad sector entries once it is let go.

Hold times run on the host's real-time clock, so they keep running while
the VM is paused: a held request can expire while the guest is stopped
and complete as soon as it resumes.

Rule options
^^^^^^^^^^^^

- ``id`` (string, required): name of the rule, used to remove it and
  reported on held requests.  Must be non-empty and unique on the node.
- ``ops`` (array, default all): any of ``read``, ``write``, ``flush``,
  ``discard``, ``write-zeroes``.  An empty list is an error.
- ``sector`` (default 0) / ``count``: sector range the rule covers.
  Without ``count`` the rule covers the whole device; with it, flushes
  never match because a flush has no sector range.
- ``probability`` (0.0--1.0, default 1.0): fraction of matching requests to
  hold.  This is what tail latency is made of.
- ``delay-ms`` (default 0) and ``delay-max-ms`` (default ``delay-ms``):
  how long to hold the request.  If ``delay-max-ms`` is larger, the hold
  time is drawn uniformly from [``delay-ms``, ``delay-max-ms``), which
  makes held requests complete out of order with respect to later,
  undelayed ones.  ``delay-max-ms`` less than ``delay-ms`` is an error.
- ``stall`` (default false): hold the request indefinitely instead.
- ``errno`` (default 0): fail the request with this error once the hold
  expires.  Zero means the request is passed on to the image and completes
  normally.
- ``max-hits`` (positive): drop the rule after it has held this many
  requests.  ``x-inject-error-delay-list`` reports how many are left.

The upper bound on ``delay-ms`` and ``delay-max-ms`` is 86400000 (24
hours); use ``stall`` for anything longer.  Randomised hold times and
``probability`` draw from a per-node PRNG that can be seeded at startup
with the ``seed`` option, so a run can be reproduced.  Without ``seed``
the PRNG is seeded randomly, and it cannot be reseeded at runtime.

Rules can be configured on the command line the same way bad sectors
are::

    -blockdev driver=inject-error,image=fmt0,node-name=err0,seed=1,\
             delays.0.id=bootflush,delays.0.ops.0=flush,\
             delays.0.delay-ms=30000

QMP commands
^^^^^^^^^^^^

**x-inject-error-delay-add** -- add a rule::

    -> { "execute": "x-inject-error-delay-add",
         "arguments": { "node-name": "err0",
                        "rule": { "id": "tail",
                                  "probability": 0.001,
                                  "delay-ms": 10000,
                                  "delay-max-ms": 60000 } } }
    <- { "return": {} }

Arguments are ``node-name`` and ``rule``, an object with the options
above.

**x-inject-error-delay-remove** -- remove the rule named ``id``, or every
rule if ``id`` is omitted, and return how many were removed.  Requests
already held are unaffected.  Naming a rule that doesn't exist is an
error::

    -> { "execute": "x-inject-error-delay-remove",
         "arguments": { "node-name": "err0", "id": "tail" } }
    <- { "return": { "count": 1 } }

**x-inject-error-delay-list** -- list the rules with their options, as
``id``, ``ops``, ``sector``, ``count`` (absent for the whole device),
``probability``, ``delay-ms``, ``delay-max-ms``, ``stall``, ``errno``,
``max-hits`` (the number left, absent if unlimited) and ``hits``, how
many requests each has held so far::

    -> { "execute": "x-inject-error-delay-list",
         "arguments": { "node-name": "err0" } }
    <- { "return": [ { "id": "tail",
                       "ops": [ "read", "write", "flush",
                                "discard", "write-zeroes" ],
                       "sector": 0, "probability": 0.001,
                       "delay-ms": 10000, "delay-max-ms": 60000,
                       "stall": false, "errno": 0, "hits": 3 } ] }

**x-inject-error-delay-inflight** -- list the requests currently being
held: ``id`` (to pass to the release command), ``rule-id`` (the rule that
matched it, still reported after that rule is removed), ``op``, ``sector`` and ``count`` (absent for
flushes), ``stalled``, ``remaining-ms`` (absent for stalls) and the
``errno`` it will fail with, 0 for none::

    -> { "execute": "x-inject-error-delay-inflight",
         "arguments": { "node-name": "err0" } }
    <- { "return": [ { "id": 7, "rule-id": "stall", "op": "write",
                       "sector": 2048, "count": 8,
                       "stalled": true, "errno": 0 } ] }

**x-inject-error-delay-release** -- release held requests and return how
many were released.  Without ``request-id`` every held request is
released; naming one that isn't held is an error.  ``disposition``
overrides what the rule asked for: ``complete`` passes the request on to
the image, ``error`` fails it with ``errno`` (default EIO, a positive
32-bit integer)::

    -> { "execute": "x-inject-error-delay-release",
         "arguments": { "node-name": "err0", "disposition": "error" } }
    <- { "return": { "count": 2 } }

Drain and device reset
^^^^^^^^^^^^^^^^^^^^^^

Draining a block node has to make progress, and a guest-initiated device
reset drains.  A stall therefore ends when the guest resets the device,
with each request keeping the disposition its rule asked for.  While the
node is drained no new request is matched against the rules, so I/O
issued during the drain goes straight through.  The same applies to any
other drain, such as one started by a block job or by ``blockdev-del``.  This is
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
    guest software reads to identify a device.  It is returned for every
    INQUIRY with EVPD clear, even one with a non-zero page code, which
    QEMU would otherwise reject.

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
    SENSE(10) was used, and whatever the page control, DBD and subpage
    fields say: only the 6-bit page code is compared, so a ``page``
    above 0x3F never matches.  For "all pages" (page 0x3F), register an
    override with page=0x3F.  The injected bytes must therefore include
    the mode parameter header in the format of the CDB the guest will
    send.

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
- ``data`` (string, required): base64-encoded response bytes, 1 to 65536
  of them; replaces the entire response verbatim with no validation

Setting an override replaces any earlier one of the same type and page.
The device is looked up by ID; an unknown ID fails with "Device '...' not
found", and any other kind of device with "Device '...' is not a
scsi-hd, scsi-cd, usb-storage, or ufs-lu device".

Example -- inject a short serial number (VPD page 0x80, "TEST1234")::

    -> { "execute": "x-scsi-disk-inject-response-set",
         "arguments": { "id": "disk0",
                        "type": "inquiry-vpd",
                        "page": 128,
                        "data": "AIAACFRFU1QxMjM0" } }
    <- { "return": {} }

**x-scsi-disk-inject-response-clear** -- clear response overrides.

Arguments:

- ``id`` (string, required): device ID
- ``type`` (string, optional): which override type to clear; omit to
  clear all overrides on the device
- ``page`` (int, optional): specific page to clear; required when
  ``type`` is ``inquiry-vpd`` or ``mode-sense-page``, and an error with
  ``inquiry-standard`` or without ``type``.  Clearing a page that has no
  override is not an error.

Example -- clear all overrides::

    -> { "execute": "x-scsi-disk-inject-response-clear",
         "arguments": { "id": "disk0" } }
    <- { "return": {} }

Example -- clear just VPD page 0x80::

    -> { "execute": "x-scsi-disk-inject-response-clear",
         "arguments": { "id": "disk0",
                        "type": "inquiry-vpd",
                        "page": 128 } }
    <- { "return": {} }

Notes
^^^^^

- Override data replaces the **entire** response including any headers.
  For VPD pages this means the 4-byte header (device type, page code,
  page length) is part of the injected data.  The ``scsi-inject.py``
  helper constructs these headers automatically.

- The maximum injected response size is 65536 bytes.  For VPD page 0x80
  (serial number), this means a maximum serial string of 65532 bytes
  (65536 minus the 4-byte VPD header).  What the guest receives is
  further cut to the allocation length in its CDB, as for any INQUIRY or
  MODE SENSE; a guest that sizes its buffer from the page length field
  will then ask again for the full length.

- Overrides apply to ``scsi-hd`` and ``scsi-cd`` devices (emulated
  SCSI), including the internal SCSI disk inside ``usb-storage`` and
  ``ufs-lu`` devices.  When targeting a ``usb-storage`` or ``ufs-lu``
  device, pass its device ID and the injection commands will
  automatically resolve to the internal SCSI disk.  Passthrough devices
  (``scsi-block``, ``scsi-generic``), which send INQUIRY and MODE SENSE
  to the host device via SG_IO, are refused: the set command fails with
  "Device '...' is not a scsi-hd, scsi-cd, usb-storage, or ufs-lu
  device".

- Overrides are not migrated.  After live migration, the fuzzer harness
  must re-inject any desired overrides.

- Overrides persist across guest reboots (they are not cleared on device
  reset).  Use the clear command to remove them.  Unplugging the device
  discards them.

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
    and other namespace-level properties.  The same override answers
    Identify Namespace for an allocated NSID (CNS 11h).  It is looked up
    before QEMU checks that the namespace exists, so any NSID the
    controller accepts as valid can be given an override, including one
    with no namespace attached; the broadcast NSID and NSIDs above the
    controller's maximum are still rejected with Invalid Namespace.

QMP commands
^^^^^^^^^^^^

**x-nvme-inject-response-set** -- set a response override.

Arguments:

- ``id`` (string, required): device ID of the NVMe controller
- ``type`` (string, required): ``identify-ctrl`` or ``identify-ns``
- ``nsid`` (int, 1-based): namespace ID; required (and non-zero) for
  ``identify-ns``, must not be present for ``identify-ctrl``
- ``data`` (string, optional): base64-encoded response bytes, 1 to 4096
  of them; replaces the response verbatim with no validation.  Only the
  bytes given are transferred, so short data leaves the rest of the
  guest's buffer as it was.  At least one of ``data`` or ``status`` must
  be specified.
- ``status`` (int, optional): NVMe status field to return in the
  completion queue entry, as a 16-bit value in QEMU's encoding (status
  code type in bits 8-10, the Do Not Retry bit as 0x4000).  At least one
  of ``data`` or ``status`` must be specified.  If only ``status`` is
  given, the command fails with this status and no data is transferred;
  if both are, the data is transferred and the command then completes
  with the status.

Setting an override replaces any earlier one for the same type and
NSID.

Example -- inject Identify Controller data (here only four bytes)::

    -> { "execute": "x-nvme-inject-response-set",
         "arguments": { "id": "nvme0",
                        "type": "identify-ctrl",
                        "data": "AQIDBA==" } }
    <- { "return": {} }

Example -- inject an NVMe error status for Identify Namespace::

    -> { "execute": "x-nvme-inject-response-set",
         "arguments": { "id": "nvme0",
                        "type": "identify-ns",
                        "nsid": 1,
                        "status": 6 } }
    <- { "return": {} }

The status value ``6`` corresponds to ``NVME_INTERNAL_DEV_ERROR``.

**x-nvme-inject-response-clear** -- clear response overrides.

Arguments:

- ``id`` (string, required): device ID of the NVMe controller
- ``type`` (string, optional): which override type to clear; omit to
  clear all overrides on the controller
- ``nsid`` (int, optional): namespace ID to clear; required when
  ``type`` is ``identify-ns``, and an error with ``identify-ctrl`` or
  without ``type``

Example -- clear all overrides::

    -> { "execute": "x-nvme-inject-response-clear",
         "arguments": { "id": "nvme0" } }
    <- { "return": {} }

Example -- clear just Identify Namespace for NSID 1::

    -> { "execute": "x-nvme-inject-response-clear",
         "arguments": { "id": "nvme0",
                        "type": "identify-ns",
                        "nsid": 1 } }
    <- { "return": {} }

Notes
^^^^^

- The injected data is sent as-is with no validation.  Only the bytes
  given are transferred, so data shorter than the normal 4096-byte
  identify response leaves the rest of the guest's buffer untouched.

- Overrides are not migrated.  After live migration, the fuzzer harness
  must re-inject any desired overrides.

- Overrides persist across guest reboots (they are not cleared on
  controller reset).  Use the clear command to remove them.  Unplugging
  the controller discards them.

- The controller is found by its device ID; anything else fails with
  "Device '...' is not an NVMe controller".

ATA Response Injection
----------------------

ATA response injection does for IDE and SATA hard disks what the SCSI and
NVMe overrides do for theirs: it replaces the data the guest gets back from
the commands it uses to identify a disk and judge its health, or makes those
commands fail.  Use it to fuzz ``hdparm``, ``smartctl``, ``udev``'s ATA
identification, ``libatasmart``, firmware and boot loaders that parse
IDENTIFY DEVICE, and the guest kernel's own ATA probing.

It works on any ``ide-hd`` device, whether attached to a PATA controller
(``piix3-ide``, ``piix4-ide``, the ISA IDE bus) or to an AHCI controller
(``ich9-ahci``, ``ahci``), since both go through the same IDE core.
``ide-cd`` and ``ide-cf`` devices are refused.

Supported override types
^^^^^^^^^^^^^^^^^^^^^^^^

``identify-device``
    The 512-byte IDENTIFY DEVICE (ECh) data: model, serial and firmware
    strings, geometry, capacity, supported features and transfer modes.

``smart-read-data``
    The 512-byte SMART READ DATA (B0h, feature D0h) attribute table.

``smart-read-thresh``
    The 512-byte SMART READ ATTRIBUTE THRESHOLDS (B0h, feature D1h)
    table.

The override is used only once the command would otherwise have been
answered.  A SMART command still has to carry the SMART signature
(LBA mid 4Fh, LBA high C2h), and SMART has to be enabled on the drive --
it is by default, but a guest that issues SMART DISABLE OPERATIONS gets
those commands aborted as usual, override or not.

QMP commands
^^^^^^^^^^^^

**x-ide-inject-response-set** -- set a response override.

Arguments:

- ``id`` (string, required): device ID of the ``ide-hd`` device
- ``type`` (string, required): ``identify-device``, ``smart-read-data``
  or ``smart-read-thresh``
- ``data`` (string, optional): base64-encoded response bytes, 1 to 512
  of them.  They are sent as the command's 512-byte PIO data block,
  padded with zeros if shorter.  Nothing is recomputed, including the
  IDENTIFY DEVICE integrity word and the SMART data checksum, so the
  guest sees whatever checksum the bytes contain.
- ``error`` (int, optional): a non-zero value for the ATA Error
  register.  The command then completes with ERR set in the Status
  register (DRDY|ERR) and this value in the Error register, raises its
  interrupt, and transfers no data, even if ``data`` is also given.
  ``4`` is ABRT, an aborted command; ``0x40`` is UNC, an uncorrectable
  data error.

At least one of ``data`` and ``error`` must be given.  Setting an
override replaces any earlier one of the same type.  Failures:
"Device '...' not found", "Device '...' is not an ide-hd device", "at
least one of 'data' or 'error' must be specified", "error register value
must be non-zero" and "data length must be between 1 and 512 bytes".

Example -- replace IDENTIFY DEVICE with a short buffer (the rest of the
512 bytes reads as zero)::

    -> { "execute": "x-ide-inject-response-set",
         "arguments": { "id": "ide-disk0",
                        "type": "identify-device",
                        "data": "QABgAA==" } }
    <- { "return": {} }

Example -- make SMART READ DATA fail with ABRT::

    -> { "execute": "x-ide-inject-response-set",
         "arguments": { "id": "ide-disk0",
                        "type": "smart-read-data",
                        "error": 4 } }
    <- { "return": {} }

**x-ide-inject-response-clear** -- clear response overrides.

Arguments:

- ``id`` (string, required): device ID of the ``ide-hd`` device
- ``type`` (string, optional): which override to clear; omit to clear
  all three.  Clearing a type with no override is not an error.

Example::

    -> { "execute": "x-ide-inject-response-clear",
         "arguments": { "id": "ide-disk0",
                        "type": "identify-device" } }
    <- { "return": {} }

Notes
^^^^^

- Overrides are not migrated, persist across guest reboots and device
  resets, and are discarded when the device is unplugged.

- The guest kernel reads IDENTIFY DEVICE when it probes the disk and
  keeps what it read.  Tools such as ``hdparm -I`` and ``smartctl`` send
  their own commands through ATA pass-through and see an override at
  once; to make the kernel itself re-read IDENTIFY, rescan or re-probe
  the disk (for libata, ``echo 1 > /sys/block/sda/device/rescan``).

- An override on IDENTIFY DEVICE that reports a different capacity or
  geometry changes only what the guest is told.  The disk still has its
  real size, and I/O beyond it fails as usual.



Command-Line Tools
------------------

scsi-inject.py
^^^^^^^^^^^^^^

A high-level CLI for SCSI response injection.  It handles binary SCSI
response construction and base64 encoding internally.
Run it via the build venv, which provides the ``qemu.qmp`` package it
needs::

    build/run scripts/scsi-inject.py [options] <command> [args]

Connection options (choose one; the long forms are ``--socket``,
``--host`` and ``--port``)::

    -s /path/to/qmp.sock        # Unix socket (preferred)
    -H localhost -P 4445         # TCP; these are the defaults

A QMP error is printed and the script exits with status 1.

Response injection commands.  ``serial``, ``device-id`` and ``inquiry``
take ``--dev-type N`` (default 0, a disk), the peripheral device type put
in the first byte of the response; use 5 for a scsi-cd.  Strings are
encoded as ASCII, with anything else replaced by ``?``.

``serial <device> <string>``
    Set VPD page 0x80 (unit serial number).  The string is not padded or
    terminated, and the only limit is QEMU's 65532-byte maximum for it
    -- the normal 36-character QEMU cap is bypassed entirely::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            serial disk0 "VERY_LONG_SERIAL_0123456789ABCDEF0123456789"

``device-id <device> <string>``
    Set VPD page 0x83 (device identification) to a single designation
    descriptor: code set ASCII, association with the logical unit,
    designator type T10 vendor ID, holding the string as given (at most
    255 bytes, the most a descriptor's length byte can say)::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            device-id disk0 "MY_CUSTOM_DEVICE_ID_STRING"

``inquiry <device> [--vendor V] [--product P] [--version V] [--removable]``
    Set the standard INQUIRY response.  It builds a 96-byte response
    claiming SPC-3 (version 5), response data format 2 with HiSup, and
    Sync and CmdQue set.  ``--vendor`` (default ``QEMU``), ``--product``
    (default ``QEMU HARDDISK``) and ``--version`` (default ``1.0``) are
    space padded and cut to 8, 16 and 4 characters; ``--removable`` sets
    the RMB bit::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            inquiry disk0 --vendor "ACME" --product "FuzzyDisk 9000"

``vpd-raw <device> <page> <hex>``
    Set a raw VPD page from hex-encoded bytes (complete response
    including the 4-byte VPD header).  Page codes take a ``0x`` prefix
    for hex::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            vpd-raw disk0 0x80 00800024564552594c4f4e47

``mode-sense-raw <device> <page> <hex>``
    Set a raw MODE SENSE response from hex-encoded bytes, header
    included::

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

A CLI for the inject-error filter: bad sector regions and latency rules.
Run via the build venv::

    build/run scripts/inject-error.py [options] <command> [args]

Connection options (same as scsi-inject.py)::

    -s /path/to/qmp.sock        # Unix socket (preferred)
    -H localhost -P 4445         # TCP; these are the defaults

Wherever an errno is taken it may be a number or one of the names
``EPERM``, ``EIO``, ``ENOMEM``, ``ENODEV``, ``EINVAL``, ``ENOSPC`` and
``ENODATA`` (case does not matter).  Sectors accept a ``0x`` prefix.  The
``list``, ``delay-list`` and ``inflight`` commands take ``--json`` to also
print the raw QMP reply.

Commands:

``list <node>``
    List all active error entries on a node::

        build/run scripts/inject-error.py -s /tmp/qmp.sock list err0

``add <node> <sector> [options]``
    Add a bad sector region.  Options: ``-c/--count`` (default 1),
    ``-e/--errno`` (default EIO), ``-b/--behavior`` (default
    ``persistent``), ``-R/--no-reads`` to let reads through, ``-w/--writes``
    to fail writes too (``-r/--reads`` is accepted for symmetry and is
    the default)::

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
    Remove all error entries from a node, by removing the one range that
    spans them all::

        build/run scripts/inject-error.py -s /tmp/qmp.sock clear err0

``scenario <node> <scenario> <id> [options]``
    Add a latency rule for one of the named failure modes, under the name
    ``id``.  Every field of the rule can still be overridden with the
    ``delay-add`` options below.  The scenarios and the rule each one
    starts from:

    ======================== ==================================================
    Scenario                 Rule
    ======================== ==================================================
    ``fixed-latency``        ``delay-ms`` 50
    ``tail-latency``         ``probability`` 0.001, ``delay-ms`` 10000,
                             ``delay-max-ms`` 60000
    ``stall``                ``stall``
    ``timeout-then-success`` ``delay-ms`` 45000
    ``timeout-then-failure`` ``delay-ms`` 45000, ``errno`` 5 (EIO)
    ``backend-disconnect``   ``stall``; ``release --error`` fails what is
                             held, ``delay-remove`` reconnects
    ``flush-latency``        ``ops`` flush, ``delay-ms`` 30000
    ``queue-saturation``     ``stall``, ``max-hits`` 32
    ``out-of-order``         ``probability`` 0.25, ``delay-ms`` 100,
                             ``delay-max-ms`` 5000
    ``reset-race``           ``delay-ms`` 30000, ``delay-max-ms`` 90000
    ======================== ==================================================

    For example::

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            scenario err0 tail-latency slow

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            scenario err0 fixed-latency lag --delay-ms 200

``delay-add <node> <id> [options]``
    Add a latency rule from scratch.  Options: ``--ops`` (comma separated
    list), ``--sector``, ``-c/--count``, ``-p/--probability``,
    ``-d/--delay-ms``, ``-D/--delay-max-ms``, ``--stall``, ``-e/--errno``
    and ``--max-hits``, each mapping to the rule option of the same name
    and left to QEMU's default when not given::

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

``release <node> [-i/--request-id N] [--complete|--error] [-e ERRNO]``
    Release held requests, optionally overriding how they complete.
    ``-e/--errno`` (default EIO) only matters with ``--error``::

        build/run scripts/inject-error.py -s /tmp/qmp.sock \
            release err0 --error --errno EIO
