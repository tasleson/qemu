Storage Error and Response Injection
=====================================

This branch adds a mechanism for testing how guest software handles
storage errors and slow or unresponsive storage:

- **inject-error** block filter driver -- injects I/O errors (bad sectors)
  and latency (slow, stalled and timing-out requests) at the block layer,
  under any emulated disk

It is controlled at runtime via QMP.  It is meant for fuzzing and for
testing guest drivers and storage management software, not for
production use: every command is marked ``unstable`` and carries an
``x-`` prefix, and none of the injected state is migrated.

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

Each of these takes one rule; the rule column shows what it configures.

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
