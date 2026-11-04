Storage Error and Response Injection
=====================================

This branch adds several complementary mechanisms for testing how guest
software handles storage errors, slow or unresponsive storage, and unusual
hardware responses:

- **inject-error** block filter driver -- injects I/O errors (bad sectors)
  and latency (slow, stalled and timing-out requests) at the block layer,
  under any emulated disk
- **SCSI target faults** -- make a SCSI target, or one LUN of it, stop
  answering until the guest performs the error recovery that brings it back
- **virtio-scsi TMF delay and broken-ring diagnostics** -- hold back the
  answer to a guest's task management functions, and record what a
  virtio-scsi request ring looked like when the device gave up on it
- **SCSI response injection** -- overrides INQUIRY and MODE SENSE responses
  at the SCSI emulation layer
- **NVMe response injection** -- overrides Identify Controller and Identify
  Namespace responses at the NVMe emulation layer
- **ATA response injection** -- overrides IDENTIFY DEVICE and SMART data, or
  fails those commands, on IDE and SATA (AHCI) hard disks
- **SD/MMC response injection** -- overrides an SD or eMMC card's CID and
  CSD registers and sets error bits in the card status it reports

Most are controlled at runtime via QMP; the virtio-scsi knobs are device
properties set on the command line.  They are meant for fuzzing and for
testing guest drivers and storage management software, not for
production use: every command is marked ``unstable`` and carries an ``x-``
prefix, and none of the injected state is migrated.

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

Hold times run on the host's real-time clock.  Unlike SCSI target faults
they keep running while the VM is paused, so a held request can expire
while the guest is stopped and complete as soon as it resumes.

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


.. _storage-injection-target-faults:

SCSI Target Faults
------------------

Latency rules see the guest's recovery only as a drain of their block
node.  They can't tell an abort from a LUN reset from an adapter reset, an
ABORT TASK never reaches them, and the rule is still armed afterwards, so
the commands the guest reissues stall again and recovery never appears to
work.  A rule also covers one node, so a target with several LUNs needs a
rule on each.

A *SCSI target fault* works at the SCSI layer instead.  It is armed on an
adapter for a target, or one LUN of it, and holds the commands sent there
before they run.  Each fault names the least disruptive recovery that
fixes it; when the guest performs that recovery, the fault clears by
itself and the commands the recovery did not cancel go on to run.  This is
what a real target that needed resetting looks like from the initiator,
and it lets a guest driver's whole escalation path be exercised: aborts,
then LUN resets, then target resets, then resetting the adapter.

Held commands have not reached the device, so a held write never lands on
the backend, and aborting or resetting cancels a held command at once.
They are still listed as outstanding, so QUERY TASK finds them.

Faults are only supported on virtio-scsi; naming another adapter fails
with "Device '...' does not support SCSI target faults", and naming a
device that is not a SCSI adapter at all fails with "Device '...' is not
a SCSI adapter".  Faults address channel 0 only, which is the only
channel virtio-scsi has.  They block migration while any is armed, and
are discarded without releasing anything when the adapter is unplugged.

Recovery levels
^^^^^^^^^^^^^^^

From least to most disruptive:

================ ===============================================================
``abort-task``   ABORT TASK addressed to the fault's target or LUN, whatever
                 tag it names: one that isn't outstanding still gets FUNCTION
                 COMPLETE, so it counts too
``task-set``     ABORT TASK SET or CLEAR TASK SET
``lun-reset``    LOGICAL UNIT RESET.  For a fault on a whole target, a reset of
                 any of its LUNs.
``target-reset`` I_T NEXUS RESET
``bus-reset``    resetting the adapter; for virtio-scsi, a device reset, which
                 includes a system reset
``manual``       nothing the guest does; only ``x-scsi-fault-remove``
================ ===============================================================

A recovery attempt below the fault's ``clear-on`` level does what
``below-clear`` says:

- ``proceed`` (default): the attempt does its normal work, so it cancels the
  held commands, but the fault stays and holds the commands the guest sends
  next -- a reset that "succeeds" on a target that is still wedged.
- ``reject``: the TMF fails with FUNCTION REJECTED and changes nothing.
- ``hang``: the TMF gets no answer until the fault clears, or until
  ``tmf-hang-ms`` runs out, and is then carried out and answered.  A device
  reset drops it like anything else outstanding on the ring.  How long it
  waits is fixed when it arrives.  Whenever a fault goes away it is looked
  at again against the faults still armed: if none of them hangs it any
  more it goes ahead, or is rejected if one says so, and otherwise its wait
  can only get shorter.  Arming another hanging fault afterwards never
  makes it wait longer, and nothing else -- such as other TMFs finishing --
  changes it.

A device reset can't be refused, so it always behaves like ``proceed``.

Fault options
^^^^^^^^^^^^^

- ``id`` (string, required): name of the fault on its adapter; adding a
  second fault with the same name fails.
- ``target`` (required) and ``lun``: what the fault covers.  Without
  ``lun`` it covers every LUN of the target.  They must not exceed the
  adapter's limits (255 and 16383 for virtio-scsi).
- ``delay-ms`` / ``delay-max-ms``: hold each command for that long, drawn
  uniformly from [``delay-ms``, ``delay-max-ms``), and then run it, for a
  target that is slow rather than stuck.  Both are at most 86400000 (a
  day).  Without either, commands are held until the fault clears.  A
  delay fault still clears on ``clear-on``, by default a LUN reset, so use
  ``clear-on: manual`` for latency that should outlast the guest's
  recovery.
- ``probability`` (default 1.0) and ``max-hits`` (at least 1): hold only
  that fraction of commands, or stop holding after that many.  The fault
  stays armed until it clears either way.  The random choices come from a
  PRNG per adapter that is seeded randomly and cannot be seeded, so
  unlike inject-error a run is not reproducible command for command.
  ``delay-max-ms`` less than ``delay-ms`` is an error.
- ``clear-on`` (default ``lun-reset``), ``below-clear`` (default
  ``proceed``) and ``tmf-hang-ms`` (at most 86400000, counted from when the
  TMF arrived; a TMF several faults hang waits for all of them): see above.
  ``tmf-hang-ms`` is refused unless ``below-clear`` is ``hang``.
- ``hold-at`` (default ``submit``): where commands are held.  ``submit``,
  before they run, is the only choice so far.

Faults are evaluated in the order they were added, and the first one
that matches a command holds it.  A recovery attempt, on the other hand,
is shown to every fault in its scope: it counts as an attempt on each, a
``reject`` from any of them rejects it, and a ``hang`` from any of them
hangs it (no answer beats a refusal).  A device that is being unplugged
never has its commands held.

Times are in guest time: they don't run while the VM is stopped.  Nor does
anything a fault clearing would complete to the guest -- released commands
and hung TMFs -- happen while the VM is stopped; it waits until it runs
again.

Held commands are released in the order the guest sent them, as far as
each LUN and request queue goes; nothing orders commands to different LUNs,
or on queues served by different iothreads, against each other.

A unit attention is taken by the first command created after it is raised,
as usual in QEMU.  If a fault holds that command, the unit attention is
reported when the command is released, possibly after later commands.  If
the command is aborted or reset instead, it never ran, so the unit
attention is given back for the next command.  It goes back as if raised
again: if another one is pending by then, the more important of the two
stays, by the same precedence QEMU always applies.  A reset that cancels
the command raises its own afterwards, which takes precedence over it.

Unit attentions are taken and given back without a lock, from the
iothread that runs the command, as QEMU already takes them.  With
``iothread-vq-mapping``, two iothreads could in principle give one back to
the same LUN at once and leave a mix of the two; this hasn't been seen.

QMP commands and events
^^^^^^^^^^^^^^^^^^^^^^^

The adapter is named by its device ID or QOM path, e.g. the ID of a
``virtio-scsi-pci`` device; a virtio proxy is looked through to the device
on its virtio bus, but nothing further down is, so naming a bridge is an
error rather than a way to reach the adapters behind it.  Events give the
adapter exactly as the fault was added, so a fault added by QOM path is
reported by QOM path.

**x-scsi-fault-add** -- arm a fault.  Arguments are ``device`` and
``fault``, an object with the options above::

    -> { "execute": "x-scsi-fault-add",
         "arguments": { "device": "scsi0",
                        "fault": { "id": "hang1", "target": 1,
                                   "clear-on": "target-reset" } } }
    <- { "return": {} }

**x-scsi-fault-remove** -- disarm the fault named ``id``, or every fault
if ``id`` is omitted, and return how many were removed.  The commands they
hold run, as if the recovery had happened, and each sends a
``SCSI_FAULT_CLEARED`` event with recovery ``manual``.  Naming a fault
that isn't armed is an error ("No fault named '...' on '...'")::

    -> { "execute": "x-scsi-fault-remove",
         "arguments": { "device": "scsi0", "id": "hang1" } }
    <- { "return": { "count": 1 } }

**x-scsi-fault-list** -- list the armed faults, in evaluation order.  Each
entry repeats the fault's options (``id``, ``target``, ``lun``,
``hold-at``, ``probability``, ``max-hits``, ``clear-on``, ``below-clear``,
``tmf-hang-ms``), says whether it ``stall``\ s or, if not, its
``delay-ms`` and ``delay-max-ms``, and adds ``hits`` (commands held so
far), ``held`` (commands held right now), ``attempts`` (recovery attempts
seen, by kind) and ``last-attempt``::

    -> { "execute": "x-scsi-fault-list",
         "arguments": { "device": "scsi0" } }
    <- { "return": [ { "id": "hang1", "target": 1,
                       "hold-at": "submit", "stall": true,
                       "probability": 1.0,
                       "clear-on": "target-reset",
                       "below-clear": "proceed",
                       "hits": 12, "held": 4,
                       "attempts": { "abort-task": 0, "task-set": 0,
                                     "lun-reset": 2,
                                     "target-reset": 0,
                                     "bus-reset": 0 },
                       "last-attempt": "lun-reset" } ] }

**SCSI_FAULT_CLEARED** is sent whenever a fault clears, with the
``device`` exactly as given to ``x-scsi-fault-add``, the ``bus`` name
(``scsi0.0`` for an adapter with ID ``scsi0``), the fault's ``id``,
``recovery``, what cleared it (``manual`` for ``x-scsi-fault-remove``),
and ``held``, how many commands it was holding at that moment::

    <- { "event": "SCSI_FAULT_CLEARED",
         "data": { "device": "scsi0", "bus": "scsi0.0",
                   "id": "hang1", "recovery": "target-reset",
                   "held": 0 },
         "timestamp": { "seconds": 1265044230, "microseconds": 450486 } }

A recovery only clears a fault if it succeeds: a TMF answered with
anything but FUNCTION COMPLETE or FUNCTION SUCCEEDED (for example one
addressed to a LUN that doesn't exist) leaves it armed.  A device reset,
including a system reset, clears every fault whose ``clear-on`` is
``bus-reset`` or below.  Those are released, but a TMF some fault left
hanging may go ahead at the same time and cancel some of them, so the count
is an upper bound on what runs.  A harness can wait for the event rather
than watch traces; ``scripts/scsi-inject.py fault-wait`` does.  It keeps
its QMP connection open while it waits, so give QEMU a second ``-qmp``
socket for anything else the harness does meanwhile.  It exits with 0 once
the fault clears, 4 if ``--timeout`` runs out, and 5 if the fault isn't
armed when it starts -- already cleared, or never added; it can't tell
which.  It exits with 1 on other errors, and 2 for a bad command line.

The ``scsi_fault_*`` and ``virtio_scsi_tmf_*`` trace events show each
command held and released and each recovery attempt with what the faults
made of it.

Scenarios
^^^^^^^^^

=============================== ===============================================
Scenario                        Fault
=============================== ===============================================
LUN hangs until it is reset     ``target`` and ``lun``; the defaults do the
                                rest
Aborts don't help, a LUN reset  ``clear-on`` ``lun-reset``; each abort
does                            cancels only the command it names
Wedged target that LUN resets   ``clear-on`` ``target-reset``,
don't fix                       ``below-clear`` ``proceed``
Target refuses resets until     ``clear-on`` ``bus-reset``,
the adapter is reset            ``below-clear`` ``reject``
Reset that times out            ``below-clear`` ``hang``, with
                                ``tmf-hang-ms`` past the guest's TMF timeout
Dead target                     ``clear-on`` ``manual``
Slow target                     ``delay-ms`` and ``delay-max-ms``, with
                                ``probability`` for tail latency and
                                ``clear-on`` ``manual`` so it outlasts
                                recovery
Commands that run after the     ``clear-on`` ``manual``, ``below-clear``
guest gave up on them           ``hang``, plus a second such fault with
                                ``probability`` 0.0; remove the first, then
                                the second
=============================== ===============================================

The last one needs the second fault because removing a fault that both
holds commands and hangs a LUN reset doesn't let the commands complete:
nothing orders their release against the reset going ahead, and in
practice the reset wins and the guest sees them fail.  Whether their data
was transferred first varies: with an iothread they are usually cancelled
before they run, while in the main loop the release gets to send them and
the reset then cancels only their completion.  A fault with
``probability`` 0.0 holds nothing but still hangs the reset
(``probability`` only decides which commands are held), so with it in
place the first removal lets the held commands run and complete normally,
and removing it then lets the reset go ahead.
``fault-below-hang-holds-none`` in ``tests/qtest/virtio-scsi-test.c``
checks that order, in the main loop and with an iothread.

.. _storage-injection-virtio-scsi:

virtio-scsi TMF Delay and Ring Diagnostics
------------------------------------------

Four experimental properties on ``virtio-scsi-pci`` (and the other
virtio-scsi transports) support work on guest drivers' error recovery:
one delays task management responses, the other three diagnose a request
ring the device gives up on.  They are qdev properties, so they can only
be set when the device is created; ``qom-set`` on a running device fails
with "Attempt to set property ... after it was realized".

====================== ======= ===============================================
Property               Default Effect
====================== ======= ===============================================
``x-tmf-delay-ms``     0       how long to hold back each delayed TMF response
``x-tmf-delay-count``  0       how many TMF responses to delay; 0 disables
``x-diag``             on      the broken-ring diagnostics' work while the
                               device is healthy
``x-stop-on-broken``   off     pause the VM when a request ring breaks
====================== ======= ===============================================

For example::

    -device virtio-scsi-pci,id=scsi0,x-tmf-delay-ms=30000,x-tmf-delay-count=1
    -device virtio-scsi-pci,id=scsi1,x-stop-on-broken=on

Delaying TMF responses
^^^^^^^^^^^^^^^^^^^^^^

With both ``x-tmf-delay-ms`` and ``x-tmf-delay-count`` non-zero, the
adapter holds back the response to each of the next ``x-tmf-delay-count``
task management functions it answers for ``x-tmf-delay-ms`` milliseconds
of guest time, then completes it.  The count goes down by one for each
response held, so with a count of 1 only the first TMF the guest sends
is delayed and everything after it is answered normally.

The TMF itself is carried out at once: a LUN reset has already reset the
LUN and cancelled its commands, and any SCSI target fault it was enough
for has already cleared, by the time its response is held.  Only the
guest's view of it is late.  That is the point: a guest driver that
issues a reset and waits for the answer stays in its reset path for as
long as the delay lasts, so whatever else times out meanwhile -- a second
LUN's commands, the reset itself -- has to be handled while the first is
still in flight.

Only TMFs answered as soon as they are processed are delayed: LOGICAL
UNIT RESET, I_T NEXUS RESET, QUERY TASK, QUERY TASK SET, an ABORT TASK
whose command is not outstanding, any TMF that fails (unknown target,
wrong LUN, CLEAR ACA or another unsupported function), and a TMF a SCSI
target fault rejects.  An ABORT TASK that finds its command, ABORT TASK
SET and CLEAR TASK SET complete later in the request's AioContext, and
a TMF a target fault leaves hanging is answered when the fault lets it
go; none of those are delayed or counted.  Asynchronous notification
requests on the control queue are never delayed.

A device reset drops every held TMF response without writing it to the
ring, since the ring it belongs to no longer exists after the reset; the
guest never sees an answer.  The same happens to TMFs a target fault
left hanging, and at unplug.  The ``tmf-delay-device-reset`` test in
``tests/qtest/virtio-scsi-test.c`` checks this.

``virtio_scsi_tmf_delay`` traces each response as it is held, with the
delay; ``virtio_scsi_tmf_resp`` traces it when it is finally sent, and
``virtio_scsi_tmf_drop`` when a reset drops it.

Broken-ring diagnostics
^^^^^^^^^^^^^^^^^^^^^^^

When a virtio device finds something it cannot accept on a ring -- a
descriptor chain that loops, is too long or points outside guest RAM,
or for virtio-scsi a request whose headers have the wrong size -- it
reports the error, marks itself
broken, and stops processing until the guest resets it.  The message says
what was wrong but not which request, and by the time anyone looks the
guest may have reused the memory.  For guest driver bugs that free or
rewrite a request the device still owns, which request and what it held
when the guest published it is the whole question.

Two layers of diagnostics answer it.  Both report through trace events
(see `Tracepoints`_), so enable those first: nothing beyond the usual
error message is printed otherwise.

**Chain capture, in the virtio core.**  For any virtio device using split
rings, when popping a request marks the device broken, the core reads
the avail entry it was popping and the descriptor chain behind it, right
then, and keeps the result until the queue is next reset.  It traces
``virtqueue_chain_error`` (device, queue, avail position, head
descriptor and whether it could be read), ``virtqueue_chain_summary``
(whether the chain is indirect, how many entries it has and how many of
them have zero length, the index of the first such, whether an indirect
table is all zeros, an FNV-1a hash of the table or chain, and the first
16 bytes of the first buffer as two 64-bit words -- for virtio-scsi, the
LUN and tag of the command) and one ``virtqueue_chain_entry`` for each of
the first eight entries and for the first zero-length entry.  The device
is named by its proxy's ID (``scsi0`` for ``-device
virtio-scsi-pci,id=scsi0``).  The capture reads guest RAM only; an
address that is not RAM is not read and is reported as a read failure,
and at most 64 KiB of an indirect table is read.  Packed rings are not
covered, and neither is a device that breaks for a reason other than the
chain, such as virtio-scsi's "wrong size for virtio-scsi headers".

**Snapshot comparison, in virtio-scsi.**  The capture shows what the
device read, not whether that is what the guest published.  So, while
``x-diag`` is on, virtio-scsi also records request-queue entries the
guest has published but the device has not yet popped, the first time it
sees each one:

- when a TMF arrives, before it is carried out, for every request queue
  (traced as ``virtio_scsi_tmf_snapshot``, with a running TMF number);
- when the adapter is drained -- which a LUN or target reset does --
  and, for as long as the drain lasts, on every kick the guest sends.
  During a drain the request queue handlers are detached and nothing is
  popped, so virtio-scsi attaches a watch in their place that only
  records what is published and re-enables guest notifications each
  time (``virtio_scsi_drain_begin`` and ``virtio_scsi_drain_snapshot``
  report how many entries were pending and new, and how many kicks the
  watch saw).

When a request queue then breaks, the entry that broke it is compared
with its snapshot and ``virtio_scsi_broken_verdict`` says what happened:

================= ============================================================
Verdict           Meaning
================= ============================================================
``no-snapshot``   the entry was never seen pending, so there is nothing to
                  compare (it was published and popped outside a TMF or
                  drain)
``head-changed``  the avail slot now names a different descriptor: guest
                  ring bookkeeping went wrong
``unchanged``     same chain, byte for byte: what the guest published is
                  what failed; look at the snapshot's zero-length entries
``zeroed``        an indirect table that was valid while pending is now all
                  zeros: the guest cleared a request it had handed over
``rewritten``     the chain changed some other way: the guest reused the
                  memory while the request was still queued
``unreadable``    the head descriptor is unchanged but the chain behind it
                  is not in RAM, so there is nothing to compare
``no-chain``      the ring broke over something other than the chain, for
                  example bad header sizes
``not-request``   the control or event queue broke
``diag-off``      ``x-diag=off``: no snapshots were taken
================= ============================================================

With a snapshot, ``virtio_scsi_broken_before``,
``virtio_scsi_broken_before_detail`` and ``virtio_scsi_broken_before_entry``
describe the entry as it was first seen: where (``tmf``, ``drain`` or
``kick``), after which TMF, how long ago, and the same chain fields as
the core's capture.  The verdict line also says whether the head
descriptor still belonged to a request the device had in flight
(``head_inflight``), and how many overlaps had been seen.

**Overlap tracking.**  Independently, while ``x-diag`` is on, every
request popped is checked against the requests the adapter still has in
flight.  One that uses the same command header address, or the same
queue and head descriptor, means the guest handed the device memory the
device still owns; ``virtio_scsi_req_overlap`` reports it, with both
requests' queue, head and tag and how long ago the older one was popped.
The first 256 are traced; all are counted.

Every adapter's diagnostic state is reset with the device.

**x-diag=off** turns off everything virtio-scsi does while the device is
healthy -- the per-request tracking, the TMF and drain snapshots, and the
drain watch -- leaving only the core's chain capture, and the verdict is
then ``diag-off``.  It exists to measure the diagnostics' own effect:
the drain watch keeps guest notifications enabled during a drain and so
changes when the guest kicks, which can change the timing of exactly the
races being chased.

**x-stop-on-broken=on** pauses the VM, as ``stop`` would, the first time a
virtio-scsi device with the property set breaks, and traces
``virtio_scsi_stop_on_broken``.  The guest's memory is then still as the
driver left it when the device read the bad request, which is when to
take a ``dump-guest-memory``.  The latch is per QEMU process: later
breaks, on that device after a reset or on another one, do not pause the
VM again.  Resume it with ``cont``.

Telling adapters apart
^^^^^^^^^^^^^^^^^^^^^^

The TMF, reset and broken-ring trace events carry ``bus=``, the name of
the adapter's SCSI bus (``scsi0.0`` for ``-device virtio-scsi-pci,id=scsi0``),
and the TMF ones the target as well as the LUN, so a VM with several
adapters can be traced as one.  ``virtio_scsi_reset`` marks each device
reset and ``virtio_scsi_broken`` gives the bus and queue (0 control, 1
event, 2 and up the request queues) of each break.


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



SD/MMC Response Injection
-------------------------

SD response injection targets SD and eMMC card emulation.  It replaces the
contents of the Card Identification (CID) and Card-Specific Data (CSD)
registers that the card returns, and can OR arbitrary bits into the card
status the card reports with its responses, which is how a card signals
errors such as ADDRESS_ERROR, CARD_ECC_FAILED or a locked card.  Use it to
fuzz the guest's MMC core and host controller drivers, and tools such as
``mmc-utils`` that parse those registers.

It works on any SD or MMC card model (``sd-card``, ``sd-card-spi``,
``emmc``), on whatever controller it is attached to, such as
``sdhci-pci`` on x86.  The card needs an ``id``::

    -device sdhci-pci,id=sdhci0
    -device sd-card,drive=sd1,bus=sd-bus,id=sd0

Override types and card status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``cid``
    The 16-byte CID register returned by ALL_SEND_CID (CMD2) and
    SEND_CID (CMD10): manufacturer and OEM IDs, product name and
    revision, serial number, manufacturing date and CRC.

``csd``
    The 16-byte CSD register returned by SEND_CSD (CMD9): capacity,
    block lengths, timing and access parameters.

In SD mode the register is returned in the 136-bit R2 response; data
shorter than 16 bytes is padded with zeros.  In SPI mode the register is
sent on the data lines, and only as many bytes as were given are sent.
Either way the bytes are used verbatim: the CRC7 in the last byte is not
recomputed, so a guest that checks it sees a mismatch unless the
injected data carries a correct one.

Card status injection is separate from the register overrides.  Bits
given as ``card-status`` are ORed into the card status reported in every
R1 and R1b response, into the status bits of the R6 response that
publishes the RCA, and into the R1 and R2 status bytes of SPI responses.
They stay until cleared, whatever ``type`` they were set with, and the
card's own clear-on-read behaviour does not remove them.  The bit layout
is the card status register's, as in the SD specification (for example
bit 31 OUT_OF_RANGE, bit 30 ADDRESS_ERROR, bit 25 CARD_IS_LOCKED, bit 21
CARD_ECC_FAILED, bit 19 ERROR).

QMP commands
^^^^^^^^^^^^

**x-sd-inject-response-set** -- set a register override, card status
injection, or both.

Arguments:

- ``id`` (string, required): device ID of the card
- ``type`` (string, required): ``cid`` or ``csd``.  It says which
  register ``data`` replaces, and must be given even when only
  ``card-status`` is.
- ``data`` (string, optional): base64-encoded register contents, 1 to
  16 bytes
- ``card-status`` (int, optional): 32-bit card status bits to OR in.
  Setting it again replaces the previous value.

At least one of ``data`` and ``card-status`` must be given.  ``data``
replaces any earlier override of the same register and leaves card
status injection as it was.  Failures: "Device '...' not found",
"Device '...' is not an SD/MMC card", "at least one of 'data' or
'card-status' must be specified" and "data length must be between 1 and
16 bytes".

Example -- replace the CID::

    -> { "execute": "x-sd-inject-response-set",
         "arguments": { "id": "sd0",
                        "type": "cid",
                        "data": "AwBARkFLRTEwEjRWeAEeAQ==" } }
    <- { "return": {} }

Example -- report ERROR (bit 19) in every R1 response::

    -> { "execute": "x-sd-inject-response-set",
         "arguments": { "id": "sd0",
                        "type": "csd",
                        "card-status": 524288 } }
    <- { "return": {} }

**x-sd-inject-response-clear** -- clear overrides.

Arguments:

- ``id`` (string, required): device ID of the card
- ``type`` (string, optional): the register override to clear.  Omit it
  to clear both registers and card status injection; with it, card
  status injection stays.

Example::

    -> { "execute": "x-sd-inject-response-clear",
         "arguments": { "id": "sd0" } }
    <- { "return": {} }

Notes
^^^^^

- Overrides are not migrated, persist across card resets, and are
  discarded when the card is removed.

- The guest reads CID and CSD while initialising the card, so an
  override generally takes effect at the next card initialisation: after
  a guest reboot, a rescan of the host controller, or a remove and
  re-insert.  Card status bits take effect on the next response.

- Setting card status bits that make the guest give up on the card,
  such as CARD_IS_LOCKED during initialisation, can leave it without a
  usable card until they are cleared and the card is re-initialised.


.. _storage-injection-tracepoints:

Tracepoints
-----------

The branch adds trace events for observing what guest drivers do around an
injected failure.  Enable them like any others (see :ref:`tracing`), for
example ``-trace 'virtio_scsi_tmf_*' -trace 'scsi_fault_*'``.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Events
     - What they show
   * - ``virtio_blk_handle_flush``, ``virtio_blk_handle_discard``, ``virtio_blk_handle_write_zeroes``
     - each virtio-blk flush, discard and write-zeroes request as it arrives, with its sector range and flags where applicable (a flush has neither)
   * - ``scsi_disk_emulate_command_SYNCHRONIZE_CACHE``
     - each SYNCHRONIZE CACHE a scsi-disk receives, with its LBA
   * - ``scsi_req_return_ua``
     - a unit attention given back because the command that took it was held by a target fault and then cancelled
   * - ``scsi_fault_add``, ``scsi_fault_hold``, ``scsi_fault_release``, ``scsi_fault_recovery``, ``scsi_fault_clear``
     - target faults armed, commands held and released, each recovery attempt and what the faults made of it, and faults clearing
   * - ``virtio_scsi_tmf_req``, ``virtio_scsi_tmf_resp``
     - TMFs as they arrive and are answered, now with the target and ``bus=``
   * - ``virtio_scsi_tmf_delay``, ``virtio_scsi_tmf_hang``, ``virtio_scsi_tmf_drop``
     - TMF responses held by ``x-tmf-delay``, TMFs a target fault leaves hanging, and held or hung TMFs a reset drops
   * - ``virtio_scsi_reset``
     - each virtio-scsi device reset
   * - ``virtio_scsi_broken``, ``virtio_scsi_broken_*``, ``virtio_scsi_stop_on_broken``, ``virtio_scsi_tmf_snapshot``, ``virtio_scsi_drain_begin``, ``virtio_scsi_drain_snapshot``, ``virtio_scsi_req_overlap``
     - a request ring breaking, and the broken-ring diagnostics described above
   * - ``virtqueue_chain_error``, ``virtqueue_chain_summary``, ``virtqueue_chain_entry``
     - the descriptor chain a split ring broke on, for any virtio device

The existing ``virtio_scsi_tmf_req`` and ``virtio_scsi_tmf_resp`` events
changed their arguments, so scripts that parse them need updating.  The
``subtype`` they print is the virtio-scsi TMF code: 0 ABORT TASK, 1 ABORT
TASK SET, 2 CLEAR ACA, 3 CLEAR TASK SET, 4 I_T NEXUS RESET, 5 LOGICAL
UNIT RESET, 6 QUERY TASK, 7 QUERY TASK SET.  The ``response`` is the
virtio-scsi response code: 0 means FUNCTION COMPLETE, 3 BAD TARGET, 10
FUNCTION SUCCEEDED, 11 FUNCTION REJECTED, 12 INCORRECT LUN.


Command-Line Tools
------------------

scsi-inject.py
^^^^^^^^^^^^^^

A high-level CLI for SCSI response injection and SCSI target faults.  It
handles binary SCSI response construction and base64 encoding internally.
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

Target fault commands.  Each maps to one QMP command; see `SCSI Target
Faults`_ for what the options mean.

``fault-add <adapter> <id> <target> [options]``
    Arm a fault with ``x-scsi-fault-add``.  The options are ``--lun``,
    ``--delay-ms``, ``--delay-max-ms``, ``--probability``,
    ``--max-hits``, ``--clear-on``, ``--below-clear`` and
    ``--tmf-hang-ms``, each passed through only when given, so QEMU's
    defaults apply otherwise::

        build/run scripts/scsi-inject.py -s /tmp/qmp.sock \
            fault-add scsi0 hang1 1 --clear-on target-reset

``fault-remove <adapter> [id]``
    Disarm one fault, or all of them, and print how many were removed.

``fault-list <adapter> [--json]``
    Print one line per armed fault -- where it is, how long it holds,
    what clears it, how many commands it holds now and has held in all,
    and the recovery attempts it has seen -- or with ``--json`` the raw
    QMP reply.

``fault-wait <adapter> <id> [--timeout SECONDS]``
    Wait for the fault's ``SCSI_FAULT_CLEARED`` event and print what
    cleared it and how many commands it held.  The adapter must be named
    exactly as it was given to ``fault-add``, since that is what the
    event reports.  See `QMP commands and events`_ for its exit
    statuses.


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
