================================================
QEMU -- Storage Error Injection Branch
================================================

This is an experimental fork/branch of `QEMU <https://www.qemu.org/>`_ for
testing how guest operating systems and storage management software handle
storage hardware errors and unusual device responses.

It adds these injection mechanisms, each controlled at runtime via QMP
except where noted:

- **Block-layer I/O error and latency injection** -- a filter driver
  (``inject-error``) that sits in front of any disk image.  It returns errors
  (EIO, ENOSPC, etc.) for configurable sector ranges, simulating bad sectors
  and media failures, and it can hold requests -- for a fixed time, a random
  time, or indefinitely -- to simulate slow, stalled and timing-out storage.

- **SCSI target faults** -- make a SCSI target, or one LUN of it, stop
  answering on a virtio-scsi adapter until the guest performs the error
  recovery that brings it back (an abort, a LUN reset, a target reset, an
  adapter reset), with lesser recovery attempts going through, being
  rejected, or left unanswered.

- **virtio-scsi TMF delay and broken-ring diagnostics** -- device
  properties (``x-tmf-delay-ms``/``-count``, ``x-diag``,
  ``x-stop-on-broken``) that hold back task management responses, and
  record and explain what a request ring looked like when the device gave
  up on it, optionally pausing the VM at that moment.

- **SCSI response injection** -- overrides for INQUIRY and MODE SENSE
  responses on emulated SCSI devices, allowing you to present arbitrary
  vendor strings, serial numbers, VPD pages, and mode pages to the guest.

- **NVMe response injection** -- overrides for Identify Controller and
  Identify Namespace data, or an error status for those commands.

- **ATA response injection** -- overrides for IDENTIFY DEVICE and SMART
  data on IDE and SATA disks, or ATA errors for those commands.

- **SD/MMC response injection** -- overrides for an SD or eMMC card's CID
  and CSD registers, and error bits in the card status it reports.

It also adds tracepoints for the requests and recovery these exercise,
and helper scripts: command-line clients (``scripts/inject-error.py``,
``scripts/scsi-inject.py``), Linux and Windows test VM setup scripts, and
long-running harnesses for the Windows ``viostor`` and ``vioscsi`` drivers.

Background
==========

This branch grew out of an earlier experiment, the `block_error_inject
<https://github.com/tasleson/qemu/tree/block_error_inject>`_ branch, which
I gave a talk on at the 2020 linux.conf.au titled `VM block error injection, a novel
approach for testing Linux storage
<https://www.youtube.com/watch?v=dgY6iIaqiOY>`_.  That branch added a QMP
interface for marking block ranges bad, and had the emulated SCSI, NVMe and
AHCI devices report media errors for them, so a guest's storage stack could
be tested against a failing disk without failing hardware.

The work here starts from the same idea and broadens it.  Errors come from a
block filter driver that works under any disk device rather than from code in
each device model; latency, stalls and late completions join hard errors;
devices can be made to return arbitrary identification data; and a SCSI
target can stop answering until the guest carries out the recovery that
brings it back.

What you can do with this
=========================

- Simulate bad sectors (persistent, transient, or fix-on-write) on any
  virtual disk and observe how the guest kernel, filesystem, and userspace
  tools react.

- Inject arbitrarily long or malformed SCSI serial numbers, device
  identifiers, and INQUIRY responses to fuzz tools like ``sg_inq``,
  ``lsscsi``, ``udev``, ``multipathd``, and ``libstoragemgmt``.

- Override MODE SENSE pages to test how guest drivers handle unexpected
  caching, geometry, or device characteristic responses.

- Feed malformed NVMe Identify, ATA IDENTIFY/SMART, or SD CID/CSD data to
  ``nvme-cli``, ``hdparm``, ``smartctl``, the guest kernel's probing code
  and anything else that parses them.

- Hold I/O requests to reproduce the timing failures that guest storage
  drivers are worst at: fixed and tail latency, complete stalls, completions
  that arrive after the guest has already timed the request out, flush-only
  latency, queue saturation, out-of-order completion, and completions racing
  a device reset.  Requests are held asynchronously, so the guest keeps
  running and takes its own recovery paths.

- Exercise a SCSI driver's whole error escalation path against targets
  that need a particular kind of reset to come back, and see which
  recovery cleared each fault and how long it took.

- Catch a guest driver handing a virtio-scsi device a request it no
  longer owns, with the ring frozen at the moment of the break.

- Spin up a ready-made Linux test VM with SCSI disks behind inject-error
  filters, or one with a disk on every storage controller QEMU emulates on
  x86, using the included setup scripts.

- Run hours-long, unattended soak tests of the Windows ``vioscsi`` driver
  under tail latency, stalls that only its resets end, and rotating target
  faults, including a recipe that bugchecks a driver which completes
  requests on reset that the device still owns.

Documentation
=============

- `docs/devel/storage-error-injection.rst
  <docs/devel/storage-error-injection.rst>`_ -- every mechanism: QMP
  commands, device properties, tracepoints, the command-line clients, the
  Linux test VMs, and an end-to-end walkthrough.

- `docs/devel/storage-error-injection-harnesses.rst
  <docs/devel/storage-error-injection-harnesses.rst>`_ -- the Windows guest
  setup and the ``fuzz-windows-inject-*`` harnesses.

All QMP commands added here carry an ``x-`` prefix and the ``unstable``
feature, and none of the injected state is migrated.


Building
========

Standard QEMU build process:

.. code-block:: shell

  mkdir build
  cd build
  ../configure
  make

See the `QEMU build documentation <https://wiki.qemu.org/Hosts/Linux>`_ for
platform-specific details.


Upstream QEMU
=============

This branch is based on upstream QEMU.  For general QEMU documentation,
bug tracking, and contribution guidelines, see:


* `QEMU website <https://www.qemu.org/>`_
* `QEMU source <https://gitlab.com/qemu-project/qemu.git>`_
* `QEMU documentation <https://www.qemu.org/docs/master/>`_

QEMU is released under the GNU General Public License, version 2.
See the LICENSE file for details.


Branches
========

``storage-error-injection`` is a moving branch: it is periodically rebased
onto a newer upstream QEMU stable release, and force-pushed.  Pull it with
``git pull --rebase``, or re-fetch it, rather than merging into it.

Before each rebase, the state of the branch on its previous base is kept as
``storage-error-injection/<version>``, for example
``storage-error-injection/v11.1.0``.  Those branches are never rewritten, so
use one if you need a base that will not move under you, or to see what a
rebase changed:

.. code-block:: shell

  git range-diff v11.1.0..storage-error-injection/v11.1.0 \
                 v11.2.0..storage-error-injection
