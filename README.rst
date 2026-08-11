================================================
QEMU -- Storage Error Injection Branch
================================================

This is an experimental fork/branch of `QEMU <https://www.qemu.org/>`_ for
testing how guest operating systems and storage management software handle
storage hardware errors and unusual device responses.

It adds two runtime-controllable injection mechanisms:

- **Block-layer I/O error injection** -- a filter driver (``inject-error``)
  that sits in front of any disk image and returns errors (EIO, ENOSPC, etc.)
  for configurable sector ranges, simulating bad sectors and media failures.

- **SCSI response injection** -- overrides for INQUIRY and MODE SENSE
  responses on emulated SCSI devices, allowing you to present arbitrary
  vendor strings, serial numbers, VPD pages, and mode pages to the guest.

Both are controlled at runtime via QMP commands and come with CLI helper
scripts for interactive use.

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

- Spin up a ready-made test VM with multiple SCSI disks behind
  inject-error filters using the included setup script.

For full details -- QMP commands, CLI usage, VM setup, and an end-to-end
walkthrough -- see `docs/devel/storage-error-injection.rst
<docs/devel/storage-error-injection.rst>`_.


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
