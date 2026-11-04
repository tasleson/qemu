Windows Storage Driver Harnesses
================================

The injection mechanisms in :doc:`storage-error-injection` are building
blocks.  This page documents the harnesses built on them to test the
Windows VirtIO storage drivers, ``viostor`` (virtio-blk) and ``vioscsi``
(virtio-scsi), from the kvm-guest-drivers-windows project.  Each harness
boots a Windows guest from a prepared golden image, drives I/O inside it
through the QEMU guest agent, injects a particular kind of misbehaving
storage, and watches for the guest bugchecking, hanging, corrupting data,
or breaking a virtio ring.  They are host-side Python scripts that need
nothing in the guest beyond the drivers, the guest agent, and optionally
an I/O tool.

The harnesses share their machinery, ``scripts/vioscsi_soak_common.py``,
described once below.

.. contents:: Contents
   :local:
   :depth: 2


Setting up the Windows guest
----------------------------

``scripts/setup-windows-inject-vm.sh`` creates and runs the Windows VM
whose installed disk becomes the golden image every harness boots from::

    scripts/setup-windows-inject-vm.sh create      # disks, NVRAM
    WIN_ISO=/path/to/Win11.iso \
        scripts/setup-windows-inject-vm.sh install  # boot the installer
    scripts/setup-windows-inject-vm.sh run          # boot the installed system
    scripts/setup-windows-inject-vm.sh build-run    # rebuild QEMU, then run
    scripts/setup-windows-inject-vm.sh status       # disks, firmware, sockets

Host prerequisites
^^^^^^^^^^^^^^^^^^

- A QEMU build in ``$HOME/projects/qemu/build``.  This script has that
  path built in; the harnesses instead find the build next to themselves
  (see `Environment`_).
- KVM.
- UEFI firmware with Secure Boot at the Fedora ``edk2-ovmf`` paths,
  ``/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2`` and
  ``OVMF_VARS_4M.secboot.qcow2``.  ``create`` copies the second to
  ``OVMF_VARS.qcow2`` in the VM directory.
- ``swtpm``, for the TPM 2.0 Windows 11 requires.  State lives in ``tpm/``
  in the VM directory; ``run`` starts swtpm itself.
- The virtio-win driver ISO saved as ``virtio-win.iso`` in the VM
  directory (``create`` prints the download URL if it is missing).  It is
  attached as a CD-ROM on every boot, and ``install`` refuses to run
  without it.
- A Windows installer ISO, by default
  ``$HOME/Downloads/Win11_25H2_English_x64_v2.iso`` or ``WIN_ISO``.
- The ``virbr0`` bridge (libvirt's default network) and
  ``/usr/libexec/qemu-bridge-helper`` allowed to use it, for the setup
  VM's network.  The harnesses give their VMs no network.
- A GTK display.

The VM directory is ``$HOME/VirtualMachines/qemu/windows_inject``.

The VM
^^^^^^

A q35 machine with KVM, SMM and Secure Boot, ``-cpu host`` with the usual
Hyper-V enlightenments, 8G of RAM and 4 vCPUs by default, a TPM, a
``vmcoreinfo`` device for crash dumps, a guest agent channel, and these
disks, each behind an inject-error filter:

====== ============== =========== ==================================== ======
Node   Device ID      Controller  Image                                Size
====== ============== =========== ==================================== ======
err0   disk0          AHCI (SATA) ``boot.qcow2``, the Windows install  80G
err1   diskblk1       virtio-blk  ``blk-data1.qcow2``                  20G
err2   disk1          virtio-scsi ``scsi-disk1.qcow2`` (target 0)      20G
err3   disk2          virtio-scsi ``scsi-disk2.qcow2`` (target 1)      20G
====== ============== =========== ==================================== ======

The boot disk is SATA so that Windows Setup sees it without extra
drivers and booting does not depend on a driver under test.  The
virtio-scsi adapter is ``scsi0``.  QMP is ``qmp.sock`` and the guest
agent ``qga.sock`` in the VM directory; the QEMU monitor is on stdio.

Environment variables:

``WIN_ISO``
    Installer ISO for ``install``.

``RAM``, ``CPUS``
    Guest memory (default 8G) and vCPUs (default 4).

``TRACE_EVENTS``, ``NO_TRACE``
    Tracing is on by default, with ``scripts/windows-storage-trace-events``
    (see :ref:`storage-injection-tracepoints`) written to ``trace.log`` in
    the VM directory.  ``TRACE_EVENTS`` names another events file;
    setting ``NO_TRACE`` to anything turns tracing off.

``BOOT_DELAY_ERR0`` to ``BOOT_DELAY_ERR3``
    Latency rules armed on that node when the VM starts, so they are in
    effect from the guest's very first I/O, including firmware and boot.
    One or more rules separated by ``;``, each a comma-separated list of
    rule options (``id``, ``ops``, ``sector``, ``count``,
    ``probability``, ``delay-ms``, ``delay-max-ms``, ``stall``,
    ``errno``, ``max-hits``), with several ``ops`` joined by ``+``::

        BOOT_DELAY_ERR1="id=tail,ops=read+write,probability=0.01,delay-ms=20,delay-max-ms=2000" \
            scripts/setup-windows-inject-vm.sh run

    The values are not checked by the script; QEMU rejects a bad one at
    startup.

``BOOT_DELAY_SEED``
    The ``seed`` given to every node that has a ``BOOT_DELAY_ERR*`` rule.

Unknown commands print the usage and exit with status 1.

One-time guest setup
^^^^^^^^^^^^^^^^^^^^

Install Windows to the SATA disk, then, from the virtio-win CD:

1. Install the ``vioscsi`` driver once Windows shows the virtio-scsi
   controller, and ``viostor`` for the virtio-blk disk.  The harnesses
   attach their own, new controllers and disks; a driver installed once
   binds to them.
2. Install the virtio-serial driver and ``qemu-ga``
   (``guest-agent\qemu-ga-x86_64.msi``).  The harnesses detect a booted
   guest by its answering ``guest-ping``, and launch all guest I/O
   through it.
3. Disable automatic restart after a bugcheck, from an elevated
   PowerShell, so a crashed guest stays at its blue screen where the
   harness can see it::

       Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name AutoReboot -Value 0

4. Optionally install the ``fwcfg`` driver.  QEMU's ``dump-guest-memory``
   writes Windows crash dumps (``format=win-dmp``) using what the guest
   publishes through ``vmcoreinfo``, and without that driver the dumps
   are not fully symbolized (see kvm-guest-drivers-windows issue 877).
5. Optionally copy in the I/O tools a harness's ``--io-driver`` can use:
   ``diskspd.exe`` (default ``C:\Tools\diskspd.exe``), a Windows
   ``fio.exe`` (default ``C:\Program Files\fio\fio.exe``),
   ``paranoid.exe`` (default ``C:\test\paranoid.exe``), and a vioscsi
   telemetry script (default ``C:\test\GetVioScsiTelemetry.ps1``).
6. Shut down cleanly.  ``boot.qcow2``, ``OVMF_VARS.qcow2`` and ``tpm/``
   are now the golden image.  The harnesses never write to them: every
   run boots from overlays and a copy of the TPM state.



The shared soak library
-----------------------

``scripts/vioscsi_soak_common.py`` is a library, not a script; it does
nothing on its own.  The soak harnesses are thin wrappers around its
soak driver, or run their own loop on the library's parts.  This section
describes what they have in common, so the harness sections only cover
what differs.

Environment
^^^^^^^^^^^

The harnesses do not depend on the user's home directory layout beyond
these defaults, each overridable from the environment:

============== ===============================================================
Variable       Default
============== ===============================================================
``QEMU_SRC``   the checkout the script is in
``QEMU_BUILD`` ``$QEMU_SRC/build``; ``qemu-system-x86_64``, ``qemu-img`` and
               the ``pyvenv`` providing ``qemu.qmp`` come from here
``VM_DIR``     ``$HOME/VirtualMachines/qemu/windows_inject``, where the golden
               image is and under which each harness keeps its runs
``OVMF_CODE``  ``/usr/share/edk2/ovmf/OVMF_CODE_4M.secboot.qcow2``
============== ===============================================================

Build QEMU first: the harnesses import ``qemu.qmp`` from the build's
``pyvenv`` and exit with an error if it is not there, or if the golden
``boot.qcow2``, ``OVMF_VARS.qcow2`` or the QEMU binary is missing.
``swtpm`` is needed on the host, ``taskset`` for
``--host-pressure-cores``, and ``gdb`` to capture QEMU's thread stacks
when a dump hangs (optional).

The VM a soak boots
^^^^^^^^^^^^^^^^^^^

Each run gets a directory ``run-<unix time>`` under the harness's own
directory in ``VM_DIR``.  In it go a qcow2 overlay of the golden
``boot.qcow2``, one of ``OVMF_VARS.qcow2``, a private copy of the golden
TPM state (so several harnesses can run at once), and the run's sockets
and logs.

The VM is the setup VM minus its display, network and data disks: the
same machine, firmware and TPM, the boot disk on SATA behind an
inject-error node with no rules, ``-display none``, the serial port
logged to ``serial.log``, and QEMU's output, including traces, in
``qemu.log`` with timestamps (``-msg timestamp=on``).  To it the harness
adds ``--adapters`` virtio-scsi-pci adapters (``scsi0``, ``scsi1``, ...),
each with ``--targets`` targets of ``--luns-per-target`` LUNs.  Every LUN
is a fresh, empty 4G qcow2 image behind its own inject-error node seeded
with ``--seed``, attached as a ``scsi-hd`` with a unique serial number.
By default each adapter gets its own iothread, so LUN I/O doesn't share
the main loop with the guest agent and QMP; ``--iothreads N`` creates N
iothreads assigned round-robin, and 0 keeps everything in the main loop.

Unless turned off, the adapters are created with ``x-stop-on-broken=on``
(``--stop-on-broken``) and the virtio-scsi TMF, reset and broken-ring
trace events are enabled (``--tmf-trace``); see
:ref:`storage-injection-virtio-scsi`.  ``--no-ring-diag`` creates them
with ``x-diag=off``.  ``--qga-trace`` (on by default) also enables trace
events for the guest agent's virtio-serial port, so a silent agent can be
told apart from a lost reply.

The guest side
^^^^^^^^^^^^^^

After boot, which must happen within 180 seconds of starting QEMU (the
guest agent answering ``guest-ping``), the harness reads which vioscsi
driver the guest has (`The vioscsi driver record`_), asks the guest over
the agent which ``PhysicalDriveN`` has each LUN's serial number, and
starts a writer for each LUN.  ``--io-driver`` picks the writer:

``powershell`` (default)
    A built-in PowerShell loop writing 64 KiB blocks, round-robin over
    the first 32 MiB of the raw disk, one write at a time with a flush
    after each.  Writes only, and nothing is verified.

``diskspd``
    ``diskspd.exe`` on the raw disk: 50% writes, 64 KiB blocks, 4
    threads with 32 outstanding I/Os each, caching disabled.

``fio``
    ``fio.exe`` on the raw disk: random 50/50 read/write, 64 KiB blocks
    over 32 MiB, direct I/O at queue depth 128, with crc32c verification
    that stops at the first mismatch.

``paranoid``
    One ``paranoid.exe`` over every LUN at once: a 50/50 random mix that
    verifies what it reads and stops at the first mismatch, after first
    writing every LUN end to end.  Its per-request timeout is set past the
    longest hold the harness's rules can cause.  (tail-latency and
    reset-inflight only.)

The deep-queue drivers matter for the reset harnesses: a stall then
holds dozens of commands per LUN rather than one.  ``fio`` and
``paranoid`` are the verifying drivers, and only for them does a writer
exiting early end the run: as ``data-corruption`` if it read back data
that did not match, ``io-error`` if a request was failed to it, or
``writer-exited`` if neither can be told.  Each writer's output is kept
as ``writer-<pid>.stdout.log`` and ``.stderr.log``; paranoid's failure
evidence is fetched from the guest as ``paranoid-disk<N>.jsonl``.

Five seconds after the writers start, a pre-flight probe checks that the
LUNs are being written to, over a window of the longest hold the rules
can cause plus 10 seconds so that it spans a whole burst cycle, trying
twice if need be; less than 2 writes per second in all
ends the run as ``no-io``.  With ``--fill-wait`` (on by default for
``paranoid``, whose first pass fills the disks) the rules are left out of
the command line and armed over QMP only once every LUN image has grown
to its full size on the host, so that pass runs at full speed;
``--fill-timeout-minutes`` (default 120) bounds the wait, and a fill that
stalls for 10 minutes or times out ends the run as ``fill-failed``.

The vioscsi driver record
^^^^^^^^^^^^^^^^^^^^^^^^^

Every Windows harness, the boot and scsi-reset ones included, reads from
the guest which vioscsi build it has and keeps that as ``vioscsi_driver``
in its result, so results from different builds can't be mixed up.  It
holds the driver version and date of each vioscsi device, the
``vioscsi.sys`` path, file version and SHA-256, the service's state, and
``action_on_reset``: the ``VioscsiActionOnReset`` value in
``HKLM\SYSTEM\CurrentControlSet\Services\vioscsi\Parameters\Device``.
That value picks what the driver does with a reset (0 complete-requests,
1 do-nothing, 2 send-tmf in reset_via_tmf builds only, ``0xDEADDEAD``
bugcheck), so one set by hand in the golden image changes what every
reset in a run does.  ``action_on_reset`` is ``{"set": false, "value":
null}`` when the value is absent, and the driver's own default applies.
Otherwise it has ``"set": true``, the registry ``kind``, the ``value``
(a ``REG_DWORD`` as an unsigned number, any other kind as its text) and a
``name``: what the driver does for a value it defines, ``unknown, 0x...``
for a ``REG_DWORD`` it doesn't, and ``not a REG_DWORD`` or ``not a
number`` when the driver couldn't read it as one.  It is ``null`` if the
guest couldn't read the registry; ``errors`` then says why.  The
harnesses only read it; none of them sets it.  The record is printed as
one line, for example::

    vioscsi driver: 100.95.104.26200 (2024-09-30), vioscsi.sys 100.95.104.26200 sha256 3F...; VioscsiActionOnReset = 1 (do-nothing)

A guest without a vioscsi device, such as the boot fuzzer's, gives ``no
vioscsi device present`` rather than an error.  If the guest's script
fails or its output can't be parsed, ``vioscsi_driver`` holds an
``error`` and the run goes ahead.  A guest agent that stops answering
fails the run as it would at any first guest-exec, except in the boot
fuzzer, which reads the record only after its verdict and never lets it
change the outcome.

During the soak
^^^^^^^^^^^^^^^

Every two seconds the harness reads ``qemu.log``, checks QEMU is alive,
and samples the guest.  It ends the run when:

- QEMU reports a virtio-scsi ring broken (``virtio-broken``).  With
  ``--stop-on-broken`` the VM is paused at the break; the harness writes a
  Windows crash dump of it to ``break.dmp``, removing the injection
  first since the dump drains every disk, and then resumes it.  The
  broken-ring diagnostics from the trace are attached to the result,
  along with each adapter's recent TMFs.  ``--watch-after-break MINUTES``
  then keeps the guest running that long to see whether it goes on to
  bugcheck, saving a screenshot a minute as ``watch-NNN.ppm`` and the
  bugcheck, if any, as ``panic.dmp``.
- The guest goes dark: the guest agent has not answered for 15 seconds,
  the screen has not changed for 20 seconds, and no LUN has completed a
  write for the longest hold plus 30 seconds.  That is
  ``crash-suspected``; the harness takes ``screen.ppm`` and dumps guest
  memory to ``crash.dmp``.
- The guest reports a bugcheck through ``hv-crash``, which every run
  enables with ``-action panic=pause`` (``guest-panicked``).  The STOP
  code and parameters go in the result's ``guest_panic``, and the
  harness takes a screenshot and dumps guest memory to ``panic.dmp``.
- QEMU exits (``qemu-exited``).
- A verifying writer exits, as above.
- The harness's own condition is met (``cycles-complete``).
- The duration runs out (``completed``).

Every ``--heartbeat-seconds`` (default 300) it prints and records a
progress line with the write rate since the last one, which swings with
the holds: keep it well above the longest hold.  ``status.json`` in the
run directory always holds the result so far, so a long run can be
followed while it goes.

``--dump-on-agent-stall`` dumps guest memory to ``crash.dmp`` as soon as
the agent fails to answer a request before the soak starts (resolving
drives, launching a writer), while the guest is still stuck, instead of
only after it has stayed silent for the whole probe.  That takes minutes,
needs about the guest's RAM in disk space, and removes the injection.

When the run ends, the harness runs the guest telemetry script
(``--vioscsi-telemetry-script``, an empty string to skip) and saves its
output as ``vioscsi-telemetry.log``, stops the writers, and shuts QEMU
down.

Results and exit status
^^^^^^^^^^^^^^^^^^^^^^^

The result is written to ``result-<unix time>.json`` next to the run
directories, and the outcome printed.  It holds the outcome and elapsed
time, the harness's rule settings, what the harness measured, the writers' states,
QEMU's error output, the virtio-scsi trace tallies (``tmf_trace``,
``broken_events``, ``req_overlaps``) and the paths of whatever artifacts
were kept.  The run directory also has ``meta.json``, the configuration
as the run started.

======================= ======================================================
Outcome                 Meaning
======================= ======================================================
``completed``           ran the whole duration without a finding
``cycles-complete``     the harness stopped early on purpose, without a finding
``crash-suspected``     the guest went dark
``guest-panicked``      the guest reported a bugcheck through hv-crash
``virtio-broken``       a virtio-scsi ring broke
``data-corruption``     data read back did not match what was written
``io-error``            a verifying writer had a request failed
``writer-exited``       a verifying writer exited for another reason
``qemu-exited``         QEMU exited during the run
``no-io``               the writers never got going
``fill-failed``         ``--fill-wait`` never saw the LUNs fill
``boot-failed``         the guest agent never answered after boot
``error``               the harness itself failed
======================= ======================================================

After ``completed`` or ``cycles-complete`` the overlays, LUN images and
screenshot are deleted unless ``--keep-all`` is given; after anything
else everything is kept.  ``--disk-dir`` puts the LUN images somewhere
other than the run directory, for instance on faster storage.

The exit status is 0 for ``completed`` and ``cycles-complete``, and 1 for
every other outcome, in which case the artifact directory is printed.
Before anything starts, argparse rejects a malformed command line (an
unknown option, a missing or non-numeric value) with status 2, while an
option value the harness itself rejects (``--ops bogus``, say) or a
missing prerequisite exits with 1.

Options every soak harness has
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The harnesses built on the library's soak driver take all of these.

``--tmf-trace`` / ``--no-tmf-trace`` (on)
    Trace TMFs, resets and broken rings per adapter.

``--stop-on-broken`` / ``--no-stop-on-broken`` (on)
    Pause and dump at a ring break.

``--watch-after-break MINUTES`` (0)
    Keep watching after a break, as above.

``--ring-diag`` / ``--no-ring-diag`` (on)
    ``x-diag``; off to measure the diagnostics' effect on timing.

``--dump-on-agent-stall`` / ``--no-dump-on-agent-stall`` (off)
    Dump at once when the agent stalls before the soak.

``--qga-trace`` / ``--no-qga-trace`` (on)
    Trace the guest agent's port.

``--iothreads N`` (one per adapter)
    How many iothreads to create.

``--adapters`` (1), ``--targets`` (1), ``--luns-per-target`` (1)
    The LUN layout; at most 256 targets and 16384 LUNs per target.

``--duration-hours`` (4.0)
    How long to soak.

``--io-driver`` (``powershell``), ``--diskspd-path``, ``--fio-path``, ``--paranoid-path``
    The writer and where its executable is in the guest.

``--fill-wait`` / ``--no-fill-wait``, ``--fill-timeout-minutes`` (120)
    Wait for the LUNs to fill before arming the rules.

``--vioscsi-telemetry-script`` (``C:\test\GetVioScsiTelemetry.ps1``)
    Guest script whose output is collected at the end.

``--heartbeat-seconds`` (300)
    Progress line interval.

``--ram`` (8G), ``--cpus`` (5)
    Guest size.

``--host-pressure-cores CPULIST``
    Run QEMU under ``taskset -c CPULIST``, to squeeze it onto a few host
    cores and widen race windows.

``--seed`` (1)
    The inject-error PRNG seed for every LUN.

``--disk-dir DIR``, ``--keep-all``
    Where the LUN images go, and whether to keep them after a clean run.
