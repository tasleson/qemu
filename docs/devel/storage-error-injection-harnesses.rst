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

=========================================== ======== ==========================
Harness                                     Driver   What it injects
=========================================== ======== ==========================
``fuzz-windows-inject-boot.py``             viostor  a grid of latency rules on
                                                     the boot disk, one boot per
                                                     grid point
``fuzz-windows-inject-scsi-reset.py``       vioscsi  stalls on several LUNs at
                                                     once, so their resets race
``fuzz-windows-inject-tail-latency.py``     vioscsi  hours of a few requests
                                                     held past the guest's
                                                     timeout
``fuzz-windows-inject-reset-inflight.py``   vioscsi  hours of stalls that only
                                                     the guest's own resets end
``fuzz-windows-inject-target-fault.py``     vioscsi  hours of SCSI target faults
                                                     in rotation, and the
                                                     ``--bsod`` reset-race
                                                     recipe
=========================================== ======== ==========================

The last three share their machinery, ``scripts/vioscsi_soak_common.py``,
described once below; the first two use parts of it.

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

``fuzz-windows-inject-boot.py`` boots the golden image from virtio-blk
rather than SATA, so the installed Windows has to be able to start from
a viostor disk.


The shared soak library
-----------------------

``scripts/vioscsi_soak_common.py`` is a library, not a script; it does
nothing on its own.  The tail-latency and reset-inflight harnesses are
thin wrappers around its soak driver, and the target-fault harness runs
its own loop on the library's parts.  This section describes what they
have in common, so the harness sections only cover what differs.

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

``cached-read``
    See `fuzz-windows-inject-target-fault.py`_ (target-fault only).

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

The tail-latency and reset-inflight harnesses take all of these;
target-fault takes the ones it needs (see its section).

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


fuzz-windows-inject-boot.py
---------------------------

Sweeps viostor's boot path through a grid of latency rules.  Each grid
point boots a fresh overlay of the golden image from a virtio-blk disk
behind inject-error node ``err0``, with one rule and possibly some timed
actions, and waits for the guest to finish booting or crash.

A rule armed when QEMU starts would mostly hit the firmware, which reads
the boot disk with its own virtio-blk driver long before Windows does.
So the harness traces ``virtio_set_status`` and arms rules, and times
actions, from the moment Windows' driver takes the device over -- seen as
the second reset and renegotiation of the same device -- where a grid
point asks for that.

Categories, each a family of grid points (``--dry-run`` lists them all;
124 in total):

======================= =======================================================
Category                What the grid varies
======================= =======================================================
``baseline``            nothing injected
``fixed-latency``       reads, writes or flushes delayed 50 ms to 10 s
``tail-latency``        0.1% to 2% of requests delayed, over ranges from
                        20-500 ms up to 200 ms-30 s
``stall``               reads, writes or flushes stalled for 2 to 60 s, then
                        ended by a release or by ``system_reset``
``timeout-success``     reads or writes held 35 to 90 s, then completed
``timeout-failure``     the same, then failed with EIO or ETIMEDOUT
``backend-disconnect``  everything stalled; after 5 to 30 s the held requests
                        are failed with EIO, 10 or 30 s later the rule is
                        removed, and half a second after that whatever it
                        held in between is completed
``flush-latency``       flushes delayed 0.5 to 30 s
``queue-saturation``    the first 4 to 256 reads, or requests of any kind,
                        stalled so the queue fills behind them
``out-of-order``        a random spread of hold times, up to 8 s
``reset-race``          reads or writes held and released 25 to 65 s in,
                        around the guest's timeout
======================= =======================================================

The sum of all delays one rule can add is capped at 3 minutes through
``max-hits``, and every boot at 10 minutes.

Options:

``--categories LIST``
    Comma-separated categories, or ``all`` (the default).

``--limit N``
    At most N grid points per category.

``--shuffle``
    Shuffle each category's grid points (before ``--limit``).

``--stop-on-first-crash``
    Stop at the first ``crash-suspected``.

``--dry-run``
    Print the grid and exit.

The VM has 8G and 4 vCPUs; neither can be changed from the command line.

Each grid point gets ``run-NNNN-<category>`` under ``$VM_DIR/fuzz``, with
``meta.json`` (the case and the full QEMU command line), the overlays,
``serial.log``, a screenshot and the ``virtio_set_status`` trace, all
deleted after a ``boot-ok``.  One JSON line per grid point is appended to
``results-<unix time>.jsonl`` in ``$VM_DIR/fuzz``; a grid point that
booted also has `the vioscsi driver record`_ of the golden image.  The
guest reads it off the boot disk, so the harness first removes the grid
point's rule and completes any request the rule still holds; the read
then neither waits out the rule's delays nor gets its error.  If that
fails, the record says why in ``disarm_error``.

======================= =======================================================
Outcome                 Meaning
======================= =======================================================
``boot-ok``             the guest agent answered after every action had run
``crash-suspected``     the screen stopped changing, without the agent
                        answering, for 90 seconds more than the 3-minute
                        cap on one rule's delays, which a slowed boot
                        screen can legitimately sit through; the first 20
                        seconds (the firmware splash) are not watched
``timeout``             neither within 10 minutes
``not-injected``        the guest booted before Windows' driver was seen
                        taking over, so the injection never happened
``inject-failed``       a QMP command to inject or act failed
``error``               the grid point could not be run
======================= =======================================================

At the end it lists the crash candidates, then every other grid point
that did not end in ``boot-ok``, each with its run directory.  The exit
status is 1 if any grid point ended in anything but ``boot-ok``, else 0.
A malformed command line exits with 2, from argparse; an unknown
category or a missing prerequisite exits with 1.


fuzz-windows-inject-scsi-reset.py
---------------------------------

Races concurrent LUN resets on one vioscsi adapter.  The suspected bug is
that vioscsi keeps one TMF buffer and one reset-in-progress flag per
adapter, so a second LUN's reset arriving while the first one's TMF is
still in flight can reuse state the device is still using.  QEMU answers
a single LUN reset quickly -- the reset drains the LUN, and draining ends
an inject-error stall at once -- so the lever is concurrency: stall
several LUNs at almost the same moment, let the guest's storport time
them all out together, and repeat under varying gaps and host load.

Each trial boots the golden image with ``--luns`` scratch LUNs on one
adapter, starts a writer per LUN, lets I/O settle, then arms a ``stall``
(or, with ``--mode delay``, a timed hold) rule on each LUN's node in turn
with ``gap-ms`` between them.  It holds for ``--run-timeout`` seconds
watching for a crash, releases the stalls, and waits up to
``--recovery-timeout`` for every LUN to be written to again.  With
``--cycles`` above 1 it repeats that in the same boot.

Options (defaults in brackets):

``--luns`` [3]
    LUNs on the shared adapter.

``--gaps-ms`` [0,5,20,50,100,250,500]
    Gaps between arming each LUN's stall, one sweep value per trial.

``--mode`` [stall]
    ``stall`` holds until released or reset, so the guest's timeout
    drives the race; ``delay`` holds for ``--delay-ms`` [70000] up to
    ``--delay-max-ms``.

``--repeat`` [3]
    Trials per gap.

``--run-timeout`` [90], ``--recovery-timeout`` [120]
    Seconds to hold, and to wait for recovery after release.

``--cycles`` [1], ``--inter-cycle-settle`` [2.0]
    Stall/reset/recover cycles per trial, and the clean I/O before each.

``--io-driver`` [powershell], ``--diskspd-path``
    ``powershell`` or ``diskspd``, as described above, except that
    diskspd here writes only (``-w100``) instead of a 50/50 mix.

``--tmf-delay-ms`` [0], ``--tmf-delay-count`` [0]
    Create the adapter with ``x-tmf-delay-ms`` and ``x-tmf-delay-count``
    so the first TMF responses are held back.  This turns the trial into
    an escalation experiment: nothing forces a second reset, and the
    trace shows whether storport sends one on its own while the first is
    held (``escalations_during_delay`` in the result).

``--ram`` [8G], ``--cpus`` [5], ``--host-pressure-cores``
    Guest size, and ``taskset`` cores for QEMU.

``--seed-base`` [1]
    Seed of the first trial; each later trial uses the next.

``--keep-all``, ``--stop-on-first-crash``, ``--dry-run``
    Keep artifacts of clean trials, stop at the first finding, or just
    print the trials.

Trials go in ``$VM_DIR/fuzz-scsi-reset/run-NNNN``, with
``windows-storage-trace-events`` traced to ``trace.log`` there when the
file exists, and one JSON line per trial in ``results-<unix
time>.jsonl``, with `the vioscsi driver record`_.  After each trial a
one-line summary of the TMFs and resets seen in the trace is printed.

``recovered``
    Every LUN was written to again after the release.

``crash-suspected``
    The guest went dark while stalled; its memory is dumped to
    ``crash.dmp``.

``recovered-unresponsive``
    The LUNs never resumed and the guest agent is gone; dumped.

``io-stuck``
    The guest agent answers but the LUNs never resumed; dumped.

``qemu-exited``
    QEMU exited.

``boot-failed``, ``no-io``, ``error``
    As for the soak harnesses.

The four after ``recovered`` are findings.  The exit status is 1 if
any trial ended in anything but ``recovered``, else 0.  As for the other
harnesses, a malformed command line exits with 2 and a rejected option
value or missing prerequisite with 1.


fuzz-windows-inject-tail-latency.py
-----------------------------------

The simplest soak: one VM for hours, and a single latency rule on every
LUN that holds a small fraction of reads and writes past Windows'
storport timeout (about 60 seconds) and then completes them normally.
The rule is in each LUN's ``-blockdev`` from the start (or, with
``--fill-wait``, armed once the LUNs are full) and is never changed.

Besides the common options:

``--probability`` [0.05]
    Fraction of matching requests held.

``--delay-ms`` [61000], ``--delay-max-ms`` [65000]
    Hold time, drawn from that range.

``--ops`` [read,write]
    Which operations the rule matches.

Expect bursts, not a steady rate.  With a deep queue, each outstanding
request rolls the dice many times a second, so nearly the whole queue is
caught by a hold at about the same moment: I/O runs for an instant, goes
dark for a minute, completes in one burst, and repeats.  That puts dozens
of requests past the guest's timeout at once, which is what provokes its
reset path.  Runs live in ``$VM_DIR/soak-tail-latency``.


fuzz-windows-inject-reset-inflight.py
-------------------------------------

Drives vioscsi through resets with a large, measured number of commands
outstanding.  Two rules go on every LUN, in this order since the first
match wins: a ``stall`` rule taking ``--stall-probability`` of requests,
which nothing in QEMU ever completes on its own, and a baseline rule that
slows every other request a little so the guest keeps issuing I/O.  The
stalled set grows until storport times the oldest out and escalates.
The LUN, target or adapter reset that follows drains the LUN, which wakes
every request the stall rule holds; the rules stay, and the cycle starts
again with no help from the host.

Every reset is a cycle in the result: its kind, when, on which adapter,
how many requests were held just before it (sampled with
``x-inject-error-delay-inflight``, so possibly a poll interval stale),
and which TMFs led up to it.  The summary prints the deepest hold seen
at a reset.

Besides the common options:

``--stall-probability`` [0.02]
    Fraction of requests stalled.  Higher reaches a reset sooner with
    fewer requests moving meanwhile.

``--baseline-delay-ms`` [5], ``--baseline-delay-max-ms`` [50]
    The hold for everything else.

``--ops`` [read,write]
    Which operations both rules match.

``--stall-budget-ms`` [300000]
    How long a stalled request may legitimately wait for a reset.  A
    stall has no hold time of its own, so this stands in for one when
    sizing the I/O probe, the dark-guest I/O threshold and paranoid's
    request timeout.

``--cycles N`` [0]
    End the run as ``cycles-complete`` once N resets of any kind have
    been seen; 0 runs for the whole duration.

``--release-after-reset-ms MS``
    Rather than leaving every completion to the reset's drain, release
    the adapter's held requests this long after a reset is seen, to land
    them at a chosen point in the driver's recovery.

Runs live in ``$VM_DIR/soak-reset-inflight``.


fuzz-windows-inject-target-fault.py
-----------------------------------

The latency harnesses' storage misbehaves on a timer, whatever the guest
does.  Real targets get stuck and stay stuck until the initiator does the
right recovery.  This harness uses :ref:`SCSI target faults
<storage-injection-target-faults>` for that: for hours, it takes one
target at a time -- picked at random with ``--seed`` -- arms a fault on
it in one of a rotating set of scenarios, waits until the guest's
recovery clears it (the ``SCSI_FAULT_CLEARED`` event) or a deadline
passes, cools down, and moves on.  Each fault holds commands before they
run, so a held write never reaches the disk and a recovery that cancels
it really does throw it away.

The VM must have at least two targets in all (``--adapters`` times
``--targets``): the dark-guest check watches the LUNs no fault holds.

Scenarios
^^^^^^^^^

=========================== ===================================================
Scenario                    The fault
=========================== ===================================================
``lun-reset-clears``        hung until a LUN reset; aborts cancel what it holds
                            but leave it hung
``abort-clears``            hung until the guest aborts a command to it, or does
                            anything stronger
``needs-target-reset``      hung until a target (I_T nexus) reset; LUN resets go
                            through but leave it hung
``reject-lun-reset``        hung until a target reset; LUN resets fail with
                            FUNCTION REJECTED
``hang-lun-reset``          hung until a target reset; a LUN reset gets no answer
                            for ``--tmf-hang-ms``, then goes through and leaves
                            it hung
``slow-target``             every command held 5 to 15 seconds then run, for
                            ``--window-s``
``late-completion``         ``--late-probability`` of commands held 61 to 65
                            seconds, past the guest's timeout, then run, for
                            ``--window-s``
``dead-target``             hung whatever the guest does, until the harness
                            removes it after ``--dead-target-s``
``late-dma``                target 0 hung, with LUN resets left hanging, until
                            the harness lets the held reads run
                            ``--late-dma-delay-s`` after its trigger
=========================== ===================================================

All but ``late-dma`` rotate by default.  ``late-dma`` makes a reset race
deliberate: a driver completing requests at a reset while the device
still owns their buffers.
It uses the two-fault arrangement from the last of the target fault
scenarios: a fault holding target 0's commands, and a second one with
probability 0 that only hangs LUN resets, both ``clear-on`` ``manual``.
When the trigger comes -- the first read the guest's readers see fail
(``--late-dma-release-after read-error``, the default with the cached-read
driver), by which time Windows should have given up on the read and
reused its pages, or the first recovery attempt the fault sees
(``recovery``, the default otherwise) -- the harness waits
``--late-dma-delay-s`` and removes the first fault, so the held reads run
and their data lands in memory the guest may already have reused, and
then the second.  A driver that completed those reads to Windows when it
reset should then bugcheck or corrupt data.

Each cycle in the result records how it ended -- ``recovered`` (with
``cleared_by`` and ``time_to_clear_s``, timed from when the fault was
armed), ``not-recovered`` (the guest didn't get there within
``--recovery-deadline-s``, or late-dma never saw its trigger),
``window-ended``, ``replaced`` (dead-target), ``released`` (late-dma, with
a ``late_dma`` record of when and why), ``removed`` (someone else removed
it over QMP), ``interrupted`` (the harness removed every fault for a
dump, a broken ring, an error or the end of the run) or ``arm-failed``
(three in a row end the run) -- with the commands it held, the recovery
attempts it saw, the TMFs the guest sent the target and the adapter
resets during it.  ``scenario_summary`` adds them up per scenario.

The cached-read driver
^^^^^^^^^^^^^^^^^^^^^^

``--io-driver cached-read`` formats every LUN NTFS before the soak and
writes one file to it, ``--cached-read-file-gib`` in size (default 1.25
times ``--ram``, so not even one LUN's file can stay cached), each chunk
stamped with its LUN and offset.  Readers then read the files over and
over through the file cache, so the LUN traffic is paging reads into
physical pages the memory manager recycles -- which is where a read that
completes after the driver gave up on it does damage.  Every chunk read
is checked; a failed read is counted, a wrong one ends the run as
``data-corruption``.  It needs nothing in the guest beyond the Storage
cmdlets, but formatting and writing the files takes a while, especially
on NFS-backed images.

The --bsod recipe
^^^^^^^^^^^^^^^^^

``--bsod`` puts this together into one run meant to bugcheck a vioscsi
that completes requests the device still owns.  It runs only
``late-dma`` cycles with the cached-read driver and ``hv-crash``, turns
``--stop-on-broken`` off, and doesn't end the run for a writer exiting.  Unless given explicitly, it also sets ``--ram`` to 4G,
``--recovery-deadline-s`` to 900 and the layout to 2 adapters of 1
target.  It ends as ``guest-panicked`` at the first bugcheck, with the
STOP code and parameters printed and in ``guest_panic``, and the dump in
``panic.dmp``; as ``data-corruption`` if ``--bsod-cycles`` cycles pass
without one but a reader read back wrong data; as ``cycles-complete`` if
they pass clean.  A broken ring doesn't end it at once: the harness
removes every fault and keeps watching for 300 seconds, so a bugcheck
the break leads to still ends the run as ``guest-panicked``; if none
comes, it ends as ``virtio-broken``.

To compare drivers, run ``--bsod`` once with each build installed in the
golden image: the upstream driver is expected to bugcheck, and one that
waits for the TMF response before completing anything (reset_via_tmf) to
survive.  `The vioscsi driver record`_ in each result says which build
a run had.

Options
^^^^^^^

The common options apply, except ``--watch-after-break``, ``--fill-wait``,
``--fill-timeout-minutes`` and ``--paranoid-path``; ``--io-driver`` takes
``powershell``, ``diskspd``, ``fio`` or ``cached-read``.  Several
defaults differ: ``--targets`` is 2, ``--ram`` is 8G (4G under
``--bsod``), and ``--seed`` (1) seeds only the choice of target --
QEMU picks which commands a probability or delay fault holds on its own,
with no seed.  In addition:

``--hv-crash`` / ``--no-hv-crash`` (on)
    Give the guest the Hyper-V crash MSRs and run QEMU with
    ``-action panic=pause``, so a bugcheck pauses the VM as
    ``guest-panicked`` and the run ends with the STOP code, a screenshot
    and ``panic.dmp``, rather than being noticed later as
    ``crash-suspected``.  ``--bsod`` needs it.

``--scenarios LIST``
    Scenarios to rotate through, in order (default all but late-dma;
    late-dma alone under ``--bsod``).

``--recovery-deadline-s`` [300, 900 under --bsod]
    How long a scenario waiting for recovery gets before the harness
    removes the fault and records ``not-recovered``, and how long
    late-dma waits for its trigger.

``--late-dma-delay-s`` [10.0], ``--late-dma-release-after``
    See late-dma above.

``--bsod``, ``--bsod-cycles`` [3]
    See the recipe above.

``--window-s`` [300.0]
    How long slow-target and late-completion stay armed.

``--dead-target-s`` [240.0]
    How long dead-target stays dead.

``--cooldown-s`` [60.0]
    Pause between one cycle ending and the next starting.

``--tmf-hang-ms`` [30000]
    How long hang-lun-reset leaves a LUN reset unanswered.

``--late-probability`` [0.05]
    Fraction of commands late-completion holds.

``--cached-read-file-gib``
    Size of each LUN's file for cached-read.

Runs live in ``$VM_DIR/soak-target-fault``.  With ``--stop-on-broken``,
the dump at a break removes every fault and no more are armed for the
rest of the run.
