# vioscsi BSOD investigation: triage and reset-race theory

🤖 Assisted-by: Claude Code (Claude Opus 5.5)

This document summarizes an investigation into a cluster of Windows guest
BSOD reports that all mention `virtio-scsi`, filed against
[virtio-win/kvm-guest-drivers-windows](https://github.com/virtio-win/kvm-guest-drivers-windows).
It exists to let a human or an AI agent pick this work back up without
re-deriving it from scratch. The reproduction harnesses it produced are
the `scripts/fuzz-windows-inject-*.py` scripts; see
[storage-error-injection.rst](storage-error-injection.rst) for the
underlying `inject-error` tooling it's built on.

## The issues

| # | Title | Bugcheck | Status |
|---|---|---|---|
| [877](https://github.com/virtio-win/kvm-guest-drivers-windows/issues/877) | BSOD with virtio-scsi (PassMark stress) | PFN_LIST_CORRUPT / CRITICAL_PROCESS_DIED | Unreproduced by Red Hat QE; no dump ever captured |
| [893](https://github.com/virtio-win/kvm-guest-drivers-windows/issues/893) | WS2022 BSOD on startup after updates | SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7E) | Root-caused, reliably reproducible |
| [1405](https://github.com/virtio-win/kvm-guest-drivers-windows/issues/1405) | vioscsi.sys BSOD on shutdown | DRIVER_POWER_STATE_FAILURE (0x9F) | Weak attribution to vioscsi |
| [1367](https://github.com/virtio-win/kvm-guest-drivers-windows/issues/1367) | vioscsi BSOD after CPU benchmark | VIDEO_DXGKRNL_FATAL_ERROR | Likely mistagged, not storage-related |
| [1014](https://github.com/virtio-win/kvm-guest-drivers-windows/issues/1014) | Stable BSODs copying large amounts of data | PAGE_HASH_ERRORS_INPAGE / CRITICAL_PROCESS_DIED | Unreproduced; best lead for a real driver bug |

**These are not one bug.** They're five different symptoms that happen to
share the `vioscsi` label. Triage detail:

- **#893 — solved, just not shipped-fixed.** The crash is a genuine
  divide-by-zero in Microsoft's own `pci.sys`
  (`PciGetMessageAffinityMask`), triggered when a guest has ≥2 CPU
  sockets, a NUMA node with zero vCPUs assigned, and a virtio device
  (scsi or blk) — exposed by a specific Windows Server 2022 update
  (KB5023705 / KB5026370). Reliable repro and workarounds exist (see the
  issue thread, comment from `frwbr`). Belongs in a Microsoft bug report,
  not a vioscsi fix.
- **#1014 — the most promising lead for an actual vioscsi bug.** BSODs
  and `Reset to device \Device\RaidPortN` events during large sustained
  copies to a virtio-scsi/virtio-blk disk backed by a slow ZFS zvol
  (dedup enabled). This is what motivated the source-level analysis
  below.
- **#1405 — weak attribution.** WinDbg blames `vioscsi.sys` because it
  owns the blocked device stack, but the reporter's own IRP inspection
  traced the actual stall into the audio stack. Driver build was ~6
  years old at time of report.
- **#1367 — likely not a vioscsi bug at all.** Reporter confirmed it also
  happens with virtio-blk; the bugcheck (`VIDEO_DXGKRNL_FATAL_ERROR`) is
  a GPU/WDDM fault; a second reporter's crash (during driver install) was
  fixed by switching CPU model from `host` to `qemu x86-64-v3`. Points to
  an AMD EPYC CPU-passthrough issue, unrelated to storage.
- **#877 — unreproduced, needs live data.** Red Hat QE tried multiple
  backend/config variations without success. No usable dump was ever
  obtained — see the crash-dump-collection recipe below, which addresses
  exactly this gap.

## The reset path (targeting #1014 / #877)

Reading the `vioscsi` driver source shows how "slow storage" can turn
into a corruption-class bugcheck through the driver's own timeout/reset
handling, rather than storage latency being fatal on its own. Driver
references below are to
[d92b9c07](https://github.com/virtio-win/kvm-guest-drivers-windows/tree/d92b9c073ec1108f51846d0bd109c5796b46fd36/vioscsi)
and name functions, since line numbers drift.

### The path

A storport request timeout (the `disk:TimeOutValue` /
`vioscsi\Parameters:IoTimeoutValue` registry values, ~60-90s, per
AlexMKX's differential testing in #1014) drives an
`SRB_FUNCTION_RESET_LOGICAL_UNIT` down to vioscsi. `PreProcessRequest`
dispatches it to `CompletePendingRequestsOnReset` under the default
action-on-reset setting (`VioscsiResetCompleteRequests`, set in
`VioScsiFindAdapter`), which is what every real-world deployment runs:

```c
// CompletePendingRequestsOnReset (paraphrased)
if (!reset_in_progress) {
    reset_in_progress = TRUE;
    StorPortPause(DeviceExtension, 10);
    DeviceReset(DeviceExtension);      // posts a LUN reset TMF, returns at once
    for (each request queue) {
        // complete EVERY pending SRB on the adapter with SRB_STATUS_BUS_RESET,
        // not just the ones on the LUN that timed out
    }
    StorPortResume(DeviceExtension);
}
reset_in_progress = FALSE;             // not gated on the TMF response
```

`DeviceReset()` (`helper.c`) doesn't wait for the device. It builds the
TMF in a single per-adapter buffer (`adaptExt->tmf_cmd`), posts it on the
control queue, sets `adaptExt->tmf_infly = TRUE` and returns. The response
is reaped later by the interrupt handler (`VioScsiInterrupt` /
`VioScsiMSInterrupt`). Note too that the TMF always carries
`lun[1] = 0`, so whatever LUN timed out, it resets target 0.

### Late data transfers into completed requests

The force-complete loop tells Windows that every pending SRB is finished
while the device may still own its data buffers. `ProcessQueue` does
guard the *completion*: a late response is looked up by ID in the
`srb_list` the reset path drained, under the same per-queue lock, and is
dropped with `"No SRB found for ID..."` if it is gone. Nothing guards the
*data transfer*. For a read, the device writes the data into guest
memory when the request finishes, which can be after Windows was told
`BUS_RESET` and has reused the pages.

Where that data lands decides the symptom (this part is inference, not
observed):

- I/O to a raw disk from an application buffer (what fio, diskspd and
  paranoid in these harnesses do; the PowerShell writer only writes)
  DMAs into the application's own buffer. The
  application still owns it, so the result is a verify failure or silent
  data corruption, not a bugcheck.
- Paging I/O (file reads through the cache manager, page-file reads,
  image loads) DMAs into physical pages that the memory manager puts back
  on its lists when the I/O fails. A late write into one of those is
  stray DMA into whatever the kernel used the page for next. That is the
  class of `PFN_LIST_CORRUPT`, `PAGE_HASH_ERRORS_INPAGE` and
  `CRITICAL_PROCESS_DIED` reported in #1014 and #877, whose reporters
  were copying large files.

The `reset_via_tmf` driver branch makes `VioscsiResetSendTmf` the default:
it waits for the TMF response, by which point the device has finished or
cancelled every request on the LUN, before completing anything.

### Overlapping resets

`reset_in_progress` is cleared as soon as the force-complete loop ends,
and storport takes `DeviceReset()`'s immediate `TRUE` as the reset being
done. So a second reset can arrive while the first TMF is still in
flight, and `DeviceReset()` then rebuilds and reposts `tmf_cmd` while the
device owns it. The only guard is `ASSERT(adaptExt->tmf_infly == FALSE)`,
which compiles to nothing in the retail driver. The INTx handler also
clears `tmf_infly` on every interrupt, whether or not a TMF came back.

This overlap is real and needs no fault injection: an `NT_VERIFY` version
of that guard fired in testing from storport's hierarchical reset path
(`RaidUnitHierarchicalReset`), which led to the coalescing fix
(driver commit 1b67babe). What it does on a retail driver is not
established. The rebuilt TMF has the same contents and the same buffer
addresses, so it may well be harmless there, and it should not be assumed
to be the corruption path.

### Holding the reset open from QEMU

On the QEMU side, `VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET` (in
`virtio_scsi_do_tmf()`) cold-resets that SCSI device, which drains its
block node. `inject_error_drain_begin()` wakes every request a delay or
stall rule holds as soon as the drain starts. So with the `inject-error`
rules alone, the held requests finish during the TMF, only milliseconds
after the driver force-completed them, and the race depends on
scheduling jitter.

Two QEMU knobs widen it on purpose:

- `x-tmf-delay-ms` / `x-tmf-delay-count` on `virtio-scsi-pci` hold the
  response of a TMF that has already been carried out. That keeps the
  driver's reset in flight to race a second reset, but the data transfers
  have already happened by then.
- `x-scsi-fault-add` with `below-clear: hang` holds a TMF *before* it is
  carried out, and the commands the fault holds have not run yet. They
  only complete normally if they are released while the TMF is still
  held: removing a fault that does both lets the LUN reset fail them to
  the guest, with an iothread usually before they run, in the main loop
  after their data has gone in. A second fault with `probability: 0.0`
  keeps the TMF hung while the first is removed, so the commands run and
  complete as late as the harness wants (see
  [storage-error-injection.rst](storage-error-injection.rst)).
  This is the one that can put a read's data into memory Windows has
  already reused.

## Confirming it

This is grounded in reading source, not a confirmed root cause for the
reported BSODs. Two things would nail it down:

1. **A dump from a reproduction.** Use `-device vmcoreinfo` plus the
   guest-side `fwcfg` driver (from the virtio-win ISO), so a crash
   produces a symbolized `win-dmp` via QMP `dump-guest-memory`, instead of
   relying on Windows' own in-guest dump writer. That writer is what
   stalled at 0% and produced no usable dump in #877. With `hv-crash` and
   `-action panic=pause`, a bugcheck parks the VM in `guest-panicked` and
   QEMU's `GUEST_PANICKED` event carries the bugcheck code and arguments.
2. **An A/B on the same recipe.** The upstream driver should bugcheck,
   and the `reset_via_tmf` driver should survive. `--bsod` in the
   target-fault harness is that recipe, and `--action-on-reset` runs both
   arms on the one `reset_via_tmf` binary (see below). A bugcheck from a lab
   recipe shows the fix closes that path. It does not show that #1014 or
   #877 were that path; only a reporter's dump can.

## Reproduction harnesses

All of them boot the golden image from `setup-windows-inject-vm.sh`,
attach scratch SCSI LUNs, drive I/O through `qemu-guest-agent` and share
`scripts/vioscsi_soak_common.py`; see each script's header and `--help`:

- `fuzz-windows-inject-scsi-reset.py`: stalls several LUNs on one adapter
  with a swept gap between the arm calls, optionally with `x-tmf-delay`,
  to make storport reset them close together.
- `fuzz-windows-inject-tail-latency.py`: long soak with a probabilistic
  tail-latency rule across many adapters and targets.
- `fuzz-windows-inject-target-fault.py`: soak with SCSI target faults,
  checking how far up the escalation path the driver goes. With `--bsod`
  it runs the bugcheck recipe instead (below).
- `fuzz-windows-inject-reset-inflight.py`: resets adapters under a deep
  queue.

They have been run many times, and the reset path above has produced
hangs, broken rings and data corruption, but never a bugcheck. Their I/O
goes to raw disks from application buffers, which (per the reasoning
above) turns a late transfer into a verify failure rather than a crash,
and most of them stop at the first such failure. In the soak library
`hv-crash` is only enabled with `--watch-after-break`, `x-stop-on-broken`
pauses the VM at a ring break, and the scsi-reset harness decides a crash
happened from guest-agent silence and a still screen.

`fuzz-windows-inject-target-fault.py --bsod` is the run meant to see one.
Its LUNs are NTFS volumes, each with a file bigger than guest RAM that is
read in a loop through the file cache (`--io-driver=cached-read`), so the
LUN reads are paging I/O. Each `late-dma` cycle holds every command to
target 0 of one adapter (the target the upstream `DeviceReset()`
addresses) and leaves the LUN reset hanging. Once a read on that target
has failed to the reader, which is when Windows frees its pages, the
harness waits `--late-dma-delay-s` and lets the held reads run, with the
reset still hung by a second fault. Meanwhile the readers on a second
adapter keep the memory manager reusing pages; `DeviceReset()` pauses
its own adapter (`StorPortPause`), so readers there would not. The guest
runs with `hv-crash`, so a bugcheck ends the run as `guest-panicked` with
its STOP code and a `win-dmp`. Every chunk of the files says which LUN
and offset it is, and the readers check what they read, so a late
transfer that lands somewhere harmless still shows: surviving
`--bsod-cycles` cycles ends the run as `data-corruption` if a reader read
back wrong data, and as `cycles-complete` only if none did.

The A/B needs only one driver build. `reset_via_tmf` picks what a reset
does from `VioscsiActionOnReset` (a `REG_DWORD` under
`HKLM\SYSTEM\CurrentControlSet\Services\vioscsi\Parameters\Device`,
read once per adapter in `VioScsiFindAdapter`): 0 is
`VioscsiResetCompleteRequests`, the upstream behaviour, and 2 (or no
value) is `VioscsiResetSendTmf`. Every run boots from a fresh overlay of
the golden image, so `--action-on-reset` sets the value in the run's own
guest after boot, disables and re-enables every vioscsi controller so the
driver reads it, and waits for every LUN to come back before the LUNs are
prepared. With the `reset_via_tmf` build installed in the golden image:

```
scripts/fuzz-windows-inject-target-fault.py --bsod --action-on-reset complete-requests
scripts/fuzz-windows-inject-target-fault.py --bsod --action-on-reset send-tmf --vioscsi-sha256 <HEX>
```

`<HEX>` is the SHA-256 of that `vioscsi.sys`; every run prints it and
records it in the result's `vioscsi_driver`, with the driver version and
date and the registry value it found. The harness needs it for any arm
but `complete-requests` because nothing the driver reports says which
values it knows, and writing one it doesn't is not harmless. Released
drivers since eff7b430, which added the value, know 0, 1 and
`0xDEADDEAD` only, and their reset switch has no default, so 2 falls
through into the `SRB_FUNCTION_WMI` case with the reset SRB. Drivers
before eff7b430 ignore the value and always call
`CompletePendingRequests` on a reset, so `complete-requests` is what
every build does and is the one arm written to an unnamed driver. To test
a released driver, run without `--action-on-reset`: its arm is whatever
that release does, and `vioscsi_driver` says which release it was.

The result's `action_on_reset` records the arm asked for, what the
registry read back and which controllers were restarted. What the driver
itself took can't be read from a running guest: the telemetry IOCTL's
`STOR_TELEMETRY` has no field for it. The event ring does, in every reset
request it records, so `Tools/debug/evring.py events panic.dmp` in the
driver repo shows "action on reset 0x0" on the `complete-requests` arm.
That arm can also end `virtio-broken` before it bugchecks: completing
requests the device still holds lets Storport reuse SRB extensions whose
descriptor tables the device has not read yet. That is most likely
the same bug, though a ring can break for other reasons; the dump taken
at the break is what tells.

None of this has been run against Windows yet. The trigger in particular
rests on an assumption about Windows, not an observation: that a read
completed with `SRB_STATUS_BUS_RESET` is retried into the same pages, so
a late transfer only does harm once the retries have run out and the
read has failed. `--late-dma-release-after=recovery` releases at the
first reset instead, in case that turns out to be wrong. The QEMU side of
the ordering, by contrast, is pinned by a qtest
(`fault-below-hang-holds-none` in `tests/qtest/virtio-scsi-test.c`, run
in the main loop and with an iothread).
