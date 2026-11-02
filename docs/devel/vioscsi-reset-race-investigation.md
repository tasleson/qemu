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
  carried out, and the commands the fault holds have not run yet. When
  the fault is removed they run and transfer their data, as late as the
  harness wants (see [storage-error-injection.rst](storage-error-injection.rst)).
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
   and the `reset_via_tmf` driver should survive. A bugcheck from a lab
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
  checking how far up the escalation path the driver goes.
- `fuzz-windows-inject-reset-inflight.py`: resets adapters under a deep
  queue.

They have been run many times, and the reset path above has produced
hangs, broken rings and data corruption. None of them is set up to see a
bugcheck: their I/O goes to raw disks from application buffers, which
(per the reasoning above) turns a late transfer into a verify failure rather than
a crash, and they stop at the first such failure. `hv-crash` is only
enabled with `--watch-after-break`, `x-stop-on-broken` pauses the VM at
a ring break, and the scsi-reset harness decides a crash happened from
guest-agent silence and a still screen.
