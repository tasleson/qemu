# vioscsi BSOD investigation: triage and reset-race theory

🤖 Assisted-by: Claude Code (Sonnet 5)

This document summarizes an investigation into a cluster of Windows guest
BSOD reports that all mention `virtio-scsi`, filed against
[virtio-win/kvm-guest-drivers-windows](https://github.com/virtio-win/kvm-guest-drivers-windows).
It exists to let a human or an AI agent pick this work back up without
re-deriving it from scratch. The reproduction harness this investigation
produced is `scripts/fuzz-windows-inject-scsi-reset.py`; see
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

## The reset-race theory (targeting #1014 / #877)

Reading the current `vioscsi` driver source
([vioscsi.c](https://github.com/virtio-win/kvm-guest-drivers-windows/blob/master/vioscsi/vioscsi.c),
[helper.c](https://github.com/virtio-win/kvm-guest-drivers-windows/blob/master/vioscsi/helper.c))
shows a plausible mechanism for how "slow storage" turns into a
corruption-class bugcheck via the driver's own timeout/reset handling,
rather than storage latency being fatal on its own.

### The path

A storport request timeout (the `disk:TimeOutValue` /
`vioscsi\Parameters:IoTimeoutValue` registry values, ~60-90s, per
AlexMKX's differential testing in #1014) drives an
`SRB_FUNCTION_RESET_LOGICAL_UNIT` down to vioscsi. `PreProcessRequest`
(`vioscsi.c:1624`) dispatches this to `CompletePendingRequestsOnReset`
under the driver's default action-on-reset setting
(`adaptExt->action_on_reset = VioscsiResetCompleteRequests`,
`vioscsi.c:445` — what every real-world deployment runs):

```c
// vioscsi.c:1499-1550, CompletePendingRequestsOnReset (paraphrased)
StorPortPause(DeviceExtension, 10);
DeviceReset(DeviceExtension);          // fires an async TMF LUN reset, returns immediately
for (each queue) {
    // force-complete EVERY pending SRB on this queue with SRB_STATUS_BUS_RESET,
    // regardless of whether it was the one that actually timed out
}
StorPortResume(DeviceExtension);
adaptExt->reset_in_progress = FALSE;   // cleared unconditionally, NOT gated on the TMF response
```

`DeviceReset()` (`helper.c:216`) doesn't block on the backend finishing
the reset — it builds a task-management-function (TMF) request into a
**single shared per-adapter scratch buffer** (`adaptExt->tmf_cmd`), sets
`adaptExt->tmf_infly = TRUE`, and returns. The response is only reaped
later, from the interrupt handler, when the control-queue completion
arrives (`vioscsi.c:964-984`).

### Where it's safe

The obvious worry — a late completion for an already-force-completed SRB
causing a double-complete/use-after-free — is guarded against.
`ProcessQueue` (`vioscsi.c:1456-1481`) looks a completing request up by ID
in the same `srb_list` that the reset path drains, under the same
per-queue lock; if the reset path already removed it, the late completion
is just logged (`"No SRB found for ID..."`) and dropped. This is *not*
memory-unsafe, though it is a data-integrity smell: Windows was told
`BUS_RESET` for an I/O that may have actually landed at the backend.

### Where it isn't

Two things are **adapter-wide, not per-LUN**, and neither is gated on the
prior reset's TMF response actually arriving:

1. **`reset_in_progress`** is cleared unconditionally right after the
   force-complete loop finishes — not gated on `tmf_infly` clearing. If a
   *second* LUN's own timeout fires a reset while the first LUN's TMF is
   still outstanding, `DeviceReset()` re-enters and reuses the single
   shared `adaptExt->tmf_cmd` scratch buffer/SGL (`helper.c:220-259`),
   guarded only by `ASSERT(adaptExt->tmf_infly == FALSE)` — which
   compiles to nothing in a free/retail build (what every reporter runs).
   That's the driver handing the same DMA buffer to the device a second
   time while the device may still be reading/writing it for the first,
   unacknowledged TMF.
2. **`StorPortResume()`** fires as soon as the force-complete loop
   finishes, before the backend-side reset is confirmed done, so new I/O
   to the same LUN can be issued while the earlier reset TMF is still in
   flight.

Both require **multiple in-flight requests timing out close together** to
trigger — exactly AlexMKX's setup in #1014 (three separate
`virtio-scsi-pci` controllers/iothreads/LUNs, sustained slow ZFS-with-
dedup backend; throttling bandwidth down or reducing guest RAM made it
fail *faster*, both consistent with more requests queuing/timing out
concurrently). The bugcheck codes reported (`PFN_LIST_CORRUPT`,
`PAGE_HASH_ERRORS_INPAGE`, `CRITICAL_PROCESS_DIED`) are the class of
symptom a stray DMA write into memory the kernel has since repurposed
would produce.

### The race window is narrower than it first looks

QEMU's own handling of the LUN-reset TMF matters here. On the QEMU side,
`VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET` (`hw/scsi/virtio-scsi.c:528`) calls
`device_cold_reset()` on that one SCSI device, which drains its block
node — and `inject_error_drain_begin()`
(`block/inject-error.c:443`) wakes *every* held/delayed request on that
node the instant drain starts, not after the injected delay elapses. So a
single LUN's own TMF round-trip resolves in however long QEMU takes to
schedule and run that drain (normally fast), **not** in however long an
injected stall/delay holds the data request. The corruption-shaped race
is therefore governed by host/guest **scheduling jitter between two
independent LUN resets landing close together**, not by how long any one
LUN is held — which is why the reproduction harness stalls *multiple*
LUNs concurrently and sweeps the arm-timing gap between them, rather than
just holding one disk for a long time.

## Confirming it

This is a well-grounded hypothesis from reading current source, not a
confirmed root cause. Two things would nail it down:

1. **A checked/debug `vioscsi.sys` build.** `ASSERT` compiles to nothing
   in the retail driver every reporter runs, so on retail this race (if
   real) manifests as silent corruption; on a checked build it should
   bugcheck immediately and attributably the moment two resets overlap —
   far cheaper to confirm than catching silent corruption.
2. **A dump from an actual repro.** Set up `-device vmcoreinfo` +
   the guest-side `fwcfg` driver (from the virtio-win ISO) so a crash
   produces a symbolized `win-dmp` via QMP `dump-guest-memory`, instead of
   relying on Windows' own in-guest dump writer — which is exactly the
   mechanism that stalled at 0% and produced no usable dump in #877.
   Inspect `adaptExt->tmf_infly` / `adaptExt->reset_in_progress` and
   whether corrupted memory correlates with the `tmf_cmd` scratch buffer.

## Reproduction harness

`scripts/fuzz-windows-inject-scsi-reset.py` automates the above: it boots
the golden Windows image from `setup-windows-inject-vm.sh`, attaches N
scratch SCSI LUNs to one `virtio-scsi-pci` adapter (default 3, matching
#1014's shape), drives sustained raw writes to all of them via
`qemu-guest-agent`, then arms a `stall` rule on every LUN concurrently
with a swept host-side gap between each arm call, watching for guest-agent
silence as the crash signal and attempting a `win-dmp` capture on a
suspected crash. See the script's own header comment for the full
mechanism writeup and `--help` for prerequisites and options.

It has not yet been run against a live VM as of this writing — the golden
image (`setup-windows-inject-vm.sh create`/`install`, plus
qemu-guest-agent and the vioscsi driver installed in-guest) still needs
to be set up on whichever machine runs it.
