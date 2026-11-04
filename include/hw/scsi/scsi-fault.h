/*
 * SCSI target faults
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_SCSI_SCSI_FAULT_H
#define HW_SCSI_SCSI_FAULT_H

#include "hw/scsi/scsi.h"
#include "qapi/qapi-types-scsi.h"

/* What an HBA should do with a recovery request, see scsi_fault_recovery() */
typedef enum SCSIFaultAction {
    SCSI_FAULT_ACTION_PROCEED,  /* carry it out */
    SCSI_FAULT_ACTION_REJECT,   /* fail it without doing anything */
    SCSI_FAULT_ACTION_HANG,     /* don't answer it yet */
} SCSIFaultAction;

/*
 * scsi_fault_hold: Hold a command for a fault
 *
 * Called by scsi_req_enqueue() in the request's AioContext once @req is on
 * its device's request list.  Returns true if a fault holds the command, in
 * which case the command must not be sent to the device: the fault sends it
 * later and hands what send_command returned to the HBA's fault_resume().
 */
bool scsi_fault_hold(SCSIRequest *req);

/*
 * scsi_fault_unhold: Forget a held command
 *
 * Called in the request's AioContext when a held command leaves its
 * device's request list without having been released, i.e. when it is
 * cancelled.
 */
void scsi_fault_unhold(SCSIRequest *req);

/* Whether any fault is armed on @bus.  Any thread. */
static inline bool scsi_fault_armed(SCSIBus *bus)
{
    return qatomic_load_acquire(&bus->fault_count) != 0;
}

/*
 * scsi_fault_recovery: Tell the faults about a recovery request
 * @bus: the bus the recovery is for
 * @level: what kind of recovery it is
 * @target: the target it addresses, ignored for bus-reset
 * @lun: the LUN it addresses, ignored for target-reset and bus-reset
 * @count: count it as an attempt; false to re-evaluate a request that was
 *     told to hang
 * @hang_ms: set to how long a hung request should wait at most, or -1 to
 *     wait until the faults that hang it clear
 *
 * Called from the main loop before an HBA carries a recovery out.  Returns
 * what the HBA should do with it.  If it is carried out, the HBA must call
 * scsi_fault_recovery_done() when it has finished cancelling commands.
 */
SCSIFaultAction scsi_fault_recovery(SCSIBus *bus, ScsiFaultRecovery level,
                                    int target, int lun, bool count,
                                    int64_t *hang_ms);

/*
 * scsi_fault_recovery_done: A recovery request has been carried out
 *
 * Called from the main loop.  Clears the faults the recovery was enough
 * for, and releases the commands they still hold.
 */
void scsi_fault_recovery_done(SCSIBus *bus, ScsiFaultRecovery level,
                              int target, int lun);

/* Remove every fault on @bus without releasing anything.  Main loop. */
void scsi_fault_bus_cleanup(SCSIBus *bus);

#endif
