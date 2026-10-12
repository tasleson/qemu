/*
 * Stubs for the SCSI target fault QMP commands
 *
 * The QAPI schema is shared by all targets, but the implementation lives in
 * the SCSI bus code, which only some targets build.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-scsi.h"

void qmp_x_scsi_fault_add(const char *device, ScsiFaultOptions *fault,
                          Error **errp)
{
    error_setg(errp, "SCSI target faults are not available in this build");
}

ScsiFaultCount *qmp_x_scsi_fault_remove(const char *device, const char *id,
                                        Error **errp)
{
    error_setg(errp, "SCSI target faults are not available in this build");
    return NULL;
}

ScsiFaultInfoList *qmp_x_scsi_fault_list(const char *device, Error **errp)
{
    error_setg(errp, "SCSI target faults are not available in this build");
    return NULL;
}
