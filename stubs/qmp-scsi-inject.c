/*
 * Stubs for the SCSI disk response injection QMP commands
 *
 * The QAPI schema is shared by all targets, but the implementation lives in
 * a device model that only some targets build.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-scsi.h"

void qmp_x_scsi_disk_inject_response_set(const char *id,
                                         ScsiInjectResponseType type,
                                         bool has_page, uint8_t page,
                                         const char *data, Error **errp)
{
    error_setg(errp,
               "SCSI disk response injection is not available in this build");
}

void qmp_x_scsi_disk_inject_response_clear(const char *id, bool has_type,
                                           ScsiInjectResponseType type,
                                           bool has_page, uint8_t page,
                                           Error **errp)
{
    error_setg(errp,
               "SCSI disk response injection is not available in this build");
}
