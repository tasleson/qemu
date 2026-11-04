/*
 * Stubs for the NVMe response injection QMP commands
 *
 * The QAPI schema is shared by all targets, but the implementation lives in
 * a device model that only some targets build.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-nvme.h"

void qmp_x_nvme_inject_response_set(const char *id,
                                    NvmeInjectResponseType type, bool has_nsid,
                                    uint32_t nsid, const char *data,
                                    bool has_status, uint16_t status,
                                    Error **errp)
{
    error_setg(errp, "NVMe response injection is not available in this build");
}

void qmp_x_nvme_inject_response_clear(const char *id, bool has_type,
                                      NvmeInjectResponseType type,
                                      bool has_nsid, uint32_t nsid,
                                      Error **errp)
{
    error_setg(errp, "NVMe response injection is not available in this build");
}
