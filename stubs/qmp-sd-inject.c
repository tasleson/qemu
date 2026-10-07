/*
 * Stubs for the SD card response injection QMP commands
 *
 * The QAPI schema is shared by all targets, but the implementation lives in
 * a device model that only some targets build.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-sd.h"

void qmp_x_sd_inject_response_set(const char *id, SdInjectResponseType type,
                                  const char *data, bool has_card_status,
                                  uint32_t card_status, Error **errp)
{
    error_setg(errp,
               "SD card response injection is not available in this build");
}

void qmp_x_sd_inject_response_clear(const char *id, bool has_type,
                                    SdInjectResponseType type, Error **errp)
{
    error_setg(errp,
               "SD card response injection is not available in this build");
}
