/*
 * Stubs for the IDE response injection QMP commands
 *
 * The QAPI schema is shared by all targets, but the implementation lives in
 * a device model that only some targets build.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-ide.h"

void qmp_x_ide_inject_response_set(const char *id, IdeInjectResponseType type,
                                   const char *data, bool has_error,
                                   uint8_t error, Error **errp)
{
    error_setg(errp, "IDE response injection is not available in this build");
}

void qmp_x_ide_inject_response_clear(const char *id, bool has_type,
                                     IdeInjectResponseType type, Error **errp)
{
    error_setg(errp, "IDE response injection is not available in this build");
}
