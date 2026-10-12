/*
 * SCSI target faults
 *
 * A fault makes a target, or one LUN of it, stop answering: the commands
 * sent to it are held before they run, until the guest performs the kind of
 * error recovery that brings the target back.  The fault then clears by
 * itself and the commands the recovery did not cancel go on to run, which is
 * what a real target that needed resetting looks like from the initiator.
 * Recovery that is not enough can do its normal work, be rejected, or get no
 * answer, so a guest driver's whole escalation path can be exercised.
 *
 * Held commands stay on their device's request list, so the TMFs the HBA
 * implements find them as usual.  They have not been sent to the device, so
 * cancelling one completes it at once and nothing reaches the backend.
 *
 * Threading: faults are added, removed and told about recovery in the main
 * loop.  Commands are held, released and cancelled in their own AioContext:
 * the fault state is on the request (a fault serial number and an optional
 * timer), and the main loop only changes the fault table and schedules a BH
 * for each device and AioContext with requests, which releases whatever no
 * armed fault holds any more in the order the guest sent it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-scsi.h"
#include "qapi/qapi-events-scsi.h"
#include "qemu/lockable.h"
#include "qemu/main-loop.h"
#include "qemu/rcu.h"
#include "qemu/timer.h"
#include "hw/core/qdev.h"
#include "hw/scsi/scsi.h"
#include "hw/scsi/scsi-fault.h"
#include "hw/core/sysbus.h"
#include "hw/virtio/virtio-bus.h"
#include "migration/blocker.h"
#include "system/runstate.h"
#include "trace.h"

/*
 * Longest hold time a fault may ask for.  Anything beyond a day is
 * indistinguishable from holding until recovery, which needs no delay.
 */
#define SCSI_FAULT_DELAY_MAX_MS ((int64_t)24 * 60 * 60 * 1000)

typedef struct SCSIFault {
    uint32_t serial;            /* never 0, unique on the bus */
    char *id;
    char *device;               /* as given to x-scsi-fault-add */
    uint32_t target;
    bool has_lun;
    uint32_t lun;
    bool stall;
    int64_t delay_min_ms;       /* only meaningful when !stall */
    int64_t delay_max_ms;
    double probability;
    int64_t max_hits;           /* negative: unlimited */
    ScsiFaultRecovery clear_on;
    ScsiFaultBelowClear below_clear;
    int64_t tmf_hang_ms;        /* negative: until the fault clears */
    uint64_t hits;
    uint64_t attempts[SCSI_FAULT_RECOVERY__MAX];
    bool has_last_attempt;
    ScsiFaultRecovery last_attempt;
    QTAILQ_ENTRY(SCSIFault) next;
} SCSIFault;

typedef struct SCSIFaultTable {
    QemuMutex lock;             /* protects everything below */
    QTAILQ_HEAD(, SCSIFault) faults;
    uint32_t next_serial;
    GRand *rand;
    Error *migration_blocker;   /* set while any fault is armed */

    /* Main loop only, see scsi_fault_let_go() */
    bool let_go_pending;
    VMChangeStateEntry *vmstate;
    QEMUBH *let_go_bh;
} SCSIFaultTable;

static const char *scsi_fault_bus_name(SCSIBus *bus)
{
    return bus->qbus.name;
}

static void scsi_fault_free(SCSIFault *f)
{
    g_free(f->id);
    g_free(f->device);
    g_free(f);
}

static SCSIFault *scsi_fault_find(SCSIFaultTable *t, const char *id)
{
    SCSIFault *f;

    QTAILQ_FOREACH(f, &t->faults, next) {
        if (!strcmp(f->id, id)) {
            return f;
        }
    }
    return NULL;
}

static bool scsi_fault_serial_armed(SCSIBus *bus, uint32_t serial)
{
    SCSIFaultTable *t = bus->faults;
    SCSIFault *f;

    QEMU_LOCK_GUARD(&t->lock);
    QTAILQ_FOREACH(f, &t->faults, next) {
        if (f->serial == serial) {
            return true;
        }
    }
    return false;
}

static bool scsi_fault_matches(SCSIFault *f, SCSIRequest *req)
{
    return req->dev->channel == 0 && req->dev->id == f->target &&
           (!f->has_lun || req->lun == f->lun);
}

/*
 * Whether a recovery of kind @level addressed to @target/@lun reaches @f.
 * A LUN-level recovery reaches a fault that covers the whole target, so a
 * reset of any of its LUNs can bring the target back.
 */
static bool scsi_fault_in_scope(SCSIFault *f, ScsiFaultRecovery level,
                                int target, int lun)
{
    switch (level) {
    case SCSI_FAULT_RECOVERY_BUS_RESET:
        return true;
    case SCSI_FAULT_RECOVERY_TARGET_RESET:
        return f->target == target;
    default:
        return f->target == target && (!f->has_lun || f->lun == lun);
    }
}

void scsi_fault_unhold(SCSIRequest *req)
{
    qatomic_set(&req->fault_serial, 0);
    if (req->fault_timer) {
        timer_free(req->fault_timer);
        req->fault_timer = NULL;
    }
}

/* Send a held command to its device.  Runs in the request's AioContext. */
static void scsi_fault_release(SCSIRequest *req)
{
    int32_t len;

    scsi_fault_unhold(req);
    if (req->io_canceled || !req->enqueued) {
        return;
    }

    trace_scsi_fault_release(scsi_fault_bus_name(req->bus), req->dev->id,
                             req->lun, req->tag);
    scsi_req_ref(req);
    len = req->ops->send_command(req, req->cmd.buf);
    req->bus->info->fault_resume(req, len);
    scsi_req_unref(req);
}

static void scsi_fault_timer_cb(void *opaque)
{
    scsi_fault_release(opaque);
}

bool scsi_fault_hold(SCSIRequest *req)
{
    SCSIBus *bus = req->bus;
    SCSIFaultTable *t = bus->faults;
    SCSIFault *f;
    int64_t delay_ms = -1;

    assert(bus->info->fault_resume);

    /*
     * Don't hold commands for a device that is being unplugged.  The
     * request went on the device's list under requests_lock, so either that
     * happened before unrealize's purge looked at the list, and the purge
     * finds and cancels it, or unrealize had already marked the device
     * unrealized and the command runs as if there was no fault, so the drain
     * that follows waits for it like for any other.  A held command doesn't
     * count as in flight, so nothing else would wait for it.
     */
    if (!qdev_is_realized(&req->dev->qdev)) {
        return false;
    }

    WITH_QEMU_LOCK_GUARD(&t->lock) {
        QTAILQ_FOREACH(f, &t->faults, next) {
            if (!scsi_fault_matches(f, req)) {
                continue;
            }
            if (f->max_hits >= 0 && f->hits >= f->max_hits) {
                continue;
            }
            if (f->probability < 1.0 &&
                g_rand_double(t->rand) >= f->probability) {
                continue;
            }

            /*
             * Set under the lock: once a fault is gone from the table, any
             * request it held already carries its serial and is on the
             * request list, so releasing what no fault holds finds it.
             */
            f->hits++;
            qatomic_set(&req->fault_serial, f->serial);
            if (!f->stall) {
                delay_ms = f->delay_min_ms;
                if (f->delay_max_ms > f->delay_min_ms) {
                    delay_ms = g_rand_double_range(t->rand, f->delay_min_ms,
                                                   f->delay_max_ms);
                }
            }
            trace_scsi_fault_hold(scsi_fault_bus_name(bus), f->id,
                                  req->dev->id, req->lun, req->tag,
                                  req->cmd.buf[0], delay_ms);
            break;
        }
    }

    if (!req->fault_serial) {
        return false;
    }
    if (delay_ms >= 0) {
        req->fault_timer = aio_timer_new(req->ctx, QEMU_CLOCK_VIRTUAL,
                                         SCALE_MS, scsi_fault_timer_cb, req);
        timer_mod(req->fault_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + delay_ms);
    }
    return true;
}

/* Runs in the request's AioContext, see scsi_fault_release_orphans() */
static void scsi_fault_release_orphan(SCSIRequest *req, void *opaque)
{
    uint32_t serial = qatomic_read(&req->fault_serial);

    if (serial && !scsi_fault_serial_armed(req->bus, serial)) {
        scsi_fault_release(req);
    }
}

/* Release every command on @bus whose fault is gone.  Main loop. */
static void scsi_fault_release_orphans(SCSIBus *bus)
{
    BusChild *kid;

    RCU_READ_LOCK_GUARD();
    QTAILQ_FOREACH_RCU(kid, &bus->qbus.children, sibling) {
        SCSIDevice *d = SCSI_DEVICE(kid->child);

        if (qdev_is_realized(&d->qdev)) {
            scsi_device_for_each_req_async_in_order(
                d, scsi_fault_release_orphan, NULL);
        }
    }
}

/* Number of commands on @bus that the fault @serial holds.  Main loop. */
static int64_t scsi_fault_count_held(SCSIBus *bus, uint32_t serial)
{
    BusChild *kid;
    int64_t held = 0;

    RCU_READ_LOCK_GUARD();
    QTAILQ_FOREACH_RCU(kid, &bus->qbus.children, sibling) {
        SCSIDevice *d = SCSI_DEVICE(kid->child);
        SCSIRequest *req;

        if (!qdev_is_realized(&d->qdev)) {
            continue;
        }
        WITH_QEMU_LOCK_GUARD(&d->requests_lock) {
            QTAILQ_FOREACH(req, &d->requests, next) {
                held += qatomic_read(&req->fault_serial) == serial;
            }
        }
    }
    return held;
}

/*
 * Release what no fault holds any more, and let the HBA look again at the
 * recovery requests it was told to leave hanging.  Both complete requests to
 * the guest, which must not happen while the VM is stopped (say a fault is
 * removed while it is paused), so then wait until it runs again.  Main loop.
 */
static void scsi_fault_let_go(SCSIBus *bus)
{
    if (!runstate_is_running()) {
        bus->faults->let_go_pending = true;
        return;
    }
    bus->faults->let_go_pending = false;

    scsi_fault_release_orphans(bus);
    if (bus->info->fault_removed) {
        bus->info->fault_removed(bus);
    }
}

/* After every handler has seen the VM start, so the HBA is running too */
static void scsi_fault_let_go_bh(void *opaque)
{
    SCSIBus *bus = opaque;

    if (bus->faults->let_go_pending) {
        scsi_fault_let_go(bus);
    }
}

static void scsi_fault_vm_state_change(void *opaque, bool running,
                                       RunState state)
{
    SCSIBus *bus = opaque;

    if (running && bus->faults->let_go_pending) {
        qemu_bh_schedule(bus->faults->let_go_bh);
    }
}

/*
 * Take the faults in @gone, already unlinked from the table, off @bus:
 * report them, release what they held and tell the HBA.  Main loop.
 */
static void scsi_fault_retire(SCSIBus *bus, GPtrArray *gone,
                              ScsiFaultRecovery recovery)
{
    SCSIFaultTable *t = bus->faults;
    guint i;

    if (!gone->len) {
        return;
    }

    for (i = 0; i < gone->len; i++) {
        SCSIFault *f = g_ptr_array_index(gone, i);
        int64_t held = scsi_fault_count_held(bus, f->serial);

        trace_scsi_fault_clear(scsi_fault_bus_name(bus), f->id,
                               ScsiFaultRecovery_str(recovery), held);
        qapi_event_send_scsi_fault_cleared(f->device,
                                           scsi_fault_bus_name(bus), f->id,
                                           recovery, held);
        scsi_fault_free(f);
    }

    if (qatomic_sub_fetch(&bus->fault_count, gone->len) == 0) {
        migrate_del_blocker(&t->migration_blocker);
    }

    scsi_fault_let_go(bus);
}

SCSIFaultAction scsi_fault_recovery(SCSIBus *bus, ScsiFaultRecovery level,
                                    int target, int lun, bool count,
                                    int64_t *hang_ms)
{
    SCSIFaultTable *t = bus->faults;
    SCSIFaultAction action = SCSI_FAULT_ACTION_PROCEED;
    bool hang_forever = false;
    SCSIFault *f;

    assert(level < SCSI_FAULT_RECOVERY_MANUAL);
    *hang_ms = 0;
    if (!scsi_fault_armed(bus)) {
        *hang_ms = -1;
        return action;
    }

    QEMU_LOCK_GUARD(&t->lock);
    QTAILQ_FOREACH(f, &t->faults, next) {
        ScsiFaultBelowClear below = SCSI_FAULT_BELOW_CLEAR_PROCEED;

        if (!scsi_fault_in_scope(f, level, target, lun)) {
            continue;
        }

        /* An adapter reset can't be refused */
        if (level < f->clear_on && level != SCSI_FAULT_RECOVERY_BUS_RESET) {
            below = f->below_clear;
        }

        /* Getting no answer is worse than being refused */
        switch (below) {
        case SCSI_FAULT_BELOW_CLEAR_REJECT:
            action = MAX(action, SCSI_FAULT_ACTION_REJECT);
            break;
        case SCSI_FAULT_BELOW_CLEAR_HANG:
            /* A hung request waits for every fault that hangs it */
            action = SCSI_FAULT_ACTION_HANG;
            if (f->tmf_hang_ms < 0) {
                hang_forever = true;
            } else {
                *hang_ms = MAX(*hang_ms, f->tmf_hang_ms);
            }
            break;
        default:
            break;
        }

        if (count) {
            f->attempts[level]++;
            f->has_last_attempt = true;
            f->last_attempt = level;
            trace_scsi_fault_recovery(scsi_fault_bus_name(bus), f->id,
                                      ScsiFaultRecovery_str(level),
                                      target, lun,
                                      level >= f->clear_on ? "clear" :
                                      ScsiFaultBelowClear_str(below));
        }
    }

    if (action != SCSI_FAULT_ACTION_HANG || hang_forever) {
        *hang_ms = -1;
    }
    return action;
}

void scsi_fault_recovery_done(SCSIBus *bus, ScsiFaultRecovery level,
                              int target, int lun)
{
    SCSIFaultTable *t = bus->faults;
    g_autoptr(GPtrArray) gone = g_ptr_array_new();
    SCSIFault *f, *next;

    if (!scsi_fault_armed(bus)) {
        return;
    }

    WITH_QEMU_LOCK_GUARD(&t->lock) {
        QTAILQ_FOREACH_SAFE(f, &t->faults, next, next) {
            if (level >= f->clear_on &&
                scsi_fault_in_scope(f, level, target, lun)) {
                QTAILQ_REMOVE(&t->faults, f, next);
                g_ptr_array_add(gone, f);
            }
        }
    }

    scsi_fault_retire(bus, gone, level);
}

void scsi_fault_bus_cleanup(SCSIBus *bus)
{
    SCSIFaultTable *t = bus->faults;
    SCSIFault *f, *next;

    if (!t) {
        return;
    }

    QTAILQ_FOREACH_SAFE(f, &t->faults, next, next) {
        QTAILQ_REMOVE(&t->faults, f, next);
        scsi_fault_free(f);
    }
    if (t->migration_blocker) {
        migrate_del_blocker(&t->migration_blocker);
    }
    qatomic_set(&bus->fault_count, 0);
    bus->faults = NULL;

    qemu_del_vm_change_state_handler(t->vmstate);
    qemu_bh_delete(t->let_go_bh);
    g_rand_free(t->rand);
    qemu_mutex_destroy(&t->lock);
    g_free(t);
}

static SCSIBus *scsi_fault_own_bus(DeviceState *dev)
{
    BusState *child;

    QLIST_FOREACH(child, &dev->child_bus, sibling) {
        if (object_dynamic_cast(OBJECT(child), TYPE_SCSI_BUS)) {
            return SCSI_BUS(child);
        }
    }
    return NULL;
}

/*
 * Find the SCSI bus of the adapter @dev.  A virtio proxy such as
 * virtio-scsi-pci keeps it on the device on its virtio bus, so look through
 * that, but no further: naming a bridge or the machine must not arm faults on
 * whatever adapter happens to be below it.
 */
static SCSIBus *scsi_fault_adapter_bus(DeviceState *dev)
{
    SCSIBus *bus = scsi_fault_own_bus(dev);
    BusState *child;

    if (bus) {
        return bus;
    }
    QLIST_FOREACH(child, &dev->child_bus, sibling) {
        BusChild *kid;

        if (!object_dynamic_cast(OBJECT(child), TYPE_VIRTIO_BUS)) {
            continue;
        }
        QTAILQ_FOREACH(kid, &child->children, sibling) {
            bus = scsi_fault_own_bus(kid->child);
            if (bus) {
                return bus;
            }
        }
    }
    return NULL;
}

static SCSIBus *scsi_fault_find_bus(const char *device, Error **errp)
{
    DeviceState *dev;
    SCSIBus *bus;

    if (strchr(device, '/')) {
        dev = (DeviceState *)object_resolve_path_type(device, TYPE_DEVICE,
                                                      NULL);
    } else {
        dev = qdev_find_recursive(sysbus_get_default(), device);
    }
    if (!dev) {
        error_setg(errp, "Device '%s' not found", device);
        return NULL;
    }

    bus = scsi_fault_adapter_bus(dev);
    if (!bus) {
        error_setg(errp, "Device '%s' is not a SCSI adapter", device);
        return NULL;
    }
    if (!bus->info->fault_resume) {
        error_setg(errp, "Device '%s' does not support SCSI target faults",
                   device);
        return NULL;
    }
    return bus;
}

static SCSIFaultTable *scsi_fault_table(SCSIBus *bus)
{
    SCSIFaultTable *t = bus->faults;

    if (!t) {
        t = g_new0(SCSIFaultTable, 1);
        qemu_mutex_init(&t->lock);
        QTAILQ_INIT(&t->faults);
        t->rand = g_rand_new();
        t->vmstate = qemu_add_vm_change_state_handler(
            scsi_fault_vm_state_change, bus);
        t->let_go_bh = qemu_bh_new(scsi_fault_let_go_bh, bus);
        bus->faults = t;
    }
    return t;
}

static bool scsi_fault_check_ms(const char *name, int64_t ms, Error **errp)
{
    if (ms < 0 || ms > SCSI_FAULT_DELAY_MAX_MS) {
        error_setg(errp, "%s must be between 0 and %" PRId64, name,
                   SCSI_FAULT_DELAY_MAX_MS);
        return false;
    }
    return true;
}

void qmp_x_scsi_fault_add(const char *device, ScsiFaultOptions *opts,
                          Error **errp)
{
    SCSIBus *bus;
    SCSIFaultTable *t;
    SCSIFault *f;

    bus = scsi_fault_find_bus(device, errp);
    if (!bus) {
        return;
    }

    if (opts->target > bus->info->max_target) {
        error_setg(errp, "target must be at most %d", bus->info->max_target);
        return;
    }
    if (opts->has_lun && opts->lun > bus->info->max_lun) {
        error_setg(errp, "lun must be at most %d", bus->info->max_lun);
        return;
    }
    if (opts->has_probability &&
        !(opts->probability >= 0.0 && opts->probability <= 1.0)) {
        error_setg(errp, "probability must be between 0.0 and 1.0");
        return;
    }
    if ((opts->has_delay_ms &&
         !scsi_fault_check_ms("delay-ms", opts->delay_ms, errp)) ||
        (opts->has_delay_max_ms &&
         !scsi_fault_check_ms("delay-max-ms", opts->delay_max_ms, errp)) ||
        (opts->has_tmf_hang_ms &&
         !scsi_fault_check_ms("tmf-hang-ms", opts->tmf_hang_ms, errp))) {
        return;
    }
    if (opts->has_delay_max_ms && opts->delay_max_ms <
        (opts->has_delay_ms ? opts->delay_ms : 0)) {
        error_setg(errp, "delay-max-ms must not be less than delay-ms");
        return;
    }
    if (opts->has_max_hits && opts->max_hits < 1) {
        error_setg(errp, "max-hits must be at least 1");
        return;
    }
    if (opts->has_tmf_hang_ms &&
        (!opts->has_below_clear ||
         opts->below_clear != SCSI_FAULT_BELOW_CLEAR_HANG)) {
        error_setg(errp, "tmf-hang-ms needs below-clear set to hang");
        return;
    }

    t = scsi_fault_table(bus);
    QEMU_LOCK_GUARD(&t->lock);

    if (scsi_fault_find(t, opts->id)) {
        error_setg(errp, "A fault named '%s' already exists on '%s'",
                   opts->id, device);
        return;
    }

    if (!t->migration_blocker) {
        error_setg(&t->migration_blocker,
                   "SCSI target faults are armed on bus '%s'",
                   scsi_fault_bus_name(bus));
        if (migrate_add_blocker(&t->migration_blocker, errp) < 0) {
            return;
        }
    }

    f = g_new0(SCSIFault, 1);
    f->serial = ++t->next_serial ?: ++t->next_serial;  /* 0 means none */
    f->id = g_strdup(opts->id);
    f->device = g_strdup(device);
    f->target = opts->target;
    f->has_lun = opts->has_lun;
    f->lun = opts->lun;
    f->stall = !opts->has_delay_ms && !opts->has_delay_max_ms;
    f->delay_min_ms = opts->has_delay_ms ? opts->delay_ms : 0;
    f->delay_max_ms = opts->has_delay_max_ms ? opts->delay_max_ms
                                             : f->delay_min_ms;
    f->probability = opts->has_probability ? opts->probability : 1.0;
    f->max_hits = opts->has_max_hits ? opts->max_hits : -1;
    f->clear_on = opts->has_clear_on ? opts->clear_on
                                     : SCSI_FAULT_RECOVERY_LUN_RESET;
    f->below_clear = opts->has_below_clear ? opts->below_clear
                                           : SCSI_FAULT_BELOW_CLEAR_PROCEED;
    f->tmf_hang_ms = opts->has_tmf_hang_ms ? opts->tmf_hang_ms : -1;
    QTAILQ_INSERT_TAIL(&t->faults, f, next);

    trace_scsi_fault_add(scsi_fault_bus_name(bus), f->id, f->target,
                         f->has_lun ? (int)f->lun : -1,
                         ScsiFaultRecovery_str(f->clear_on),
                         ScsiFaultBelowClear_str(f->below_clear));

    /* Pairs with scsi_fault_armed(): the table is complete before this */
    qatomic_inc(&bus->fault_count);
}

ScsiFaultCount *qmp_x_scsi_fault_remove(const char *device, const char *id,
                                        Error **errp)
{
    g_autoptr(GPtrArray) gone = g_ptr_array_new();
    ScsiFaultCount *ret;
    SCSIFaultTable *t;
    SCSIFault *f, *next;
    SCSIBus *bus;

    bus = scsi_fault_find_bus(device, errp);
    if (!bus) {
        return NULL;
    }

    t = bus->faults;
    if (t) {
        WITH_QEMU_LOCK_GUARD(&t->lock) {
            QTAILQ_FOREACH_SAFE(f, &t->faults, next, next) {
                if (!id || !strcmp(f->id, id)) {
                    QTAILQ_REMOVE(&t->faults, f, next);
                    g_ptr_array_add(gone, f);
                }
            }
        }
    }

    if (id && !gone->len) {
        error_setg(errp, "No fault named '%s' on '%s'", id, device);
        return NULL;
    }

    ret = g_new0(ScsiFaultCount, 1);
    ret->count = gone->len;
    scsi_fault_retire(bus, gone, SCSI_FAULT_RECOVERY_MANUAL);
    return ret;
}

ScsiFaultInfoList *qmp_x_scsi_fault_list(const char *device, Error **errp)
{
    ScsiFaultInfoList *head = NULL, **tail = &head;
    SCSIFaultTable *t;
    SCSIFault *f;
    SCSIBus *bus;

    bus = scsi_fault_find_bus(device, errp);
    if (!bus) {
        return NULL;
    }

    t = bus->faults;
    if (!t) {
        return NULL;
    }

    QEMU_LOCK_GUARD(&t->lock);
    QTAILQ_FOREACH(f, &t->faults, next) {
        ScsiFaultInfo *info = g_new0(ScsiFaultInfo, 1);
        ScsiFaultAttempts *attempts = g_new0(ScsiFaultAttempts, 1);

        info->id = g_strdup(f->id);
        info->target = f->target;
        info->has_lun = f->has_lun;
        info->lun = f->lun;
        info->hold_at = SCSI_FAULT_HOLD_AT_SUBMIT;
        info->stall = f->stall;
        info->has_delay_ms = info->has_delay_max_ms = !f->stall;
        info->delay_ms = f->delay_min_ms;
        info->delay_max_ms = f->delay_max_ms;
        info->probability = f->probability;
        info->has_max_hits = f->max_hits >= 0;
        info->max_hits = f->max_hits;
        info->clear_on = f->clear_on;
        info->below_clear = f->below_clear;
        info->has_tmf_hang_ms = f->tmf_hang_ms >= 0;
        info->tmf_hang_ms = f->tmf_hang_ms;
        info->hits = f->hits;
        info->held = scsi_fault_count_held(bus, f->serial);

        attempts->abort_task = f->attempts[SCSI_FAULT_RECOVERY_ABORT_TASK];
        attempts->task_set = f->attempts[SCSI_FAULT_RECOVERY_TASK_SET];
        attempts->lun_reset = f->attempts[SCSI_FAULT_RECOVERY_LUN_RESET];
        attempts->target_reset =
            f->attempts[SCSI_FAULT_RECOVERY_TARGET_RESET];
        attempts->bus_reset = f->attempts[SCSI_FAULT_RECOVERY_BUS_RESET];
        info->attempts = attempts;
        info->has_last_attempt = f->has_last_attempt;
        info->last_attempt = f->last_attempt;

        QAPI_LIST_APPEND(tail, info);
    }
    return head;
}
