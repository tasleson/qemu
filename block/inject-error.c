/*
 * Block filter driver for media error and latency injection
 *
 * Simulates bad sectors by returning errors for I/O operations that
 * touch configured sector ranges.  Sits in the block graph between the
 * guest device and the backing image.  Device emulators (SCSI, NVMe,
 * AHCI) already translate block-layer errors into protocol-specific
 * error responses.
 *
 * Latency rules additionally let a request be held for a configured
 * time, or indefinitely, before it is passed on to the image or
 * failed.  A held request only yields its own coroutine: the QEMU
 * event loop and the vCPU threads keep running, so the guest sees a
 * slow disk rather than a frozen VMM and can keep queueing I/O,
 * resetting the device or timing the request out while it is held.
 *
 * Copyright (c) 2026 Tony Asleson <tasleson@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "block/block-io.h"
#include "block/block_int.h"
#include "block/block-global-state.h"
#include "block/qdict.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-block-core.h"
#include "qapi/qapi-visit-block-core.h"
#include "qobject/qdict.h"

typedef struct InjectErrorEntry {
    int64_t offset;
    int64_t length;
    int error;
    bool reads;
    bool writes;
    InjectErrorBehavior behavior;
    QLIST_ENTRY(InjectErrorEntry) next;
} InjectErrorEntry;

/*
 * Longest hold time a rule may ask for.  Anything beyond a day is
 * indistinguishable from a stall, which has its own option.
 */
#define INJECT_DELAY_MAX_MS ((int64_t)24 * 60 * 60 * 1000)

#define INJECT_DELAY_OP_BIT(op) (1u << (op))
#define INJECT_DELAY_OPS_ALL ((1u << INJECT_DELAY_OP__MAX) - 1)

typedef struct InjectDelayRule {
    char *id;
    uint32_t ops;
    int64_t offset;
    int64_t length;         /* negative: rule covers the whole device */
    double probability;
    int64_t delay_min_ns;
    int64_t delay_max_ns;
    bool stall;
    int error;              /* 0: pass the request on to the image */
    int64_t max_hits;       /* negative: unlimited */
    int64_t hits;
    QTAILQ_ENTRY(InjectDelayRule) next;
} InjectDelayRule;

/*
 * A request the filter is currently holding.  It is heap allocated and
 * reference counted because a releaser has to keep it alive while it
 * wakes the sleeping coroutine outside of the state lock.
 */
typedef struct InjectDelayedReq {
    int refcnt;             /* atomic */
    int64_t id;
    QemuCoSleep sleep;
    InjectDelayOp op;
    int64_t offset;
    int64_t length;
    char *rule_id;
    bool stalled;
    int64_t deadline_ns;    /* only meaningful when !stalled */

    /* Both guarded by BDRVInjectErrorState::lock */
    int result;             /* 0 or negative errno */
    bool released;

    QLIST_ENTRY(InjectDelayedReq) next;
} InjectDelayedReq;

/* What a matching latency rule wants done to a request. */
typedef struct InjectDelayAction {
    bool fired;
    int64_t delay_ns;
    bool stall;
    int error;
    char *rule_id;
} InjectDelayAction;

typedef struct BDRVInjectErrorState {
    QLIST_HEAD(, InjectErrorEntry) entries;
    QTAILQ_HEAD(, InjectDelayRule) rules;
    QLIST_HEAD(, InjectDelayedReq) inflight;
    int64_t next_req_id;
    GRand *rand;
    bool draining;
    QemuMutex lock;
} BDRVInjectErrorState;

static bool ranges_overlap(int64_t a_off, int64_t a_len,
                           int64_t b_off, int64_t b_len)
{
    return a_off < b_off + b_len && b_off < a_off + a_len;
}

static void add_entry(BDRVInjectErrorState *s, int64_t sector, int64_t count,
                      int error, bool reads, bool writes,
                      InjectErrorBehavior behavior)
{
    InjectErrorEntry *entry = g_new0(InjectErrorEntry, 1);

    entry->offset = sector * BDRV_SECTOR_SIZE;
    entry->length = count * BDRV_SECTOR_SIZE;
    entry->error = error;
    entry->reads = reads;
    entry->writes = writes;
    entry->behavior = behavior;

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        QLIST_INSERT_HEAD(&s->entries, entry, next);
    }
}

/* Must be called with lock held.  Returns negative errno or 0. */
static int check_errors(BDRVInjectErrorState *s, int64_t offset, int64_t bytes,
                        bool is_write)
{
    InjectErrorEntry *entry, *next;
    int error;

    QLIST_FOREACH_SAFE(entry, &s->entries, next, next) {
        if (!ranges_overlap(offset, bytes, entry->offset, entry->length)) {
            continue;
        }

        if (is_write && entry->behavior == INJECT_ERROR_BEHAVIOR_FIX_ON_WRITE) {
            QLIST_REMOVE(entry, next);
            g_free(entry);
            continue;
        }

        if (is_write ? !entry->writes : !entry->reads) {
            continue;
        }

        error = entry->error;

        if (entry->behavior == INJECT_ERROR_BEHAVIOR_TRANSIENT) {
            QLIST_REMOVE(entry, next);
            g_free(entry);
        }

        return -error;
    }

    return 0;
}

static void inject_req_unref(InjectDelayedReq *req)
{
    if (qatomic_fetch_dec(&req->refcnt) == 1) {
        g_free(req->rule_id);
        g_free(req);
    }
}

/* Must be called with lock held. */
static void inject_delay_rule_remove(BDRVInjectErrorState *s,
                                     InjectDelayRule *rule)
{
    QTAILQ_REMOVE(&s->rules, rule, next);
    g_free(rule->id);
    g_free(rule);
}

/* Must be called with lock held. */
static InjectDelayRule *inject_delay_rule_find(BDRVInjectErrorState *s,
                                               const char *id)
{
    InjectDelayRule *rule;

    QTAILQ_FOREACH(rule, &s->rules, next) {
        if (!strcmp(rule->id, id)) {
            return rule;
        }
    }

    return NULL;
}

static int inject_delay_rule_add(BDRVInjectErrorState *s,
                                 InjectDelayRuleOptions *opts, Error **errp)
{
    int64_t sector = opts->has_sector ? opts->sector : 0;
    double probability = opts->has_probability ? opts->probability : 1.0;
    int64_t delay_ms = opts->has_delay_ms ? opts->delay_ms : 0;
    int64_t delay_max_ms = opts->has_delay_max_ms ? opts->delay_max_ms
                                                  : delay_ms;
    int64_t error = opts->has_q_errno ? opts->q_errno : 0;
    InjectDelayRule *rule;
    InjectDelayOpList *op;
    uint32_t ops = 0;

    if (!opts->id[0]) {
        error_setg(errp, "rule id must not be empty");
        return -EINVAL;
    }
    if (sector < 0) {
        error_setg(errp, "sector must be non-negative");
        return -EINVAL;
    }
    if (opts->has_count && opts->count <= 0) {
        error_setg(errp, "count must be positive");
        return -EINVAL;
    }
    if (!(probability >= 0.0) || probability > 1.0) {
        error_setg(errp, "probability must be between 0.0 and 1.0");
        return -EINVAL;
    }
    if (delay_ms < 0 || delay_ms > INJECT_DELAY_MAX_MS) {
        error_setg(errp, "delay-ms must be between 0 and %" PRId64,
                   INJECT_DELAY_MAX_MS);
        return -EINVAL;
    }
    if (delay_max_ms < delay_ms || delay_max_ms > INJECT_DELAY_MAX_MS) {
        error_setg(errp, "delay-max-ms must be between delay-ms and %" PRId64,
                   INJECT_DELAY_MAX_MS);
        return -EINVAL;
    }
    if (error < 0 || error > INT_MAX) {
        error_setg(errp, "errno must be a non-negative 32-bit integer");
        return -EINVAL;
    }
    if (opts->has_max_hits && opts->max_hits <= 0) {
        error_setg(errp, "max-hits must be positive");
        return -EINVAL;
    }

    if (opts->has_ops) {
        for (op = opts->ops; op; op = op->next) {
            ops |= INJECT_DELAY_OP_BIT(op->value);
        }
        if (!ops) {
            error_setg(errp, "ops must name at least one kind of I/O");
            return -EINVAL;
        }
    } else {
        ops = INJECT_DELAY_OPS_ALL;
    }

    QEMU_LOCK_GUARD(&s->lock);

    if (inject_delay_rule_find(s, opts->id)) {
        error_setg(errp, "a delay rule named '%s' already exists", opts->id);
        return -EEXIST;
    }

    rule = g_new0(InjectDelayRule, 1);
    rule->id = g_strdup(opts->id);
    rule->ops = ops;
    rule->offset = sector * BDRV_SECTOR_SIZE;
    rule->length = opts->has_count ? opts->count * BDRV_SECTOR_SIZE : -1;
    rule->probability = probability;
    rule->delay_min_ns = delay_ms * SCALE_MS;
    rule->delay_max_ns = delay_max_ms * SCALE_MS;
    rule->stall = opts->has_stall && opts->stall;
    rule->error = error;
    rule->max_hits = opts->has_max_hits ? opts->max_hits : -1;

    QTAILQ_INSERT_TAIL(&s->rules, rule, next);
    return 0;
}

/*
 * Find the first rule that wants to hold this request and fill in @act.
 * Must be called with lock held; consumes one of the rule's remaining
 * hits and drops the rule once it is exhausted.
 */
static void inject_delay_match(BDRVInjectErrorState *s, InjectDelayOp op,
                               int64_t offset, int64_t bytes,
                               InjectDelayAction *act)
{
    InjectDelayRule *rule, *next;

    QTAILQ_FOREACH_SAFE(rule, &s->rules, next, next) {
        if (!(rule->ops & INJECT_DELAY_OP_BIT(op))) {
            continue;
        }

        /* A flush has no sector range, so a range-limited rule can't match. */
        if (rule->length >= 0 &&
            (op == INJECT_DELAY_OP_FLUSH ||
             !ranges_overlap(offset, bytes, rule->offset, rule->length))) {
            continue;
        }

        if (rule->probability < 1.0 &&
            g_rand_double(s->rand) >= rule->probability) {
            continue;
        }

        act->fired = true;
        act->stall = rule->stall;
        act->error = rule->error;
        act->rule_id = g_strdup(rule->id);
        act->delay_ns = rule->delay_min_ns;
        if (rule->delay_max_ns > rule->delay_min_ns) {
            act->delay_ns = g_rand_double_range(s->rand, rule->delay_min_ns,
                                                rule->delay_max_ns);
        }

        rule->hits++;
        if (rule->max_hits >= 0 && --rule->max_hits == 0) {
            inject_delay_rule_remove(s, rule);
        }
        return;
    }
}

/*
 * Wake held requests.  @request_id is matched unless @all is true; when
 * @set_result is true the requests complete with @result instead of the
 * disposition their rule asked for.  Returns the number woken.
 *
 * The requests are woken with the lock dropped: waking a coroutine that
 * runs in the caller's AioContext enters it right away, and it needs the
 * lock to take itself off the in-flight list.
 */
static int inject_delay_wake(BDRVInjectErrorState *s, bool all,
                             int64_t request_id, bool set_result, int result)
{
    g_autoptr(GPtrArray) wake = g_ptr_array_new();
    InjectDelayedReq *req;
    guint i;

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        QLIST_FOREACH(req, &s->inflight, next) {
            if (req->released || (!all && req->id != request_id)) {
                continue;
            }
            if (set_result) {
                req->result = result;
            }
            req->released = true;
            qatomic_inc(&req->refcnt);
            g_ptr_array_add(wake, req);
        }
    }

    for (i = 0; i < wake->len; i++) {
        req = g_ptr_array_index(wake, i);
        qemu_co_sleep_wake(&req->sleep);
        inject_req_unref(req);
    }

    return wake->len;
}

/*
 * Hold the request if a latency rule matches it.  Returns 0 if the
 * request should proceed to the image, or a negative errno the request
 * should fail with.
 */
static int coroutine_fn inject_delay(BlockDriverState *bs, InjectDelayOp op,
                                     int64_t offset, int64_t bytes)
{
    BDRVInjectErrorState *s = bs->opaque;
    InjectDelayAction act = { 0 };
    InjectDelayedReq *req;
    bool done = false;
    int result;

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        if (!s->draining) {
            inject_delay_match(s, op, offset, bytes, &act);
        }
        if (!act.fired) {
            return 0;
        }

        req = g_new0(InjectDelayedReq, 1);
        req->refcnt = 2;                /* the list and this coroutine */
        req->id = ++s->next_req_id;
        req->op = op;
        req->offset = offset;
        req->length = bytes;
        req->rule_id = act.rule_id;
        req->stalled = act.stall;
        req->result = -act.error;
        req->deadline_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) +
                           act.delay_ns;
        QLIST_INSERT_HEAD(&s->inflight, req, next);
    }

    while (!done) {
        int64_t remaining = 0;

        WITH_QEMU_LOCK_GUARD(&s->lock) {
            done = req->released;
            result = req->result;
        }
        if (done) {
            break;
        }

        if (req->stalled) {
            qemu_co_sleep(&req->sleep);
            continue;
        }

        remaining = req->deadline_ns - qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        if (remaining <= 0) {
            break;
        }
        qemu_co_sleep_ns_wakeable(&req->sleep, QEMU_CLOCK_REALTIME, remaining);
    }

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        QLIST_REMOVE(req, next);
    }
    inject_req_unref(req);              /* the list's reference */
    inject_req_unref(req);

    return result;
}

/*
 * Drain has to make progress, so a device reset or a block job can't be
 * left waiting on a stalled request: wake everything, keeping whatever
 * disposition its rule asked for.  A guest reset therefore ends a stall,
 * which is what real recovery looks like.
 */
static void inject_error_drain_begin(BlockDriverState *bs)
{
    BDRVInjectErrorState *s = bs->opaque;

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        s->draining = true;
    }

    inject_delay_wake(s, true, 0, false, 0);
}

static void inject_error_drain_end(BlockDriverState *bs)
{
    BDRVInjectErrorState *s = bs->opaque;

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        s->draining = false;
    }
}

static int inject_error_parse_options(BDRVInjectErrorState *s,
                                      QDict *options, Error **errp)
{
    g_autoptr(BlockdevOptions) full_opts = NULL;
    BlockdevOptionsInjectError *opts;
    InjectErrorSectorOptionsList *cur;
    InjectDelayRuleOptionsList *rule;
    Visitor *v;
    int ret = 0;

    qdict_put_str(options, "driver", "inject-error");

    v = qobject_input_visitor_new_flat_confused(options, errp);
    if (!v) {
        ret = -EINVAL;
        goto out;
    }

    visit_type_BlockdevOptions(v, NULL, &full_opts, errp);
    visit_free(v);
    if (!full_opts) {
        ret = -EINVAL;
        goto out;
    }

    assert(full_opts->driver == BLOCKDEV_DRIVER_INJECT_ERROR);
    opts = &full_opts->u.inject_error;

    if (opts->has_seed) {
        g_rand_set_seed(s->rand, opts->seed);
    }

    for (cur = opts->errors; cur; cur = cur->next) {
        InjectErrorSectorOptions *e = cur->value;
        int64_t count = e->has_count ? e->count : 1;
        int error_num = e->has_q_errno ? e->q_errno : EIO;
        bool reads = e->has_reads ? e->reads : true;
        bool writes = e->has_writes ? e->writes : false;
        InjectErrorBehavior behavior = e->has_behavior ? e->behavior :
                                       INJECT_ERROR_BEHAVIOR_PERSISTENT;

        if (e->sector < 0) {
            error_setg(errp, "sector must be non-negative");
            ret = -EINVAL;
            goto out;
        }
        if (count <= 0) {
            error_setg(errp, "count must be positive");
            ret = -EINVAL;
            goto out;
        }
        if (error_num <= 0 || error_num > INT_MAX) {
            error_setg(errp, "errno must be a positive 32-bit integer");
            ret = -EINVAL;
            goto out;
        }

        add_entry(s, e->sector, count, error_num, reads, writes, behavior);
    }

    for (rule = opts->delays; rule; rule = rule->next) {
        ret = inject_delay_rule_add(s, rule->value, errp);
        if (ret < 0) {
            goto out;
        }
    }

out:
    qdict_extract_subqdict(options, NULL, "errors.");
    qdict_extract_subqdict(options, NULL, "delays.");
    qdict_del(options, "seed");
    qdict_del(options, "driver");
    return ret;
}

static void inject_error_close(BlockDriverState *bs)
{
    BDRVInjectErrorState *s = bs->opaque;
    InjectErrorEntry *entry, *next;
    InjectDelayRule *rule, *rule_next;

    /* Requests are drained before close, so nothing can be held here. */
    assert(QLIST_EMPTY(&s->inflight));

    QLIST_FOREACH_SAFE(entry, &s->entries, next, next) {
        QLIST_REMOVE(entry, next);
        g_free(entry);
    }

    QTAILQ_FOREACH_SAFE(rule, &s->rules, next, rule_next) {
        inject_delay_rule_remove(s, rule);
    }

    g_rand_free(s->rand);
    qemu_mutex_destroy(&s->lock);
}

static int inject_error_open(BlockDriverState *bs, QDict *options,
                             int flags, Error **errp)
{
    BDRVInjectErrorState *s = bs->opaque;
    int ret;

    qemu_mutex_init(&s->lock);
    QLIST_INIT(&s->entries);
    QTAILQ_INIT(&s->rules);
    QLIST_INIT(&s->inflight);
    s->rand = g_rand_new();

    ret = inject_error_parse_options(s, options, errp);
    if (ret < 0) {
        goto fail;
    }

    ret = bdrv_open_file_child(NULL, options, "image", bs, errp);
    if (ret < 0) {
        goto fail;
    }

    {
        GRAPH_RDLOCK_GUARD_MAINLOOP();

        bs->supported_write_flags = BDRV_REQ_WRITE_UNCHANGED |
            (BDRV_REQ_FUA & bs->file->bs->supported_write_flags);
        bs->supported_zero_flags = BDRV_REQ_WRITE_UNCHANGED |
            ((BDRV_REQ_FUA | BDRV_REQ_MAY_UNMAP | BDRV_REQ_NO_FALLBACK) &
                bs->file->bs->supported_zero_flags);
    }

    return 0;

fail:
    inject_error_close(bs);
    return ret;
}

static int64_t coroutine_fn GRAPH_RDLOCK
inject_error_co_getlength(BlockDriverState *bs)
{
    return bdrv_co_getlength(bs->file->bs);
}

static int coroutine_fn GRAPH_RDLOCK
inject_error_co_preadv(BlockDriverState *bs, int64_t offset, int64_t bytes,
                       QEMUIOVector *qiov, BdrvRequestFlags flags)
{
    BDRVInjectErrorState *s = bs->opaque;
    int ret;

    ret = inject_delay(bs, INJECT_DELAY_OP_READ, offset, bytes);
    if (ret) {
        return ret;
    }

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        ret = check_errors(s, offset, bytes, false);
    }

    if (ret) {
        return ret;
    }

    return bdrv_co_preadv(bs->file, offset, bytes, qiov, flags);
}

static int coroutine_fn GRAPH_RDLOCK
inject_error_co_pwritev(BlockDriverState *bs, int64_t offset, int64_t bytes,
                        QEMUIOVector *qiov, BdrvRequestFlags flags)
{
    BDRVInjectErrorState *s = bs->opaque;
    int ret;

    ret = inject_delay(bs, INJECT_DELAY_OP_WRITE, offset, bytes);
    if (ret) {
        return ret;
    }

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        ret = check_errors(s, offset, bytes, true);
    }

    if (ret) {
        return ret;
    }

    return bdrv_co_pwritev(bs->file, offset, bytes, qiov, flags);
}

static int coroutine_fn GRAPH_RDLOCK
inject_error_co_pwrite_zeroes(BlockDriverState *bs, int64_t offset,
                              int64_t bytes, BdrvRequestFlags flags)
{
    BDRVInjectErrorState *s = bs->opaque;
    int ret;

    ret = inject_delay(bs, INJECT_DELAY_OP_WRITE_ZEROES, offset, bytes);
    if (ret) {
        return ret;
    }

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        ret = check_errors(s, offset, bytes, true);
    }

    if (ret) {
        return ret;
    }

    return bdrv_co_pwrite_zeroes(bs->file, offset, bytes, flags);
}

static int coroutine_fn GRAPH_RDLOCK
inject_error_co_pdiscard(BlockDriverState *bs, int64_t offset, int64_t bytes)
{
    BDRVInjectErrorState *s = bs->opaque;
    int ret;

    ret = inject_delay(bs, INJECT_DELAY_OP_DISCARD, offset, bytes);
    if (ret) {
        return ret;
    }

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        ret = check_errors(s, offset, bytes, true);
    }

    if (ret) {
        return ret;
    }

    return bdrv_co_pdiscard(bs->file, offset, bytes);
}

static int coroutine_fn GRAPH_RDLOCK
inject_error_co_flush(BlockDriverState *bs)
{
    int ret;

    ret = inject_delay(bs, INJECT_DELAY_OP_FLUSH, 0, 0);
    if (ret) {
        return ret;
    }

    return bdrv_co_flush(bs->file->bs);
}

static int coroutine_fn GRAPH_RDLOCK
inject_error_co_block_status(BlockDriverState *bs, unsigned int mode,
                             int64_t offset, int64_t bytes, int64_t *pnum,
                             int64_t *map, BlockDriverState **file)
{
    *pnum = bytes;
    *map = offset;
    *file = bs->file->bs;
    return BDRV_BLOCK_RAW | BDRV_BLOCK_OFFSET_VALID;
}

static BlockDriver bdrv_inject_error = {
    .format_name            = "inject-error",
    .instance_size          = sizeof(BDRVInjectErrorState),
    .is_filter              = true,

    .bdrv_open              = inject_error_open,
    .bdrv_close             = inject_error_close,
    .bdrv_child_perm        = bdrv_default_perms,

    .bdrv_co_getlength      = inject_error_co_getlength,

    .bdrv_co_preadv         = inject_error_co_preadv,
    .bdrv_co_pwritev        = inject_error_co_pwritev,
    .bdrv_co_pwrite_zeroes  = inject_error_co_pwrite_zeroes,
    .bdrv_co_pdiscard       = inject_error_co_pdiscard,
    .bdrv_co_flush          = inject_error_co_flush,
    .bdrv_co_block_status   = inject_error_co_block_status,

    .bdrv_drain_begin       = inject_error_drain_begin,
    .bdrv_drain_end         = inject_error_drain_end,
};

static void bdrv_inject_error_init(void)
{
    bdrv_register(&bdrv_inject_error);
}

block_init(bdrv_inject_error_init);

/* QMP command implementations */

/* Look up an inject-error node's state by node name. */
static BDRVInjectErrorState *inject_error_find(const char *node_name,
                                               Error **errp)
{
    BlockDriverState *bs = bdrv_find_node(node_name);

    if (!bs) {
        error_setg(errp, "Node '%s' not found", node_name);
        return NULL;
    }

    if (bs->drv != &bdrv_inject_error) {
        error_setg(errp, "Node '%s' is not an inject-error node", node_name);
        return NULL;
    }

    return bs->opaque;
}

void qmp_x_inject_error_add(const char *node_name, int64_t sector,
                            bool has_count, int64_t count,
                            bool has_q_errno, int64_t q_errno,
                            bool has_behavior, InjectErrorBehavior behavior,
                            bool has_reads, bool reads,
                            bool has_writes, bool writes,
                            Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);

    if (!s) {
        return;
    }

    if (sector < 0) {
        error_setg(errp, "sector must be non-negative");
        return;
    }
    if (!has_count) {
        count = 1;
    }
    if (count <= 0) {
        error_setg(errp, "count must be positive");
        return;
    }
    if (!has_q_errno) {
        q_errno = EIO;
    }
    if (q_errno <= 0 || q_errno > INT_MAX) {
        error_setg(errp, "errno must be a positive 32-bit integer");
        return;
    }
    if (!has_behavior) {
        behavior = INJECT_ERROR_BEHAVIOR_PERSISTENT;
    }
    if (!has_reads) {
        reads = true;
    }
    if (!has_writes) {
        writes = false;
    }

    add_entry(s, sector, count, q_errno, reads, writes, behavior);
}

void qmp_x_inject_error_remove(const char *node_name, int64_t sector,
                               bool has_count, int64_t count,
                               Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);
    InjectErrorEntry *entry, *next;
    int64_t offset, length;

    if (!s) {
        return;
    }

    if (sector < 0) {
        error_setg(errp, "sector must be non-negative");
        return;
    }
    if (!has_count) {
        count = 1;
    }
    if (count <= 0) {
        error_setg(errp, "count must be positive");
        return;
    }

    offset = sector * BDRV_SECTOR_SIZE;
    length = count * BDRV_SECTOR_SIZE;

    QEMU_LOCK_GUARD(&s->lock);
    QLIST_FOREACH_SAFE(entry, &s->entries, next, next) {
        if (ranges_overlap(offset, length, entry->offset, entry->length)) {
            QLIST_REMOVE(entry, next);
            g_free(entry);
        }
    }
}

InjectErrorEntryInfoList *qmp_x_inject_error_list(const char *node_name,
                                                  Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);
    InjectErrorEntryInfoList *head = NULL, **tail = &head;
    InjectErrorEntry *entry;

    if (!s) {
        return NULL;
    }

    QEMU_LOCK_GUARD(&s->lock);
    QLIST_FOREACH(entry, &s->entries, next) {
        InjectErrorEntryInfo *info = g_new0(InjectErrorEntryInfo, 1);

        info->sector = entry->offset / BDRV_SECTOR_SIZE;
        info->count = entry->length / BDRV_SECTOR_SIZE;
        info->q_errno = entry->error;
        info->behavior = entry->behavior;
        info->reads = entry->reads;
        info->writes = entry->writes;

        QAPI_LIST_APPEND(tail, info);
    }

    return head;
}

void qmp_x_inject_error_delay_add(const char *node_name,
                                  InjectDelayRuleOptions *rule, Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);

    if (s) {
        inject_delay_rule_add(s, rule, errp);
    }
}

InjectDelayCount *qmp_x_inject_error_delay_remove(const char *node_name,
                                                  const char *id, Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);
    InjectDelayCount *ret;
    InjectDelayRule *rule, *next;
    int64_t removed = 0;

    if (!s) {
        return NULL;
    }

    WITH_QEMU_LOCK_GUARD(&s->lock) {
        QTAILQ_FOREACH_SAFE(rule, &s->rules, next, next) {
            if (!id || !strcmp(rule->id, id)) {
                inject_delay_rule_remove(s, rule);
                removed++;
            }
        }
    }

    if (id && !removed) {
        error_setg(errp, "No delay rule named '%s'", id);
        return NULL;
    }

    ret = g_new0(InjectDelayCount, 1);
    ret->count = removed;
    return ret;
}

InjectDelayRuleInfoList *qmp_x_inject_error_delay_list(const char *node_name,
                                                       Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);
    InjectDelayRuleInfoList *head = NULL, **tail = &head;
    InjectDelayRule *rule;
    InjectDelayOp op;

    if (!s) {
        return NULL;
    }

    QEMU_LOCK_GUARD(&s->lock);
    QTAILQ_FOREACH(rule, &s->rules, next) {
        InjectDelayRuleInfo *info = g_new0(InjectDelayRuleInfo, 1);
        InjectDelayOpList **op_tail = &info->ops;

        info->id = g_strdup(rule->id);
        for (op = 0; op < INJECT_DELAY_OP__MAX; op++) {
            if (rule->ops & INJECT_DELAY_OP_BIT(op)) {
                QAPI_LIST_APPEND(op_tail, op);
            }
        }
        info->sector = rule->offset / BDRV_SECTOR_SIZE;
        info->has_count = rule->length >= 0;
        info->count = info->has_count ? rule->length / BDRV_SECTOR_SIZE : 0;
        info->probability = rule->probability;
        info->delay_ms = rule->delay_min_ns / SCALE_MS;
        info->delay_max_ms = rule->delay_max_ns / SCALE_MS;
        info->stall = rule->stall;
        info->q_errno = rule->error;
        info->has_max_hits = rule->max_hits >= 0;
        info->max_hits = rule->max_hits;
        info->hits = rule->hits;

        QAPI_LIST_APPEND(tail, info);
    }

    return head;
}

InjectDelayRequestInfoList *
qmp_x_inject_error_delay_inflight(const char *node_name, Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);
    InjectDelayRequestInfoList *head = NULL, **tail = &head;
    InjectDelayedReq *req;
    int64_t now;

    if (!s) {
        return NULL;
    }

    now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    QEMU_LOCK_GUARD(&s->lock);
    QLIST_FOREACH(req, &s->inflight, next) {
        InjectDelayRequestInfo *info = g_new0(InjectDelayRequestInfo, 1);

        info->id = req->id;
        info->rule_id = g_strdup(req->rule_id);
        info->op = req->op;
        info->has_sector = req->op != INJECT_DELAY_OP_FLUSH;
        info->has_count = info->has_sector;
        if (info->has_sector) {
            info->sector = req->offset / BDRV_SECTOR_SIZE;
            info->count = req->length / BDRV_SECTOR_SIZE;
        }
        info->stalled = req->stalled;
        info->has_remaining_ms = !req->stalled;
        if (info->has_remaining_ms) {
            info->remaining_ms = MAX(req->deadline_ns - now, 0) / SCALE_MS;
        }
        info->q_errno = -req->result;

        QAPI_LIST_APPEND(tail, info);
    }

    return head;
}

InjectDelayCount *qmp_x_inject_error_delay_release(const char *node_name,
                                                   bool has_request_id,
                                                   int64_t request_id,
                                                   bool has_disposition,
                                                   InjectDelayDisposition disp,
                                                   bool has_q_errno,
                                                   int64_t q_errno,
                                                   Error **errp)
{
    BDRVInjectErrorState *s = inject_error_find(node_name, errp);
    InjectDelayCount *ret;
    int result = 0;
    int released;

    if (!s) {
        return NULL;
    }

    if (!has_q_errno) {
        q_errno = EIO;
    }
    if (q_errno <= 0 || q_errno > INT_MAX) {
        error_setg(errp, "errno must be a positive 32-bit integer");
        return NULL;
    }

    if (has_disposition && disp == INJECT_DELAY_DISPOSITION_ERROR) {
        result = -q_errno;
    }

    released = inject_delay_wake(s, !has_request_id, request_id,
                                 has_disposition, result);

    if (has_request_id && !released) {
        error_setg(errp, "No held request with id %" PRId64, request_id);
        return NULL;
    }

    ret = g_new0(InjectDelayCount, 1);
    ret->count = released;
    return ret;
}
