/*
 * Block filter driver for media error injection
 *
 * Simulates bad sectors by returning errors for I/O operations that
 * touch configured sector ranges.  Sits in the block graph between the
 * guest device and the backing image.  Device emulators (SCSI, NVMe,
 * AHCI) already translate block-layer errors into protocol-specific
 * error responses.
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

typedef struct BDRVInjectErrorState {
    QLIST_HEAD(, InjectErrorEntry) entries;
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

static int inject_error_parse_entries(BDRVInjectErrorState *s,
                                      QDict *options, Error **errp)
{
    g_autoptr(BlockdevOptions) full_opts = NULL;
    BlockdevOptionsInjectError *opts;
    InjectErrorSectorOptionsList *cur;
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

out:
    qdict_extract_subqdict(options, NULL, "errors.");
    qdict_del(options, "driver");
    return ret;
}

static void inject_error_close(BlockDriverState *bs)
{
    BDRVInjectErrorState *s = bs->opaque;
    InjectErrorEntry *entry, *next;

    QLIST_FOREACH_SAFE(entry, &s->entries, next, next) {
        QLIST_REMOVE(entry, next);
        g_free(entry);
    }

    qemu_mutex_destroy(&s->lock);
}

static int inject_error_open(BlockDriverState *bs, QDict *options,
                             int flags, Error **errp)
{
    BDRVInjectErrorState *s = bs->opaque;
    int ret;

    qemu_mutex_init(&s->lock);
    QLIST_INIT(&s->entries);

    ret = inject_error_parse_entries(s, options, errp);
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
    .bdrv_co_flush_to_disk  = inject_error_co_flush,
    .bdrv_co_block_status   = inject_error_co_block_status,
};

static void bdrv_inject_error_init(void)
{
    bdrv_register(&bdrv_inject_error);
}

block_init(bdrv_inject_error_init);

/* QMP command implementations */

void qmp_x_inject_error_add(const char *node_name, int64_t sector,
                            bool has_count, int64_t count,
                            bool has_q_errno, int64_t q_errno,
                            bool has_behavior, InjectErrorBehavior behavior,
                            bool has_reads, bool reads,
                            bool has_writes, bool writes,
                            Error **errp)
{
    BlockDriverState *bs;
    BDRVInjectErrorState *s;

    bs = bdrv_find_node(node_name);
    if (!bs) {
        error_setg(errp, "Node '%s' not found", node_name);
        return;
    }

    if (bs->drv != &bdrv_inject_error) {
        error_setg(errp, "Node '%s' is not an inject-error node", node_name);
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

    s = bs->opaque;
    add_entry(s, sector, count, q_errno, reads, writes, behavior);
}

void qmp_x_inject_error_remove(const char *node_name, int64_t sector,
                               bool has_count, int64_t count,
                               Error **errp)
{
    BlockDriverState *bs;
    BDRVInjectErrorState *s;
    InjectErrorEntry *entry, *next;
    int64_t offset, length;

    bs = bdrv_find_node(node_name);
    if (!bs) {
        error_setg(errp, "Node '%s' not found", node_name);
        return;
    }

    if (bs->drv != &bdrv_inject_error) {
        error_setg(errp, "Node '%s' is not an inject-error node", node_name);
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
    s = bs->opaque;

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
    BlockDriverState *bs;
    BDRVInjectErrorState *s;
    InjectErrorEntryInfoList *head = NULL, **tail = &head;
    InjectErrorEntry *entry;

    bs = bdrv_find_node(node_name);
    if (!bs) {
        error_setg(errp, "Node '%s' not found", node_name);
        return NULL;
    }

    if (bs->drv != &bdrv_inject_error) {
        error_setg(errp, "Node '%s' is not an inject-error node", node_name);
        return NULL;
    }

    s = bs->opaque;

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
