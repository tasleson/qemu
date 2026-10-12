/*
 * QTest testcase for VirtIO SCSI
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH
 * Copyright (c) 2015 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest-single.h"
#include "qemu/bswap.h"
#include "qemu/module.h"
#include "scsi/constants.h"
#include "libqos/libqos-pc.h"
#include "libqos/libqos-spapr.h"
#include "libqos/virtio.h"
#include "libqos/virtio-pci.h"
#include "standard-headers/linux/virtio_config.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_pci.h"
#include "standard-headers/linux/virtio_scsi.h"
#include "libqos/virtio-scsi.h"
#include "libqos/qgraph.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "qobject/qjson.h"
#include "qapi/error.h"

#define PCI_SLOT                0x02
#define PCI_FN                  0x00
#define QVIRTIO_SCSI_TIMEOUT_US (1 * 1000 * 1000)

#define MAX_NUM_QUEUES 64

typedef struct {
    QVirtioDevice *dev;
    int num_queues;
    QVirtQueue *vq[MAX_NUM_QUEUES + 2];
} QVirtioSCSIQueues;

static QGuestAllocator *alloc;

static void qvirtio_scsi_pci_free(QVirtioSCSIQueues *vs)
{
    int i;

    for (i = 0; i < vs->num_queues + 2; i++) {
        qvirtqueue_cleanup(vs->dev->bus, vs->vq[i], alloc);
    }
    g_free(vs);
}

static uint64_t qvirtio_scsi_alloc(QVirtioSCSIQueues *vs, size_t alloc_size,
                                   const void *data)
{
    uint64_t addr;

    addr = guest_alloc(alloc, alloc_size);
    if (data) {
        memwrite(addr, data, alloc_size);
    }

    return addr;
}

static uint8_t virtio_scsi_do_command(QVirtioSCSIQueues *vs,
                                      const uint8_t *cdb,
                                      const uint8_t *data_in,
                                      size_t data_in_len,
                                      uint8_t *data_out, size_t data_out_len,
                                      struct virtio_scsi_cmd_resp *resp_out)
{
    QVirtQueue *vq;
    struct virtio_scsi_cmd_req req = { { 0 } };
    struct virtio_scsi_cmd_resp resp = { .response = 0xff, .status = 0xff };
    uint64_t req_addr, resp_addr, data_in_addr = 0, data_out_addr = 0;
    uint8_t response;
    uint32_t free_head;
    QTestState *qts = global_qtest;

    vq = vs->vq[2];

    req.lun[0] = 1; /* Select LUN */
    req.lun[1] = 1; /* Select target 1 */
    memcpy(req.cdb, cdb, VIRTIO_SCSI_CDB_SIZE);

    /* XXX: Fix endian if any multi-byte field in req/resp is used */

    /* Add request header */
    req_addr = qvirtio_scsi_alloc(vs, sizeof(req), &req);
    free_head = qvirtqueue_add(qts, vq, req_addr, sizeof(req), false, true);

    if (data_out_len) {
        data_out_addr = qvirtio_scsi_alloc(vs, data_out_len, data_out);
        qvirtqueue_add(qts, vq, data_out_addr, data_out_len, false, true);
    }

    /* Add response header */
    resp_addr = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
    qvirtqueue_add(qts, vq, resp_addr, sizeof(resp), true, !!data_in_len);

    if (data_in_len) {
        data_in_addr = qvirtio_scsi_alloc(vs, data_in_len, data_in);
        qvirtqueue_add(qts, vq, data_in_addr, data_in_len, true, false);
    }

    qvirtqueue_kick(qts, vs->dev, vq, free_head);
    qvirtio_wait_used_elem(qts, vs->dev, vq, free_head, NULL,
                           QVIRTIO_SCSI_TIMEOUT_US);

    response = readb(resp_addr +
                     offsetof(struct virtio_scsi_cmd_resp, response));

    if (resp_out) {
        memread(resp_addr, resp_out, sizeof(*resp_out));
    }

    guest_free(alloc, req_addr);
    guest_free(alloc, resp_addr);
    guest_free(alloc, data_in_addr);
    guest_free(alloc, data_out_addr);
    return response;
}

static QVirtioSCSIQueues *qvirtio_scsi_init(QVirtioDevice *dev)
{
    QVirtioSCSIQueues *vs;
    const uint8_t test_unit_ready_cdb[VIRTIO_SCSI_CDB_SIZE] = {};
    struct virtio_scsi_cmd_resp resp;
    uint64_t features;
    int i;

    vs = g_new0(QVirtioSCSIQueues, 1);
    vs->dev = dev;

    features = qvirtio_get_features(dev);
    features &= ~(QVIRTIO_F_BAD_FEATURE | (1ull << VIRTIO_RING_F_EVENT_IDX));
    qvirtio_set_features(dev, features);

    vs->num_queues = qvirtio_config_readl(dev, 0);

    g_assert_cmpint(vs->num_queues, <, MAX_NUM_QUEUES);

    for (i = 0; i < vs->num_queues + 2; i++) {
        vs->vq[i] = qvirtqueue_setup(dev, alloc, i);
    }

    qvirtio_set_driver_ok(dev);

    /* Clear the POWER ON OCCURRED unit attention */
    g_assert_cmpint(virtio_scsi_do_command(vs, test_unit_ready_cdb,
                                           NULL, 0, NULL, 0, &resp),
                    ==, 0);
    g_assert_cmpint(resp.status, ==, CHECK_CONDITION);
    g_assert_cmpint(resp.sense[0], ==, 0x70); /* Fixed format sense buffer */
    g_assert_cmpint(resp.sense[2], ==, UNIT_ATTENTION);
    g_assert_cmpint(resp.sense[12], ==, 0x29); /* POWER ON */
    g_assert_cmpint(resp.sense[13], ==, 0x00);

    return vs;
}

static void hotplug(void *obj, void *data, QGuestAllocator *t_alloc)
{
    QTestState *qts = global_qtest;

    qtest_qmp_device_add(qts, "scsi-hd", "scsihd", "{'drive': 'drv1'}");
    qtest_qmp_device_del(qts, "scsihd");
}

/* Test WRITE SAME with the lba not aligned */
static void test_unaligned_write_same(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    uint8_t buf1[512] = { 0 };
    uint8_t buf2[512] = { 1 };
    const uint8_t write_same_cdb_1[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00
    };
    const uint8_t write_same_cdb_2[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x33, 0x00, 0x00
    };
    const uint8_t write_same_cdb_ndob[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x33, 0x00, 0x00
    };

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_1, NULL, 0, buf1, 512,
                               NULL));

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_2, NULL, 0, buf2, 512,
                               NULL));

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_ndob, NULL, 0, NULL, 0,
                               NULL));

    qvirtio_scsi_pci_free(vs);
}

/* Test UNMAP with a large LBA, issue #345 */
static void test_unmap_large_lba(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    const uint8_t unmap[VIRTIO_SCSI_CDB_SIZE] = {
        0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00
    };

    /*
     * Default null-co device size is 2**30
     * LBA 0x7fff is ~ 1/8 into device, with 4k blocks
     * if check_lba_range incorrectly using 512 bytes, will trigger sense error
     */
    uint8_t unmap_params[0x18] = {
        0x00, 0x16, /* unmap data length */
        0x00, 0x10, /* unmap block descriptor data length */
        0x00, 0x00, 0x00, 0x00, /* reserved */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, /* LBA */
        0x00, 0x00, 0x03, 0xff, /* sector count */
        0x00, 0x00, 0x00, 0x00, /* reserved */
    };
    struct virtio_scsi_cmd_resp resp;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    virtio_scsi_do_command(vs, unmap, NULL, 0, unmap_params,
                           sizeof(unmap_params), &resp);
    g_assert_cmphex(resp.response, ==, 0);
    g_assert_cmphex(resp.status, !=, CHECK_CONDITION);

    qvirtio_scsi_pci_free(vs);
}

static void test_write_to_cdrom(void *obj, void *data,
                                QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    uint8_t buf[2048] = { 0 };
    const uint8_t write_cdb[VIRTIO_SCSI_CDB_SIZE] = {
        /* WRITE(10) to LBA 0, transfer length 1 */
        0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
    };
    struct virtio_scsi_cmd_resp resp;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    virtio_scsi_do_command(vs, write_cdb, NULL, 0, buf, 2048, &resp);
    g_assert_cmphex(resp.response, ==, 0);
    g_assert_cmphex(resp.status, ==, CHECK_CONDITION);
    g_assert_cmphex(resp.sense[0], ==, 0x70);
    g_assert_cmphex(resp.sense[2], ==, DATA_PROTECT);
    g_assert_cmphex(resp.sense[12], ==, 0x27); /* WRITE PROTECTED */
    g_assert_cmphex(resp.sense[13], ==, 0x00); /* WRITE PROTECTED */

    qvirtio_scsi_pci_free(vs);
}

static void test_iothread_attach_node(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSIPCI *scsi_pci = obj;
    QVirtioSCSI *scsi = &scsi_pci->scsi;
    QVirtioSCSIQueues *vs;
    g_autofree char *tmp_path = NULL;
    int fd;
    int ret;

    uint8_t buf[512] = { 0 };
    const uint8_t write_cdb[VIRTIO_SCSI_CDB_SIZE] = {
        /* WRITE(10) to LBA 0, transfer length 1 */
        0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
    };

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    /* Create a temporary qcow2 overlay*/
    fd = g_file_open_tmp("qtest.XXXXXX", &tmp_path, NULL);
    g_assert(fd >= 0);
    close(fd);

    if (!have_qemu_img()) {
        g_test_message("QTEST_QEMU_IMG not set or qemu-img missing; "
                       "skipping snapshot test");
        goto fail;
    }

    mkqcow2(tmp_path, 64);

    /* Attach the overlay to the null0 node */
    qtest_qmp_assert_success(scsi_pci->pci_vdev.pdev->bus->qts,
                             "{'execute': 'blockdev-add', 'arguments': {"
                             "   'driver': 'qcow2', 'node-name': 'overlay',"
                             "   'backing': 'null0', 'file': {"
                             "     'driver': 'file', 'filename': %s}}}",
                             tmp_path);

    /* Send a request to see if the AioContext is still right */
    ret = virtio_scsi_do_command(vs, write_cdb, NULL, 0, buf, 512, NULL);
    g_assert_cmphex(ret, ==, 0);

fail:
    qvirtio_scsi_pci_free(vs);
    unlink(tmp_path);
}

static void test_iothread_virtio_error(void *obj, void *data,
                                       QGuestAllocator *t_alloc)
{
    QVirtioSCSIPCI *scsi_pci = obj;
    QVirtioSCSI *scsi = &scsi_pci->scsi;
    QVirtioSCSIQueues *vs;
    QVirtQueue *vq;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);
    vq = vs->vq[2];

    /* Move avail.idx out of bounds to trigger virtio_error() */
    qvirtqueue_set_avail_idx(global_qtest, scsi->vdev, vq, vq->size * 2);
    scsi->vdev->bus->virtqueue_kick(scsi->vdev, vq);

    /*
     * Reset the device out of the error state. If QEMU hangs or crashes then
     * this will fail.
     */
    qvirtio_reset(scsi->vdev);

    qvirtio_scsi_pci_free(vs);
}

static void virtio_scsi_lun_reset(QVirtioSCSIQueues *vs)
{
    QTestState *qts = global_qtest;
    QVirtQueue *vq = vs->vq[0];
    uint32_t subtype = VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET;
    struct virtio_scsi_ctrl_tmf_req tmf = {
        .type = VIRTIO_SCSI_T_TMF,  /* 0 in either byte order */
        .subtype = qvirtio_is_big_endian(vs->dev) ? cpu_to_be32(subtype)
                                                  : cpu_to_le32(subtype),
        .lun = { 1, 1, 0, 0 },
    };
    struct virtio_scsi_ctrl_tmf_resp resp = { .response = 0xff };
    uint64_t tmf_addr, resp_addr;
    uint32_t head;

    tmf_addr = qvirtio_scsi_alloc(vs, sizeof(tmf), &tmf);
    resp_addr = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
    head = qvirtqueue_add(qts, vq, tmf_addr, sizeof(tmf), false, true);
    qvirtqueue_add(qts, vq, resp_addr, sizeof(resp), true, false);
    qvirtqueue_kick(qts, vs->dev, vq, head);
    qvirtio_wait_used_elem(qts, vs->dev, vq, head, NULL,
                           QVIRTIO_SCSI_TIMEOUT_US);
    g_assert_cmpint(readb(resp_addr), ==, VIRTIO_SCSI_S_OK);

    guest_free(alloc, tmf_addr);
    guest_free(alloc, resp_addr);
}

/*
 * A request published but not yet consumed when a TMF arrives is
 * snapshotted then, so when it breaks the queue the device can say whether
 * it was already bad when published. Here it was (a zero-length entry in
 * its indirect table): the device has to give up on the queue without
 * falling over, and recover on reset. The trace says verdict=unchanged.
 */
static void test_zero_length_pending_at_tmf(void *obj, void *data,
                                            QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QTestState *qts = global_qtest;
    QVirtioSCSIQueues *vs;
    QVirtQueue *vq;
    QVRingIndirectDesc *indirect;
    struct virtio_scsi_cmd_req req = { .lun = { 1, 1, 0, 0 }, .tag = 0x5a5a };
    struct virtio_scsi_cmd_resp resp = { .response = 0xff };
    uint64_t req_addr, resp_addr;
    uint32_t head;
    gint64 start;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);
    vq = vs->vq[2];
    if (!vq->indirect ||
        !(vs->dev->features & (1ull << VIRTIO_F_VERSION_1))) {
        /* Without VERSION_1 there is no NEEDS_RESET to wait for */
        g_test_skip("needs indirect descriptors and VIRTIO_F_VERSION_1");
        qvirtio_scsi_pci_free(vs);
        return;
    }

    req_addr = qvirtio_scsi_alloc(vs, sizeof(req), &req);
    resp_addr = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
    indirect = qvring_indirect_desc_setup(qts, vs->dev, alloc, 3);
    qvring_indirect_desc_add(vs->dev, qts, indirect, req_addr, sizeof(req),
                             false);
    qvring_indirect_desc_add(vs->dev, qts, indirect, req_addr, 0, false);
    qvring_indirect_desc_add(vs->dev, qts, indirect, resp_addr, sizeof(resp),
                             true);
    head = qvirtqueue_add_indirect(qts, vq, indirect);

    /* Published but not kicked: the TMF finds it pending */
    qvirtqueue_publish(qts, vs->dev, vq, head);
    virtio_scsi_lun_reset(vs);
    vs->dev->bus->virtqueue_kick(vs->dev, vq);

    start = g_get_monotonic_time();
    while (!(vs->dev->bus->get_status(vs->dev) &
             VIRTIO_CONFIG_S_NEEDS_RESET)) {
        g_assert(g_get_monotonic_time() - start <= QVIRTIO_SCSI_TIMEOUT_US);
    }
    g_assert_false(qvirtqueue_get_buf(qts, vq, NULL, NULL));

    qvirtio_reset(scsi->vdev);
    guest_free(alloc, indirect->desc);
    g_free(indirect);
    guest_free(alloc, req_addr);
    guest_free(alloc, resp_addr);
    qvirtio_scsi_pci_free(vs);
}

/*
 * An indirect table address that isn't RAM (here, unassigned space between
 * the end of the small qtest RAM and the PCI BARs). The diagnostics peek at
 * it both when the TMF snapshots the pending entry and when it breaks the
 * queue; they must decline the read rather than dispatch to whatever is
 * there, and the device must still go to NEEDS_RESET and recover.
 */
#define VIRTIO_SCSI_TEST_NON_RAM_ADDR 0x40000000ULL

static void test_unreadable_chain_pending_at_tmf(void *obj, void *data,
                                                 QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QTestState *qts = global_qtest;
    QVirtioSCSIQueues *vs;
    QVirtQueue *vq;
    uint32_t head;
    gint64 start;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);
    vq = vs->vq[2];
    if (!vq->indirect ||
        !(vs->dev->features & (1ull << VIRTIO_F_VERSION_1)) ||
        strcmp(qtest_get_arch(), "x86_64")) {
        g_test_skip("needs x86_64, indirect descriptors and VERSION_1");
        qvirtio_scsi_pci_free(vs);
        return;
    }

    /* An indirect head whose table lives at a non-RAM address */
    head = vq->free_head++;
    vq->num_free--;
    qtest_writeq(qts, vq->desc + 16 * head, VIRTIO_SCSI_TEST_NON_RAM_ADDR);
    qtest_writel(qts, vq->desc + 16 * head + 8,
                 2 * sizeof(struct vring_desc));
    qtest_writew(qts, vq->desc + 16 * head + 12, VRING_DESC_F_INDIRECT);

    qvirtqueue_publish(qts, vs->dev, vq, head);
    virtio_scsi_lun_reset(vs);
    vs->dev->bus->virtqueue_kick(vs->dev, vq);

    start = g_get_monotonic_time();
    while (!(vs->dev->bus->get_status(vs->dev) &
             VIRTIO_CONFIG_S_NEEDS_RESET)) {
        g_assert(g_get_monotonic_time() - start <= QVIRTIO_SCSI_TIMEOUT_US);
    }
    g_assert_false(qvirtqueue_get_buf(qts, vq, NULL, NULL));

    qvirtio_reset(scsi->vdev);
    qvirtio_scsi_pci_free(vs);
}

/*
 * Two requests in flight at once that share a command header -- what a
 * driver reissuing a request the device still holds looks like. The device
 * reports the overlap but still processes both.
 */
static void test_shared_header_overlap(void *obj, void *data,
                                       QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QTestState *qts = global_qtest;
    QVirtioSCSIQueues *vs;
    QVirtQueue *vq;
    struct virtio_scsi_cmd_req req = { .lun = { 1, 1, 0, 0 }, .tag = 0xa5 };
    struct virtio_scsi_cmd_resp resp = { .response = 0xff };
    uint64_t req_addr, resp_addr[2];
    uint32_t head[2];
    int i, done = 0;
    gint64 start;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);
    vq = vs->vq[2];

    req_addr = qvirtio_scsi_alloc(vs, sizeof(req), &req);
    for (i = 0; i < 2; i++) {
        resp_addr[i] = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
        head[i] = qvirtqueue_add(qts, vq, req_addr, sizeof(req), false, true);
        qvirtqueue_add(qts, vq, resp_addr[i], sizeof(resp), true, false);
        qvirtqueue_publish(qts, vs->dev, vq, head[i]);
    }
    vs->dev->bus->virtqueue_kick(vs->dev, vq);

    /* Both may complete under one interrupt, so poll the used ring */
    start = g_get_monotonic_time();
    while (done < 2) {
        uint32_t got;

        if (qvirtqueue_get_buf(qts, vq, &got, NULL)) {
            g_assert(got == head[0] || got == head[1]);
            done++;
        }
        g_assert(g_get_monotonic_time() - start <= QVIRTIO_SCSI_TIMEOUT_US);
    }
    for (i = 0; i < 2; i++) {
        g_assert_cmpint(readb(resp_addr[i] +
                              offsetof(struct virtio_scsi_cmd_resp, response)),
                        ==, VIRTIO_SCSI_S_OK);
        guest_free(alloc, resp_addr[i]);
    }
    guest_free(alloc, req_addr);
    qvirtio_scsi_pci_free(vs);
}


/*
 * SCSI target faults.  The tests run against the adapter libqos names vs0,
 * with LUNs 0 and 1 on target 1 and LUN 0 on target 2 added by
 * virtio_scsi_setup_fault().
 */

#define FAULT_DEVICE "vs0"
#define FAULT_MS (1000 * 1000LL)  /* in ns, for qtest_clock_step() */

/* A command or TMF that has been submitted but not waited for */
typedef struct {
    QVirtQueue *vq;
    uint32_t head;
    uint64_t req_addr;
    uint64_t resp_addr;
    uint64_t data_addr;
} FaultPending;

/* Submit a command reading @data_len bytes, or none, to @target/@lun */
static void fault_cmd(QVirtioSCSIQueues *vs, FaultPending *p, uint8_t target,
                      uint8_t lun, uint64_t tag, const uint8_t *cdb,
                      size_t cdb_len, size_t data_len)
{
    QTestState *qts = global_qtest;
    struct virtio_scsi_cmd_req req = {
        .lun = { 1, target, 0, lun },
        .tag = tag,
    };
    struct virtio_scsi_cmd_resp resp = { .response = 0xff, .status = 0xff };

    memcpy(req.cdb, cdb, cdb_len);
    p->vq = vs->vq[2];
    p->req_addr = qvirtio_scsi_alloc(vs, sizeof(req), &req);
    p->resp_addr = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
    p->data_addr = data_len ? qvirtio_scsi_alloc(vs, data_len, NULL) : 0;
    p->head = qvirtqueue_add(qts, p->vq, p->req_addr, sizeof(req), false,
                             true);
    qvirtqueue_add(qts, p->vq, p->resp_addr, sizeof(resp), true, !!data_len);
    if (data_len) {
        qvirtqueue_add(qts, p->vq, p->data_addr, data_len, true, false);
    }
    qvirtqueue_kick(qts, vs->dev, p->vq, p->head);
}

/* Submit a READ(10) of one block to @target/@lun */
static void fault_read(QVirtioSCSIQueues *vs, FaultPending *p, uint8_t target,
                       uint8_t lun, uint64_t tag)
{
    static const uint8_t cdb[] = { READ_10, 0, 0, 0, 0, 0, 0, 0, 1, 0 };

    fault_cmd(vs, p, target, lun, tag, cdb, sizeof(cdb), 512);
}

static void fault_tmf(QVirtioSCSIQueues *vs, FaultPending *p, uint32_t subtype,
                      uint8_t target, uint8_t lun, uint64_t tag)
{
    QTestState *qts = global_qtest;
    struct virtio_scsi_ctrl_tmf_req tmf = {
        .type = VIRTIO_SCSI_T_TMF,  /* 0 in either byte order */
        .subtype = qvirtio_is_big_endian(vs->dev) ? cpu_to_be32(subtype)
                                                  : cpu_to_le32(subtype),
        .lun = { 1, target, 0, lun },
        .tag = tag,
    };
    struct virtio_scsi_ctrl_tmf_resp resp = { .response = 0xff };

    p->vq = vs->vq[0];
    p->req_addr = qvirtio_scsi_alloc(vs, sizeof(tmf), &tmf);
    p->resp_addr = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
    p->data_addr = 0;
    p->head = qvirtqueue_add(qts, p->vq, p->req_addr, sizeof(tmf), false,
                             true);
    qvirtqueue_add(qts, p->vq, p->resp_addr, sizeof(resp), true, false);
    qvirtqueue_kick(qts, vs->dev, p->vq, p->head);
}

/* Wait until the device has used each of the @n requests in @p */
static void fault_wait(FaultPending *const *p, int n)
{
    QTestState *qts = global_qtest;
    gint64 start = g_get_monotonic_time();
    uint32_t done = 0;
    int i, j;

    g_assert_cmpint(n, <=, 32);
    while (done != (1u << n) - 1) {
        for (i = 0; i < n; i++) {
            uint32_t got;

            if (!qvirtqueue_get_buf(qts, p[i]->vq, &got, NULL)) {
                continue;
            }
            for (j = 0; j < n; j++) {
                if (p[j]->vq == p[i]->vq && p[j]->head == got &&
                    !(done & (1u << j))) {
                    break;
                }
            }
            g_assert_cmpint(j, <, n);
            done |= 1u << j;
        }
        g_assert(g_get_monotonic_time() - start <= QVIRTIO_SCSI_TIMEOUT_US);
    }
}

static void fault_wait1(FaultPending *p)
{
    fault_wait(&p, 1);
}

/* Nothing has been used on the control and first request queue */
static void fault_assert_idle(QVirtioSCSIQueues *vs)
{
    g_assert_false(qvirtqueue_get_buf(global_qtest, vs->vq[0], NULL, NULL));
    g_assert_false(qvirtqueue_get_buf(global_qtest, vs->vq[2], NULL, NULL));
}

static uint8_t fault_response(FaultPending *p)
{
    /* response is the first byte of a TMF response */
    if (p->vq->index == 0) {
        return readb(p->resp_addr);
    }
    return readb(p->resp_addr + offsetof(struct virtio_scsi_cmd_resp,
                                         response));
}

static uint8_t fault_status(FaultPending *p)
{
    return readb(p->resp_addr + offsetof(struct virtio_scsi_cmd_resp, status));
}

static void fault_free(FaultPending *p)
{
    guest_free(alloc, p->req_addr);
    guest_free(alloc, p->resp_addr);
    guest_free(alloc, p->data_addr);
}

/* A READ to @target/@lun completes GOOD, once unit attentions are cleared */
static void fault_assert_read_good(QVirtioSCSIQueues *vs, uint8_t target,
                                   uint8_t lun)
{
    int i;

    for (i = 0; i < 3; i++) {
        FaultPending p;
        uint8_t status;

        fault_read(vs, &p, target, lun, 0x100 + i);
        fault_wait1(&p);
        g_assert_cmpint(fault_response(&p), ==, VIRTIO_SCSI_S_OK);
        status = fault_status(&p);
        fault_free(&p);
        if (status == GOOD) {
            return;
        }
        g_assert_cmpint(status, ==, CHECK_CONDITION);
    }
    g_assert_not_reached();
}

static void fault_add(const char *fault)
{
    qtest_qmp_assert_success(global_qtest,
                             "{'execute': 'x-scsi-fault-add',"
                             " 'arguments': {'device': %s, 'fault': %p}}",
                             FAULT_DEVICE,
                             qobject_from_json(fault, &error_abort));
}

/* A command that has to fail */
static void G_GNUC_PRINTF(1, 2) fault_assert_failure(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    qobject_unref(qtest_vqmp_assert_failure_ref(global_qtest, fmt, ap));
    va_end(ap);
}

static void fault_remove_all(void)
{
    qtest_qmp_assert_success(global_qtest,
                             "{'execute': 'x-scsi-fault-remove',"
                             " 'arguments': {'device': %s}}", FAULT_DEVICE);
}

/* The x-scsi-fault-list entry for @id, NULL if it isn't armed */
static QDict *fault_info(const char *id)
{
    QDict *rsp = qtest_qmp(global_qtest,
                           "{'execute': 'x-scsi-fault-list',"
                           " 'arguments': {'device': %s}}", FAULT_DEVICE);
    QDict *ret = NULL;
    QListEntry *e;

    g_assert(qdict_haskey(rsp, "return"));
    QLIST_FOREACH_ENTRY(qdict_get_qlist(rsp, "return"), e) {
        QDict *info = qobject_to(QDict, qlist_entry_obj(e));

        if (!strcmp(qdict_get_str(info, "id"), id)) {
            ret = qdict_clone_shallow(info);
        }
    }
    qobject_unref(rsp);
    return ret;
}

/* Wait until the fault @id holds @n commands */
static void fault_wait_held(const char *id, int64_t n)
{
    gint64 start = g_get_monotonic_time();

    for (;;) {
        QDict *info = fault_info(id);
        int64_t held;

        g_assert(info);
        held = qdict_get_int(info, "held");
        qobject_unref(info);
        if (held == n) {
            return;
        }
        g_assert(g_get_monotonic_time() - start <= QVIRTIO_SCSI_TIMEOUT_US);
    }
}

static int64_t fault_attempts(const char *id, const char *recovery)
{
    QDict *info = fault_info(id);
    int64_t n;

    g_assert(info);
    n = qdict_get_int(qdict_get_qdict(info, "attempts"), recovery);
    qobject_unref(info);
    return n;
}

/* Wait for the SCSI_FAULT_CLEARED event for @id */
static void fault_wait_cleared(const char *id, const char *recovery,
                               int64_t held)
{
    QDict *ev = qtest_qmp_eventwait_ref(global_qtest, "SCSI_FAULT_CLEARED");
    QDict *data = qdict_get_qdict(ev, "data");

    g_assert_cmpstr(qdict_get_str(data, "device"), ==, FAULT_DEVICE);
    g_assert_cmpstr(qdict_get_str(data, "id"), ==, id);
    g_assert_cmpstr(qdict_get_str(data, "recovery"), ==, recovery);
    g_assert_cmpint(qdict_get_int(data, "held"), ==, held);
    qobject_unref(ev);
}

static QVirtioSCSIQueues *fault_start(QVirtioSCSIPCI *scsi_pci,
                                      QGuestAllocator *t_alloc)
{
    QDict *ev;

    /* Forget events from earlier tests, such as the reset between them */
    while ((ev = qtest_qmp_event_ref(global_qtest, "SCSI_FAULT_CLEARED"))) {
        qobject_unref(ev);
    }
    alloc = t_alloc;
    return qvirtio_scsi_init(scsi_pci->scsi.vdev);
}

static void fault_end(QVirtioSCSIQueues *vs)
{
    fault_remove_all();
    qvirtio_scsi_pci_free(vs);
}

/*
 * A stuck LUN: commands get no answer until the guest resets the LUN, which
 * cancels them; afterwards the LUN works again.
 */
static void test_fault_lun_reset(void *obj, void *data,
                                 QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;
    FaultPending *both[] = { &cmd, &tmf };

    fault_add("{'id': 'f', 'target': 1, 'lun': 0}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("f", 1);
    fault_assert_idle(vs);

    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    fault_wait(both, 2);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd), ==, VIRTIO_SCSI_S_RESET);
    fault_wait_cleared("f", "lun-reset", 0);
    g_assert_null(fault_info("f"));

    fault_assert_read_good(vs, 1, 0);
    fault_free(&cmd);
    fault_free(&tmf);
    fault_end(vs);
}

/*
 * A fault an abort clears: the aborted command comes back aborted, and the
 * other command the target was holding goes on to run.
 */
static void test_fault_abort_task(void *obj, void *data,
                                  QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd1, cmd2, tmf;
    FaultPending *all[] = { &cmd1, &cmd2, &tmf };

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'abort-task'}");
    fault_read(vs, &cmd1, 1, 0, 1);
    fault_read(vs, &cmd2, 1, 0, 2);
    fault_wait_held("f", 2);

    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_ABORT_TASK, 1, 0, 1);
    fault_wait(all, 3);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd1), ==, VIRTIO_SCSI_S_ABORTED);
    g_assert_cmpint(fault_response(&cmd2), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_status(&cmd2), ==, GOOD);
    fault_wait_cleared("f", "abort-task", 1);

    fault_free(&cmd1);
    fault_free(&cmd2);
    fault_free(&tmf);
    fault_end(vs);
}

/*
 * A LUN reset that "works" on a target that needs a target reset: it cancels
 * what was held, but the next command is held again.
 */
static void test_fault_below_proceed(void *obj, void *data,
                                     QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd1, cmd2, tmf1, tmf2;
    FaultPending *first[] = { &cmd1, &tmf1 };
    FaultPending *second[] = { &cmd2, &tmf2 };
    QDict *info;

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'target-reset'}");
    fault_read(vs, &cmd1, 1, 0, 1);
    fault_wait_held("f", 1);

    fault_tmf(vs, &tmf1, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    fault_wait(first, 2);
    g_assert_cmpint(fault_response(&tmf1), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd1), ==, VIRTIO_SCSI_S_RESET);
    g_assert_cmpint(fault_attempts("f", "lun-reset"), ==, 1);
    info = fault_info("f");
    g_assert_cmpstr(qdict_get_str(info, "last-attempt"), ==, "lun-reset");
    qobject_unref(info);

    fault_read(vs, &cmd2, 1, 0, 2);
    fault_wait_held("f", 1);
    fault_assert_idle(vs);

    fault_tmf(vs, &tmf2, VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET, 1, 0, 0);
    fault_wait(second, 2);
    g_assert_cmpint(fault_response(&tmf2), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd2), ==, VIRTIO_SCSI_S_RESET);
    fault_wait_cleared("f", "target-reset", 0);
    fault_assert_read_good(vs, 1, 0);

    fault_free(&cmd1);
    fault_free(&cmd2);
    fault_free(&tmf1);
    fault_free(&tmf2);
    fault_end(vs);
}

/* A LUN reset the target refuses, and that changes nothing */
static void test_fault_below_reject(void *obj, void *data,
                                    QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'reject'}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("f", 1);

    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    fault_wait1(&tmf);
    g_assert_cmpint(fault_response(&tmf), ==,
                    VIRTIO_SCSI_S_FUNCTION_REJECTED);
    fault_wait_held("f", 1);
    fault_assert_idle(vs);

    /* Removing the fault lets the command run */
    fault_remove_all();
    fault_wait1(&cmd);
    g_assert_cmpint(fault_response(&cmd), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_status(&cmd), ==, GOOD);
    fault_wait_cleared("f", "manual", 1);

    fault_free(&cmd);
    fault_free(&tmf);
    fault_end(vs);
}

/*
 * A LUN reset that gets no answer until a target reset brings the target
 * back; it is then carried out and answered too.
 */
static void test_fault_below_hang(void *obj, void *data,
                                  QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, lun_reset, target_reset;
    FaultPending *all[] = { &cmd, &lun_reset, &target_reset };

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang'}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("f", 1);

    fault_tmf(vs, &lun_reset, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    g_assert_cmpint(fault_attempts("f", "lun-reset"), ==, 1);
    fault_wait_held("f", 1);
    fault_assert_idle(vs);

    fault_tmf(vs, &target_reset, VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET, 1, 0, 0);
    fault_wait(all, 3);
    g_assert_cmpint(fault_response(&target_reset), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&lun_reset), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd), ==, VIRTIO_SCSI_S_RESET);
    fault_wait_cleared("f", "target-reset", 0);

    fault_free(&cmd);
    fault_free(&lun_reset);
    fault_free(&target_reset);
    fault_end(vs);
}

/*
 * With tmf-hang-ms, a hung LUN reset is carried out after that long even
 * though the fault is still there, and the next command is held again.
 */
static void test_fault_below_hang_timeout(void *obj, void *data,
                                          QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd1, cmd2, tmf;
    FaultPending *first[] = { &cmd1, &tmf };

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang', 'tmf-hang-ms': 5000}");
    fault_read(vs, &cmd1, 1, 0, 1);
    fault_wait_held("f", 1);

    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    g_assert_cmpint(fault_attempts("f", "lun-reset"), ==, 1);
    qtest_clock_step(global_qtest, 4999 * FAULT_MS);
    fault_assert_idle(vs);
    qtest_clock_step(global_qtest, FAULT_MS);
    fault_wait(first, 2);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd1), ==, VIRTIO_SCSI_S_RESET);

    fault_read(vs, &cmd2, 1, 0, 2);
    fault_wait_held("f", 1);
    fault_remove_all();
    fault_wait1(&cmd2);
    g_assert_cmpint(fault_response(&cmd2), ==, VIRTIO_SCSI_S_OK);
    fault_wait_cleared("f", "manual", 1);

    fault_free(&cmd1);
    fault_free(&cmd2);
    fault_free(&tmf);
    fault_end(vs);
}

/* A slow target: each command runs after a delay, with no recovery */
static void test_fault_delay(void *obj, void *data, QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd;
    QDict *info;

    fault_add("{'id': 'f', 'target': 1, 'delay-ms': 2000}");
    info = fault_info("f");
    g_assert_false(qdict_get_bool(info, "stall"));
    g_assert_cmpint(qdict_get_int(info, "delay-ms"), ==, 2000);
    qobject_unref(info);

    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("f", 1);
    qtest_clock_step(global_qtest, 1999 * FAULT_MS);
    fault_assert_idle(vs);
    qtest_clock_step(global_qtest, FAULT_MS);
    fault_wait1(&cmd);
    g_assert_cmpint(fault_response(&cmd), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_status(&cmd), ==, GOOD);

    /* A slow target is still armed: nothing cleared it */
    info = fault_info("f");
    g_assert_cmpint(qdict_get_int(info, "hits"), ==, 1);
    g_assert_cmpint(qdict_get_int(info, "held"), ==, 0);
    qobject_unref(info);

    fault_free(&cmd);
    fault_end(vs);
}

/*
 * A fault on one LUN holds only that LUN's commands and is not cleared by
 * resetting another LUN; a fault on a whole target is.
 */
static void test_fault_scope(void *obj, void *data, QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf, cmd2, tmf2;
    FaultPending *second[] = { &cmd2, &tmf2 };

    fault_add("{'id': 'lun0', 'target': 1, 'lun': 0}");
    fault_assert_read_good(vs, 1, 1);
    fault_assert_read_good(vs, 2, 0);

    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("lun0", 1);
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 1, 0);
    fault_wait1(&tmf);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_attempts("lun0", "lun-reset"), ==, 0);
    fault_wait_held("lun0", 1);
    fault_remove_all();
    fault_wait1(&cmd);
    g_assert_cmpint(fault_response(&cmd), ==, VIRTIO_SCSI_S_OK);
    fault_wait_cleared("lun0", "manual", 1);

    fault_add("{'id': 'target1', 'target': 1}");
    fault_read(vs, &cmd2, 1, 0, 2);
    fault_wait_held("target1", 1);
    fault_tmf(vs, &tmf2, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 1, 0);
    fault_wait(second, 2);
    g_assert_cmpint(fault_response(&tmf2), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd2), ==, VIRTIO_SCSI_S_OK);
    fault_wait_cleared("target1", "lun-reset", 1);

    fault_free(&cmd);
    fault_free(&tmf);
    fault_free(&cmd2);
    fault_free(&tmf2);
    fault_end(vs);
}

/* x-scsi-fault-list counters, x-scsi-fault-remove, and argument checking */
static void test_fault_qmp(void *obj, void *data, QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    QTestState *qts = global_qtest;
    FaultPending cmd1, cmd2;
    FaultPending *both[] = { &cmd1, &cmd2 };
    QDict *info, *rsp;

    fault_assert_read_good(vs, 2, 0);
    fault_add("{'id': 'f', 'target': 2, 'clear-on': 'manual',"
              " 'max-hits': 2}");
    fault_read(vs, &cmd1, 2, 0, 1);
    fault_read(vs, &cmd2, 2, 0, 2);
    fault_wait_held("f", 2);
    info = fault_info("f");
    g_assert_cmpint(qdict_get_int(info, "hits"), ==, 2);
    g_assert_cmpint(qdict_get_int(info, "max-hits"), ==, 2);
    g_assert_true(qdict_get_bool(info, "stall"));
    g_assert_cmpstr(qdict_get_str(info, "clear-on"), ==, "manual");
    g_assert_cmpstr(qdict_get_str(info, "hold-at"), ==, "submit");
    g_assert_false(qdict_haskey(info, "lun"));
    g_assert_false(qdict_haskey(info, "last-attempt"));
    qobject_unref(info);

    /* Past max-hits, commands run */
    fault_assert_read_good(vs, 2, 0);
    fault_wait_held("f", 2);

    fault_assert_failure(
        "{'execute': 'x-scsi-fault-add', 'arguments': {'device': %s,"
        " 'fault': {'id': 'f', 'target': 1}}}", FAULT_DEVICE);
    fault_assert_failure(
        "{'execute': 'x-scsi-fault-add', 'arguments': {'device': %s,"
        " 'fault': {'id': 'g', 'target': 1, 'probability': 1.5}}}",
        FAULT_DEVICE);
    fault_assert_failure(
        "{'execute': 'x-scsi-fault-add', 'arguments': {'device': %s,"
        " 'fault': {'id': 'g', 'target': 1, 'tmf-hang-ms': 10}}}",
        FAULT_DEVICE);
    fault_assert_failure(
        "{'execute': 'x-scsi-fault-add', 'arguments': {'device': %s,"
        " 'fault': {'id': 'g', 'target': 1, 'delay-ms': 10,"
        " 'delay-max-ms': 5}}}", FAULT_DEVICE);
    fault_assert_failure(
        "{'execute': 'x-scsi-fault-remove', 'arguments': {'device': %s,"
        " 'id': 'nope'}}", FAULT_DEVICE);

    rsp = qtest_qmp_assert_success_ref(qts,
        "{'execute': 'x-scsi-fault-remove', 'arguments': {'device': %s,"
        " 'id': 'f'}}", FAULT_DEVICE);
    g_assert_cmpint(qdict_get_int(rsp, "count"), ==, 1);
    qobject_unref(rsp);
    fault_wait(both, 2);
    g_assert_cmpint(fault_status(&cmd1), ==, GOOD);
    g_assert_cmpint(fault_status(&cmd2), ==, GOOD);
    fault_wait_cleared("f", "manual", 2);
    g_assert_null(fault_info("f"));

    fault_free(&cmd1);
    fault_free(&cmd2);
    fault_end(vs);
}

/*
 * Faults are refused on adapters that don't support them, and on things
 * that aren't adapters.
 */
static void test_fault_unsupported(void *obj, void *data,
                                   QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    g_autofree char *host = NULL;
    QDict *rsp;

    if (qtest_has_device("lsi53c895a")) {
        fault_assert_failure(
            "{'execute': 'x-scsi-fault-add', 'arguments': {'device': 'lsi0',"
            " 'fault': {'id': 'f', 'target': 1}}}");
    }
    fault_assert_failure(
        "{'execute': 'x-scsi-fault-add', 'arguments': {'device': 'nope',"
        " 'fault': {'id': 'f', 'target': 1}}}");
    fault_assert_failure(
        "{'execute': 'x-scsi-fault-add', 'arguments': {'device': 'hd10',"
        " 'fault': {'id': 'f', 'target': 1}}}");
    /*
     * Nor is a device with an adapter somewhere below it, such as the host
     * bridge of the PCI bus the adapter is on
     */
    rsp = qtest_qmp(global_qtest,
                    "{'execute': 'qom-get', 'arguments': {"
                    " 'path': '/machine/peripheral/" FAULT_DEVICE "',"
                    " 'property': 'parent_bus'}}");
    host = g_path_get_dirname(qdict_get_str(rsp, "return"));
    qobject_unref(rsp);
    rsp = qtest_qmp(global_qtest,
                    "{'execute': 'x-scsi-fault-add', 'arguments': {'device': %s,"
                    " 'fault': {'id': 'f', 'target': 1}}}", host);
    g_assert_nonnull(strstr(qdict_get_str(qdict_get_qdict(rsp, "error"),
                                          "desc"),
                            "is not a SCSI adapter"));
    qobject_unref(rsp);
    fault_assert_failure(
        "{'execute': 'x-scsi-fault-add', 'arguments': {'device': %s,"
        " 'fault': {'id': 'f', 'target': 256}}}", FAULT_DEVICE);

    fault_end(vs);
}

/*
 * The guest resets the adapter while a command is held and a LUN reset hangs.
 * The command is cancelled and the TMF dropped: neither its timeout nor the
 * fault going away later answers it on the ring the guest sets up next.  A
 * fault that clears on adapter reset is gone, one that doesn't stays.
 */
static void test_fault_device_reset(void *obj, void *data,
                                    QGuestAllocator *t_alloc)
{
    QVirtioSCSIPCI *scsi_pci = obj;
    QVirtioDevice *dev = scsi_pci->scsi.vdev;
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;

    fault_add("{'id': 'f', 'target': 1, 'lun': 1, 'clear-on': 'manual',"
              " 'below-clear': 'hang', 'tmf-hang-ms': 1000}");
    fault_add("{'id': 'g', 'target': 2, 'clear-on': 'bus-reset'}");
    fault_read(vs, &cmd, 1, 1, 1);
    fault_wait_held("f", 1);
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 1, 0);
    g_assert_cmpint(fault_attempts("f", "lun-reset"), ==, 1);

    qvirtio_reset(dev);
    fault_wait_cleared("g", "bus-reset", 0);
    g_assert_null(fault_info("g"));
    g_assert_cmpint(fault_attempts("f", "bus-reset"), ==, 1);
    fault_wait_held("f", 0);

    qvirtio_scsi_pci_free(vs);
    qvirtio_start_device(dev);
    vs = qvirtio_scsi_init(dev);

    qtest_clock_step(global_qtest, 2000 * FAULT_MS);
    fault_assert_read_good(vs, 2, 0);
    fault_assert_idle(vs);
    fault_remove_all();
    fault_wait_cleared("f", "manual", 0);
    fault_assert_read_good(vs, 1, 1);
    fault_assert_idle(vs);
    fault_end(vs);
}


/*
 * ABORT TASK SET or CLEAR TASK SET aborts what the LUN holds and clears a
 * fault waiting for it, which releases what the fault held on another LUN.
 */
static void fault_task_set(void *obj, QGuestAllocator *t_alloc,
                           uint32_t subtype)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd1, cmd2, other, tmf;
    FaultPending *all[] = { &cmd1, &cmd2, &tmf, &other };

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'task-set'}");
    fault_read(vs, &cmd1, 1, 0, 1);
    fault_read(vs, &cmd2, 1, 0, 2);
    fault_read(vs, &other, 1, 1, 3);
    fault_wait_held("f", 3);

    fault_tmf(vs, &tmf, subtype, 1, 0, 0);
    fault_wait(all, 4);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd1), ==, VIRTIO_SCSI_S_ABORTED);
    g_assert_cmpint(fault_response(&cmd2), ==, VIRTIO_SCSI_S_ABORTED);
    g_assert_cmpint(fault_response(&other), ==, VIRTIO_SCSI_S_OK);
    fault_wait_cleared("f", "task-set", 1);
    fault_assert_read_good(vs, 1, 0);

    fault_free(&cmd1);
    fault_free(&cmd2);
    fault_free(&other);
    fault_free(&tmf);
    fault_end(vs);
}

static void test_fault_abort_task_set(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    fault_task_set(obj, t_alloc, VIRTIO_SCSI_T_TMF_ABORT_TASK_SET);
}

static void test_fault_clear_task_set(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    fault_task_set(obj, t_alloc, VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET);
}

/* QUERY TASK finds a held command, and isn't a recovery attempt */
static void test_fault_query_task(void *obj, void *data,
                                  QGuestAllocator *t_alloc)
{
    static const char *const kinds[] = {
        "abort-task", "task-set", "lun-reset", "target-reset", "bus-reset",
    };
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, held, absent;
    QDict *info;
    int i;

    fault_add("{'id': 'f', 'target': 1, 'lun': 0}");
    fault_read(vs, &cmd, 1, 0, 7);
    fault_wait_held("f", 1);

    fault_tmf(vs, &held, VIRTIO_SCSI_T_TMF_QUERY_TASK, 1, 0, 7);
    fault_wait1(&held);
    g_assert_cmpint(fault_response(&held), ==,
                    VIRTIO_SCSI_S_FUNCTION_SUCCEEDED);
    fault_tmf(vs, &absent, VIRTIO_SCSI_T_TMF_QUERY_TASK, 1, 0, 8);
    fault_wait1(&absent);
    g_assert_cmpint(fault_response(&absent), ==, VIRTIO_SCSI_S_OK);

    fault_wait_held("f", 1);
    for (i = 0; i < ARRAY_SIZE(kinds); i++) {
        g_assert_cmpint(fault_attempts("f", kinds[i]), ==, 0);
    }
    info = fault_info("f");
    g_assert_false(qdict_haskey(info, "last-attempt"));
    qobject_unref(info);

    fault_remove_all();
    fault_wait1(&cmd);
    g_assert_cmpint(fault_status(&cmd), ==, GOOD);

    fault_free(&cmd);
    fault_free(&held);
    fault_free(&absent);
    fault_end(vs);
}

/*
 * A held command that took a pending unit attention never ran, so if it is
 * aborted the unit attention goes to the next command instead of being lost.
 */
static void test_fault_unit_attention(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd1, cmd2, cmd3, reset, abort;
    FaultPending *first[] = { &cmd1, &reset };
    FaultPending *second[] = { &cmd2, &abort };
    uint64_t sense;

    fault_add("{'id': 'f', 'target': 1, 'lun': 0,"
              " 'clear-on': 'target-reset'}");
    fault_read(vs, &cmd1, 1, 0, 1);
    fault_wait_held("f", 1);

    /* Cancels the held command, but leaves a unit attention pending */
    fault_tmf(vs, &reset, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    fault_wait(first, 2);
    g_assert_cmpint(fault_response(&reset), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd1), ==, VIRTIO_SCSI_S_RESET);

    /* The next command takes the unit attention, and is held */
    fault_read(vs, &cmd2, 1, 0, 2);
    fault_wait_held("f", 1);
    fault_tmf(vs, &abort, VIRTIO_SCSI_T_TMF_ABORT_TASK, 1, 0, 2);
    fault_wait(second, 2);
    g_assert_cmpint(fault_response(&abort), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&cmd2), ==, VIRTIO_SCSI_S_ABORTED);
    fault_remove_all();
    fault_wait_cleared("f", "manual", 0);

    fault_read(vs, &cmd3, 1, 0, 3);
    fault_wait1(&cmd3);
    g_assert_cmpint(fault_response(&cmd3), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_status(&cmd3), ==, CHECK_CONDITION);
    sense = cmd3.resp_addr + offsetof(struct virtio_scsi_cmd_resp, sense);
    g_assert_cmpint(readb(sense + 2), ==, UNIT_ATTENTION);
    g_assert_cmpint(readb(sense + 12), ==, 0x29);   /* RESET */
    g_assert_cmpint(readb(sense + 13), ==, 0x00);
    fault_assert_read_good(vs, 1, 0);

    fault_free(&cmd1);
    fault_free(&cmd2);
    fault_free(&cmd3);
    fault_free(&reset);
    fault_free(&abort);
    fault_end(vs);
}

/*
 * A hung ABORT TASK goes ahead when the fault is removed, and aborts the
 * command it names before the removal releases it.
 */
static void test_fault_hung_abort(void *obj, void *data,
                                  QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;
    FaultPending *both[] = { &cmd, &tmf };

    fault_add("{'id': 'f', 'target': 1, 'below-clear': 'hang'}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("f", 1);
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_ABORT_TASK, 1, 0, 1);
    g_assert_cmpint(fault_attempts("f", "abort-task"), ==, 1);
    fault_assert_idle(vs);

    fault_remove_all();
    fault_wait(both, 2);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpuint(fault_response(&cmd), !=, 0xff);
    fault_wait_cleared("f", "manual", 1);

    fault_free(&cmd);
    fault_free(&tmf);
    fault_end(vs);
}

/*
 * A TMF two faults hang waits for both.  Once the one without a timeout
 * goes, the other's tmf-hang-ms applies, counted from when the TMF came.
 */
static void test_fault_below_hang_recheck(void *obj, void *data,
                                          QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;

    fault_add("{'id': 'forever', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang'}");
    fault_add("{'id': 'timed', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang', 'tmf-hang-ms': 1000}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("forever", 1);
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    g_assert_cmpint(fault_attempts("timed", "lun-reset"), ==, 1);

    qtest_clock_step(global_qtest, 1500 * FAULT_MS);
    fault_assert_idle(vs);

    /* Its time is already up, so the TMF goes ahead straight away */
    qtest_qmp_assert_success(global_qtest,
                             "{'execute': 'x-scsi-fault-remove',"
                             " 'arguments': {'device': %s, 'id': 'forever'}}",
                             FAULT_DEVICE);
    fault_wait_cleared("forever", "manual", 1);
    fault_wait1(&cmd);
    g_assert_cmpint(fault_status(&cmd), ==, GOOD);
    qtest_clock_step(global_qtest, FAULT_MS);
    fault_wait1(&tmf);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_nonnull(fault_info("timed"));

    fault_free(&cmd);
    fault_free(&tmf);
    fault_end(vs);
}

/* The same, removing the fault before the other's time is up */
static void test_fault_below_hang_recheck_early(void *obj, void *data,
                                                QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;

    fault_add("{'id': 'forever', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang'}");
    fault_add("{'id': 'timed', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang', 'tmf-hang-ms': 1000}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("forever", 1);
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    g_assert_cmpint(fault_attempts("timed", "lun-reset"), ==, 1);

    qtest_clock_step(global_qtest, 500 * FAULT_MS);
    qtest_qmp_assert_success(global_qtest,
                             "{'execute': 'x-scsi-fault-remove',"
                             " 'arguments': {'device': %s, 'id': 'forever'}}",
                             FAULT_DEVICE);
    fault_wait_cleared("forever", "manual", 1);
    fault_wait1(&cmd);
    g_assert_cmpint(fault_status(&cmd), ==, GOOD);

    qtest_clock_step(global_qtest, 499 * FAULT_MS);
    fault_assert_idle(vs);
    qtest_clock_step(global_qtest, FAULT_MS);
    fault_wait1(&tmf);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);

    fault_free(&cmd);
    fault_free(&tmf);
    fault_end(vs);
}

/*
 * A hung TMF keeps the wait it got when it came.  A hanging fault added
 * afterwards doesn't stretch it: not when an unrelated TMF finishes, and not
 * when another fault goes away and the TMF is looked at again.
 */
static void test_fault_below_hang_added(void *obj, void *data,
                                        QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending tmf, other;
    QDict *info;

    fault_add("{'id': 'first', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang', 'tmf-hang-ms': 1000}");
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    g_assert_cmpint(fault_attempts("first", "lun-reset"), ==, 1);
    fault_assert_idle(vs);

    fault_add("{'id': 'later', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang', 'tmf-hang-ms': 5000}");

    /* Finishes in the request AioContext, so it is answered via the BH */
    fault_tmf(vs, &other, VIRTIO_SCSI_T_TMF_ABORT_TASK_SET, 2, 0, 0);
    fault_wait1(&other);
    g_assert_cmpint(fault_response(&other), ==, VIRTIO_SCSI_S_OK);

    qtest_clock_step(global_qtest, 500 * FAULT_MS);
    qtest_qmp_assert_success(global_qtest,
                             "{'execute': 'x-scsi-fault-remove',"
                             " 'arguments': {'device': %s, 'id': 'first'}}",
                             FAULT_DEVICE);
    fault_wait_cleared("first", "manual", 0);

    qtest_clock_step(global_qtest, 499 * FAULT_MS);
    fault_assert_idle(vs);
    qtest_clock_step(global_qtest, FAULT_MS);
    fault_wait1(&tmf);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    info = fault_info("later");
    g_assert_nonnull(info);
    qobject_unref(info);

    fault_free(&tmf);
    fault_free(&other);
    fault_end(vs);
}

/*
 * Held commands are released in the order the guest sent them.  TEST UNIT
 * READY completes as it is sent, so the used ring shows that order; READs
 * would complete in whatever order the block layer finishes them.
 */
static void test_fault_release_order(void *obj, void *data,
                                     QGuestAllocator *t_alloc)
{
    static const uint8_t tur[] = { TEST_UNIT_READY, 0, 0, 0, 0, 0 };
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd[4];
    gint64 start;
    int i, n = 0;

    fault_assert_read_good(vs, 2, 0);
    fault_add("{'id': 'f', 'target': 2}");
    for (i = 0; i < ARRAY_SIZE(cmd); i++) {
        fault_cmd(vs, &cmd[i], 2, 0, i + 1, tur, sizeof(tur), 0);
    }
    fault_wait_held("f", ARRAY_SIZE(cmd));

    fault_remove_all();
    start = g_get_monotonic_time();
    while (n < ARRAY_SIZE(cmd)) {
        uint32_t got;

        if (qvirtqueue_get_buf(global_qtest, vs->vq[2], &got, NULL)) {
            g_assert_cmpuint(got, ==, cmd[n].head);
            g_assert_cmpint(fault_status(&cmd[n]), ==, GOOD);
            n++;
        }
        g_assert(g_get_monotonic_time() - start <= QVIRTIO_SCSI_TIMEOUT_US);
    }
    fault_wait_cleared("f", "manual", ARRAY_SIZE(cmd));

    for (i = 0; i < ARRAY_SIZE(cmd); i++) {
        fault_free(&cmd[i]);
    }
    fault_end(vs);
}

/* Removing a delay fault runs its commands now, and their timers are gone */
static void test_fault_delay_remove(void *obj, void *data,
                                    QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd;

    fault_add("{'id': 'f', 'target': 1, 'delay-ms': 2000}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("f", 1);
    fault_remove_all();
    fault_wait1(&cmd);
    g_assert_cmpint(fault_status(&cmd), ==, GOOD);
    qtest_clock_step(global_qtest, 3000 * FAULT_MS);
    fault_assert_idle(vs);

    fault_free(&cmd);
    fault_end(vs);
}

/*
 * A fault removed while the VM is stopped completes nothing to the guest,
 * neither the commands it held nor the TMF it left hanging, until the VM
 * runs again.
 */
static void test_fault_stopped(void *obj, void *data,
                               QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;
    FaultPending *both[] = { &cmd, &tmf };

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang'}");
    fault_read(vs, &cmd, 1, 0, 1);
    fault_wait_held("f", 1);
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    g_assert_cmpint(fault_attempts("f", "lun-reset"), ==, 1);

    qtest_qmp_assert_success(global_qtest, "{'execute': 'stop'}");
    fault_remove_all();
    fault_wait_cleared("f", "manual", 1);
    g_usleep(200 * 1000);
    qtest_qmp_assert_success(global_qtest, "{'execute': 'query-status'}");
    fault_assert_idle(vs);

    qtest_qmp_assert_success(global_qtest, "{'execute': 'cont'}");
    fault_wait(both, 2);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpuint(fault_response(&cmd), !=, 0xff);

    fault_free(&cmd);
    fault_free(&tmf);
    fault_end(vs);
}

/*
 * Unplugging a LUN cancels the command a fault holds for it.  A TMF to it
 * that a fault left hanging goes ahead when the fault is removed, and finds
 * the LUN gone.
 */
static void test_fault_unplug(void *obj, void *data, QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending cmd, tmf;

    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'target-reset',"
              " 'below-clear': 'hang'}");
    fault_read(vs, &cmd, 1, 1, 1);
    fault_wait_held("f", 1);
    fault_tmf(vs, &tmf, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 1, 0);
    g_assert_cmpint(fault_attempts("f", "lun-reset"), ==, 1);

    qtest_qmp_device_del(global_qtest, "hd11");
    fault_wait1(&cmd);
    g_assert_cmpint(fault_response(&cmd), ==, VIRTIO_SCSI_S_ABORTED);
    fault_wait_held("f", 0);
    fault_assert_idle(vs);

    fault_remove_all();
    fault_wait1(&tmf);
    g_assert_cmpint(fault_response(&tmf), ==, VIRTIO_SCSI_S_INCORRECT_LUN);
    fault_wait_cleared("f", "manual", 0);
    fault_assert_read_good(vs, 1, 0);

    fault_free(&cmd);
    fault_free(&tmf);
    fault_end(vs);
}

/* Submit a READ like fault_read(), on request queue @queue */
static void fault_read_on(QVirtioSCSIQueues *vs, FaultPending *p, int queue,
                          uint8_t target, uint8_t lun, uint64_t tag)
{
    QVirtQueue *vq = vs->vq[2];

    vs->vq[2] = vs->vq[2 + queue];
    fault_read(vs, p, target, lun, tag);
    vs->vq[2] = vq;
}

/*
 * With iothread-vq-mapping, one device has commands held in two
 * AioContexts.  Recovery and removal reach both.
 */
static void test_fault_vq_mapping(void *obj, void *data,
                                  QGuestAllocator *t_alloc)
{
    QVirtioSCSIQueues *vs = fault_start(obj, t_alloc);
    FaultPending c[6], reset, abort_set;
    FaultPending *first[] = { &c[0], &c[1], &reset };
    FaultPending *second[] = { &c[2], &c[3], &abort_set };
    FaultPending *third[] = { &c[4], &c[5] };
    int i;

    g_assert_cmpint(vs->num_queues, ==, 2);
    fault_add("{'id': 'f', 'target': 1, 'clear-on': 'target-reset'}");

    fault_read_on(vs, &c[0], 0, 1, 0, 1);
    fault_read_on(vs, &c[1], 1, 1, 0, 2);
    fault_wait_held("f", 2);
    fault_tmf(vs, &reset, VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET, 1, 0, 0);
    fault_wait(first, 3);
    g_assert_cmpint(fault_response(&reset), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&c[0]), ==, VIRTIO_SCSI_S_RESET);
    g_assert_cmpint(fault_response(&c[1]), ==, VIRTIO_SCSI_S_RESET);

    fault_read_on(vs, &c[2], 0, 1, 0, 3);
    fault_read_on(vs, &c[3], 1, 1, 0, 4);
    fault_wait_held("f", 2);
    fault_tmf(vs, &abort_set, VIRTIO_SCSI_T_TMF_ABORT_TASK_SET, 1, 0, 0);
    fault_wait(second, 3);
    g_assert_cmpint(fault_response(&abort_set), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&c[2]), ==, VIRTIO_SCSI_S_ABORTED);
    g_assert_cmpint(fault_response(&c[3]), ==, VIRTIO_SCSI_S_ABORTED);

    fault_read_on(vs, &c[4], 0, 1, 0, 5);
    fault_read_on(vs, &c[5], 1, 1, 0, 6);
    fault_wait_held("f", 2);
    fault_remove_all();
    fault_wait(third, 2);
    g_assert_cmpint(fault_response(&c[4]), ==, VIRTIO_SCSI_S_OK);
    g_assert_cmpint(fault_response(&c[5]), ==, VIRTIO_SCSI_S_OK);
    fault_wait_cleared("f", "manual", 2);

    for (i = 0; i < ARRAY_SIZE(c); i++) {
        fault_free(&c[i]);
    }
    fault_free(&reset);
    fault_free(&abort_set);
    fault_end(vs);
}

static void *virtio_scsi_hotplug_setup(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive id=drv1,if=none,file=null-co://,"
                    "file.read-zeroes=on,format=raw");
    return arg;
}

static void *virtio_scsi_setup(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive file=blkdebug::null-co://,"
                    "file.image.read-zeroes=on,"
                    "if=none,id=dr1,format=raw,file.align=4k "
                    "-device scsi-hd,drive=dr1,lun=0,scsi-id=1");
    return arg;
}

static void *virtio_scsi_setup_4k(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive file=blkdebug::null-co://,"
                    "file.image.read-zeroes=on,"
                    "if=none,id=dr1,format=raw "
                    "-device scsi-hd,drive=dr1,lun=0,scsi-id=1"
                    ",logical_block_size=4k,physical_block_size=4k");
    return arg;
}

static void *virtio_scsi_setup_cd(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive file=null-co://,"
                    "file.read-zeroes=on,"
                    "if=none,id=dr1,format=raw "
                    "-device scsi-cd,drive=dr1,lun=0,scsi-id=1");
    return arg;
}

static void *virtio_scsi_setup_iothread(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -object iothread,id=thread0"
                    " -blockdev driver=null-co,read-zeroes=on,node-name=null0"
                    " -device scsi-hd,drive=null0");
    return arg;
}

static void *virtio_scsi_setup_fault(GString *cmd_line, void *arg)
{
    static const struct {
        int target, lun;
    } luns[] = { { 1, 0 }, { 1, 1 }, { 2, 0 } };
    int i;

    for (i = 0; i < ARRAY_SIZE(luns); i++) {
        g_string_append_printf(cmd_line,
                               " -blockdev driver=null-co,read-zeroes=on,"
                               "node-name=null%d%d"
                               " -device scsi-hd,bus=" FAULT_DEVICE ".0,"
                               "drive=null%d%d,id=hd%d%d,scsi-id=%d,lun=%d",
                               luns[i].target, luns[i].lun,
                               luns[i].target, luns[i].lun,
                               luns[i].target, luns[i].lun,
                               luns[i].target, luns[i].lun);
    }
    /* An adapter that doesn't support faults */
    if (qtest_has_device("lsi53c895a")) {
        g_string_append(cmd_line, " -device lsi53c895a,id=lsi0");
    }
    return arg;
}

static void *virtio_scsi_setup_fault_iothread(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line, " -object iothread,id=thread0");
    return virtio_scsi_setup_fault(cmd_line, arg);
}

static void replace_once(GString *s, const char *old, const char *new)
{
    const char *p = strstr(s->str, old);
    gssize pos;

    g_assert(p);
    pos = p - s->str;
    g_string_erase(s, pos, strlen(old));
    g_string_insert(s, pos, new);
}

/*
 * Two request queues, each in its own iothread.  iothread-vq-mapping takes
 * a list, which only JSON -device can give, and JSON devices are created
 * after the others, so everything on the adapter's bus has to be JSON too.
 */
static void *virtio_scsi_setup_fault_vq_mapping(GString *cmd_line, void *arg)
{
    static const struct {
        int target, lun;
    } luns[] = { { 1, 0 }, { 1, 1 }, { 2, 0 } };
    int i;

    replace_once(cmd_line, "-device virtio-scsi-pci,id=vs0,addr=04.0",
        "-object iothread,id=t0 -object iothread,id=t1"
        " -device '{\"driver\": \"virtio-scsi-pci\", \"id\": \"vs0\","
        " \"addr\": \"04.0\", \"num_queues\": 2,"
        " \"iothread-vq-mapping\": [{\"iothread\": \"t0\", \"vqs\": [0]},"
        " {\"iothread\": \"t1\", \"vqs\": [1]}]}'");
    replace_once(cmd_line, "-device scsi-hd,bus=vs0.0,drive=drv0",
        "-device '{\"driver\": \"scsi-hd\", \"bus\": \"vs0.0\","
        " \"drive\": \"drv0\"}'");
    for (i = 0; i < ARRAY_SIZE(luns); i++) {
        g_string_append_printf(cmd_line,
            " -blockdev driver=null-co,read-zeroes=on,node-name=null%d%d"
            " -device '{\"driver\": \"scsi-hd\", \"bus\": \"vs0.0\","
            " \"drive\": \"null%d%d\", \"id\": \"hd%d%d\","
            " \"scsi-id\": %d, \"lun\": %d}'",
            luns[i].target, luns[i].lun, luns[i].target, luns[i].lun,
            luns[i].target, luns[i].lun, luns[i].target, luns[i].lun);
    }
    return arg;
}

static void register_virtio_scsi_test(void)
{
    QOSGraphTestOptions opts = { };

    opts.before = virtio_scsi_hotplug_setup;
    qos_add_test("hotplug", "virtio-scsi", hotplug, &opts);

    opts.before = virtio_scsi_setup;
    qos_add_test("unaligned-write-same", "virtio-scsi",
                 test_unaligned_write_same, &opts);

    opts.before = virtio_scsi_setup_4k;
    qos_add_test("large-lba-unmap", "virtio-scsi",
                 test_unmap_large_lba, &opts);

    qos_add_test("zero-length-pending-at-tmf", "virtio-scsi",
                 test_zero_length_pending_at_tmf, &opts);
    qos_add_test("unreadable-chain-pending-at-tmf", "virtio-scsi",
                 test_unreadable_chain_pending_at_tmf, &opts);
    qos_add_test("shared-header-overlap", "virtio-scsi",
                 test_shared_header_overlap, &opts);

    opts.before = virtio_scsi_setup_cd;
    qos_add_test("write-to-cdrom", "virtio-scsi", test_write_to_cdrom, &opts);

    opts.before = virtio_scsi_setup_iothread;
    opts.edge = (QOSGraphEdgeOptions) {
        .extra_device_opts = "iothread=thread0",
    };
    qos_add_test("iothread-attach-node", "virtio-scsi-pci",
                 test_iothread_attach_node, &opts);

    opts.before = virtio_scsi_setup_iothread;
    opts.edge = (QOSGraphEdgeOptions) {
        .extra_device_opts = "iothread=thread0",
    };
    qos_add_test("iothread-virtio-error", "virtio-scsi-pci",
                 test_iothread_virtio_error, &opts);

    {
        static const struct {
            const char *name;
            QOSTestFunc fn;
        } fault_tests[] = {
            { "fault-lun-reset", test_fault_lun_reset },
            { "fault-abort-task", test_fault_abort_task },
            { "fault-below-proceed", test_fault_below_proceed },
            { "fault-below-reject", test_fault_below_reject },
            { "fault-below-hang", test_fault_below_hang },
            { "fault-below-hang-timeout", test_fault_below_hang_timeout },
            { "fault-delay", test_fault_delay },
            { "fault-scope", test_fault_scope },
            { "fault-qmp", test_fault_qmp },
            { "fault-unsupported", test_fault_unsupported },
            { "fault-device-reset", test_fault_device_reset },
            { "fault-abort-task-set", test_fault_abort_task_set },
            { "fault-clear-task-set", test_fault_clear_task_set },
            { "fault-query-task", test_fault_query_task },
            { "fault-hung-abort", test_fault_hung_abort },
            { "fault-below-hang-recheck", test_fault_below_hang_recheck },
            { "fault-below-hang-recheck-early",
              test_fault_below_hang_recheck_early },
            { "fault-below-hang-added", test_fault_below_hang_added },
            { "fault-release-order", test_fault_release_order },
            { "fault-delay-remove", test_fault_delay_remove },
            { "fault-stopped", test_fault_stopped },
            { "fault-unit-attention", test_fault_unit_attention },
        };
        int i;

        for (i = 0; i < ARRAY_SIZE(fault_tests); i++) {
            g_autofree char *iothread_name =
                g_strdup_printf("%s-iothread", fault_tests[i].name);

            opts.before = virtio_scsi_setup_fault;
            opts.edge = (QOSGraphEdgeOptions) { };
            qos_add_test(fault_tests[i].name, "virtio-scsi-pci",
                         fault_tests[i].fn, &opts);

            opts.before = virtio_scsi_setup_fault_iothread;
            opts.edge = (QOSGraphEdgeOptions) {
                .extra_device_opts = "iothread=thread0",
            };
            qos_add_test(iothread_name, "virtio-scsi-pci",
                         fault_tests[i].fn, &opts);
        }
    }

    /* Unplugging a LUN changes the setup, so don't share it */
    opts.before = virtio_scsi_setup_fault;
    opts.edge = (QOSGraphEdgeOptions) {
        .extra_device_opts = "num_queues=1",
    };
    qos_add_test("fault-unplug", "virtio-scsi-pci", test_fault_unplug, &opts);
    opts.before = virtio_scsi_setup_fault_iothread;
    opts.edge = (QOSGraphEdgeOptions) {
        .extra_device_opts = "iothread=thread0,num_queues=1",
    };
    qos_add_test("fault-unplug-iothread", "virtio-scsi-pci", test_fault_unplug,
                 &opts);

    opts.before = virtio_scsi_setup_fault_vq_mapping;
    opts.edge = (QOSGraphEdgeOptions) { };
    qos_add_test("fault-vq-mapping", "virtio-scsi-pci", test_fault_vq_mapping,
                 &opts);
}

libqos_init(register_virtio_scsi_test);
