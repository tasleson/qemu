/*
 * QTest testcase for VirtIO Serial
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest-single.h"
#include "qemu/bswap.h"
#include "qemu/module.h"
#include "libqos/virtio-serial.h"
#include "standard-headers/linux/virtio_console.h"

#define QVIRTIO_SERIAL_TIMEOUT_US (30 * 1000 * 1000)

/* With VIRTIO_CONSOLE_F_MULTIPORT: port 0 rx/tx, then control rx/tx */
#define CONTROL_OVQ 3
/* Port 1's rx and tx queues */
#define PORT1_IVQ 4
#define PORT1_OVQ 5

/*
 * Far more than a host socket buffer holds, so the write to a peer that
 * isn't reading comes up short and the port throttles.
 */
#define THROTTLE_BUF_SIZE (4 * 1024 * 1024)

/* Tests only initialization so far. TODO: Replace with functional tests */
static void virtio_serial_nop(void *obj, void *data, QGuestAllocator *alloc)
{
    /* no operation */
}

static void serial_hotplug(void *obj, void *data, QGuestAllocator *alloc)
{
    qtest_qmp_device_add(global_qtest, "virtserialport", "hp-port", "{}");
    qtest_qmp_device_del(global_qtest, "hp-port");
}

#ifndef _WIN32

static void port_close_cleanup(void *data)
{
    char *sock_path = data;
    g_autofree char *dir = g_path_get_dirname(sock_path);

    unlink(sock_path);
    rmdir(dir);
    g_free(sock_path);
}

static void *port_close_setup(GString *cmd_line, void *arg)
{
    g_autoptr(GError) err = NULL;
    g_autofree char *dir = g_dir_make_tmp("qtest-vser-XXXXXX", &err);
    char *sock_path;

    g_assert_no_error(err);
    sock_path = g_build_filename(dir, "sock", NULL);
    g_string_append_printf(cmd_line,
                           " -chardev socket,id=vser-chr,path=%s,"
                           "server=on,wait=off"
                           " -device virtserialport,bus=vser0.0,nr=1,"
                           "chardev=vser-chr ", sock_path);
    g_test_queue_destroy(port_close_cleanup, sock_path);
    return sock_path;
}

static void wait_port_state(const char *state)
{
    gint64 start_time = g_get_monotonic_time();

    for (;;) {
        g_autofree char *qtree = qtest_hmp(global_qtest, "info qtree");

        if (strstr(qtree, state)) {
            return;
        }
        g_assert(g_get_monotonic_time() - start_time <=
                 QVIRTIO_SERIAL_TIMEOUT_US);
        g_usleep(10 * 1000);
    }
}

static void send_control(QVirtioDevice *dev, QGuestAllocator *alloc,
                         QVirtQueue *vq, uint32_t id, uint16_t event,
                         uint16_t value)
{
    struct virtio_console_control cpkt;
    uint64_t addr;
    uint32_t free_head;

    if (qvirtio_is_big_endian(dev)) {
        cpkt.id = cpu_to_be32(id);
        cpkt.event = cpu_to_be16(event);
        cpkt.value = cpu_to_be16(value);
    } else {
        cpkt.id = cpu_to_le32(id);
        cpkt.event = cpu_to_le16(event);
        cpkt.value = cpu_to_le16(value);
    }

    addr = guest_alloc(alloc, sizeof(cpkt));
    memwrite(addr, &cpkt, sizeof(cpkt));
    free_head = qvirtqueue_add(global_qtest, vq, addr, sizeof(cpkt),
                               false, false);
    qvirtqueue_kick(global_qtest, dev, vq, free_head);
    qvirtio_wait_used_elem(global_qtest, dev, vq, free_head, NULL,
                           QVIRTIO_SERIAL_TIMEOUT_US);
    guest_free(alloc, addr);
}

static int connect_port(const char *sock_path)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int fd;

    g_assert_cmpuint(strlen(sock_path), <, sizeof(addr.sun_path));
    strcpy(addr.sun_path, sock_path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(connect(fd, (struct sockaddr *)&addr, sizeof(addr)),
                    ==, 0);
    wait_port_state("port 1, guest on, host on, throttle off");
    return fd;
}

/*
 * A guest write the host side could only partly take is held by the
 * port until the chardev becomes writable again.  If the host side goes
 * away instead, the guest must still get the buffer back: its write only
 * completes when it does, so a lost buffer hangs the writer for good.
 * And the next connection must start out unthrottled, or the guest's
 * writes never reach it.
 */
static void close_while_throttled(QVirtioSerial *serial, const char *sock_path,
                                  QGuestAllocator *alloc, bool guest_reading)
{
    QVirtioDevice *dev = serial->vdev;
    static const char msg[] = "hello";
    char reply[sizeof(msg)];
    QVirtQueue *control_ovq, *ivq = NULL, *ovq;
    uint64_t features, buf, rx_buf = 0;
    uint32_t free_head, desc_idx;
    int fd;

    features = qvirtio_get_features(dev);
    g_assert(features & (1ull << VIRTIO_CONSOLE_F_MULTIPORT));
    features &= ~(QVIRTIO_F_BAD_FEATURE |
                  (1ull << VIRTIO_RING_F_INDIRECT_DESC) |
                  (1ull << VIRTIO_RING_F_EVENT_IDX));
    qvirtio_set_features(dev, features);
    control_ovq = qvirtqueue_setup(dev, alloc, CONTROL_OVQ);
    ovq = qvirtqueue_setup(dev, alloc, PORT1_OVQ);
    if (guest_reading) {
        ivq = qvirtqueue_setup(dev, alloc, PORT1_IVQ);
    }
    qvirtio_set_driver_ok(dev);

    send_control(dev, alloc, control_ovq, 1, VIRTIO_CONSOLE_PORT_OPEN, 1);
    if (guest_reading) {
        /*
         * With room to receive into, the chardev watches its socket for
         * input, so the close shows up there rather than as a failed
         * write: the other order of the same race.
         */
        rx_buf = guest_alloc(alloc, 64);
        free_head = qvirtqueue_add(global_qtest, ivq, rx_buf, 64, true, false);
        qvirtqueue_kick(global_qtest, dev, ivq, free_head);
    }

    /* Never read from fd, so the port throttles part way through */
    fd = connect_port(sock_path);
    buf = guest_alloc(alloc, THROTTLE_BUF_SIZE);
    free_head = qvirtqueue_add(global_qtest, ovq, buf, THROTTLE_BUF_SIZE,
                               false, false);
    qvirtqueue_kick(global_qtest, dev, ovq, free_head);
    wait_port_state("port 1, guest on, host on, throttle on");
    g_assert_false(qvirtqueue_get_buf(global_qtest, ovq, &desc_idx, NULL));

    close(fd);
    qvirtio_wait_used_elem(global_qtest, dev, ovq, free_head, NULL,
                           QVIRTIO_SERIAL_TIMEOUT_US);
    wait_port_state("port 1, guest on, host off, throttle off");

    fd = connect_port(sock_path);
    memwrite(buf, msg, sizeof(msg));
    free_head = qvirtqueue_add(global_qtest, ovq, buf, sizeof(msg),
                               false, false);
    qvirtqueue_kick(global_qtest, dev, ovq, free_head);
    qvirtio_wait_used_elem(global_qtest, dev, ovq, free_head, NULL,
                           QVIRTIO_SERIAL_TIMEOUT_US);
    g_assert_cmpint(read(fd, reply, sizeof(reply)), ==, sizeof(msg));
    g_assert_cmpstr(reply, ==, msg);
    close(fd);

    guest_free(alloc, buf);
    qvirtqueue_cleanup(dev->bus, ovq, alloc);
    if (guest_reading) {
        guest_free(alloc, rx_buf);
        qvirtqueue_cleanup(dev->bus, ivq, alloc);
    }
    qvirtqueue_cleanup(dev->bus, control_ovq, alloc);
}

static void serial_close_while_throttled(void *obj, void *data,
                                         QGuestAllocator *alloc)
{
    close_while_throttled(obj, data, alloc, false);
}

static void serial_close_while_throttled_reading(void *obj, void *data,
                                                 QGuestAllocator *alloc)
{
    close_while_throttled(obj, data, alloc, true);
}

#endif /* _WIN32 */

static void register_virtio_serial_test(void)
{
    QOSGraphTestOptions opts = { };

    opts.edge.before_cmd_line = "-device virtconsole,bus=vser0.0";
    qos_add_test("console-nop", "virtio-serial", virtio_serial_nop, &opts);

    opts.edge.before_cmd_line = "-device virtserialport,bus=vser0.0";
    qos_add_test("serialport-nop", "virtio-serial", virtio_serial_nop, &opts);

    qos_add_test("hotplug", "virtio-serial", serial_hotplug, NULL);

#ifndef _WIN32
    opts.edge.before_cmd_line = NULL;
    opts.before = port_close_setup;
    qos_add_test("close-while-throttled", "virtio-serial",
                 serial_close_while_throttled, &opts);
    qos_add_test("close-while-throttled-reading", "virtio-serial",
                 serial_close_while_throttled_reading, &opts);
#endif
}
libqos_init(register_virtio_serial_test);
