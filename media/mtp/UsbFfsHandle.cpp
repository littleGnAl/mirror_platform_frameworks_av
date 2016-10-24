/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <utils/Log.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cutils/properties.h>
#include <dirent.h>
#include <errno.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <unistd.h>
#include <pthread.h>

#include <algorithm>
#include <atomic>

#include <android-base/logging.h>
#include "UsbHandle.h"
#include "aio.h"

#define USB_FFS_MTP_OUT     USB_FFS_MTP_EP(ep1)
#define USB_FFS_MTP_IN      USB_FFS_MTP_EP(ep2)
#define USB_FFS_MTP_INTR    USB_FFS_MTP_EP(ep3)

#define MAX_PACKET_SIZE_FS  64
#define MAX_PACKET_SIZE_HS  512
#define MAX_PACKET_SIZE_SS  1024

// Must be divisible by all max packet size values
#define MAX_FILE_CHUNK_SIZE 3145728
#define USB_FFS_MAX_WRITE 262144
#define USB_FFS_MAX_READ 262144

#define MAX_MTP_FILE_SIZE 0xFFFFFFFF

#define cpu_to_le16(x)  htole16(x)
#define cpu_to_le32(x)  htole32(x)

class UsbFfsHandle : public UsbHandle {
    private:
        int writeHandle(int fd, const void *data, int len);
        int readHandle(int fd, void *data, int len);
        int spliceReadHandle(int fd, int fd_out, int len);
        bool initFunctionfs();
        void closeConfig();
        void closeEndpoints();

        bool ptp;

        bool ready;
        pthread_cond_t ready_notify;
        pthread_mutex_t ready_lock;

        int control;
        int bulk_out; /* "out" from the host's perspective => source for mtp server */
        int bulk_in;  /* "in" from the host's perspective => sink for mtp server */
        int intr;

    public:
        int read(void *data, int len);
        int write(const void *data, int len);

        int receiveFile(mtp_file_range mfr);
        int sendFile(mtp_file_range mfr);
        int sendEvent(mtp_event me);

        int start();
        int close();

        int configure(bool ptp);

        UsbFfsHandle();
        ~UsbFfsHandle();
};

/* FunctionFS header objects */

struct mtp_data_header {
    /* length of packet, including this header */
    __le32 length;
    /* container type (2 for data packet) */
    __le16 type;
    /* MTP command code */
    __le16 command;
    /* MTP transaction ID */
    __le32 transaction_id;
};

struct func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_endpoint_descriptor_no_audio intr;
} __attribute__((packed));

struct ss_func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_ss_ep_comp_descriptor source_comp;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_ss_ep_comp_descriptor sink_comp;
    struct usb_endpoint_descriptor_no_audio intr;
    struct usb_ss_ep_comp_descriptor intr_comp;
} __attribute__((packed));

struct desc_v1 {
    struct usb_functionfs_descs_head_v1 {
        __le32 magic;
        __le32 length;
        __le32 fs_count;
        __le32 hs_count;
    } __attribute__((packed)) header;
    struct func_desc fs_descs, hs_descs;
} __attribute__((packed));

struct desc_v2 {
    struct usb_functionfs_descs_head_v2 header;
    // The rest of the structure depends on the flags in the header.
    __le32 fs_count;
    __le32 hs_count;
    __le32 ss_count;
    __le32 os_count;
    struct func_desc fs_descs, hs_descs;
    struct ss_func_desc ss_descs;
    struct usb_os_desc_header os_header;
    struct usb_ext_compat_desc os_desc;
} __attribute__((packed));

static struct usb_interface_descriptor mtp_interface_desc = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bNumEndpoints = 3,
    .bInterfaceClass = USB_CLASS_STILL_IMAGE,
    .bInterfaceSubClass = 1,
    .bInterfaceProtocol = 1,
    .iInterface = 1, /* first string from the provided table */
};

static struct usb_interface_descriptor ptp_interface_desc = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bNumEndpoints = 3,
    .bInterfaceClass = USB_CLASS_STILL_IMAGE,
    .bInterfaceSubClass = 1,
    .bInterfaceProtocol = 1,
};

struct usb_endpoint_descriptor_no_audio fs_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
};

struct usb_endpoint_descriptor_no_audio fs_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
};

struct usb_endpoint_descriptor_no_audio fs_intr = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 3 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
    .bInterval = 6,
};

struct usb_endpoint_descriptor_no_audio hs_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
};

struct usb_endpoint_descriptor_no_audio hs_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
};

struct usb_endpoint_descriptor_no_audio hs_intr = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 3 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
    .bInterval = 6,
};

struct usb_endpoint_descriptor_no_audio ss_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
};

struct usb_endpoint_descriptor_no_audio ss_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
};

struct usb_endpoint_descriptor_no_audio ss_intr = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 3 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
    .bInterval = 6,
};

static usb_ss_ep_comp_descriptor ss_source_comp = {
    .bLength = sizeof(ss_source_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
    .bMaxBurst = 2,
};

static usb_ss_ep_comp_descriptor ss_sink_comp = {
    .bLength = sizeof(ss_sink_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
    .bMaxBurst = 2,
};

static usb_ss_ep_comp_descriptor ss_intr_comp = {
    .bLength = sizeof(ss_intr_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
//    .wBytesPerInterval = cpu_to_le16(64)
};

static struct func_desc mtp_fs_descriptors = {
    .intf = mtp_interface_desc,
    .source = fs_source,
    .sink = fs_sink,
    .intr = fs_intr,
};

static struct func_desc mtp_hs_descriptors = {
    .intf = mtp_interface_desc,
    .source = hs_source,
    .sink = hs_sink,
    .intr = hs_intr,
};

static struct ss_func_desc mtp_ss_descriptors = {
    .intf = mtp_interface_desc,
    .source = ss_source,
    .source_comp = ss_source_comp,
    .sink = ss_sink,
    .sink_comp = ss_sink_comp,
    .intr = ss_intr,
    .intr_comp = ss_intr_comp,
};

static struct func_desc ptp_fs_descriptors = {
    .intf = ptp_interface_desc,
    .source = fs_source,
    .sink = fs_sink,
    .intr = fs_intr,
};

static struct func_desc ptp_hs_descriptors = {
    .intf = ptp_interface_desc,
    .source = hs_source,
    .sink = hs_sink,
    .intr = hs_intr,
};

static struct ss_func_desc ptp_ss_descriptors = {
    .intf = ptp_interface_desc,
    .source = ss_source,
    .source_comp = ss_source_comp,
    .sink = ss_sink,
    .sink_comp = ss_sink_comp,
    .intr = ss_intr,
    .intr_comp = ss_intr_comp,
};

struct usb_ext_compat_desc os_desc_compat = {
    .bFirstInterfaceNumber = 1,
    .Reserved1 = 0,
    .CompatibleID = {0},
    .SubCompatibleID = {0},
    .Reserved2 = {0},
};

static struct usb_os_desc_header os_desc_header = {
    .interface = 1,
    .dwLength = cpu_to_le32(sizeof(os_desc_header) + sizeof(os_desc_compat)),
    .bcdVersion = cpu_to_le16(1),
    .wIndex = cpu_to_le16(4),
    .bCount = 1,
    .Reserved = 0,
};

#define STR_INTERFACE_ "MTP"

static const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE_)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
    .header = {
        .magic = cpu_to_le32(FUNCTIONFS_STRINGS_MAGIC),
        .length = cpu_to_le32(sizeof(strings)),
        .str_count = cpu_to_le32(1),
        .lang_count = cpu_to_le32(1),
    },
    .lang0 = {
        cpu_to_le16(0x0409), /* en-us */
        STR_INTERFACE_,
    },
};

UsbFfsHandle::UsbFfsHandle()
    :   ready(false),
        ready_notify(PTHREAD_COND_INITIALIZER),
        ready_lock(PTHREAD_MUTEX_INITIALIZER),
        control(-1),
        bulk_out(-1),
        bulk_in(-1),
        intr(-1)
{
}

UsbFfsHandle::~UsbFfsHandle() {}

void UsbFfsHandle::closeEndpoints() {
    if (intr > 0) {
        ::close(intr);
        intr = -1;
    }
    if (bulk_in > 0) {
        ::close(bulk_in);
        bulk_in = -1;
    }
    if (bulk_out > 0) {
        ::close(bulk_out);
        bulk_out = -1;
    }
}

bool UsbFfsHandle::initFunctionfs()
{
    ssize_t ret;
    struct desc_v1 v1_descriptor;
    struct desc_v2 v2_descriptor;

    v2_descriptor.header.magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2);
    v2_descriptor.header.length = cpu_to_le32(sizeof(v2_descriptor));
    v2_descriptor.header.flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                                 FUNCTIONFS_HAS_SS_DESC | FUNCTIONFS_HAS_MS_OS_DESC;
    v2_descriptor.fs_count = 4;
    v2_descriptor.hs_count = 4;
    v2_descriptor.ss_count = 7;
    v2_descriptor.os_count = 1;
    v2_descriptor.fs_descs = ptp ? ptp_fs_descriptors : mtp_fs_descriptors;
    v2_descriptor.hs_descs = ptp ? ptp_hs_descriptors : mtp_hs_descriptors;
    v2_descriptor.ss_descs = ptp ? ptp_ss_descriptors : mtp_ss_descriptors;
    v2_descriptor.os_header = os_desc_header;
    v2_descriptor.os_desc = os_desc_compat;

    if (control < 0) { // might have already done this before
        control = TEMP_FAILURE_RETRY(open(USB_FFS_MTP_EP0, O_RDWR));
        if (control < 0) {
            ALOGE("[ %s: cannot open control endpoint: %s]", USB_FFS_MTP_EP0, strerror(errno));
            goto err;
        }

        ret = TEMP_FAILURE_RETRY(::write(control, &v2_descriptor, sizeof(v2_descriptor)));
        if (ret < 0) {
            v1_descriptor.header.magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC);
            v1_descriptor.header.length = cpu_to_le32(sizeof(v1_descriptor));
            v1_descriptor.header.fs_count = 4;
            v1_descriptor.header.hs_count = 4;
            v1_descriptor.fs_descs = ptp ? ptp_fs_descriptors : mtp_fs_descriptors;
            v1_descriptor.hs_descs = ptp ? ptp_hs_descriptors : mtp_hs_descriptors;
            ALOGE("[ %s: Switching to V1_descriptor format: %s ]", USB_FFS_MTP_EP0, strerror(errno));
            ret = TEMP_FAILURE_RETRY(::write(control, &v1_descriptor, sizeof(v1_descriptor)));
            if (ret < 0) {
                ALOGE("[ %s: write descriptors failed: %s ]", USB_FFS_MTP_EP0, strerror(errno));
                goto err;
            }
        }
        ret = TEMP_FAILURE_RETRY(::write(control, &strings, sizeof(strings)));
        if (ret < 0) {
            ALOGE("[ %s: writing strings failed: %s]", USB_FFS_MTP_EP0, strerror(errno));
            goto err;
        }
    }

    bulk_out = TEMP_FAILURE_RETRY(open(USB_FFS_MTP_OUT, O_RDWR));
    if (bulk_out < 0) {
        ALOGE("[ %s: cannot open bulk-out ep: %s ]", USB_FFS_MTP_OUT, strerror(errno));
        goto err;
    }

    bulk_in = TEMP_FAILURE_RETRY(open(USB_FFS_MTP_IN, O_RDWR));
    if (bulk_in < 0) {
        ALOGE("[ %s: cannot open bulk-in ep: %s ]", USB_FFS_MTP_IN, strerror(errno));
        goto err;
    }

    intr = TEMP_FAILURE_RETRY(open(USB_FFS_MTP_INTR, O_RDWR));
    if (intr < 0) {
        ALOGE("[ %s: cannot open intr ep: %s ]", USB_FFS_MTP_INTR, strerror(errno));
        goto err;
    }

    property_set("sys.usb.ffs.ready", "1");
    return true;

err:
    closeEndpoints();
    closeConfig();
    return false;
}

void UsbFfsHandle::closeConfig() {
    if (control > 0) {
        ::close(control);
        control = -1;
    }
}

int UsbFfsHandle::writeHandle(int fd, const void* data, int len) {
    ALOGV("MTP about to write (fd=%d, len=%d)", fd, len);
    int ret = 0;
    const char* buf = static_cast<const char*>(data);
    while (len > 0) {
        int write_len = std::min(USB_FFS_MAX_WRITE, len);
        int n = TEMP_FAILURE_RETRY(::write(fd, buf, write_len));

        if (n < 0) {
            ALOGE("write ERROR: fd = %d, n = %d: %s", fd, n, strerror(errno));
            return -1;
        } else if (n < write_len) {
            ALOGE("less written than expected");
            return -1;
        }
        buf += n;
        len -= n;
        ret += n;
    }

    ALOGV("[ done fd=%d ]", fd);
    return ret;
}

int UsbFfsHandle::write(const void* data, int len) {
    int ret = writeHandle(bulk_in, data, len);
    return ret;
}

int UsbFfsHandle::readHandle(int fd, void* data, int len) {
    ALOGV("MTP about to read (fd=%d, len=%d)", bulk_out, len);
    int ret = 0;
    char* buf = static_cast<char*>(data);
    while (len > 0) {
        int read_len = std::min(USB_FFS_MAX_READ, len);
        int n = TEMP_FAILURE_RETRY(::read(fd, buf, read_len));
        if (n < 0) {
            ALOGE("read ERROR: fd = %d, n = %d: %s", bulk_out, n, strerror(errno));
            return -1;
        }
        ret += n;
        if (n < read_len) // done reading early
            break;
        buf += n;
        len -= n;
    }

    ALOGV("[ done fd=%d ]", bulk_out);
    return ret;
}

int UsbFfsHandle::spliceReadHandle(int fd, int pipe_out, int len) {
    ALOGV("MTP about to read (fd=%d, len=%d)", bulk_out, len);
    int ret = 0;
    loff_t dummyoff;
    while (len > 0) {
        int read_len = std::min(USB_FFS_MAX_READ, len);
        dummyoff = 0;
        int n = TEMP_FAILURE_RETRY(splice(fd, &dummyoff, pipe_out, NULL, read_len, 0));
        if (n < 0) {
            ALOGE("splice read ERROR: fd = %d, n = %d: %s", bulk_out, n, strerror(errno));
            return -1;
        }
        ret += n;
        if (n < read_len) // done reading early
            break;
        len -= n;
    }

    ALOGV("[ done fd=%d ]", bulk_out);
    return ret;
}

int UsbFfsHandle::read(void* data, int len) {
    int ret = readHandle(bulk_out, data, len);
    return ret;
}

int UsbFfsHandle::close() {
    closeEndpoints();
    return 0;
}

int UsbFfsHandle::start() {
    int ret = 0;

    // Wait till configuration is complete
    pthread_mutex_lock(&ready_lock);
    while (!ready) {
        ret = pthread_cond_wait(&ready_notify, &ready_lock);
    }
    ready = false;
    pthread_mutex_unlock(&ready_lock);
    return ret;
}

int UsbFfsHandle::configure(bool usePtp) {
    // Don't do anything if ffs is already open
    if (bulk_in > 0) return 0;

    // If ptp is changed, the configuration must be rewritten
    if (ptp != usePtp) closeConfig();
    ptp = usePtp;

    if (!initFunctionfs()) {
        return -1;
    }
    // tell server that descriptors are finished
    pthread_mutex_lock(&ready_lock);
    ready = true;
    pthread_cond_signal(&ready_notify);
    pthread_mutex_unlock(&ready_lock);

    return 0;
}

/* Read from USB and write to a local file. */
int UsbFfsHandle::receiveFile(mtp_file_range mfr) {
    // When receiving files, the incoming length is given in 32 bits.
    // A >4G file is given as 0xFFFFFFFF
    uint32_t file_length = mfr.length;
    uint64_t offset = lseek(mfr.fd, 0, SEEK_CUR);

    int buf1_len = std::min((uint32_t) MAX_FILE_CHUNK_SIZE, file_length);
    void* data = malloc(buf1_len);

    // If necessary, allocate a second buffer for background r/w
    int buf2_len = std::min((uint32_t) MAX_FILE_CHUNK_SIZE,
            file_length - MAX_FILE_CHUNK_SIZE);
    void *data2 = file_length > (uint64_t) MAX_FILE_CHUNK_SIZE ?
        malloc(buf2_len) : NULL;

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    aio.aio_buf = NULL;
    const struct aiocb * const aiol[] = {&aio};
    int ret;

    posix_fadvise(mfr.fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);

    // Break down the file into pieces that fit in buffers
    while (file_length > 0) {
        size_t length = std::min((uint32_t) MAX_FILE_CHUNK_SIZE, file_length);

        // Read data from USB
        if ((ret = readHandle(bulk_out, data, length)) == -1) {
            goto fail;
        }

        if (file_length != MAX_MTP_FILE_SIZE && ret < (int) length) {
            goto fail;
        }

        if (aio.aio_buf) {
            // If this isn't the first time through the loop,
            // get the return status of the last write request
            aio_suspend(aiol, 1, NULL);

            int written = aio_return(&aio);
            if (written == -1) {
                ret = aio_error(&aio);
                goto fail;
            }
            if ((size_t) written < aio.aio_nbytes) goto fail;
        }

        // Enqueue a new write request
        aio.aio_buf = data;
        aio.aio_sink = mfr.fd;
        aio.aio_offset = offset;
        aio.aio_nbytes = ret;
        aio_write(&aio);

        if (file_length == MAX_MTP_FILE_SIZE) {
            // For larger files, receive until a short packet is received.
            if ((size_t) ret < length) {
                break;
            }
        }

        if (file_length != MAX_MTP_FILE_SIZE) file_length -= ret;
        offset += ret;
        std::swap(data, data2);
    }
    // Wait for the final write to finish
    aio_suspend(aiol, 1, NULL);
    ret = aio_return(&aio);
    if (ret == -1) {
        ret = aio_error(&aio);
        goto fail;
    }
    if ((size_t) ret < aio.aio_nbytes) goto fail;

    free(data);
    free(data2);
    return 0;

fail:
    ALOGE("Error in receiving MTP file");
    free(data);
    free(data2);
    return -1;
}

/* Read from a local file and send over USB. */
int UsbFfsHandle::sendFile(mtp_file_range mfr) {
    uint64_t file_length = mfr.length;
    uint32_t given_length = std::min((uint64_t) MAX_MTP_FILE_SIZE,
            file_length + sizeof(mtp_data_header));
    uint64_t offset = 0;
    struct usb_endpoint_descriptor bulk_in_desc;

    posix_fadvise(mfr.fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);

    int init_read_len = MAX_PACKET_SIZE_SS - sizeof(mtp_data_header);
    int buf1_len = std::max((uint64_t) MAX_PACKET_SIZE_SS, std::min(
                  (uint64_t) MAX_FILE_CHUNK_SIZE, file_length - init_read_len));
    void *data = malloc(buf1_len);

    // If necessary, allocate a second buffer for background r/w
    int buf2_len = std::min((uint64_t) MAX_FILE_CHUNK_SIZE,
            file_length - MAX_FILE_CHUNK_SIZE - init_read_len);
    void *data2 = file_length - init_read_len >
        (uint64_t) MAX_FILE_CHUNK_SIZE ? malloc(buf2_len) : NULL;

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    const struct aiocb * const aiol[] = {&aio};
    int ret, length;

    // Send the header data
    mtp_data_header *header = reinterpret_cast<mtp_data_header*>(data);
    header->length = __cpu_to_le32(given_length);
    header->type = __cpu_to_le16(2); /* data packet */
    header->command = __cpu_to_le16(mfr.command);
    header->transaction_id = __cpu_to_le32(mfr.transaction_id);

    // Windows doesn't support header/data separation even though MTP allows it
    // Handle by filling first packet with initial file data
    if (TEMP_FAILURE_RETRY(pread(mfr.fd, reinterpret_cast<char*>(data) +
                    sizeof(mtp_data_header), init_read_len, offset))
            != init_read_len) goto fail;
    file_length -= init_read_len;
    offset += init_read_len;
    if (writeHandle(bulk_in, data, MAX_PACKET_SIZE_SS) == -1) goto fail;
    if (file_length == 0) goto done;

    length = std::min((uint64_t) MAX_FILE_CHUNK_SIZE, file_length);
    // Queue up the first read
    aio.aio_buf = data;
    aio.aio_offset = offset;
    aio.aio_nbytes = length;
    aio_read(&aio);

    // Break down the file into pieces that fit in buffers
    do {
        // Wait for the previous read to finish
        aio_suspend(aiol, 1, NULL);
        ret = aio_return(&aio);
        if (ret == -1) {
            ret = aio_error(&aio);
            goto fail;
        }
        if ((size_t) ret < aio.aio_nbytes) goto fail;

        file_length -= ret;
        offset += ret;
        std::swap(data, data2);

        if (file_length > 0) {
            length = std::min((uint64_t) MAX_FILE_CHUNK_SIZE, file_length);
            // Queue up another read
            aio.aio_buf = data;
            aio.aio_offset = offset;
            aio.aio_nbytes = length;
            aio_read(&aio);
        }

        if (writeHandle(bulk_in, data2, ret) == -1) goto fail;
    } while (file_length > 0);

    if (ioctl(bulk_in, FUNCTIONFS_ENDPOINT_DESC, (unsigned long) &bulk_in_desc)) {
        ALOGE("Could not get FFS bulk-in descriptor %d", errno);
        goto fail;
    }
    if (given_length == MAX_MTP_FILE_SIZE && ret % bulk_in_desc.wMaxPacketSize == 0) {
        // If the last packet wasn't short, send a final empty packet
        if (writeHandle(bulk_in, data, 0) == -1) goto fail;
    }

done:
    free(data);
    free(data2);
    return 0;

fail:
    ALOGE("Error in sending MTP file");
    free(data);
    free(data2);
    return -1;
}

int UsbFfsHandle::sendEvent(mtp_event me) {
    unsigned length = me.length;
    int ret = writeHandle(intr, me.data, length);
    return ret;
}

UsbHandle *get_ffs_handle() {
    return new UsbFfsHandle();
}

