/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <condition_variable>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "AsyncIO.h"
#include "IMtpHandle.h"

#define cpu_to_le16(x)  htole16(x)
#define cpu_to_le32(x)  htole32(x)

constexpr char FFS_MTP_EP_OUT[] = "/dev/usb-ffs/mtp/ep1";
constexpr char FFS_MTP_EP_IN[] = "/dev/usb-ffs/mtp/ep2";
constexpr char FFS_MTP_EP_INTR[] = "/dev/usb-ffs/mtp/ep3";

constexpr int MAX_PACKET_SIZE_FS = 64;
constexpr int MAX_PACKET_SIZE_HS = 512;
constexpr int MAX_PACKET_SIZE_SS = 1024;

// Must be divisible by all max packet size values
constexpr int MAX_FILE_CHUNK_SIZE = 3145728;
constexpr int USB_FFS_MAX_WRITE = 262144;
constexpr int USB_FFS_MAX_READ = 262144;

constexpr unsigned int MAX_MTP_FILE_SIZE = 0xFFFFFFFF;

class MtpFfsHandle : public IMtpHandle {
private:
    int writeHandle(int fd, const void *data, int len);
    int readHandle(int fd, void *data, int len);
    int spliceReadHandle(int fd, int fd_out, int len);
    bool initFunctionfs();
    void closeConfig();
    void closeEndpoints();

    bool mPtp;

    bool mReady;
    std::condition_variable mReadyCond;
    std::mutex mReadyLock;

    bool mClosed;
    std::condition_variable mClosedCond;
    std::mutex mClosedLock;

    int mControl;
    int mBulkOut; /* "out" from the host's perspective => source for mtp server */
    int mBulkIn;  /* "in" from the host's perspective => sink for mtp server */
    int mIntr;

public:
    int read(void *data, int len);
    int write(const void *data, int len);

    int receiveFile(mtp_file_range mfr);
    int sendFile(mtp_file_range mfr);
    int sendEvent(mtp_event me);

    int start();
    int close();

    int configure(bool ptp);

    MtpFfsHandle();
    ~MtpFfsHandle();
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

MtpFfsHandle::MtpFfsHandle()
    :   mReady(false),
        mClosed(true),
        mControl(-1),
        mBulkOut(-1),
        mBulkIn(-1),
        mIntr(-1) {}

MtpFfsHandle::~MtpFfsHandle() {}

void MtpFfsHandle::closeEndpoints() {
    if (mIntr > 0) {
        ::close(mIntr);
        mIntr = -1;
    }
    if (mBulkIn > 0) {
        ::close(mBulkIn);
        mBulkIn = -1;
    }
    if (mBulkOut > 0) {
        ::close(mBulkOut);
        mBulkOut = -1;
    }
}

bool MtpFfsHandle::initFunctionfs() {
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
    v2_descriptor.fs_descs = mPtp ? ptp_fs_descriptors : mtp_fs_descriptors;
    v2_descriptor.hs_descs = mPtp ? ptp_hs_descriptors : mtp_hs_descriptors;
    v2_descriptor.ss_descs = mPtp ? ptp_ss_descriptors : mtp_ss_descriptors;
    v2_descriptor.os_header = os_desc_header;
    v2_descriptor.os_desc = os_desc_compat;

    if (mControl < 0) { // might have already done this before
        mControl = TEMP_FAILURE_RETRY(open(FFS_MTP_EP0, O_RDWR));
        if (mControl < 0) {
            PLOG(ERROR) << FFS_MTP_EP0 << ": cannot open control endpoint";
            goto err;
        }

        ret = TEMP_FAILURE_RETRY(::write(mControl, &v2_descriptor, sizeof(v2_descriptor)));
        if (ret < 0) {
            v1_descriptor.header.magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC);
            v1_descriptor.header.length = cpu_to_le32(sizeof(v1_descriptor));
            v1_descriptor.header.fs_count = 4;
            v1_descriptor.header.hs_count = 4;
            v1_descriptor.fs_descs = mPtp ? ptp_fs_descriptors : mtp_fs_descriptors;
            v1_descriptor.hs_descs = mPtp ? ptp_hs_descriptors : mtp_hs_descriptors;
            PLOG(ERROR) << FFS_MTP_EP0 << "Switching to V1 descriptor format";
            ret = TEMP_FAILURE_RETRY(::write(mControl, &v1_descriptor, sizeof(v1_descriptor)));
            if (ret < 0) {
                PLOG(ERROR) << FFS_MTP_EP0 << "Writing descriptors failed";
                goto err;
            }
        }
        ret = TEMP_FAILURE_RETRY(::write(mControl, &strings, sizeof(strings)));
        if (ret < 0) {
            PLOG(ERROR) << FFS_MTP_EP0 << "Writing strings failed";
            goto err;
        }
    }

    mBulkOut = TEMP_FAILURE_RETRY(open(FFS_MTP_EP_OUT, O_RDWR));
    if (mBulkOut < 0) {
        PLOG(ERROR) << FFS_MTP_EP_OUT << ": cannot open bulk out ep";
        goto err;
    }

    mBulkIn = TEMP_FAILURE_RETRY(open(FFS_MTP_EP_IN, O_RDWR));
    if (mBulkIn < 0) {
        PLOG(ERROR) << FFS_MTP_EP_IN << ": cannot open bulk in ep";
        goto err;
    }

    mIntr = TEMP_FAILURE_RETRY(open(FFS_MTP_EP_INTR, O_RDWR));
    if (mIntr < 0) {
        PLOG(ERROR) << FFS_MTP_EP0 << ": cannot open intr ep";
        goto err;
    }

    android::base::SetProperty("sys.usb.ffs.ready", "1");
    return true;

err:
    closeEndpoints();
    closeConfig();
    return false;
}

void MtpFfsHandle::closeConfig() {
    if (mControl > 0) {
        ::close(mControl);
        mControl = -1;
    }
}

int MtpFfsHandle::writeHandle(int fd, const void* data, int len) {
    PLOG(VERBOSE) << "MTP about to write fd = " << fd << ", len=" << len;
    int ret = 0;
    const char* buf = static_cast<const char*>(data);
    while (len > 0) {
        int write_len = std::min(USB_FFS_MAX_WRITE, len);
        int n = TEMP_FAILURE_RETRY(::write(fd, buf, write_len));

        if (n < 0) {
            PLOG(ERROR) << "write ERROR: fd = " << fd << ", n = " << n;
            return -1;
        } else if (n < write_len) {
            PLOG(ERROR) << "less written than expected";
            return -1;
        }
        buf += n;
        len -= n;
        ret += n;
    }
    return ret;
}

int MtpFfsHandle::write(const void* data, int len) {
    return writeHandle(mBulkIn, data, len);
}

int MtpFfsHandle::readHandle(int fd, void* data, int len) {
    PLOG(VERBOSE) << "MTP about to read fd = " << fd << ", len=" << len;
    int ret = 0;
    char* buf = static_cast<char*>(data);
    while (len > 0) {
        int read_len = std::min(USB_FFS_MAX_READ, len);
        int n = TEMP_FAILURE_RETRY(::read(fd, buf, read_len));
        if (n < 0) {
            PLOG(ERROR) << "read ERROR: fd = " << fd << ", n = " << n;
            return -1;
        }
        ret += n;
        if (n < read_len) // done reading early
            break;
        buf += n;
        len -= n;
    }
    return ret;
}

int MtpFfsHandle::spliceReadHandle(int fd, int pipe_out, int len) {
    PLOG(VERBOSE) << "MTP about to splice read fd = " << fd << ", len=" << len;
    int ret = 0;
    loff_t dummyoff;
    while (len > 0) {
        int read_len = std::min(USB_FFS_MAX_READ, len);
        dummyoff = 0;
        int n = TEMP_FAILURE_RETRY(splice(fd, &dummyoff, pipe_out, nullptr, read_len, 0));
        if (n < 0) {
            PLOG(ERROR) << "splice read ERROR: fd = " << fd << ", n = " << n;
            return -1;
        }
        ret += n;
        if (n < read_len) // done reading early
            break;
        len -= n;
    }
    return ret;
}

int MtpFfsHandle::read(void* data, int len) {
    return readHandle(mBulkOut, data, len);
}

int MtpFfsHandle::close() {
    closeEndpoints();

    // Allow configures to continue
    {
        std::lock_guard<std::mutex> lg(mClosedLock);
        mClosed = true;
    }
    mClosedCond.notify_one();
    return 0;
}

int MtpFfsHandle::start() {
    std::unique_lock<std::mutex> lk(mReadyLock);

    // Wait till configuration is complete
    mReadyCond.wait(lk, [this](){return mReady;});
    mReady = false;

    lk.unlock();
    return 0;
}

int MtpFfsHandle::configure(bool usePtp) {
    // Wait till previous server invocation has closed
    std::unique_lock<std::mutex> lk(mReadyLock);

    // Wait till configuration is complete
    mClosedCond.wait(lk, [this](){return mClosed;});
    mClosed = false;

    lk.unlock();

    // Don't do anything if ffs is already open
    if (mBulkIn > 0) return 0;

    // If ptp is changed, the configuration must be rewritten
    if (mPtp != usePtp) closeConfig();
    mPtp = usePtp;

    if (!initFunctionfs()) {
        return -1;
    }
    // tell server that descriptors are finished
    {
        std::lock_guard<std::mutex> lg(mReadyLock);
        mReady = true;
    }
    mReadyCond.notify_one();

    return 0;
}

/* Read from USB and write to a local file. */
int MtpFfsHandle::receiveFile(mtp_file_range mfr) {
    // When receiving files, the incoming length is given in 32 bits.
    // A >4G file is given as 0xFFFFFFFF
    uint32_t file_length = mfr.length;
    uint64_t offset = lseek(mfr.fd, 0, SEEK_CUR);

    int buf1_len = std::min((uint32_t) MAX_FILE_CHUNK_SIZE, file_length);
    std::vector<char> buf1(buf1_len);
    char* data = buf1.data();

    // If necessary, allocate a second buffer for background r/w
    int buf2_len = std::min((uint32_t) MAX_FILE_CHUNK_SIZE,
            file_length - MAX_FILE_CHUNK_SIZE);
    std::vector<char> buf2(buf2_len);
    char *data2 = buf2.data();

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    aio.aio_buf = nullptr;
    struct aiocb *aiol[] = {&aio};
    int ret;

    posix_fadvise(mfr.fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);

    // Break down the file into pieces that fit in buffers
    while (file_length > 0) {
        size_t length = std::min((uint32_t) MAX_FILE_CHUNK_SIZE, file_length);

        // Read data from USB
        if ((ret = readHandle(mBulkOut, data, length)) == -1) {
            return -1;
        }

        if (file_length != MAX_MTP_FILE_SIZE && ret < (int) length) {
            errno = EIO;
            return -1;
        }

        if (aio.aio_buf) {
            // If this isn't the first time through the loop,
            // get the return status of the last write request
            aio_suspend(aiol, 1, nullptr);

            int written = aio_return(&aio);
            if (written == -1) {
                errno = aio_error(&aio);
                return -1;
            }
            if ((size_t) written < aio.aio_nbytes) {
                errno = EIO;
                return -1;
            }
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
    aio_suspend(aiol, 1, nullptr);
    ret = aio_return(&aio);
    if (ret == -1) {
        errno = aio_error(&aio);
        return -1;
    }
    if ((size_t) ret < aio.aio_nbytes) {
        errno = EIO;
        return -1;
    };

    return 0;
}

/* Read from a local file and send over USB. */
int MtpFfsHandle::sendFile(mtp_file_range mfr) {
    uint64_t file_length = mfr.length;
    uint32_t given_length = std::min((uint64_t) MAX_MTP_FILE_SIZE,
            file_length + sizeof(mtp_data_header));
    uint64_t offset = 0;
    struct usb_endpoint_descriptor mBulkIn_desc;
    int packet_size;

    if (ioctl(mBulkIn, FUNCTIONFS_ENDPOINT_DESC, (unsigned long) &mBulkIn_desc)) {
        PLOG(ERROR) << "Could not get FFS bulk-in descriptor: " << strerror(errno);
        return -1;
    }
    packet_size = mBulkIn_desc.wMaxPacketSize;

    posix_fadvise(mfr.fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);

    int init_read_len = packet_size - sizeof(mtp_data_header);
    int buf1_len = std::max((uint64_t) packet_size, std::min(
                  (uint64_t) MAX_FILE_CHUNK_SIZE, file_length - init_read_len));
    std::vector<char> buf1(buf1_len);
    char *data = buf1.data();

    // If necessary, allocate a second buffer for background r/w
    int buf2_len = std::min((uint64_t) MAX_FILE_CHUNK_SIZE,
            file_length - MAX_FILE_CHUNK_SIZE - init_read_len);
    std::vector<char>buf2(buf2_len);
    char *data2 = buf2.data();

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    struct aiocb *aiol[] = {&aio};
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
            != init_read_len) return -1;
    file_length -= init_read_len;
    offset += init_read_len;
    if (writeHandle(mBulkIn, data, packet_size) == -1) return -1;
    if (file_length == 0) return 0;

    length = std::min((uint64_t) MAX_FILE_CHUNK_SIZE, file_length);
    // Queue up the first read
    aio.aio_buf = data;
    aio.aio_offset = offset;
    aio.aio_nbytes = length;
    aio_read(&aio);

    // Break down the file into pieces that fit in buffers
    while(file_length > 0) {
        // Wait for the previous read to finish
        aio_suspend(aiol, 1, nullptr);
        ret = aio_return(&aio);
        if (ret == -1) {
            errno = aio_error(&aio);
            return -1;
        }
        if ((size_t) ret < aio.aio_nbytes) {
            errno = EIO;
            return -1;
        }

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

        if (writeHandle(mBulkIn, data2, ret) == -1) return -1;
    }

    if (given_length == MAX_MTP_FILE_SIZE && ret % packet_size == 0) {
        // If the last packet wasn't short, send a final empty packet
        if (writeHandle(mBulkIn, data, 0) == -1) return -1;
    }

    return 0;
}

int MtpFfsHandle::sendEvent(mtp_event me) {
    unsigned length = me.length;
    int ret = writeHandle(mIntr, me.data, length);
    return (unsigned) ret == length ? 0 : -1;
}

IMtpHandle *get_ffs_handle() {
    return new MtpFfsHandle();
}

