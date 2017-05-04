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
#include <asyncio/AsyncIO.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/endian.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "PosixAsyncIO.h"
#include "MtpFfsHandle.h"
#include "mtp.h"

namespace {

constexpr char FFS_MTP_EP_IN[] = "/dev/usb-ffs/mtp/ep1";
constexpr char FFS_MTP_EP_OUT[] = "/dev/usb-ffs/mtp/ep2";
constexpr char FFS_MTP_EP_INTR[] = "/dev/usb-ffs/mtp/ep3";

constexpr int MAX_PACKET_SIZE_FS = 64;
constexpr int MAX_PACKET_SIZE_HS = 512;
constexpr int MAX_PACKET_SIZE_SS = 1024;

constexpr unsigned AIO_BUFS_MAX = 128;
constexpr unsigned AIO_BUF_LEN = 16384;

constexpr unsigned MAX_FILE_CHUNK_SIZE = AIO_BUFS_MAX * AIO_BUF_LEN;

constexpr uint32_t MAX_MTP_FILE_SIZE = 0xFFFFFFFF;

struct timespec DEFAULT_TIMEOUT = {0, 500000000}; // half a second

struct func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_endpoint_descriptor_no_audio intr;
} __attribute__((packed));

struct ss_func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_ss_ep_comp_descriptor sink_comp;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_ss_ep_comp_descriptor source_comp;
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
    struct func_desc fs_descs, hs_descs;
    struct ss_func_desc ss_descs;
} __attribute__((packed));

const struct usb_interface_descriptor mtp_interface_desc = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bNumEndpoints = 3,
    .bInterfaceClass = USB_CLASS_STILL_IMAGE,
    .bInterfaceSubClass = 1,
    .bInterfaceProtocol = 1,
    .iInterface = 1,
};

const struct usb_interface_descriptor ptp_interface_desc = {
    .bLength = USB_DT_INTERFACE_SIZE,
    .bDescriptorType = USB_DT_INTERFACE,
    .bInterfaceNumber = 0,
    .bNumEndpoints = 3,
    .bInterfaceClass = USB_CLASS_STILL_IMAGE,
    .bInterfaceSubClass = 1,
    .bInterfaceProtocol = 1,
};

const struct usb_endpoint_descriptor_no_audio fs_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
};

const struct usb_endpoint_descriptor_no_audio fs_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
};

const struct usb_endpoint_descriptor_no_audio fs_intr = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 3 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = MAX_PACKET_SIZE_FS,
    .bInterval = 6,
};

const struct usb_endpoint_descriptor_no_audio hs_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
};

const struct usb_endpoint_descriptor_no_audio hs_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
};

const struct usb_endpoint_descriptor_no_audio hs_intr = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 3 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = MAX_PACKET_SIZE_HS,
    .bInterval = 6,
};

const struct usb_endpoint_descriptor_no_audio ss_sink = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 1 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
};

const struct usb_endpoint_descriptor_no_audio ss_source = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 2 | USB_DIR_OUT,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
};

const struct usb_endpoint_descriptor_no_audio ss_intr = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = 3 | USB_DIR_IN,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = MAX_PACKET_SIZE_SS,
    .bInterval = 6,
};

const struct usb_ss_ep_comp_descriptor ss_sink_comp = {
    .bLength = sizeof(ss_sink_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
    .bMaxBurst = 6,
};

const struct usb_ss_ep_comp_descriptor ss_source_comp = {
    .bLength = sizeof(ss_source_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
    .bMaxBurst = 6,
};

const struct usb_ss_ep_comp_descriptor ss_intr_comp = {
    .bLength = sizeof(ss_intr_comp),
    .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
};

const struct func_desc mtp_fs_descriptors = {
    .intf = mtp_interface_desc,
    .sink = fs_sink,
    .source = fs_source,
    .intr = fs_intr,
};

const struct func_desc mtp_hs_descriptors = {
    .intf = mtp_interface_desc,
    .sink = hs_sink,
    .source = hs_source,
    .intr = hs_intr,
};

const struct ss_func_desc mtp_ss_descriptors = {
    .intf = mtp_interface_desc,
    .sink = ss_sink,
    .sink_comp = ss_sink_comp,
    .source = ss_source,
    .source_comp = ss_source_comp,
    .intr = ss_intr,
    .intr_comp = ss_intr_comp,
};

const struct func_desc ptp_fs_descriptors = {
    .intf = ptp_interface_desc,
    .sink = fs_sink,
    .source = fs_source,
    .intr = fs_intr,
};

const struct func_desc ptp_hs_descriptors = {
    .intf = ptp_interface_desc,
    .sink = hs_sink,
    .source = hs_source,
    .intr = hs_intr,
};

const struct ss_func_desc ptp_ss_descriptors = {
    .intf = ptp_interface_desc,
    .sink = ss_sink,
    .sink_comp = ss_sink_comp,
    .source = ss_source,
    .source_comp = ss_source_comp,
    .intr = ss_intr,
    .intr_comp = ss_intr_comp,
};

#define STR_INTERFACE "MTP"
const struct {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        const char str1[sizeof(STR_INTERFACE)];
    } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
    .header = {
        .magic = htole32(FUNCTIONFS_STRINGS_MAGIC),
        .length = htole32(sizeof(strings)),
        .str_count = htole32(1),
        .lang_count = htole32(1),
    },
    .lang0 = {
        .code = htole16(0x0409),
        .str1 = STR_INTERFACE,
    },
};

} // anonymous namespace

namespace android {

int MtpFfsHandle::getPacketSize(int ffs_fd) {
    struct usb_endpoint_descriptor desc;
    if (ioctl(ffs_fd, FUNCTIONFS_ENDPOINT_DESC, reinterpret_cast<unsigned long>(&desc))) {
        PLOG(ERROR) << "Could not get FFS bulk-in descriptor";
        return MAX_PACKET_SIZE_HS;
    } else {
        return desc.wMaxPacketSize;
    }
}

MtpFfsHandle::MtpFfsHandle() {}

MtpFfsHandle::~MtpFfsHandle() {}

void MtpFfsHandle::closeEndpoints() {
    mIntr.reset();
    mBulkIn.reset();
    mBulkOut.reset();
}

void MtpFfsHandle::advise(int fd) {
    for (unsigned i = 0; i < NUM_IO_BUFS; i++) {
        if (posix_madvise(mIobuf[i].bufs.data(), MAX_FILE_CHUNK_SIZE,
                POSIX_MADV_SEQUENTIAL | POSIX_MADV_WILLNEED) < 0)
            PLOG(ERROR) << "Failed to madvise";
    }
    if (posix_fadvise(fd, 0, 0,
                POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE | POSIX_FADV_WILLNEED) < 0)
        PLOG(ERROR) << "Failed to fasvise";
}

bool MtpFfsHandle::initFunctionfs() {
    ssize_t ret;
    struct desc_v1 v1_descriptor;
    struct desc_v2 v2_descriptor;

    v2_descriptor.header.magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2);
    v2_descriptor.header.length = htole32(sizeof(v2_descriptor));
    v2_descriptor.header.flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                                 FUNCTIONFS_HAS_SS_DESC;
    v2_descriptor.fs_count = 4;
    v2_descriptor.hs_count = 4;
    v2_descriptor.ss_count = 7;
    v2_descriptor.fs_descs = mPtp ? ptp_fs_descriptors : mtp_fs_descriptors;
    v2_descriptor.hs_descs = mPtp ? ptp_hs_descriptors : mtp_hs_descriptors;
    v2_descriptor.ss_descs = mPtp ? ptp_ss_descriptors : mtp_ss_descriptors;

    if (mControl < 0) { // might have already done this before
        mControl.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP0, O_RDWR)));
        if (mControl < 0) {
            PLOG(ERROR) << FFS_MTP_EP0 << ": cannot open control endpoint";
            goto err;
        }

        ret = TEMP_FAILURE_RETRY(::write(mControl, &v2_descriptor, sizeof(v2_descriptor)));
        if (ret < 0) {
            v1_descriptor.header.magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC);
            v1_descriptor.header.length = htole32(sizeof(v1_descriptor));
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
    if (mBulkIn > -1 || mBulkOut > -1 || mIntr > -1)
        LOG(WARNING) << "Endpoints were not closed before configure!";

    return true;

err:
    closeConfig();
    return false;
}

void MtpFfsHandle::closeConfig() {
    mControl.reset();
}

int MtpFfsHandle::read(void* data, size_t len) {
    return TEMP_FAILURE_RETRY(::read(mBulkOut, data, len));
}

int MtpFfsHandle::write(const void* data, size_t len) {
    return TEMP_FAILURE_RETRY(::write(mBulkIn, data, len));
}

int MtpFfsHandle::start() {
    mLock.lock();

    for (unsigned i = 0; i < NUM_IO_BUFS; i++) {
        mIobuf[i].bufs.resize(MAX_FILE_CHUNK_SIZE);
        mIobuf[i].iocb.resize(AIO_BUFS_MAX);
        mIobuf[i].iocbs.resize(AIO_BUFS_MAX);
        mIobuf[i].buf.resize(AIO_BUFS_MAX);
        for (unsigned j = 0; j < AIO_BUFS_MAX; j++) {
            mIobuf[i].buf[j] = mIobuf[i].bufs.data() + j * AIO_BUF_LEN;
            mIobuf[i].iocb[j] = &mIobuf[i].iocbs[j];
        }
    }

    memset(&mCtx, 0, sizeof(mCtx));
    memset(&mEventCtx, 0, sizeof(mEventCtx));
    if (io_setup(AIO_BUFS_MAX, &mCtx) < 0) {
        PLOG(ERROR) << "unable to setup aio";
        return -1;
    }
    if (io_setup(3, &mEventCtx) < 0) {
        PLOG(ERROR) << "unable to setup aio";
        return -1;
    }

    return 0;
}

int MtpFfsHandle::configure(bool usePtp) {
    // Wait till previous server invocation has closed
    if (!mLock.try_lock_for(std::chrono::milliseconds(1000))) {
        LOG(ERROR) << "MtpServer was unable to get configure lock";
        return -1;
    }
    int ret = 0;

    // If ptp is changed, the configuration must be rewritten
    if (mPtp != usePtp) {
        closeEndpoints();
        closeConfig();
    }
    mPtp = usePtp;

    if (!initFunctionfs()) {
        ret = -1;
    }

    if (mBulkIn < 0) {
        mBulkIn.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP_IN, O_RDWR)));
        if (mBulkIn < 0) {
            PLOG(ERROR) << FFS_MTP_EP_IN << ": cannot open bulk in ep";
            return -1;
        }
    }

    if (mBulkOut < 0) {
        mBulkOut.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP_OUT, O_RDWR)));
        if (mBulkOut < 0) {
            PLOG(ERROR) << FFS_MTP_EP_OUT << ": cannot open bulk out ep";
            return -1;
        }
    }

    if (mIntr < 0) {
        mIntr.reset(TEMP_FAILURE_RETRY(open(FFS_MTP_EP_INTR, O_RDWR)));
        if (mIntr < 0) {
            PLOG(ERROR) << FFS_MTP_EP_INTR << ": cannot open intr ep";
            return -1;
        }
    }

    mLock.unlock();
    return ret;
}

void MtpFfsHandle::close() {
    closeEndpoints();
    io_destroy(mCtx);
    io_destroy(mEventCtx);
    mLock.unlock();
}

int MtpFfsHandle::waitEvents(struct io_buffer *buf, int min_events, struct io_event *events,
        int *counter, struct timespec *timeout) {
    int num_events = TEMP_FAILURE_RETRY(io_getevents(mCtx, min_events, AIO_BUFS_MAX,
                events, timeout));
    int ret = 0;
    if (num_events == -1) {
        PLOG(ERROR) << "Mtp error getting events";
        return -1;
    } else if (num_events < min_events) {
        // Mtp protocol does not include a method for host to cancel a file transfer.
        // If the host cancels, the device will be stuck waiting until reset. We can
        // try to recover by checking if a request has timed out.
        LOG(ERROR) << "Mtp timed out " << num_events << " " << min_events;
        cancelEvents(buf->iocb.data(), events, num_events, buf->actual);
        errno = ETIMEDOUT;
        return -1;
    }
    // Add up the total amount of data and find errors on the way.
    for (unsigned j = 0; j < static_cast<unsigned>(num_events); j++) {
        if (events[j].res < 0) {
            errno = -events[j].res;
            PLOG(ERROR) << "Mtp got error event at " << j << " and " << buf->actual << " total";
            return -1;
        }
        ret += events[j].res;
    }
    if (counter)
        *counter += num_events;
    return ret;
}

int MtpFfsHandle::cancelEvents(struct iocb **iocb, struct io_event *events, unsigned start,
        unsigned end) {
    // Some manpages for io_cancel are out of date and incorrect.
    // io_cancel will return -EINPROGRESS on success and does
    // not place the event in the given memory. We have to use
    // io_getevents to wait for all the events we cancelled.
    int ret = 0;
    errno = 0;
    for (unsigned j = start; j < end; j++) {
        if (io_cancel(mCtx, iocb[j], nullptr) != -1 || errno != EINPROGRESS) {
            LOG(ERROR) << "Mtp couldn't cancel request " << j;
            ret = -1;
        }
    }
    int evs = TEMP_FAILURE_RETRY(io_getevents(mCtx, end - start, AIO_BUFS_MAX, events, nullptr));
    if (static_cast<unsigned>(evs) != end - start) {
        PLOG(ERROR) << "Mtp couldn't cancel all requests, got " << evs;
        ret = -1;
    }
    if (!errno) {
        errno = EIO;
    }
    return ret;
}

int MtpFfsHandle::iobufSubmit(struct io_buffer *buf, int fd, unsigned length, bool read) {
    int ret = 0;
    buf->actual = AIO_BUFS_MAX;
    for (unsigned j = 0; j < AIO_BUFS_MAX; j++) {
        unsigned rq_length = std::min(AIO_BUF_LEN, length - AIO_BUF_LEN * j);
        io_prep(buf->iocb[j], fd, buf->buf[j], rq_length, 0, read);

        // Not enough data, so table is truncated.
        if (rq_length < AIO_BUF_LEN || length == AIO_BUF_LEN * (j + 1)) {
            buf->actual = j + 1;
            break;
        }
    }

    ret = io_submit(mCtx, buf->actual, buf->iocb.data());
    if (ret != static_cast<int>(buf->actual)) {
        PLOG(ERROR) << "Mtp io_submit got " << ret << " expected " << buf->actual;
        if (ret != -1) {
            errno = EIO;
        }
        ret = -1;
    }
    return ret;
}

int MtpFfsHandle::receiveFile(mtp_file_range mfr, bool zero_packet) {
    // When receiving files, the incoming length is given in 32 bits.
    // A >=4G file is given as 0xFFFFFFFF
    uint32_t file_length = mfr.length;
    uint64_t offset = mfr.offset;

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    aio.aio_buf = nullptr;
    struct aiocb *aiol[] = {&aio};

    int ret = -1;
    unsigned i = 0;
    size_t length;
    struct io_event ioevs[AIO_BUFS_MAX];
    bool write = false;
    bool error = false;
    bool write_error = false;
    int packet_size = getPacketSize(mBulkOut);
    bool short_packet = false;
    advise(mfr.fd);

    // Break down the file into pieces that fit in buffers
    while (file_length > 0 || write) {
        // Queue an asynchronous read from USB.
        if (file_length > 0) {
            length = std::min(static_cast<uint32_t>(MAX_FILE_CHUNK_SIZE), file_length);
            if (iobufSubmit(&mIobuf[i], mBulkOut, length, true) == -1)
                error = true;
        }

        // Get the return status of the last write request.
        if (write) {
            aio_suspend(aiol, 1, nullptr);
            int written = aio_return(&aio);
            if (static_cast<size_t>(written) < aio.aio_nbytes) {
                errno = written == -1 ? aio_error(&aio) : EIO;
                PLOG(ERROR) << "Mtp error writing to disk";
                write_error = true;
            }
            write = false;
        }

        if (error) {
            return -1;
        }

        // Get the result of the read request, and queue a write to disk.
        if (file_length > 0) {
            unsigned num_events = 0;
            ret = 0;
            unsigned short_i = mIobuf[i].actual;
            while (num_events < short_i) {
                // Get all events up to the short read, if there is one.
                // We must wait for each event since data transfer could end at any time.
                int this_events = 0;
                int event_ret = waitEvents(&mIobuf[i], 1, ioevs, &this_events, &DEFAULT_TIMEOUT);
                if (event_ret == -1) {
                    return -1;
                }
                ret += event_ret;
                num_events += this_events;
                for (int j = 0; j < this_events; j++) {
                    // struct io_event contains a pointer to the associated struct iocb as a __u64.
                    if (static_cast<__u64>(ioevs[j].res) <
                            reinterpret_cast<struct iocb*>(ioevs[j].obj)->aio_nbytes) {
                        // We've found a short event. Store the index since
                        // events won't necessarily arrive in the order they are queued.
                        short_i = (ioevs[j].obj - reinterpret_cast<uint64_t>(mIobuf[i].iocbs.data()))
                            / sizeof(struct iocb) + 1;
                        short_packet = true;
                    }
                }
            }
            if (short_packet) {
                if (cancelEvents(mIobuf[i].iocb.data(), ioevs, short_i, mIobuf[i].actual)) {
                    LOG(ERROR) << "Mtp cancel error " << num_events << " " << mIobuf[i].actual;
                    write_error = true;
                }
            }
            if (file_length == MAX_MTP_FILE_SIZE) {
                // For larger files, receive until a short packet is received.
                if (static_cast<size_t>(ret) < length) {
                    file_length = 0;
                }
            } else if (ret < static_cast<int>(length)) {
                // If file is less than 4G and we get a short packet, it's an error.
                errno = EIO;
                LOG(ERROR) << "Mtp got unexpected short packet";
                return -1;
            } else {
                file_length -= ret;
            }

            if (write_error) {
                return -1;
            }

            // Enqueue a new write request
            aio_prepare(&aio, mIobuf[i].bufs.data(), ret, offset);
            aio_write(&aio);

            offset += ret;
            i = (i + 1) % NUM_IO_BUFS;
            write = true;
        }
    }
    if ((ret % packet_size == 0 && !short_packet) || zero_packet) {
        // Receive an empty packet if size is a multiple of the endpoint size.
        if (read(mIobuf[0].bufs.data(), packet_size) != 0) {
            return -1;
        }
    }
    return 0;
}

int MtpFfsHandle::sendFile(mtp_file_range mfr) {
    uint64_t file_length = mfr.length;
    uint32_t given_length = std::min(static_cast<uint64_t>(MAX_MTP_FILE_SIZE),
            file_length + sizeof(mtp_data_header));
    uint64_t offset = mfr.offset;
    int packet_size = getPacketSize(mBulkIn);

    // If file_length is larger than a size_t, truncating would produce the wrong comparison.
    // Instead, promote the left side to 64 bits, then truncate the small result.
    int init_read_len = std::min(
            static_cast<uint64_t>(packet_size - sizeof(mtp_data_header)), file_length);

    advise(mfr.fd);

    struct aiocb aio;
    aio.aio_fildes = mfr.fd;
    struct aiocb *aiol[] = {&aio};
    int ret = 0;
    int length, num_read;
    unsigned i = 0;
    struct io_event ioevs[AIO_BUFS_MAX];
    bool error = false;
    bool write = false;

    // Send the header data
    mtp_data_header *header = reinterpret_cast<mtp_data_header*>(mIobuf[0].bufs.data());
    header->length = htole32(given_length);
    header->type = htole16(2); // data packet
    header->command = htole16(mfr.command);
    header->transaction_id = htole32(mfr.transaction_id);

    // Some hosts don't support header/data separation even though MTP allows it
    // Handle by filling first packet with initial file data
    if (TEMP_FAILURE_RETRY(pread(mfr.fd, mIobuf[0].bufs.data() +
                    sizeof(mtp_data_header), init_read_len, offset))
            != init_read_len) return -1;
    if (this->write(mIobuf[0].bufs.data(), sizeof(mtp_data_header) + init_read_len) == -1) return -1;
    file_length -= init_read_len;
    offset += init_read_len;
    ret = init_read_len + sizeof(mtp_data_header);

    // Break down the file into pieces that fit in buffers
    while(file_length > 0 || write) {
        if (file_length > 0) {
            // Queue up a read from disk.
            length = std::min(static_cast<uint64_t>(MAX_FILE_CHUNK_SIZE), file_length);
            aio_prepare(&aio, mIobuf[i].bufs.data(), length, offset);
            aio_read(&aio);
        }

        if (write) {
            if (waitEvents(&mIobuf[(i-1)%NUM_IO_BUFS], mIobuf[(i-1)%NUM_IO_BUFS].actual, ioevs,
                        nullptr, nullptr) != ret) {
                error = true;
            }
            write = false;
        }

        if (file_length > 0) {
            // Wait for the previous read to finish
            aio_suspend(aiol, 1, nullptr);
            num_read = aio_return(&aio);
            if (static_cast<size_t>(num_read) < aio.aio_nbytes) {
                errno = num_read == -1 ? aio_error(&aio) : EIO;
                PLOG(ERROR) << "Mtp error reading from disk";
                return -1;
            }

            file_length -= num_read;
            offset += num_read;

            if (error) {
                return -1;
            }

            // Queue up a write to usb.
            if (iobufSubmit(&mIobuf[i], mBulkIn, num_read, false) == -1) {
                return -1;
            }
            write = true;
            ret = num_read;
        }

        i = (i + 1) % NUM_IO_BUFS;
    }

    if (ret % packet_size == 0) {
        // If the last packet wasn't short, send a final empty packet
        if (this->write(mIobuf[0].bufs.data(), 0) != 0) {
            return -1;
        }
    }
    return 0;
}

int MtpFfsHandle::sendEvent(mtp_event me) {
    unsigned length = me.length;
    if (length > AIO_BUF_LEN) {
        errno = EOVERFLOW;
        return -1;
    }
    struct iocb evIocb;
    struct iocb *evIocbp = &evIocb;
    io_prep(evIocbp, mIntr, me.data, length, 0, false);
    int ret = io_submit(mEventCtx, 1, &evIocbp);
    if (ret < 1) {
        PLOG(ERROR) << "Mtp failed to submit event";
    }
    // We don't wait for sending events to finish to match mtp_dev behavior.
    // Some hosts like AFT don't read events at all and waiting would block
    // the main MediaProvider thread.
    return ret == 1 ? 0 : -1;
}

} // namespace android

