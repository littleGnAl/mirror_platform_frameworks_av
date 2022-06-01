/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <MtpStringBuffer.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <linux/usbdevice_fs.h>
#include <sys/mman.h>
#include <usbhost/usbhost.h>
#include <MtpTypes.h>

using namespace android;
std::string path = "/data/local/tmp/test";
constexpr UrbPacketDivisionMode kUrbPacketDivisionModes[] = {FIRST_PACKET_ONLY_HEADER,
                                                             FIRST_PACKET_HAS_PAYLOAD};

constexpr size_t kMinSize = 0;
constexpr size_t kMaxSize = 1000;
constexpr size_t kMaxLength = 1000;

class MtpPacketFuzzerUtils {
  protected:
    struct usb_request usbRequest;
    struct usbdevfs_urb* usbDevFsUrb;

    void fillFd(int32_t& fd, FuzzedDataProvider* fdp) {
        if (fdp->ConsumeBool()) {
            std::string text = fdp->ConsumeRandomLengthString(kMaxLength);
            write(fd, text.c_str(), text.length());
        }
    };

    void fillUsbDevFsUrb(FuzzedDataProvider* fdp) {
        usbDevFsUrb->type = fdp->ConsumeIntegral<unsigned char>();
        usbDevFsUrb->endpoint = fdp->ConsumeIntegral<unsigned char>();
        usbDevFsUrb->flags = fdp->ConsumeIntegral<uint32_t>();
        std::vector<uint8_t> buffer =
                fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
        usbDevFsUrb->buffer = static_cast<void*>(buffer.data());
        usbDevFsUrb->buffer_length = buffer.size();
        usbDevFsUrb->actual_length = fdp->ConsumeIntegral<uint32_t>();
        usbDevFsUrb->start_frame = fdp->ConsumeIntegral<uint32_t>();
        usbDevFsUrb->number_of_packets = fdp->ConsumeIntegral<uint32_t>();
        usbDevFsUrb->stream_id = fdp->ConsumeIntegral<uint32_t>();
        usbDevFsUrb->error_count = fdp->ConsumeIntegral<size_t>();
        usbDevFsUrb->signr = fdp->ConsumeIntegral<uint32_t>();
        std::vector<uint8_t> userBuffer = (fdp->ConsumeBytes<uint8_t>(
                fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize)));
        usbDevFsUrb->usercontext = static_cast<void*>(userBuffer.data());
        usbDevFsUrb->iso_frame_desc[0].length = fdp->ConsumeIntegral<uint32_t>();
        usbDevFsUrb->iso_frame_desc[0].actual_length = fdp->ConsumeIntegral<uint32_t>();
    };

    void fillUsbRequest(int32_t& fd, FuzzedDataProvider* fdp) {
        fillUsbDevFsUrb(fdp);
        fillFd(fd, fdp);
        std::vector<uint8_t> buffer =
                fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
        usbRequest.buffer = static_cast<void*>(buffer.data());
        usbRequest.buffer_length = buffer.size();
        usbRequest.actual_length = fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
        usbRequest.max_packet_size = fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
        usbRequest.private_data = static_cast<void*>(usbDevFsUrb);
        usbRequest.endpoint = fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize);
        std::vector<uint8_t> clientBuffer = (fdp->ConsumeBytes<uint8_t>(
                fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize)));
        usbRequest.client_data = static_cast<void*>(clientBuffer.data());
    };

    template <typename Object>
    void writeHandle(Object obj, FuzzedDataProvider* fdp) {
        MtpDevHandle handle;
        std::vector<uint8_t> initData =
                fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
        handle.write(initData.data(), initData.size());
        obj->write(&handle);
    };
};
