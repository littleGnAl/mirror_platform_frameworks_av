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

#include <MtpDataPacket.h>
#include <MtpDevHandle.h>
#include <MtpProperty.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <sys/mman.h>
#include <usbhost/usbhost.h>
#include <utils/String16.h>

std::string path = "/data/local/tmp/test";
using namespace android;

constexpr size_t kMaxLength = 1024;
constexpr size_t kMinSize = 0;
constexpr size_t kMaxSize = 1000;

constexpr uint16_t kFeasibleTypes[] = {
        MTP_TYPE_UNDEFINED, MTP_TYPE_INT8,    MTP_TYPE_UINT8,  MTP_TYPE_INT16,   MTP_TYPE_UINT16,
        MTP_TYPE_INT32,     MTP_TYPE_UINT32,  MTP_TYPE_INT64,  MTP_TYPE_UINT64,  MTP_TYPE_INT128,
        MTP_TYPE_UINT128,   MTP_TYPE_AINT8,   MTP_TYPE_AUINT8, MTP_TYPE_AINT16,  MTP_TYPE_AUINT16,
        MTP_TYPE_AINT32,    MTP_TYPE_AUINT32, MTP_TYPE_AINT64, MTP_TYPE_AUINT64, MTP_TYPE_AINT128,
        MTP_TYPE_AUINT128,  MTP_TYPE_STR,
};

#ifdef MTP_HOST
constexpr UrbPacketDivisionMode kUrbPacketDivisionModes[] = {FIRST_PACKET_ONLY_HEADER,
                                                             FIRST_PACKET_HAS_PAYLOAD};
#endif

class MtpPropertyFuzzer {
  public:
    MtpPropertyFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();
    void fillUsbRequest(struct usb_request* usbRequest, int32_t fd);

  private:
    FuzzedDataProvider mFdp;
};

void MtpPropertyFuzzer::fillUsbRequest(struct usb_request* usbRequest, int32_t fd) {
    usbRequest->dev = usb_device_new(path.c_str(), fd);
    std::vector<uint8_t> buffer =
            mFdp.ConsumeBytes<uint8_t>(mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
    usbRequest->buffer = static_cast<void*>(buffer.data());
    usbRequest->buffer_length = buffer.size();
    usbRequest->actual_length = mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize);
    usbRequest->max_packet_size = mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize);
    usbRequest->private_data = static_cast<void*>(
            (mFdp.ConsumeBytes<uint8_t>(mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize)))
                    .data());
    usbRequest->endpoint = mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize);
    usbRequest->client_data = static_cast<void*>(
            (mFdp.ConsumeBytes<uint8_t>(mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize)))
                    .data());
}

void MtpPropertyFuzzer::process() {
    MtpProperty* mtpProperty;
    if (mFdp.ConsumeBool()) {
        mtpProperty = new MtpProperty();
    } else {
        uint16_t type = mFdp.ConsumeBool() ? mFdp.ConsumeIntegral<uint16_t>()
                                           : mFdp.PickValueInArray<uint16_t>(kFeasibleTypes);
        mtpProperty = new MtpProperty(mFdp.ConsumeIntegral<uint16_t>(), type, mFdp.ConsumeBool(),
                                      mFdp.ConsumeIntegral<uint16_t>());
    }

    while (mFdp.remaining_bytes() > 0) {
        auto invokeMtpPropertyFuzzer = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    MtpDataPacket mtpDataPacket;
                    if (mFdp.ConsumeBool()) {
                        mtpProperty->read(mtpDataPacket);

                    } else {
                        if (mFdp.ConsumeBool()) {
#ifdef MTP_DEVICE
                            android::IMtpHandle* h = new MtpDevHandle();
                            h->start(mFdp.ConsumeBool());
                            std::string text = mFdp.ConsumeRandomLengthString(kMaxLength);
                            char* data = const_cast<char*>(text.c_str());
                            h->read(static_cast<void*>(data), text.length());
                            mtpDataPacket.write(h);
                            h->close();
                            delete h;
#endif

#ifdef MTP_HOST
                            int32_t fd = memfd_create(path.c_str(), MFD_ALLOW_SEALING);
                            if (mFdp.ConsumeBool()) {
                                std::string text = mFdp.ConsumeRandomLengthString(kMaxLength);
                                write(fd, text.c_str(), text.length());
                            }
                            struct usb_request usbRequest;
                            fillUsbRequest(&usbRequest, fd);
                            mtpDataPacket.write(&usbRequest,
                                                mFdp.PickValueInArray<UrbPacketDivisionMode>(
                                                        kUrbPacketDivisionModes),
                                                fd,
                                                mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize));
                            usb_device_close(usbRequest.dev);
#endif
                        }

                        if (mFdp.ConsumeBool()) {
                            mtpProperty->write(mtpDataPacket);
                        } else {
                            mtpProperty->setCurrentValue(mtpDataPacket);
                        }
                    }
                },
                [&]() {
                    char16_t* data = nullptr;
                    std::string str = mFdp.ConsumeRandomLengthString(kMaxLength);
                    android::String16 s(str.c_str());
                    if (mFdp.ConsumeBool()) {
                        data = const_cast<char16_t*>(s.string());
                    }

                    if (mFdp.ConsumeBool()) {
                        mtpProperty->setDefaultValue(reinterpret_cast<uint16_t*>(data));
                    } else if (mFdp.ConsumeBool()) {
                        mtpProperty->setCurrentValue(reinterpret_cast<uint16_t*>(data));
                    } else {
                        mtpProperty->setCurrentValue(str.c_str());
                    }
                },
                [&]() {
                    mtpProperty->setFormRange(mFdp.ConsumeIntegral<int32_t>(),
                                              mFdp.ConsumeIntegral<int32_t>(),
                                              mFdp.ConsumeIntegral<int32_t>());
                },
                [&]() {
                    std::vector<int32_t> init;
                    for (size_t idx = 0; idx < mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize);
                         ++idx) {
                        init.push_back(mFdp.ConsumeIntegral<int32_t>());
                    }
                    mtpProperty->setFormEnum(init.data(), init.size());
                },
        });
        invokeMtpPropertyFuzzer();
    }

    delete (mtpProperty);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpPropertyFuzzer mtpPropertyFuzzer(data, size);
    mtpPropertyFuzzer.process();
    return 0;
}
