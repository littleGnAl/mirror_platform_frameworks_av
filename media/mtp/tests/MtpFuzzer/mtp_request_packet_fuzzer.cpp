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

#include <MtpDevHandle.h>
#include <MtpPacketFuzzerUtils.h>
#include <MtpRequestPacket.h>
#include <fuzzer/FuzzedDataProvider.h>

using namespace android;

class MtpRequestPacketFuzzer : MtpPacketFuzzerUtils {
  public:
    MtpRequestPacketFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        usbDevFsUrb = (struct usbdevfs_urb*)malloc(sizeof(struct usbdevfs_urb) +
                                                   sizeof(struct usbdevfs_iso_packet_desc));
    };
    ~MtpRequestPacketFuzzer() { free(usbDevFsUrb); };
    void process();

  private:
    FuzzedDataProvider mFdp;
};

void MtpRequestPacketFuzzer::process() {
    MtpRequestPacket mtpRequestPacket;
    while (mFdp.remaining_bytes() > 0) {
        auto mtpRequestAPI = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    mtpRequestPacket.allocate(mFdp.ConsumeIntegralInRange(kMinSize, kMaxSize));
                },
                [&]() { mtpRequestPacket.reset(); },
                [&]() {
                    MtpDevHandle handle;
                    std::vector<uint8_t> data = mFdp.ConsumeBytes<uint8_t>(
                            mFdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
                    handle.write(data.data(), data.size());
                    mtpRequestPacket.read(&handle);
                },
                [&]() {
                    int32_t fd = memfd_create(path.c_str(), MFD_ALLOW_SEALING);
                    fillUsbRequest(fd, &mFdp);
                    usbRequest.dev = usb_device_new(path.c_str(), fd);
                    mtpRequestPacket.write(&usbRequest);
                    usb_device_close(usbRequest.dev);
                },
        });
        mtpRequestAPI();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    MtpRequestPacketFuzzer mtpRequestPacketFuzzer(data, size);
    mtpRequestPacketFuzzer.process();
    return 0;
}
