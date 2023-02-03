/*
 * Copyright (C) 2023 The Android Open Source Project
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
#pragma once

#include <IMtpHandle.h>
#include <utils/Log.h>

#include <MtpMockHandle.h>

using namespace android;

class MtpFuzzerUtils {
  protected:
    void addPackets(MtpMockHandle* handle, const uint8_t* data, size_t size) {
        size_t off = 0;
        for (size_t i = 0; i < size; ++i) {
            // A longer delimiter could be used, but this worked in practice
            if (data[i] == '@') {
                size_t pktsz = i - off;
                if (pktsz > 0) {
                    packet_t pkt = packet_t((unsigned char*)data + off, (unsigned char*)data + i);
                    // insert into packet buffer
                    handle->add_packet(pkt);
                    off = i;
                }
            }
        }
    }
};
