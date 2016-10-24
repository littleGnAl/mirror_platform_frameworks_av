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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or         implied.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <unistd.h>

#include <android-base/logging.h>
#include "IUsbHandle.h"

#define USB_MTP_PATH "/dev/mtp_usb"

class UsbMtpHandle : public IUsbHandle {
    private:
        int mfd;
    public:
        UsbMtpHandle();
        ~UsbMtpHandle();
        int read(void *data, int len);
        int write(const void *data, int len);

        int receiveFile(mtp_file_range mfr);
        int sendFile(mtp_file_range mfr);
        int sendEvent(mtp_event me);

        int start();
        int close();

        int configure(bool ptp);
};

UsbMtpHandle::UsbMtpHandle()
    :   mfd(-1) {};

UsbMtpHandle::~UsbMtpHandle() {}

int UsbMtpHandle::read(void *data, int len) {
    return ::read(mfd, data, len);
}

int UsbMtpHandle::write(const void *data, int len) {
    return ::write(mfd, data, len);
}

int UsbMtpHandle::receiveFile(mtp_file_range mfr) {
    return ioctl(mfd, MTP_RECEIVE_FILE, reinterpret_cast<unsigned long>(&mfr));
}

int UsbMtpHandle::sendFile(mtp_file_range mfr) {
    return ioctl(mfd, MTP_SEND_FILE_WITH_HEADER, reinterpret_cast<unsigned long>(&mfr));
}

int UsbMtpHandle::sendEvent(mtp_event me) {
    return ioctl(mfd, MTP_SEND_EVENT, reinterpret_cast<unsigned long>(&me));
}

int UsbMtpHandle::start() {
    mfd = TEMP_FAILURE_RETRY(open(USB_MTP_PATH, O_RDWR));
    if (mfd == -1) return -1;
    return 0;
}

int UsbMtpHandle::close() {
    if (mfd > 0)
        return ::close(mfd);
    return 0;
}

int UsbMtpHandle::configure(bool) {
    // Nothing to do, driver can configure itself
    return 0;
}

IUsbHandle *get_mtp_handle() {
    return new UsbMtpHandle();
}
