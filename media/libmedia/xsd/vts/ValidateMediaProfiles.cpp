/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <string>

#include <android-base/file.h>
#include <android-base/properties.h>
#include "utility/ValidateXml.h"

TEST(CheckConfig, mediaProfilesValidation) {
    RecordProperty("description",
                   "Verify that the media profiles file "
                   "is valid according to the schema");

    // If "media.settings.xml" is set, it will be used as an absolute path.
    std::string mediaSettingsPath = android::base::GetProperty("media.settings.xml", "");
    if (mediaSettingsPath.empty()) {
        // If "media.settings.xml" is not set, we will search through a list of
        // preset directories.
        std::vector<char const*> searchDirs = {
                "/odm/etc",
                "/vendor/etc/",
                "/system/etc"
            };

        // The vendor may provide a vendor variant.
        std::string variant = android::base::GetProperty(
                "ro.vendor.media_profiles_xml_variant", "_V1_0");

        std::string fileName = "media_profiles" + variant + ".xml";
        EXPECT_ONE_VALID_XML_MULTIPLE_LOCATIONS(fileName.c_str(),
                                                searchDirs,
                                                "/data/local/tmp/media_profiles.xsd");
    } else {
        EXPECT_ONE_VALID_XML_MULTIPLE_LOCATIONS(android::base::Basename(mediaSettingsPath).c_str(),
                                                {android::base::Dirname(mediaSettingsPath).c_str()},
                                                "/data/local/tmp/media_profiles.xsd");
    }
}
