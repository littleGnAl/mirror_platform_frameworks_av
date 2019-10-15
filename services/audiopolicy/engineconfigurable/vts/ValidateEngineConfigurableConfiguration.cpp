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

#include <EngineConfig.h>
#include <Serializer.h>
#include <AudioPolicyConfig.h>
#include <ParameterManagerWrapper.h>

#include <gtest/gtest.h>

#include <dlfcn.h>
#include <unistd.h>
#include <string>

static const constexpr char* const kDefaultEngineLibraryNameSuffix = "default";

/**
 * @brief deviceUsesConfigurableEngine checks if the libaudiopolicyengineconfigurable library
 * is loadable to infer the device is using configurabl engine
 * @return true if the configurable engine could be loaded, false otherwise.
 */
static bool deviceUsesConfigurableEngine() {
    std::vector<const char*> locations = {"/odm/etc", "/vendor/etc", "/system/etc"};
    std::string audioPolicyConfigurationFileName{"audio_policy_configuration.xml"};
    std::string foundFile{};

    for (const auto &location : locations) {
        std::string configurationFilePath{
            std::string(location) + "/" + audioPolicyConfigurationFileName};

        if (access(configurationFilePath.c_str(), F_OK) != 0) {
            continue;
        }
        foundFile = configurationFilePath;
        break;
    }
    if (foundFile.empty()) {
        return false;
    }
    android::HwModuleCollection hwModules{};
    android::DeviceVector availableOutputDevices{};
    android::DeviceVector availableInputDevices{};
    android::sp<android::DeviceDescriptor> defaultOutputDevice{};
    android::AudioPolicyConfig config{
        hwModules, availableOutputDevices, availableInputDevices, defaultOutputDevice};

    auto ret = android::deserializeAudioPolicyFile(foundFile.c_str(), &config);
    if (ret != android::NO_ERROR) {
        return false;
    }
    return config.getEngineLibraryNameSuffix() != kDefaultEngineLibraryNameSuffix;
}

TEST(ValidateConfiguration, audioPolicyEngineConfigurable) {
    if (!deviceUsesConfigurableEngine()) {
        GTEST_SKIP() << "Device using legacy engine without parameter-framework, n-op.";
    }
    RecordProperty("description",
                   "Verify that the audio policy engine PFW configuration files "
                   "are valid according to the schemas");

    auto testAudioPolicyEnginePfw = [&](bool validateSchema, const std::string &schemasUri) {
        auto result = android::engineConfig::parse();

        ASSERT_NE(nullptr, result.parsedConfig)
                << "failed to parse audio policy engine configuration";

        ASSERT_EQ(result.nbSkippedElement, 0) << "skipped %zu elements " << result.nbSkippedElement;

        std::unique_ptr<android::audio_policy::ParameterManagerWrapper> policyParameterMgr(
                    new android::audio_policy::ParameterManagerWrapper(validateSchema, schemasUri));
        ASSERT_NE(nullptr, policyParameterMgr) << "failed to create Audio Policy Engine PFW";

        // Load the criterion types and criteria
        for (auto& criterion : result.parsedConfig->criteria) {
            android::engineConfig::CriterionType criterionType;
            for (auto &configCriterionType : result.parsedConfig->criterionTypes) {
                if (configCriterionType.name == criterion.typeName) {
                    criterionType = configCriterionType;
                    break;
                }
            }
            ASSERT_FALSE(criterionType.name.empty())
                    << "Invalid criterion type for " << criterion.name.c_str();
            policyParameterMgr->addCriterion(criterion.name, criterionType.isInclusive,
                                             criterionType.valuePairs,
                                             criterion.defaultLiteralValue);
        }
        ASSERT_EQ(0, result.nbSkippedElement) << "failed to parse Audio Policy Engine PFW criteria";

        // If the PFW cannot validate, it will not start
        std::string error;
        auto status = policyParameterMgr->start(error);
        ASSERT_EQ(status, android::NO_ERROR)
                << "failed to " << (validateSchema? "validate" : "start")
                <<" Audio Policy Engine PFW: " << error;

        ASSERT_TRUE(policyParameterMgr->isStarted());
    };

    // First round for sanity to ensure we can launch the Audio Policy Engine PFW without
    // schema validation successfully, otherwise it is not forth going on running validation...
    testAudioPolicyEnginePfw(false, {});

    // If second round fails, it means parameter-framework cannot validate schema
    testAudioPolicyEnginePfw(true, {XSD_DIR});
}

