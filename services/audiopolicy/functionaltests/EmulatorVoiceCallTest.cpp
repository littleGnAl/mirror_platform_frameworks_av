/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <gtest/gtest.h>

#include "AudioPolicyTestBase.hpp"

using namespace android;

using VoiceCallBridgeTestParams =
    std::tuple<const audio_attributes_t /*renderingAttributes*/,
        const audio_port /*txSourcePort*/,
        const audio_source_t /* sourceUseCase*/,
        const audio_port /*txSinkPort*/,
        const audio_stream_type_t /*sinkStream*/,
        bool /*txUseSwBridging, if false use HW bridging*/,
        const audio_attributes_t /*renderingAttributes*/,
        const audio_port /*rxSourcePort*/,
        const audio_source_t /* sourceUseCase*/,
        const audio_port /*rxSinkPort*/,
        const audio_stream_type_t /*rxSinkStream*/,
        bool /*rxUseSwBridging, if false use HW bridging*/>;

using VoiceCallBridgingTest = AudioPolicyTestBase<VoiceCallBridgeTestParams>;

TEST_P(VoiceCallBridgingTest, UsingSetPhoneStateAPI)
{
    /*const audio_attributes_t txAttributes =*/(void) std::get<0>(GetParam());
    const audio_port expectedTxSourcePort = std::get<1>(GetParam());
    (void) std::get<2>(GetParam());
    const audio_port expectedTxSinkPort = std::get<3>(GetParam());
    const audio_stream_type_t txStreamType = std::get<4>(GetParam());
    const bool txUseSwBridging = std::get<5>(GetParam());

    /*const audio_attributes_t rxAttributes =*/(void) std::get<6>(GetParam());
    const audio_port expectedRxSourcePort = std::get<7>(GetParam());
    (void) std::get<8>(GetParam());
    const audio_port expectedRxSinkPort = std::get<9>(GetParam());
    const audio_stream_type_t rxStreamType = std::get<10>(GetParam());
    const bool rxUseSwBridging = std::get<11>(GetParam());

    // As this test may work on dynamically inserted devices, cleanup first (disconnect them)
    disconnectPort(expectedTxSinkPort);
    disconnectPort(expectedRxSourcePort);

    audio_port txSourcePort {};
    audio_port txSinkPort {};
    audio_port rxSourcePort {};
    audio_port rxSinkPort {};

    // Register the device & ensure ports are available
    ASSERT_TRUE(connectPort(expectedTxSinkPort, txSinkPort))
            << "Could not connect port: " << dumpPort(expectedTxSinkPort);
    ASSERT_TRUE(connectPort(expectedTxSourcePort, txSourcePort))
              << "Could not connect port: " << dumpPort(expectedTxSourcePort);
    ASSERT_TRUE(connectPort(expectedRxSinkPort, rxSinkPort))
              << "Could not connect port: " << dumpPort(expectedRxSinkPort);
    ASSERT_TRUE(connectPort(expectedRxSourcePort, rxSourcePort))
            << "Could not connect port: " << dumpPort(expectedRxSourcePort);

    changeMode(AUDIO_MODE_IN_CALL);

    checkEstablishedPatch(txSourcePort, txSinkPort, txUseSwBridging, txStreamType);
    checkEstablishedPatch(rxSourcePort, rxSinkPort, rxUseSwBridging, rxStreamType);

    changeMode(AUDIO_MODE_NORMAL);

    // Ensure Bridging is disabled
    checkPatchRemoved(txSourcePort, txSinkPort);
    checkPatchRemoved(rxSourcePort, rxSinkPort);
}

static const std::vector<VoiceCallBridgeTestParams> gVoiceCallBridgeTestParams = {
    // Dynamic SCO device without name and without address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO},
      AUDIO_STREAM_VOICE_CALL, // Patch without audio source uses STREAM_PATCH
      USE_HW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BUILTIN_MIC, .ext.device.address = "bottom"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out_hw"},
      AUDIO_STREAM_PATCH,
      USE_HW_BRIDGING,
    },
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO},
      AUDIO_STREAM_VOICE_CALL, // Patch without audio source uses STREAM_PATCH
      USE_HW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out_hw"},
      AUDIO_STREAM_PATCH,
      USE_HW_BRIDGING,
    },
    // Dynamic SCO device with name and without address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco out",
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO},
      AUDIO_STREAM_VOICE_CALL,
      USE_HW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco in",
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out_hw",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out_hw"},
      AUDIO_STREAM_PATCH,
      USE_HW_BRIDGING,
    },
    // Dynamic SCO device with name and address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco out with address",
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "my_dynamic_sco_out"},
      AUDIO_STREAM_VOICE_CALL,
      USE_HW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco in with address",
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "my_dynamic_sco_in"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out_hw",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out_hw"},
      AUDIO_STREAM_PATCH,
      USE_HW_BRIDGING,
    },
    // Dynamic SCO device without name but with address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "my_dynamic_sco_out_noname"},
      AUDIO_STREAM_VOICE_CALL,
      USE_HW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "my_dynamic_sco_in_noname"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out_hw",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out_hw"},
      AUDIO_STREAM_PATCH,
      USE_HW_BRIDGING,
    },
    // Non-dynamic SCO device with name and address as per Settings XML
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my non dynamic sco out_with address",
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "sco_out_address"},
      AUDIO_STREAM_VOICE_CALL,
      USE_HW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my non dynamic sco out_with address",
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "sco_in_address"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out_hw",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out_hw"},
      AUDIO_STREAM_PATCH,
      USE_HW_BRIDGING,
    },
    // Non-dynamic SCO device without name but with address  as per Settings XML
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "sco_out_address"},
      AUDIO_STREAM_VOICE_CALL,
      USE_HW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "sco_in_address"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out_hw",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out_hw"},
      AUDIO_STREAM_PATCH,
      USE_HW_BRIDGING,
    },
    // SW BRIDGE NOW
    // Dynamic SCO device without name and without address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO},
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BUILTIN_MIC, .ext.device.address = "bottom"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      AUDIO_STREAM_PATCH,
      USE_SW_BRIDGING,
    },
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO},
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET },
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      AUDIO_STREAM_PATCH,
      USE_SW_BRIDGING,
    },
    // Dynamic SCO device with name and without address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco out",
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO},
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco in",
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET },
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      AUDIO_STREAM_PATCH,
      USE_SW_BRIDGING,
    },
    // Dynamic SCO device with name and address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco out with address",
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "my_dynamic_sco_out" },
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my dynamic sco in with address",
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "my_dynamic_sco_in"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      AUDIO_STREAM_PATCH,
      USE_SW_BRIDGING,
    },
    // Dynamic SCO device without name but with address
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "my_dynamic_sco_out_noname" },
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "my_dynamic_sco_in_noname"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      AUDIO_STREAM_PATCH,
      USE_SW_BRIDGING,
    },
    // Non-dynamic SCO device with name and address as per Settings XML
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my non dynamic sco out with address",
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "sco_out_address"},
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE, .name = "my non dynamic sco in with address",
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "sco_in_address"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      AUDIO_STREAM_PATCH,
      USE_SW_BRIDGING,
    },
    // Non-dynamic SCO device without name but with address  as per Settings XML
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BLUETOOTH_SCO, .ext.device.address = "sco_out_address"},
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING,
      attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, .ext.device.address = "sco_in_address"},
      AUDIO_SOURCE_VOICE_UPLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE, .name = "hfp_client_out",
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      AUDIO_STREAM_PATCH,
      USE_SW_BRIDGING,
    },
};

INSTANTIATE_TEST_CASE_P(
        VoiceCallTest,
        VoiceCallBridgingTest,
        ::testing::ValuesIn(gVoiceCallBridgeTestParams)
        );
