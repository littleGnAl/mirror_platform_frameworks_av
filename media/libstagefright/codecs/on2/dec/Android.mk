LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
        SoftVPX.cpp

LOCAL_C_INCLUDES := \
        $(TOP)/external/libvpx/libvpx \
        $(TOP)/external/libvpx/libvpx/vpx_codec \
        $(TOP)/external/libvpx/libvpx/vpx_ports \
        frameworks/av/media/libstagefright/include \
        frameworks/native/include/media/openmax \

LOCAL_STATIC_LIBRARIES := \
        libvpx

LOCAL_SHARED_LIBRARIES := \
        libcrypto \
        liblog \
        libstagefright \
        libstagefright_foundation \
        libstagefright_omx \
        libutils \

LOCAL_MODULE := libstagefright_soft_vpxdec
LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
