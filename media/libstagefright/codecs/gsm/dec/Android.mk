LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
        SoftGSM.cpp

LOCAL_C_INCLUDES := \
        frameworks/av/media/libstagefright/include \
        frameworks/native/include/media/openmax \
        external/libgsm/inc

LOCAL_SHARED_LIBRARIES := \
        libcrypto \
        liblog \
        libstagefright \
        libstagefright_foundation \
        libstagefright_omx \
        libutils \

LOCAL_STATIC_LIBRARIES := \
        libgsm

LOCAL_MODULE := libstagefright_soft_gsmdec
LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
