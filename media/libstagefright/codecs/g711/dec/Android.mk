LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
        SoftG711.cpp

LOCAL_C_INCLUDES := \
        frameworks/av/media/libstagefright/include \
        frameworks/native/include/media/openmax

LOCAL_SHARED_LIBRARIES := \
        libcrypto \
        liblog \
        libstagefright \
        libstagefright_foundation \
        libstagefright_omx \
        libutils \

LOCAL_MODULE := libstagefright_soft_g711dec
LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)
