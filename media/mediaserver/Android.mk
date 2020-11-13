LOCAL_PATH:= $(call my-dir)


include $(CLEAR_VARS)


LOCAL_SRC_FILES := register.cpp
LOCAL_MODULE := libregistermsext
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Werror -Wall
include $(BUILD_STATIC_LIBRARY)



include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    main_mediaserver.cpp

LOCAL_SHARED_LIBRARIES := \
    libandroidicu \
    libbinder \
    libhidlbase \
    liblog \
    libmediaplayerservice \
    libresourcemanagerservice \
    libutils \
    android.hardware.media.omx@1.0 \


LOCAL_STATIC_LIBRARIES := \
        libregistermsext_aml


LOCAL_C_INCLUDES := \
    frameworks/av/media/libmediaplayerservice \
    frameworks/av/services/mediaresourcemanager \
    external/icu/libandroidicu/include \
    frameworks/av/media/libaudioclient/include\

LOCAL_MODULE:= mediaserver
LOCAL_32_BIT_ONLY := true

LOCAL_INIT_RC := mediaserver.rc

LOCAL_CFLAGS := -Werror -Wall

LOCAL_VINTF_FRAGMENTS := manifest_media_c2_software.xml

include $(BUILD_EXECUTABLE)