LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
  frameworks/av/services/audiopolicy \
  frameworks/av/services/audiopolicy/common/include \
  frameworks/av/services/audiopolicy/engine/interface \
  $(call include-path-for, audio-utils) \

LOCAL_SHARED_LIBRARIES := \
  libaudiopolicymanagerdefault \
  libbase \
  liblog \
  libmedia_helper \
  libutils \

LOCAL_STATIC_LIBRARIES := \
  libaudiopolicycomponents \

LOCAL_SRC_FILES := \
  audiopolicymanager_tests.cpp \

LOCAL_MODULE := audiopolicy_tests

LOCAL_MODULE_TAGS := tests

LOCAL_CFLAGS := -Werror -Wall

LOCAL_MULTILIB := $(AUDIOSERVER_MULTILIB)

include $(BUILD_NATIVE_TEST)

# system/audio.h utilities test

include $(CLEAR_VARS)

LOCAL_SHARED_LIBRARIES := \
  libbase \
  liblog \
  libmedia_helper \
  libutils

LOCAL_HEADER_LIBRARIES := \
  libmedia_headers

LOCAL_SRC_FILES := \
  systemaudio_tests.cpp \

LOCAL_MODULE := systemaudio_tests

LOCAL_MODULE_TAGS := tests

LOCAL_CFLAGS := -Werror -Wall

LOCAL_MULTILIB := $(AUDIOSERVER_MULTILIB)

include $(BUILD_NATIVE_TEST)
