LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    trusty_app_test.c

LOCAL_CFLAGS := -Wall -Wno-unused-parameter

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    libtrusty \
    liblog \

LOCAL_MODULE := trusty_test 

include $(BUILD_EXECUTABLE)
