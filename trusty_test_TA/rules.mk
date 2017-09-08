LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_INCLUDES += 

MODULE_SRCS += \
        $(LOCAL_DIR)/manifest.c \
        $(LOCAL_DIR)/trusty_test_ta.c

MODULE_DEPS += \
        app/trusty \
        lib/libc-trusty \
        lib/storage

include make/module.mk

