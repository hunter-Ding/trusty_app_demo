/*
 * Copyright (C) 2017 Freedom Software
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <trusty/tipc.h>
#include <cutils/log.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define TEST_PORT "com.sprd.trusty.trusty_test"
#define DEFAULT_BUF_SIZE 256 

#define LOG_TAG "TRUSTY_TEST"

enum test_command {
    TA_REQ_SHIFT = 1,
    TA_RESP_BIT  = 1,

    TEST_FIRST = (0 << TA_REQ_SHIFT),
    WRITE_TO_STORAGE_SELF = 23,
    READ_FROM_STORAGE_SELF = 24,
    WRITE_TO_STORAGE_OTHER = 25,
    READ_FROM_STORAGE_OTHER = 26,
    REMOVE_DATAS = 27
};

typedef enum dest {
    SELF = 0,
    OTHER
} Dest;

struct test_message {
    uint32_t cmd;
    uint8_t payload[0];
};

static int test_handle = 0;

int trusty_test_connect()
{
    ALOGD("trusty_test_connect() enter...");
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, TEST_PORT);
    if (rc < 0) {
        ALOGE("tipc_connect() error: %s(%d)!\n", strerror(errno), errno);
        return rc;
    }

    test_handle = rc;

    ALOGD("trusty_test_connect() exit...");
    return 0;
}

int trusty_test_call(uint32_t cmd, void *in, uint32_t in_size, uint8_t **out,
        uint32_t *out_size)
{
    ALOGD("trusty_test_call() enter...");
    long rc;

    if (test_handle == 0) {
        ALOGE("trusty_test TA not connected.\n");
        return -EINVAL;
    }

    // here, we use a buffer pointed by msg for BOTH sending and receiving
    // so we must ensure enough size for the two; 2K maybe OK
    // size_t msg_size = in_size + sizeof(struct test_message);
    size_t msg_size = DEFAULT_BUF_SIZE;
    ALOGD("trusty_test_call() cmd=%d, in_size=%d, msg_size=%d, out_size=%d\n", cmd, in_size, msg_size, *out_size);
    struct test_message *msg = malloc(msg_size);
    if (NULL == msg) {
        ALOGE("malloc for test_message failed!\n");
    }
    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    rc = write(test_handle, msg, in_size+sizeof(struct test_message));
    if (rc < 0) {
        ALOGE("failed to send cmd (%d) to %s: %s\n", cmd,
                TEST_PORT, strerror(errno));
        return -errno;
    }
    ALOGD("write data to tee ok! rc = %ld\n", rc);
//    free(msg);

    rc = read(test_handle, msg, msg_size);
    if (rc < 0) {
        ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n",
                cmd, TEST_PORT, strerror(errno));
        return -errno;
    }
    ALOGD("read data from tee ok! rc=%ld cmd=%d msg->cmd=%d\n", rc, cmd, msg->cmd);

    if ((size_t) rc < sizeof(struct test_message)) {
        ALOGE("invalid response size (%ld)\n", rc);
        return -EINVAL;
    }

    if ((cmd | TA_RESP_BIT) != msg->cmd) {
        ALOGE("invalid command (%d)\n", msg->cmd);
        return -EINVAL;
    }

    // return struct: | cmd---- | result ---- | data ---- |
    // rc contains the sizeof cmd field in test_message
    *out_size = (size_t) rc;
    *out = (uint8_t *) msg;
    ALOGD("*out=0x%08x, msg=%p, rc=%ld, out_size=%d\n", *(struct test_message **)out,
            msg, rc, *out_size);
    //free(msg);

    ALOGD("trusty_test_call() exit...");
    return 0;
}

void trusty_test_disconnect()
{
    ALOGD("trusty_test_disconnect() enter...");

    if (test_handle != 0) {
        tipc_close(test_handle);
    }

    ALOGD("trusty_test_disconnect() exit...");
}

int call_tee_write(Dest dest, void *data, int len)
{
    uint8_t in[DEFAULT_BUF_SIZE];
    uint8_t *out;
    uint32_t out_size;
    int result;
    int offset = 0;
    enum test_command cmd;

    *(uint32_t *) (in+offset) = len;
    offset += sizeof(uint32_t);
    memcpy(in+offset, data, len);
    offset += len;
    switch (dest) {
        case SELF:
            cmd = WRITE_TO_STORAGE_SELF;
            break;
        case OTHER:
            cmd = WRITE_TO_STORAGE_OTHER;
            break;
        default:
            return -1;
    }
    if (trusty_test_call(cmd, in, offset, &out, &out_size) < 0) {
        ALOGE("trusty_test_call error!\n");
        return -1;
    }

    // return struct: | cmd(4B) ---- | result(4B) ---- | data(xB) ---- |
    result = *(int *) (out+8);
    ALOGD("call_tee_write getWRITE Result=%d, out_size=%d\n", result, out_size);

    free(out);
    return result;
}

int call_tee_read(Dest dest, void *data, int len)
{
    uint8_t in[DEFAULT_BUF_SIZE];
    uint8_t *out;
    uint32_t out_size;
    int result;
    int offset = 0;
    enum test_command cmd;

    // length to read, give a reasonable size
    *(uint32_t*) in = len;
    offset += sizeof(uint32_t);
    switch (dest) {
        case SELF:
            cmd = READ_FROM_STORAGE_SELF;
            break;
        case OTHER:
            cmd = READ_FROM_STORAGE_OTHER;
            break;
        default:
            return -1;
    }
    if (trusty_test_call(cmd, in, offset, &out, &out_size) < 0) {
        ALOGE("trusty_test_call error!\n");
        return -1;
    }

    // return struct: | cmd(4B) ---- | result(4B) ---- | data(xB) ---- |
    result = *(int *) (out+4);
    memcpy(data, out+8, result);
    ALOGD("call_tee_read getREAD Result=%d, out_size=%d\n", result, out_size);

    free(out);
    return result;
}

int clean_data_storage()
{
    uint8_t in[DEFAULT_BUF_SIZE];
    uint8_t *out;
    uint32_t out_size;
    int result;
    int offset = 0;

    ALOGD("clean_data_storage() enter...\n");
    // dummy
    *(uint32_t*) in = sizeof(uint32_t);
    offset += sizeof(uint32_t);
    *(uint32_t*) in = 99;
    offset += sizeof(uint32_t);
    if (trusty_test_call(REMOVE_DATAS, in, offset, &out, &out_size) < 0) {
        ALOGE("trusty_test_call error!\n");
        return -1;
    }

    result = *(int *) (out+8);
    ALOGD("clean_data_storage getResult = %d, out_size = %d\n", result, out_size);
    free(out);
    return result;
}

int main(int argc, char *argv[])
{
    char out_buf[DEFAULT_BUF_SIZE];
    int ret = -1;

    if (trusty_test_connect() < 0) {
        ALOGE("open session for trusty FAILED!\n");
        return -1;
    }

    // clean data saved in tee storage
    if (argc > 1 && !strcmp(argv[1], "clean")) {
        if((ret = clean_data_storage()) < 0)
            ALOGE("clean_key_storage FAILED\n");
        else
            ALOGD("clean_key_storage success\n");
        goto end;
    }

    // write and read data belonging self TA
    char data_self[] = "Hi, this is a self string!";
    ret = call_tee_write(SELF, data_self, strlen(data_self));
    if (ret < 0) {
        ALOGE("save data to self-TA failed!\n");
        ret = -1;
        goto end;
    }
    ALOGD("save %d bytes data to self-TA OK.\n", ret);

    ret = call_tee_read(SELF, out_buf, DEFAULT_BUF_SIZE-64);
    if (ret < 0) {
        ALOGE("read data from self-TA failed!\n");
        ret = -1;
        goto end;
    }
    out_buf[ret] = '\0';
    ALOGD("read data from self-TA OK: %s\n", out_buf);


    // write and read data belonging to another TA 
    char data_another[] = "Hi, this is a another string!";
    ret = call_tee_write(OTHER, data_another, strlen(data_another));
    if (ret < 0) {
        ALOGE("save data to another-TA failed!\n");
        ret = -1;
        goto end;
    }
    ALOGD("save %d bytes data to another-TA OK.\n", ret);

    ret = call_tee_read(OTHER, out_buf, DEFAULT_BUF_SIZE-64);
    if (ret < 0) {
        ALOGE("read data from another-TA failed!\n");
        ret = -1;
        goto end;
    }
    out_buf[ret] = '\0';
    ALOGD("read data from another-TA OK: %s\n", out_buf);

end:
    trusty_test_disconnect();
    return ret;
}
