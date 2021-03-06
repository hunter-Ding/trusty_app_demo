#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <trusty_std.h>
#include <trusty_ipc.h>
#include <lib/storage/storage.h>
#include <errno.h>
#include "test_log.h"
#include "trusty_test.h"

#define TEST_PORT "com.sprd.trusty.trusty_test"
//#define KEYMASTER_PORT "com.android.trusty.keymaster"
#define KEYMASTER_SECURE_PORT "com.android.trusty.keymaster.secure"
#define MAX_BUF_SIZE 4096
#define DEFAULT_BUF_SIZE 1024 

#define KEY_PUB_DCP_ID "key_pub_dcp"
#define LC128_ID "lc128"
#define SRM_ID "hdcp_srm_msg"
#define KM_ID "km_store"

static int open_km_session(void);
static int call_km_command(uint32_t cmd, void *in, uint32_t in_size, uint8_t **out,
        uint32_t *out_size);
static void close_km_session(void);

static long test_ipc_init(void) {
    int rc;
    LOGI("test_ipc_init()...\n");

    /* Initialize secure service , other TA will use this */
    rc = port_create(TEST_PORT, 1, MAX_BUF_SIZE,
            IPC_PORT_ALLOW_NS_CONNECT);
    if (rc < 0) {
        LOGE("Failed (%d) to create port %s\n", rc, TEST_PORT);
    }
    return rc;
}

static long send_response(handle_t chan,
        uint32_t cmd, uint8_t *out_buf, uint32_t out_buf_size) {
    test_message test_msg = { cmd | TEST_RESP_BIT, {} };
    iovec_t iov[2] = {
        { &test_msg, sizeof(test_msg) },
        { out_buf, out_buf_size },
    };
    ipc_msg_t msg = { 2, iov, 0, NULL };

    /* send message back to the caller */
    long rc = send_msg(chan, &msg);

    // fatal error
    if (rc < 0) {
        LOGE("failed (%ld) to send_msg for chan (%d)\n", rc, chan);
        return rc;
    }

    LOGD("send_response()... send %d length message success.\n", out_buf_size);
    return 0;
}

static int handle_request(uint32_t cmd, uint8_t *in_buf, uint32_t in_buf_size,
        uint8_t *out_buf, uint32_t *out_buf_size) {
    switch (cmd) {
    case WRITE_TO_STORAGE_SELF:
    case READ_FROM_STORAGE_SELF:
        LOGD("key_opreate for self-TA\n");
        trusty_opreate_self(cmd, in_buf, in_buf_size, out_buf, out_buf_size);
    	return 0;
    case WRITE_TO_STORAGE_OTHER:
    case READ_FROM_STORAGE_OTHER:
        LOGD("key_opreate for another-TA\n");
        trusty_opreate_other(cmd, in_buf, in_buf_size, out_buf, out_buf_size);
        return 0;
    case REMOVE_DATA:
        LOGD("key_opreate remove data\n");
        trusty_remove_data(cmd, in_buf, in_buf_size, out_buf, out_buf_size);
    	return 0;
    default:
    	return -1;
    }
}

static long handle_msg(handle_t chan) {
    /* get message info */
    ipc_msg_info_t msg_info;
    uint8_t *msg_buf, *out_buf;
    uint32_t out_buf_size = 0;
    
    long rc = get_msg(chan, &msg_info);
    /* no new messages */
    if (rc == ERR_NO_MSG) {
    	LOGI("handle_msg().. rc == ERR_NO_MSG\n");
        return 0;
    }

    // fatal error
    if (rc != NO_ERROR) {
        LOGE("failed (%ld) to get_msg for chan (%d), closing connection\n", rc, chan);
        return rc;
    }

    //if (0 < msg_info.len) {
        LOGI("get meta msg done, msg_info.len = %d\n", msg_info.len);
        msg_buf = (uint8_t *) malloc(msg_info.len);
    //}
    memset(msg_buf, 0, msg_info.len);

    /* read msg content */
    iovec_t iov = { msg_buf, msg_info.len };
    ipc_msg_t msg = { 1, &iov, 0, NULL } ;

    rc = read_msg(chan, msg_info.id, 0, &msg);
    if (rc < 0) {
        LOGE("failed to read msg (%ld) for chan (%d)\n", rc, chan);
        return rc;
    }

    if (((size_t)rc) < sizeof(test_message)) {
        LOGE("invalid message of size (%zu) for chan (%d)\n", (size_t) rc, chan);
        return -2;
    }

    /* get request command */
    test_message *test_msg = (test_message *)(msg_buf);
    // malloc for out buf
    out_buf = (uint8_t *) malloc(DEFAULT_BUF_SIZE);
    if (NULL == out_buf) {
        LOGE("test ipc, malloc for out_buf error!\n");
    }

    rc = handle_request(test_msg->cmd, test_msg->payload,
            msg_info.len - sizeof(test_message), out_buf, &out_buf_size);
    if (rc < 0) {
        LOGE("unable (%ld) to handle request\n", rc);
        return -1;
    }

    rc = send_response(chan, test_msg->cmd, out_buf, out_buf_size);
    if (rc < 0) {
        LOGE("unable (%ld) to send response\n", rc);
        return rc;
    }

    /* retire message */
    rc = put_msg(chan, msg_info.id);
    if (rc < 0) {
    	LOGE("unable (%ld) to put_msg for chan(%d)\n", rc, chan);
    }
    free(msg_buf);
    free(out_buf);
    return rc;
}

static void test_handle_port(uevent_t *ev) {
    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_HUP) ||
        (ev->event & IPC_HANDLE_POLL_MSG) ||
        (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        /* should never happen with port handles */
        LOGE("error event (0x%x) for port (%d)\n",
               ev->event, ev->handle);
        abort();
    }

    uuid_t peer_uuid;
    if (ev->event & IPC_HANDLE_POLL_READY) {
        /* incoming connection: accept it */
        int rc = accept(ev->handle, &peer_uuid);
        if (rc < 0) {
            LOGE("failed (%d) to accept on port %d\n",
                    rc, ev->handle);
            return;
        }
    }
}

static void test_handle_channel(uevent_t *ev) {
    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_READY)) {
        /* close it as it is in an error state */
        LOGE("error event (0x%x) for chan (%d)\n",
               ev->event, ev->handle);
        abort();
    }

    handle_t chan = ev->handle;
    if (ev->event & IPC_HANDLE_POLL_MSG) {
        long rc = handle_msg(chan);
        if (rc != NO_ERROR) {
            /* report an error and close channel */
            LOGE("failed (%ld) to handle event on channel %d\n", rc, ev->handle);
            close(chan);
        }
    }

    if (ev->event & IPC_HANDLE_POLL_HUP) {
        /* closed by peer. */
        close(chan);
        return;
    }
}

int main(void) {
    long rc;
    uevent_t event;

    LOGI("trusty_test Initializing\n");

    rc = test_ipc_init();
    if (rc < 0) {
        LOGE("failed (%ld) to initialize test ta", rc);
        return rc;
    }

    handle_t port = (handle_t) rc;

    /* enter main event loop */
    while (true) {
        event.handle = INVALID_IPC_HANDLE;
        event.event  = 0;
        event.cookie = NULL;

        rc = wait_any(&event, -1);
        if (rc < 0) {
            LOGE("wait_any failed (%ld)\n", rc);
            break;
        }

        if (rc == NO_ERROR) { /* got an event */
            if (event.handle == port) {
                test_handle_port(&event);
            } else {
                test_handle_channel(&event);
            }
        }
    }

    return 0;
}


int add_param(uint8_t *buf, int offset, void *arg, size_t len)
{
    memcpy(buf+offset, &len, sizeof(size_t));
    offset += sizeof(size_t);
    memcpy(buf+offset, arg, len);
    return 0;
}

int read_from_storage(void *data, int length, int type)
{
    storage_session_t session;
    file_handle_t handle;
    const char *filename;
    int ret;
    LOGD("read_from_storage ....\n");

    /* get object id and size according to type */
    switch (type) {
        case TYPE_KM:
        	LOGD("read KM file, Invalid operation in key_writer exe!\n");
            return -1;

        case TYPE_KPUB_DCP:
        	filename = KEY_PUB_DCP_ID;
        	break;

        case TYPE_LC128:
        	LOGD("read LC128 file, Invalid operation in key_writer exe!\n");
        	return -1;

        case TYPE_SRM:
        	filename = SRM_ID;
        	break;

        default:
            return -1;
    }

    ret = storage_open_session(&session, STORAGE_CLIENT_TD_PORT);
    if (ret < 0) {
        LOGE("failed (%d) to open storage session.\n", ret);
        return -1;
    }
    ret = storage_open_file(session, &handle, filename,
    		STORAGE_FILE_OPEN_CREATE, STORAGE_OP_COMPLETE);
    if (ret < 0) {
        LOGD("open file for type:%d failed!\n", type);
        storage_close_session(session);
        return -1;
    }
    ret = storage_read(handle, 0, data, length);
    if (ret < 0) {
        LOGD("read file for type:%d failed!\n", type);
        storage_close_file(handle);
        storage_close_session(session);
        return -1;
    }

    // close file and session
    storage_close_file(handle);
    storage_close_session(session);
    return ret;
}

int write_to_storage(void *data, int length, int type)
{
    storage_session_t session;
    file_handle_t handle;
    const char *filename;
    int ret;

    LOGD("write_to_storage....\n");
    switch (type) {
        case TYPE_KM:
        	LOGD("write KM file, Invalid operation in key_writer exe!\n");
            return -1;

        case TYPE_KPUB_DCP:
        	filename = KEY_PUB_DCP_ID;
            break;

        case TYPE_LC128:
            LOGD("disallow to write to file type: %d\n", type);
            return -1;

        case TYPE_SRM:
        	filename = SRM_ID;
            break;

        default:
            return -1;
    }

    ret = storage_open_session(&session, STORAGE_CLIENT_TD_PORT);
    if (ret < 0) {
        LOGE("failed (%d) to open session.\n", ret);
        return -1;
    }
    // open specified file, can't use STORAGE_FILE_OPEN_TRUNCATE flag if KM
    if (TYPE_KM == type) {
    	ret = storage_open_file(session, &handle, filename,
                STORAGE_FILE_OPEN_CREATE, STORAGE_OP_COMPLETE);
    } else {
        ret = storage_open_file(session, &handle, filename,
                STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE, STORAGE_OP_COMPLETE);
    }
    if (ret < 0) {
         LOGD("open file for type:%d failed!\n", type);
         storage_close_session(session);
         return -1;
    }
    ret = storage_write(handle, 0, data, length, STORAGE_OP_COMPLETE);
    if (ret < 0) {
        LOGD("write file for type:%d failed!\n", type);
        storage_close_file(handle);
        storage_close_session(session);
        return -1;
    }

    // close file and session
    storage_close_file(handle);
    storage_close_session(session);
    return ret;
}

int remove_all_data(void)
{
    storage_session_t session;
    const char *filename;
    int rc;

    LOGD("remove data from storage....\n");
    if ((storage_open_session(&session, STORAGE_CLIENT_TD_PORT)) < 0) {
        LOGE("failed to open session.\n");
        return -1;
    }
    // delete TYPE_KPUB_DCP && TYPE_SRM && KM files
    filename = KEY_PUB_DCP_ID;
    rc = storage_delete_file(session, filename, STORAGE_OP_COMPLETE);
    if (rc != 0 && rc != ERR_NOT_FOUND) {
         LOGD("delete TYPE_KPUB_DCP failed!\n");
         storage_close_session(session);
         return -1;
    }
    filename = SRM_ID;
    rc = storage_delete_file(session, filename, STORAGE_OP_COMPLETE);
    if (rc != 0 && rc != ERR_NOT_FOUND) {
        LOGD("delete SRM failed!\n");
        storage_close_session(session);
        return -1;
    }
    filename = KM_ID;
    rc = storage_delete_file(session, filename, STORAGE_OP_COMPLETE);
    if (rc != 0 && rc != ERR_NOT_FOUND) {
        LOGD("delete KM failed!\n");
        storage_close_session(session);
        return -1;
    }

    // close session
    storage_close_session(session);

    return 0;
}

int trusty_remove_data(int cmd, uint8_t *in_buf, uint32_t in_buf_size, uint8_t *out_buf,
        uint32_t *out_buf_size)
{
    int ret;

    ret = remove_all_data();
    add_param(out_buf, 0, &ret, sizeof(int));
    *out_buf_size = 8;
    LOGD("trusty_remove_keys exit; ret=%d, out_buf_size=%d\n", ret, *out_buf_size);
    return 0;
}

int trusty_opreate_self(int cmd, uint8_t *in_buf, uint32_t in_buf_size, uint8_t *out_buf,
        uint32_t *out_buf_size)
{
    int ret;
    uint8_t buf[DEFAULT_BUF_SIZE];
    int len = 0, offset = 0;

    if (cmd == WRITE_TO_STORAGE_SELF) {
        len = *(int*) in_buf;
        offset += sizeof(int);
        LOGD("trusty_opreate_self Write: len=%d, offset=%d\n", len, offset);
        memcpy(buf, in_buf + offset, len);
        ret = write_to_storage(buf, len, TYPE_SRM); // use SRM file for test
    } else if (cmd == READ_FROM_STORAGE_SELF) {
    	ret = read_from_storage(buf, len, TYPE_SRM);
    }

    // feedback the response
    offset = 0;
    if (cmd == WRITE_TO_STORAGE_SELF) {
        add_param(out_buf, 0, &ret, sizeof(int));
        offset += 2*sizeof(int);
    } else if (cmd == READ_FROM_STORAGE_SELF) {
        add_param(out_buf, 0, buf, ret);
        offset += sizeof(int) + ret;
    }
    *out_buf_size = offset;

    LOGD("handle_trusty_cmd_opreate_self exit; ret=%d, out_buf_size=%d\n", ret, *out_buf_size);
    return 0;
}

int trusty_opreate_other(int cmd, uint8_t *in_buf, uint32_t in_buf_size,
        uint8_t *out_buf, uint32_t *out_buf_size)
{
    int ret;
    int size, offset = 0;
    uint32_t buf_size = DEFAULT_BUF_SIZE;
    uint8_t *buf, *in_ptr;

    size = *(int*) in_buf;
    offset += sizeof(int);
    in_ptr = in_buf + offset;
    LOGD("trusty_opreate_other: size=%d, offset=%d\n", size, offset);

    if (open_km_session() < 0) {
        LOGE("open km session failed!");
        return -1;
    }
    ret = call_km_command(cmd, in_ptr, size, &buf, &buf_size);
    if (ret < 0) {
        LOGE("call keymaster command(%d) failed!", cmd);
        close_km_session();
        return -1;
    }
    close_km_session();

    // feedback the response
    offset = 0;
    if (cmd == WRITE_TO_STORAGE_OTHER) {
        add_param(out_buf, 0, &ret, sizeof(int));
        offset += 2*sizeof(int);
    } else if (cmd == READ_FROM_STORAGE_OTHER) {
        add_param(out_buf, 0, buf, ret);
        offset += sizeof(int) + ret;
    }
    *out_buf_size = offset;
    
    return NO_ERROR;
}


/*********************************************************************/
// below used to access data from other TAs
static handle_t km_handle_;

static long send_req(handle_t handle, uint32_t cmd, uint8_t *data, uint32_t size)
{
    LOGD("send_req(cmd: %d, size: %d)", cmd, size);
    iovec_t *tx_iov;
    ipc_msg_t tx_msg;
    long rc;
    km_message msg = {
        .cmd = cmd,
    };

    if (0 == handle) {
        LOGE("keymaster TA not connected.\n");
        return -EINVAL;
    }

    if (data != NULL && size > 0) {
        tx_iov = malloc(2 * sizeof(iovec_t));
        if (tx_iov == NULL) {
            goto MALLOC_FAIL;
        }
        tx_iov[0].base = &msg;
        tx_iov[0].len = sizeof(msg);
        tx_iov[1].base = data;
        tx_iov[1].len = size;
        tx_msg.iov = tx_iov;
        tx_msg.num_iov = 2;
        tx_msg.num_handles = 0;
        tx_msg.handles = NULL;
    } else {
        tx_iov = malloc(sizeof(iovec_t));
        if (tx_iov == NULL) {
            goto MALLOC_FAIL;
        }
        tx_iov->base = &msg;
        tx_iov->len = sizeof(msg);
        tx_msg.iov = tx_iov;
        tx_msg.num_iov = 1;
        tx_msg.num_handles = 0;
        tx_msg.handles = NULL;
    }
    rc = send_msg(km_handle_, &tx_msg);
    if (rc < 0) {
        LOGE("%s: failed (%ld) to send_msg\n", __func__, rc);
        return rc;
    }

    free(tx_iov);
    LOGD("send_req() exit...");
    return NO_ERROR;

MALLOC_FAIL:
    LOGE("%s: out of memory (%d)\n", __func__, __LINE__);
    return -1;
}

static long await_response(handle_t handle, struct ipc_msg_info *inf)
{
    LOGD("await_response() enter...");
    uevent_t uevt;

    if (0 == handle) {
        LOGE("keymaster TA not connected.\n");
        return -EINVAL;
    }

    long rc = wait(handle, &uevt, -1);
    if (rc != NO_ERROR) {
        LOGE("interrupted waiting for response (%ld)\n", rc);
        return rc;
    }

    rc = get_msg(handle, inf);
    if (rc != NO_ERROR) {
        LOGE("failed to get_msg (%ld)\n", rc);
    }
    LOGD("await_response() exit...");
    return rc;
}

static long read_response(handle_t handle, uint32_t msg_id,
        uint32_t cmd, uint8_t *buf, uint32_t size)
{
    LOGD("read_response() enter...");
    km_message msg;

    if (0 == handle) {
        LOGE("keymaster TA not connected.\n");
        return -EINVAL;
    }

    iovec_t rx_iov[2] = {
        {
            .base = &msg,
            .len = sizeof(msg)
        },
        {
            .base = buf,
            .len = size
        }
    };
    struct ipc_msg rx_msg = {
        .iov = rx_iov,
        .num_iov = 2,
    };

    long rc = read_msg(handle, msg_id, 0, &rx_msg);
    put_msg(handle, msg_id);
    if (msg.cmd != (cmd | TEST_RESP_BIT)) {
        LOGE("%s: invalid response (0x%x) for cmd (0x%x)\n",
                __func__, msg.cmd, cmd);
        return ERR_NOT_VALID;
    }
    
    LOGD("read_response() exit..");
    return rc;
}

static int open_km_session(void)
{
    LOGD("open_km_session() enter...");

    long rc = connect(KEYMASTER_SECURE_PORT, IPC_CONNECT_WAIT_FOR_PORT);
    if (rc < 0) {
        LOGD("open keymaster TA session FAIL(%ld)!...", rc);
        return rc;
    }

    km_handle_ = rc;
    LOGD("open_km_session() exit... km_handle_=%d", km_handle_);
    return NO_ERROR;
}

static void close_km_session(void)
{
    LOGD("close_km_session() enter...");
    close(km_handle_);
    LOGD("close_km_session() exit...");
}

static int call_km_command(uint32_t cmd, void *in, uint32_t in_size, uint8_t **out_p,
        uint32_t *out_size_p)
{
    long rc; 
    ipc_msg_info_t info;
    LOGD("call_km_command() enter...");
    
    rc = send_req(km_handle_, cmd, in, in_size);
    if (rc < 0) {
        LOGE("%s: failed (%ld) to send req\n", __func__, rc);
        return rc;
    }
    rc = await_response(km_handle_, &info);
    if (rc < 0) {
        LOGE("%s: failed (%ld) to await response\n", __func__, rc);
        return rc;
    }
    if (info.len <= sizeof(km_message)) {
        LOGE("%s: invalid response len (%zu)\n", __func__, info.len);
        put_msg(km_handle_, info.id);
        return ERR_NOT_FOUND;
    }

    size_t size = info.len - sizeof(km_message);
    uint8_t *resp_buf = malloc(size);
    if (resp_buf == NULL) {
        LOGE("%s: out of memory (%zu)\n", __func__, info.len);
        put_msg(km_handle_, info.id);
        return ERR_NO_MEMORY;
    }
    rc = read_response(km_handle_, info.id, cmd,
            resp_buf, size);
    if (rc < 0) {
        goto err_bad_read;
    }
    if ((size_t)rc != info.len) {
        // data read in does not match message length
        LOGE("%s: invalid read length: (%ld != %zu)\n",
                __func__, rc, info.len);
        rc = ERR_IO;
        goto err_bad_read;
    }

    *out_size_p = size;
    *out_p = resp_buf;
    LOGD("call_km_command() exit...");
    return NO_ERROR;

err_bad_read:
    free(resp_buf);
    LOGE("%s: failed read_msg (%ld)", __func__, rc);
    return rc;
}
