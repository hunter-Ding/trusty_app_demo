#define TEST_PORT "com.sprd.trusty.trusty_test"
#define KEYMASTER_PORT "com.android.trusty.keymaster"

enum {
    TEST_REQ_SHIFT = 1,
    TEST_RESP_BIT = 1,

    WRITE_TO_STORAGE_SELF       = (23 << TEST_REQ_SHIFT),
    READ_FROM_STORAGE_SELF      = (24 << TEST_REQ_SHIFT),
    WRITE_TO_STORAGE_OTHER      = (25 << TEST_REQ_SHIFT),
    READ_FROM_STORAGE_OTHER     = (26 << TEST_REQ_SHIFT),
    REMOVE_DATA                 = (27 << TEST_REQ_SHIFT),

    /* Add for soter usage. Begin. @{ */
    KM_GENERATE_ATTK_KEY_PAIR   = (70 << TEST_REQ_SHIFT),
    KM_VERIFY_ATTK_KEY_PAIR     = (71 << TEST_REQ_SHIFT),
    KM_EXPORT_ATTK_PUBLIC_KEY   = (72 << TEST_REQ_SHIFT),
    KM_GET_DEVICE_ID            = (73 << TEST_REQ_SHIFT),
    /* Add for soter usage. End. @} */
};

/**
 * test_message - Serial header for communicating with ta server
 * @cmd: the command, one of xx, xx. Payload must be a serialized
 *       buffer of the corresponding request object.
 * @payload: start of the serialized command specific payload
 */
typedef struct _test_message {
    uint32_t cmd;
    uint8_t payload[0];
} test_message;
typedef struct _km_message {
    uint32_t cmd;
    uint8_t payload[0];
} km_message;

enum {
    TYPE_KM,
    TYPE_KPUB_DCP,
    TYPE_LC128,
    TYPE_SRM,
    TYPE_CERTRX
};

int trusty_opreate_self(int cmd, uint8_t *in_buf, uint32_t in_buf_size,
        uint8_t *out_buf, uint32_t *out_buf_size);
int trusty_opreate_other(int cmd, uint8_t *in_buf, uint32_t in_buf_size,
        uint8_t *out_buf, uint32_t *out_buf_size);
int trusty_remove_data(int cmd, uint8_t *in_buf, uint32_t in_buf_size,
        uint8_t *out_buf, uint32_t *out_buf_size);

