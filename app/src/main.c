#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main, CONFIG_APP_LOG_LEVEL);

/* IOTEMBSYS: Add required iheadersmport shell and/or others */
// #include <zephyr/shell/shell.h>

#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>

#include <stdlib.h>
#include <stdio.h>
#include "app_version.h"

#include <zephyr/settings/settings.h>
#include <zephyr/storage/flash_map.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "api/api.pb.h"

#include <zephyr/stats/stats.h>
#include <stdio.h>
#include "app_version.h"
/* 1000 msec = 1 sec */
#define DEFAULT_SLEEP_TIME_MS   1000

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)

/* IOTEMBSYS: Add joystick key declarations. */
#define SW0_NODE	DT_ALIAS(sw0)
#define SW1_NODE	DT_ALIAS(sw1)
#define SW2_NODE	DT_ALIAS(sw2)
#define SW3_NODE	DT_ALIAS(sw3)
#define SW4_NODE	DT_ALIAS(sw4)
static const struct gpio_dt_spec sw0 = GPIO_DT_SPEC_GET_OR(SW0_NODE, gpios,
							      {0});
static const struct gpio_dt_spec sw1 = GPIO_DT_SPEC_GET_OR(SW1_NODE, gpios,
							      {0});
static const struct gpio_dt_spec sw2 = GPIO_DT_SPEC_GET_OR(SW2_NODE, gpios,
							      {0});
static const struct gpio_dt_spec sw3 = GPIO_DT_SPEC_GET_OR(SW3_NODE, gpios,
							      {0});								  								  								  
static const struct gpio_dt_spec sw4 = GPIO_DT_SPEC_GET_OR(SW4_NODE, gpios,
							      {0});								  
static struct gpio_callback button_cb_data_0;
static struct gpio_callback button_cb_data_1;
static struct gpio_callback button_cb_data_2;
static struct gpio_callback button_cb_data_3;
static struct gpio_callback button_cb_data_4;

typedef enum {
    LOCKED,
    IS_UNLOCKING,
	TIMEOUT
} LockState;

LockState currentState = LOCKED;
/*
 * A build error on this line means your board is unsupported.
 * See the blinky sample documentation for information on how to fix this.
 */
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);


#define str(s) #s
#define xstr(s) str(s)

STATS_SECT_START(app_stats)
STATS_SECT_ENTRY(ticks)
STATS_SECT_ENTRY(open_count)
STATS_SECT_END;

/* Assign a name to the `ticks` stat. */
STATS_NAME_START(app_stats)
STATS_NAME(app_stats, ticks)
STATS_NAME(app_stats, open_count)
STATS_NAME_END(app_stats);

/* Define an instance of the stats group. */
STATS_SECT_DECL(app_stats) app_stats;

#define SLOT1_PARTITION slot1_partition
#define SLOT1_PARTITION_ID FIXED_PARTITION_ID(SLOT1_PARTITION)

#define STORAGE_PARTITION storage_partition
#define STORAGE_PARTITION_ID FIXED_PARTITION_ID(STORAGE_PARTITION)

typedef enum {
	BUTTON_ACTION_NONE = 0,
	BUTTON_ACTION_SEND_TO_SERVER,
	BUTTON_ACTION_DOWN,
	BUTTON_ACTION_RIGHT,
	BUTTON_ACTION_UP,
	BUTTON_ACTION_LEFT,
} button_action_e;

/* The amount of time between GPIO blinking. */
static uint32_t blink_interval_ = DEFAULT_SLEEP_TIME_MS;

static void change_blink_interval(uint32_t new_interval_ms) {
	blink_interval_ = new_interval_ms;
}
uint8_t button_press_sequence[4];
uint8_t index = 0;
static struct k_event unblock_sender_;
static struct k_event unblock_button_;
struct k_fifo socket_queue_;
char otp_code_[8];
uint8_t otp;
static struct addrinfo* backend_addr_;

#define MAX_RECV_BUF_LEN 1024
static uint8_t recv_buf_[MAX_RECV_BUF_LEN];

/*bootloader*/
#define DEFAULT_BOOT_COUNT_VALUE 0
static uint8_t boot_count = DEFAULT_BOOT_COUNT_VALUE;

static int foo_settings_set(const char *name, size_t len,
                            settings_read_cb read_cb, void *cb_arg)
{
    const char *next;
    int rc;

    if (settings_name_steq(name, "boot_count", &next) && !next) {
        if (len != sizeof(boot_count)) {
            return -EINVAL;
        }

        rc = read_cb(cb_arg, &boot_count, sizeof(boot_count));
        if (rc >= 0) {
            /* key-value pair was properly read.
             * rc contains value length.
             */
            return 0;
        }
        /* read-out error */
        return rc;
    }

    return -ENOENT;
}

static int foo_settings_export(int (*storage_func)(const char *name,
                                                   const void *value,
                                                   size_t val_len))
{
    return storage_func("provisioning/boot_count", &boot_count, sizeof(boot_count));
}

struct settings_handler my_conf = {
    .name = "provisioning",
    .h_set = foo_settings_set,
    .h_export = foo_settings_export
};
/*bootloader*/

/* IOTEMBSYS: Add joystick press handler. Metaphorical bonus points for debouncing. */

static char ota_path_[128] = "/zephyr.signed.bin";

static void button_pressed(const struct device *dev, struct gpio_callback *cb,
		    uint32_t pins) {
	// Sophomoric "debouncing" implementation
	printk("Button %d pressed at %" PRIu32 "\n", pins, k_cycle_get_32());
	k_msleep(100);

	uint32_t interval_ms = 0;
	if (pins == BIT(sw0.pin)) {
		interval_ms = 100;
		k_event_set(&unblock_sender_, (1 << BUTTON_ACTION_SEND_TO_SERVER));
	} else if (pins == BIT(sw1.pin)) {
		// Down
		interval_ms = 200;
		k_event_set(&unblock_sender_, (1 << BUTTON_ACTION_DOWN));
	} else if (pins == BIT(sw2.pin)) {
		// Right
		interval_ms = 500;
		k_event_set(&unblock_sender_, (1 << BUTTON_ACTION_RIGHT));
	} else if (pins == BIT(sw3.pin)) {
		// Up
		interval_ms = 1000;
		k_event_set(&unblock_sender_, (1 << BUTTON_ACTION_UP));
	} else if (pins == BIT(sw4.pin)) {
		// Left
		k_event_set(&unblock_sender_, (1 << BUTTON_ACTION_LEFT));
		interval_ms = 2000;
	} else {
		printk("Unrecognized pin");
	}

	if (interval_ms != 0) {
		printk("Setting interval to %d", interval_ms);
		change_blink_interval(interval_ms);
	}
}

static int init_joystick_gpio(const struct gpio_dt_spec* button, struct gpio_callback* data) {
	int ret = -1;

	if (!gpio_is_ready_dt(button)) {
		printk("Error: button device %s is not ready\n",
		       button->port->name);
		return ret;
	}

	ret = gpio_pin_configure_dt(button, GPIO_INPUT);
	if (ret != 0) {
		printk("Error %d: failed to configure %s pin %d\n",
		       ret, button->port->name, button->pin);
		return ret;
	}

	ret = gpio_pin_interrupt_configure_dt(button,
					      GPIO_INT_EDGE_TO_ACTIVE);
	if (ret != 0) {
		printk("Error %d: failed to configure interrupt on %s pin %d\n",
			ret, button->port->name, button->pin);
		return ret;
	}

	gpio_init_callback(data, button_pressed, BIT(button->pin));
	gpio_add_callback(button->port, data);
	return ret;
}
/*Add message passing/synchronization to pass the socket from the sender to the receiver task */
static void dump_addrinfo(const struct addrinfo *ai) {
	printf("addrinfo @%p: ai_family=%d, ai_socktype=%d, ai_protocol=%d, "
	       "sa_family=%d, sin_port=%x\n",
	       ai, ai->ai_family, ai->ai_socktype, ai->ai_protocol,
	       ai->ai_addr->sa_family,
	       ((struct sockaddr_in *)ai->ai_addr)->sin_port);
}

/* IOTEMBSYS5: This helper function has been added for you. */
static int get_addr_if_needed(struct addrinfo **ai, const char* host, const char* port) {
	if (*ai != NULL) {
		// We already have the address.
		return 0;
	}
	struct addrinfo hints;
	int st;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	st = getaddrinfo(host, port, &hints, ai);
	LOG_INF("getaddrinfo status: %d\n", st);
	if (st == 0) {
		dump_addrinfo(*ai);
	}
	return st;
}
#define SERVER_HOST "ec2-54-226-227-48.compute-1.amazonaws.com"
#define SERVER_PORT 8080
#define BACKEND_HOST SERVER_HOST ":8080"
static const char kDeviceId[] = "12345";

static bool encode_status_update_request(uint8_t *buffer, size_t buffer_size, size_t *message_length)
{
	bool status;

	/* Allocate space on the stack to store the message data.
	 *
	 * Nanopb generates simple struct definitions for all the messages.
	 * - check out the contents of api.pb.h!
	 * It is a good idea to always initialize your structures
	 * so that you do not have garbage data from RAM in there.
	 */
	StatusUpdateRequest message = StatusUpdateRequest_init_zero;

	/* Create a stream that will write to our buffer. */
	pb_ostream_t stream = pb_ostream_from_buffer(buffer, buffer_size);

	/* Fill in the reboot count */
	message.boot_count = boot_count;

	message.uptime_ticks = k_uptime_get();
	strncpy(message.device_id, kDeviceId, sizeof(message.device_id));

	message.has_app_stats = true;
	message.app_stats.ticks = app_stats.ticks;
	message.app_stats.open_count = app_stats.open_count;

	/* Now we are ready to encode the message! */
	status = pb_encode(&stream, StatusUpdateRequest_fields, &message);
	*message_length = stream.bytes_written;

	if (!status) {
		printk("Encoding failed: %s\n", PB_GET_ERROR(&stream));
	}

	return status;
}

static bool decode_status_update_response(uint8_t *buffer, size_t message_length)
{
	bool status = false;
	if (message_length == 0) {
		LOG_WRN("Message length is 0");
		return status;
	}

	/* Allocate space for the decoded message. */
	StatusUpdateResponse message = StatusUpdateResponse_init_zero;

	/* Create a stream that reads from the buffer. */
	pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);

	/* Now we are ready to decode the message. */
	status = pb_decode(&stream, StatusUpdateResponse_fields, &message);

	/* Check for errors... */
	if (status) {
		/* Print the data contained in the message. */
		printk("Response message: %s\n", message.message);
	} else {
		printk("Decoding failed: %s\n", PB_GET_ERROR(&stream));
	}

	return status;
}

static bool decode_otp_response(uint8_t *buffer, size_t message_length)
{
	bool status = false;
	if (message_length == 0) {
		LOG_WRN("Message length is 0");
		otp = -1;
		return status;
	}

	/* Allocate space for the decoded message. */
	StatusUpdateResponse message = StatusUpdateResponse_init_zero;

	/* Create a stream that reads from the buffer. */
	pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);

	/* Now we are ready to decode the message. */
	status = pb_decode(&stream, StatusUpdateResponse_fields, &message);

	/* Check for errors... */
	if (status) {
		/* Print the data contained in the message. */
		printk("Response message: %s\n", message.message);
		strncpy(otp_code_, message.message, sizeof(otp_code_));
		otp = (uint8_t)atoi(otp_code_);
	} else {
		printk("Decoding failed: %s\n", PB_GET_ERROR(&stream));
	}

	return status;
}

int http_proto_payload_gen(uint8_t* buffer, size_t buf_size) {
	size_t message_length;

	/* Encode our message */
	if (!encode_status_update_request(buffer, buf_size, &message_length)) {
		LOG_ERR("Encoding request failed");
		return 0;
	} else {
		LOG_INF("Sending proto to server. Length: %d", (int)message_length);
	}

	return (int)message_length;
}

void http_proto_response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	if (final_data == HTTP_DATA_MORE) {
		LOG_INF("Partial data received (%zd bytes)", rsp->data_len);
	} else if (final_data == HTTP_DATA_FINAL) {
		LOG_INF("All the data received (%zd bytes)", rsp->data_len);

		// Decode the protobuf response.
		decode_status_update_response(rsp->body_frag_start, rsp->body_frag_len);
	}

	LOG_INF("Response to %s", (const char *)user_data);
	LOG_INF("Response status %s", rsp->http_status);
}

void http_otp_response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	if (final_data == HTTP_DATA_MORE) {
		LOG_INF("Partial data received (%zd bytes)", rsp->data_len);
	} else if (final_data == HTTP_DATA_FINAL) {
		LOG_INF("All the data received (%zd bytes)", rsp->data_len);

		// Decode the protobuf response.
		decode_otp_response(rsp->body_frag_start, rsp->body_frag_len);
	}

	LOG_INF("Response to %s", (const char *)user_data);
	LOG_INF("Response status %s", rsp->http_status);
}

static void http_update_request(void) {
	int sock;
	const int32_t timeout = 5 * MSEC_PER_SEC;

	// Get the IP address of the domain
	if (get_addr_if_needed(&backend_addr_, SERVER_HOST, xstr(SERVER_PORT)) != 0) {
		LOG_ERR("DNS lookup failed");
		return;
	}

	// Create a socket using parameters that the modem allows.
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		LOG_ERR("Creating socket failed");
		return;
	}
	if (connect(sock, backend_addr_->ai_addr, backend_addr_->ai_addrlen) < 0) {
		LOG_ERR("Connecting to socket failed");
		return;
	}

	struct http_request req;

	memset(&req, 0, sizeof(req));
	memset(recv_buf_, 0, sizeof(recv_buf_));

	req.method = HTTP_POST;
	req.url = "/status_update";
	req.host = BACKEND_HOST;
	req.protocol = "HTTP/1.1";
	req.payload_len = http_proto_payload_gen(recv_buf_, sizeof(recv_buf_));
	req.payload = req.payload_len ? recv_buf_ : NULL;
	req.response = http_proto_response_cb;
	req.recv_buf = recv_buf_;
	req.recv_buf_len = sizeof(recv_buf_);

	// This request is synchronous and blocks the thread.
	LOG_INF("Sending HTTP request");
	int ret = http_client_req(sock, &req, timeout, "IPv4 GET");
	if (ret > 0) {
		LOG_INF("HTTP request sent %d bytes", ret);
	} else {
		LOG_ERR("HTTP request failed: %d", ret);
	}

	LOG_INF("Closing the socket");
	close(sock);
}

/* IOTEMBSYS: Implement the HTTP client functionality */
static void backend_http_request(void) {
	int sock;
	const int32_t timeout = 5 * MSEC_PER_SEC;

	// Get the IP address of the domain
	if (get_addr_if_needed(&backend_addr_, SERVER_HOST, xstr(SERVER_PORT)) != 0) {
		LOG_ERR("DNS lookup failed");
		return;
	}

	// Create a socket using parameters that the modem allows.
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		LOG_ERR("Creating socket failed");
		return;
	}
	if (connect(sock, backend_addr_->ai_addr, backend_addr_->ai_addrlen) < 0) {
		LOG_ERR("Connecting to socket failed");
		return;
	}

	struct http_request req;

	memset(&req, 0, sizeof(req));
	memset(recv_buf_, 0, sizeof(recv_buf_));

	req.method = HTTP_POST;
	req.url = "/local_unlock";
	req.host = BACKEND_HOST;
	req.protocol = "HTTP/1.1";
	req.payload_len = http_proto_payload_gen(recv_buf_, sizeof(recv_buf_));
	req.payload = req.payload_len ? recv_buf_ : NULL;
	req.response = http_otp_response_cb;
	req.recv_buf = recv_buf_;
	req.recv_buf_len = sizeof(recv_buf_);

	// This request is synchronous and blocks the thread.
	LOG_INF("Sending HTTP request");
	int ret = http_client_req(sock, &req, timeout, "IPv4 GET");
	if (ret > 0) {
		LOG_INF("HTTP request sent %d bytes", ret);
	} else {
		LOG_ERR("HTTP request failed: %d", ret);
	}

	LOG_INF("Closing the socket");
	close(sock);
}
/*OTA*/

//
// OTA Download Section
//
#define OTA_HTTP_PORT 80
#define OTA_HOST "nhantt-iotemb-firmware-releases.s3.amazonaws.com"
static int total_read_size;
static int total_write_size;
static int content_length_;
static struct flash_area *image_area;
static struct addrinfo* ota_addr_;



static bool encode_ota_update_request(uint8_t *buffer, size_t buffer_size, size_t *message_length)
{
	bool status;

	/* Allocate space on the stack to store the message data.
	 *
	 * Nanopb generates simple struct definitions for all the messages.
	 * - check out the contents of api.pb.h!
	 * It is a good idea to always initialize your structures
	 * so that you do not have garbage data from RAM in there.
	 */
	OTAUpdateRequest message = OTAUpdateRequest_init_zero;

	/* Create a stream that will write to our buffer. */
	pb_ostream_t stream = pb_ostream_from_buffer(buffer, buffer_size);
	
	/* TODO: fill out the actual state. */
	message.state = OTAState_OTA_STATE_NONE;
	strncpy(message.version, APP_VERSION_STR, sizeof(message.version));
	strncpy(message.device_id, kDeviceId, sizeof(message.device_id));

	/* Now we are ready to encode the message! */
	status = pb_encode(&stream, OTAUpdateRequest_fields, &message);
	*message_length = stream.bytes_written;

	if (!status) {
		printk("Encoding failed: %s\n", PB_GET_ERROR(&stream));
	}

	return status;
}

static bool decode_ota_update_response(uint8_t *buffer, size_t message_length)
{
	bool status = false;
	if (message_length == 0) {
		LOG_WRN("Message length is 0");
		return status;
	}

	/* Allocate space for the decoded message. */
	OTAUpdateResponse message = OTAUpdateResponse_init_zero;

	/* Create a stream that reads from the buffer. */
	pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);

	/* Now we are ready to decode the message. */
	status = pb_decode(&stream, OTAUpdateResponse_fields, &message);

	/* Check for errors... */
	if (status) {
		/* Print the data contained in the message. */
		printk("OTA path: %s\n", message.path);
		strncpy(ota_path_, message.path, sizeof(ota_path_));
	} else {
		printk("Decoding failed: %s\n", PB_GET_ERROR(&stream));
	}

	return status;
}

/* IOTEMBSYS: Implement the HTTP client functionality */
static int http_ota_proto_payload_get(uint8_t* buffer, size_t buf_size) {
	size_t message_length;

	/* Encode our message */
	if (!encode_ota_update_request(buffer, buf_size, &message_length)) {
		LOG_ERR("Encoding request failed");
		return 0;
	} else {
		LOG_INF("Sending proto to server. Length: %d", (int)message_length);
	}
	return (int)message_length;
}

static void http_ota_proto_response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	if (final_data == HTTP_DATA_MORE) {
		LOG_INF("Partial data received (%zd bytes)", rsp->data_len);
	} else if (final_data == HTTP_DATA_FINAL) {
		LOG_INF("All the data received (%zd bytes)", rsp->data_len);

		// Decode the protobuf response.
		decode_ota_update_response(rsp->body_frag_start, rsp->body_frag_len);
	}

	LOG_INF("Response to %s", (const char *)user_data);
	LOG_INF("Response status %s", rsp->http_status);
}
void http_ota_response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	static uint8_t overflow_[8];
	static uint8_t overflow_count_;
	uint8_t overflow_inverse = 0;
	size_t bytes_to_write = rsp->body_frag_len;

	if (total_read_size == 0) {
		overflow_count_ = 0;
	}

	if (overflow_count_ != 0) {
		overflow_inverse = sizeof(overflow_) - overflow_count_;
		
		if (overflow_inverse > rsp->body_frag_len) {
			LOG_INF("Not enough data; copy all to overflow");
			memcpy(overflow_ + overflow_count_, rsp->body_frag_start, rsp->body_frag_len);
			overflow_count_ += rsp->body_frag_len;
			bytes_to_write -= rsp->body_frag_len;
		} else {
			memcpy(overflow_ + overflow_count_, rsp->body_frag_start, overflow_inverse);
			bytes_to_write -= overflow_inverse;
			int err = flash_area_write(image_area, total_read_size - overflow_count_, overflow_, sizeof(overflow_));
			if (err != 0) {
				LOG_ERR("Flash area write failed");
			} else {
				total_write_size += sizeof(overflow_);
			}
		}
	}

	if (bytes_to_write != 0) {
		// This is specific to STM32 flash
		// TODO(mskobov): don't write if < 8 bytes to write
		overflow_count_ = bytes_to_write % 8;
		int err = flash_area_write(image_area, total_read_size + overflow_inverse, rsp->body_frag_start + overflow_inverse, bytes_to_write - overflow_count_);
		if (err != 0) {
			LOG_ERR("Flash area write failed");
		} else {
			total_write_size += bytes_to_write - overflow_count_;
		}
		if (overflow_count_ != 0) {
			memset(overflow_, 0, sizeof(overflow_));
			memcpy(overflow_, rsp->body_frag_start + overflow_inverse + bytes_to_write - overflow_count_, overflow_count_);
			if (final_data == HTTP_DATA_FINAL) {
				err = flash_area_write(image_area, total_read_size + overflow_inverse + bytes_to_write - overflow_count_, overflow_, sizeof(overflow_));
				if (err != 0) {
					LOG_ERR("Flash area write failed");
				} else {
					// Technically, we could have written more, but we don't care about the alignment bytes.
					total_write_size += overflow_count_;
				}
			}
		}
	}

	// Count the read size to make sure it matches the content length header at the end.
	total_read_size += rsp->body_frag_len;
	content_length_ = rsp->content_length;
}
static void backend_ota_http_request(void) {
	int sock;
	const int32_t timeout = 5 * MSEC_PER_SEC;

	// Get the IP address of the domain
	if (get_addr_if_needed(&backend_addr_, SERVER_HOST, xstr(SERVER_PORT)) != 0) {
		LOG_ERR("DNS lookup failed");
		return;
	}

	// Create a socket using parameters that the modem allows.
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		LOG_ERR("Creating socket failed");
		return;
	}
	if (connect(sock, backend_addr_->ai_addr, backend_addr_->ai_addrlen) < 0) {
		LOG_ERR("Connecting to socket failed");
		return;
	}

	struct http_request req;

	memset(&req, 0, sizeof(req));
	memset(recv_buf_, 0, sizeof(recv_buf_));

	req.host = BACKEND_HOST;
	req.protocol = "HTTP/1.1";
	req.method = HTTP_POST;
	req.url = "/ota";
	req.payload = recv_buf_;
	req.payload_len = http_ota_proto_payload_get(recv_buf_, sizeof(recv_buf_));
	req.payload = req.payload_len ? recv_buf_ : NULL;
	req.response = http_ota_proto_response_cb;
	req.recv_buf = recv_buf_;
	req.recv_buf_len = sizeof(recv_buf_);

	// This request is synchronous and blocks the thread.
	LOG_INF("Sending OTA HTTP request");
	int ret = http_client_req(sock, &req, timeout, "IPv4 GET");
	if (ret > 0) {
		LOG_INF("HTTP request sent %d bytes", ret);
	} else {
		LOG_ERR("HTTP request failed: %d", ret);
	}

	LOG_INF("Closing the socket");
	close(sock);
}
static void http_ota_request() {
	int sock;
	const int32_t timeout = 120 * MSEC_PER_SEC;

	LOG_INF("Starting OTA...");

	total_read_size = 0;
	total_write_size = 0;

	// Erase a flash area if previously written to.
	int err = flash_area_open(SLOT1_PARTITION_ID, (const struct flash_area **)&image_area);
	if (err != 0) {
		LOG_ERR("Flash area open failed");
		return;
	}
	err = flash_area_erase(image_area, 0, image_area->fa_size);
	if (err != 0) {
		LOG_ERR("Flash area erase failed");
		return;
	}

	// Get the IP address of the domain
	if (get_addr_if_needed(&ota_addr_, OTA_HOST, xstr(OTA_HTTP_PORT)) != 0) {
		LOG_ERR("DNS lookup failed");
		return;
	}

	// Create a socket using parameters that the modem allows.
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		LOG_ERR("Creating socket failed");
		return;
	}
	if (connect(sock, ota_addr_->ai_addr, ota_addr_->ai_addrlen) < 0) {
		LOG_ERR("Connecting to socket failed");
		return;
	}

	struct http_request req;

	memset(&req, 0, sizeof(req));
	memset(recv_buf_, 0, sizeof(recv_buf_));

	req.method = HTTP_GET;
	req.url = ota_path_;
	req.host = OTA_HOST;
	req.protocol = "HTTP/1.1";
	req.payload_len = 0;
	req.payload_cb = NULL;
	req.response = http_ota_response_cb;
	req.recv_buf = recv_buf_;
	req.recv_buf_len = sizeof(recv_buf_);

	// This request is synchronous and blocks the thread.
	int ret = http_client_req(sock, &req, timeout, "IPv4 GET");
	if (ret > 0) {
		LOG_INF("HTTP request sent %d bytes", ret);
		LOG_INF("Received: %d", total_read_size);
		if (content_length_ != total_read_size || total_write_size != total_read_size) {
			LOG_ERR("Content length mismatch. Read: %d\tWrote: %d\tExpected: %d", total_read_size, total_write_size, content_length_);
		}
		k_msleep(1000);
	} else {
		LOG_ERR("HTTP request failed: %d", ret);
		k_msleep(1000);
	}

	LOG_INF("Closing the socket");
	close(sock);
	LOG_INF("Close image area");
	flash_area_close(image_area);
}

/**/

void decode_otp(uint8_t otp_code, uint8_t button_sequence[4]){
	uint8_t binary_str[8];
    for (int i = 7; i >= 0; i--) {
        binary_str[i] = otp_code & 1;
        otp_code >>= 1;
    }
	for (int i = 0; i < 4; i++) {
        uint8_t pair = (binary_str[i * 2] << 1) | binary_str[i * 2 + 1];
        switch(pair) {
            case 0: 
				button_sequence[i] = 1; 
			break;
            case 1:
				button_sequence[i] = 2; 
			break;
            case 2: 
				button_sequence[i] = 3; 
			break;
            case 3: 
				button_sequence[i] = 4; 
			break;
        }
    }
}
bool sequence_matched = false;
uint8_t time = 90;
bool req_in_progress_ = false;
void unlock(uint8_t otp_code){
	k_event_init(&unblock_button_);
	

	uint8_t button_sequence[4];
	decode_otp(otp_code, button_sequence);
    
    // Check if the entered sequence matches the expected sequence
	sequence_matched = true;
    for (int i = 0; i < 4; i++) {
        if (button_press_sequence[i] != button_sequence[i]) {
            sequence_matched = false;
            break;
        }
    }
	if(sequence_matched && index > 3){
		printk("\nunlock successful\n");
		time = 90;
		index = 0;	
		req_in_progress_ = false;
		currentState = TIMEOUT;
		STATS_INC(app_stats, open_count);
	}
	if(!sequence_matched){
		printk("\nsequence not match\n");
		index = 0;
	}
}
void http_client_thread(void* p1, void* p2, void* p3) {
	k_event_init(&unblock_sender_);

	while (true) {
		uint32_t  events;

		LOG_INF("Waiting for button");
		events = k_event_wait(&unblock_sender_, 0xFFF, true, K_FOREVER);
		if (events == 0) {
			printk("This should not be happening!");
			continue;
		}

		// Multiple button events are possible, so handle all without exclusion.
		if(events & (1 << BUTTON_ACTION_SEND_TO_SERVER)){
			if(currentState != TIMEOUT){
				backend_http_request();
				index = 0;
				if (otp == 0) {
        		// Unlock the lock
					printk("\nunlock successful\n");
					currentState = TIMEOUT;
					req_in_progress_ = false;
					STATS_INC(app_stats, open_count);
    			}
				else{
					currentState = IS_UNLOCKING;
					req_in_progress_ = true;
				}
			}
			else{
				time = 90;
				currentState = LOCKED;
				printk("\nLock!\n");
			}
			
			// unlock(otp_code_);
			
		}
		if (events & (1 << BUTTON_ACTION_DOWN)) {
			if(req_in_progress_){
				button_press_sequence[index] = 1;
				index += 1;
				if(index > 3){
					unlock(otp);
				}
			}
			else{
				http_ota_request();
			}
		}
		if (events & (1 << BUTTON_ACTION_RIGHT)) {
			
			if(req_in_progress_){
				button_press_sequence[index] = 2;
				index += 1;
				if(index > 3){
					unlock(otp);
				}
			}
		}
		if (events & (1 << BUTTON_ACTION_UP)) {
			if(req_in_progress_){
				button_press_sequence[index] = 3;
				index += 1;
				if(index > 3){
					unlock(otp);
				}
			}
			else
				http_update_request();
		}
		if (events & (1 << BUTTON_ACTION_LEFT)) {
			if(req_in_progress_){
				button_press_sequence[index] = 4;
				index += 1;
				if(index > 3){
					unlock(otp);
				}
			}
			else{
				backend_ota_http_request();
			}
		}
	}
}
K_THREAD_DEFINE(http_client_tid, 4000 /*stack size*/,
                http_client_thread, NULL, NULL, NULL,
                5 /*priority*/, 0, 0);\		
void main(void)
{
	int ret;
	const struct device *modem;
	if (!gpio_is_ready_dt(&led)) {
		return;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return;
	}

	/* IOTEMBSYS: Configure joystick GPIOs. */
	init_joystick_gpio(&sw0, &button_cb_data_0);
	init_joystick_gpio(&sw1, &button_cb_data_1);
	init_joystick_gpio(&sw2, &button_cb_data_2);
	init_joystick_gpio(&sw3, &button_cb_data_3);
	init_joystick_gpio(&sw4, &button_cb_data_4);

	modem = DEVICE_DT_GET(DT_NODELABEL(quectel_bg96));
	if (!device_is_ready(modem)) {
		LOG_ERR("Modem is not ready");
		return;
	}
	settings_subsys_init();
    settings_register(&my_conf);
    settings_load();
	ret = STATS_INIT_AND_REG(app_stats, STATS_SIZE_32,
				    "app_stats");
	if (ret < 0) {
		return;
	}
	boot_count++;
    settings_save_one("provisioning/boot_count", &boot_count, sizeof(boot_count));

    LOG_INF("boot_count: %d\n", boot_count);

	LOG_INF("Running blinky");
	while (1) {
		switch (currentState)
		{
		case LOCKED:
                // LED OFF
                ret = gpio_pin_set_dt(&led, 0);
        break;
        case IS_UNLOCKING:
                // LED ON
            if(sequence_matched){	
				ret = gpio_pin_set_dt(&led, 1);
			}
        break;
		case TIMEOUT:
			printk("timeout in:%d\n",time);
			time -= 1;
			k_msleep(500);
			if(time == 0){
				printk("Time out. LOCKED\n");
				time = 90;
				currentState = LOCKED;
				LOG_INF("Waiting for button");
			}
		break;
        default:
            break;
		}
		
		
		/* IOTEMBSYS: Print GPIO state to console. */
		if (ret < 0) {
			return;
		}
		STATS_INC(app_stats, ticks);
		k_msleep(500);
	}
}
