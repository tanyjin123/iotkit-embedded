/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "iot_import.h"
#include "iot_export.h"
#include "app_entry.h"

static char *g_pk = NULL;
static char *g_dn = NULL;
static char *g_ds = NULL;

static char g_topic_update[512] = {0}; 
static char g_topic_data[512] = {0}; 
static char g_topic_error[512] = {0}; 

#define PRODUCT_KEY             "a1MZxOdcBnO"
#define PRODUCT_SECRET          "h4I4dneEFp7EImTv"
#define DEVICE_NAME             "test_01"
#define DEVICE_SECRET           "t9GmMf2jb3LgWfXBaZD2r3aJrfVWBv56"

/* These are pre-defined topics */
#define FMT_TOPIC_UPDATE            "/%s/%s/update"
#define FMT_TOPIC_ERROR             "/%s/%s/update/error"
#define FMT_TOPIC_SWITCH            "/sys/%s/%s/edge/debug/switch"

#define MQTT_MSGLEN             (1024)

#define EXAMPLE_TRACE(fmt, ...)  \
    do { \
        HAL_Printf("%s|%03d :: ", __func__, __LINE__); \
        HAL_Printf(fmt, ##__VA_ARGS__); \
        HAL_Printf("%s", "\r\n"); \
    } while(0)

static int      user_argc;
static char   **user_argv;

void event_handle(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uintptr_t packet_id = (uintptr_t)msg->msg;
    iotx_mqtt_topic_info_pt topic_info = (iotx_mqtt_topic_info_pt)msg->msg;

    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_UNDEF:
            EXAMPLE_TRACE("undefined event occur.");
            break;

        case IOTX_MQTT_EVENT_DISCONNECT:
            EXAMPLE_TRACE("MQTT disconnect.");
            break;

        case IOTX_MQTT_EVENT_RECONNECT:
            EXAMPLE_TRACE("MQTT reconnect.");
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_SUCCESS:
            EXAMPLE_TRACE("subscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_TIMEOUT:
            EXAMPLE_TRACE("subscribe wait ack timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_NACK:
            EXAMPLE_TRACE("subscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_SUCCESS:
            EXAMPLE_TRACE("unsubscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_TIMEOUT:
            EXAMPLE_TRACE("unsubscribe timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_NACK:
            EXAMPLE_TRACE("unsubscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_SUCCESS:
            EXAMPLE_TRACE("publish success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_TIMEOUT:
            EXAMPLE_TRACE("publish timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_NACK:
            EXAMPLE_TRACE("publish nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            EXAMPLE_TRACE("topic message arrived but without any related handle: topic=%.*s, topic_msg=%.*s",
                          topic_info->topic_len,
                          topic_info->ptopic,
                          topic_info->payload_len,
                          topic_info->payload);
            break;

        case IOTX_MQTT_EVENT_BUFFER_OVERFLOW:
            EXAMPLE_TRACE("buffer overflow, %s", msg->msg);
            break;

        default:
            EXAMPLE_TRACE("Should NOT arrive here.");
            break;
    }
}

static char *_get_current_work_dir()
{
	char *buff = NULL;
    char *tmp = NULL;

	buff = malloc(FILENAME_MAX + 1);
	if(buff == NULL){
        printf("faild to alloc memory to save abs path ");
        return NULL;
    }
	memset(buff, 0, FILENAME_MAX + 1);
#ifdef __APPLE__
  uint32_t size = FILENAME_MAX;
  if (_NSGetExecutablePath(buff, &size) != 0) {
    // Buffer size is too small.
    printf("faild to get current directory");
    return NULL;
  }
  printf("current directory: %s\n", buff);

  tmp = strrchr(buff, '/');
  if(tmp){
      if(buff[tmp - buff - 1] == '.')
          buff[tmp - buff - 1] = '\0';
      else
          buff[tmp - buff] = '\0';
  }
#else
    int read_len = 0;
    read_len = readlink("/proc/self/exe", buff, FILENAME_MAX - 1);
    if(read_len <= 0){
        printf("faild to read /proc ");
        return NULL;
    }
    buff[read_len] = '\0';

    tmp = strrchr(buff, '/');
    if(tmp){
        buff[tmp - buff] = '\0';
    }
#endif
	return buff;
}

#define NAME_REMOTE_ACCESS_DAEMON "RemoteTerminalDaemon"
#define FMT_START_ACCESS_DAEMON   "%s %s %s %s > /dev/null &"
static int open_remote_access_daemon(const char *pk, const char *dn, const char *ds)
{
    struct stat st;
    int ret = 0;
    char *buf = NULL;
    char *path = _get_current_work_dir();

    strcat(path, "/");
    strcat(path, NAME_REMOTE_ACCESS_DAEMON);

    ret = stat(path, &st);

    if (ret == -1) {
        printf("failed to stat %s\n", path);
        free(path);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        printf("%s is not a file\n", path);
        free(path);
        return -2;
    }

    buf = calloc(1, strlen(path) + strlen(pk) + strlen(dn) + strlen(ds) + strlen(FMT_START_ACCESS_DAEMON));
    if(buf == NULL){
        printf("memory is not enough\n");
        free(path);
        return -3;
    }

    sprintf(buf, FMT_START_ACCESS_DAEMON, path, pk, dn, ds);

    ret = system(buf);

    free(path);
    free(buf);
    return ret;
}

int close_remote_access_daemon()
{
    int ret = 0;
    char buf[256] = {0};

    snprintf(buf, sizeof(buf), "ps -eo user,pid,ppid,stat,args | grep \"RemoteTerminalDaemon\" | grep -v \"grep\" | awk '{print $2}' | xargs kill -15");

    ret = system(buf);

    return ret;
}
#define MSG_START_REMOTE_SERVICE "{\"status\":1}"
#define MSG_STOP_REMOTE_SERVICE  "{\"status\":0}"

static void _demo_message_arrive(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    iotx_mqtt_topic_info_pt     ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;

    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            /* print topic name and topic message */
            EXAMPLE_TRACE("----");
            EXAMPLE_TRACE("PacketId: %d", ptopic_info->packet_id);
            EXAMPLE_TRACE("Topic: '%.*s' (Length: %d)",
                          ptopic_info->topic_len,
                          ptopic_info->ptopic,
                          ptopic_info->topic_len);
            EXAMPLE_TRACE("Payload: '%.*s' (Length: %d)",
                          ptopic_info->payload_len,
                          ptopic_info->payload,
                          ptopic_info->payload_len);
            EXAMPLE_TRACE("----");
			if(strncmp(ptopic_info->payload, MSG_START_REMOTE_SERVICE, ptopic_info->payload_len) == 0) {
				EXAMPLE_TRACE("starting remote access daemon...\n");
				open_remote_access_daemon(g_pk, g_dn, g_ds);
			} else if(strncmp(ptopic_info->payload, MSG_STOP_REMOTE_SERVICE, ptopic_info->payload_len) == 0) {
				EXAMPLE_TRACE("stopping remote access daemon...\n");
				close_remote_access_daemon();
			} else {
				EXAMPLE_TRACE("topic ignored...\n");
			} 
            break;
        default:
            EXAMPLE_TRACE("Should NOT arrive here.");
            break;
    }
}

int mqtt_client(void)
{
    int rc, msg_len, cnt = 0;
    void *pclient;
    iotx_conn_info_pt pconn_info;
    iotx_mqtt_param_t mqtt_params;
    iotx_mqtt_topic_info_t topic_msg;
    char msg_pub[128];

    /* Device AUTH */
    if (0 != IOT_SetupConnInfo(g_pk, g_dn, g_ds, (void **)&pconn_info)) {
        EXAMPLE_TRACE("AUTH request failed!");
        return -1;
    }

    /* Initialize MQTT parameter */
    memset(&mqtt_params, 0x0, sizeof(mqtt_params));

    mqtt_params.port = pconn_info->port;
    mqtt_params.host = pconn_info->host_name;
    mqtt_params.client_id = pconn_info->client_id;
    mqtt_params.username = pconn_info->username;
    mqtt_params.password = pconn_info->password;
    mqtt_params.pub_key = pconn_info->pub_key;

    mqtt_params.request_timeout_ms = 2000;
    mqtt_params.clean_session = 0;
    mqtt_params.keepalive_interval_ms = 60000;
    mqtt_params.read_buf_size = MQTT_MSGLEN;
    mqtt_params.write_buf_size = MQTT_MSGLEN;

    mqtt_params.handle_event.h_fp = event_handle;
    mqtt_params.handle_event.pcontext = NULL;


    /* Construct a MQTT client with specify parameter */
    pclient = IOT_MQTT_Construct(&mqtt_params);
    if (NULL == pclient) {
        EXAMPLE_TRACE("MQTT construct failed");
        return -1;
    }

    /* Initialize topic information */
    memset(&topic_msg, 0x0, sizeof(iotx_mqtt_topic_info_t));
    strcpy(msg_pub, "update: hello! start!");

    topic_msg.qos = IOTX_MQTT_QOS1;
    topic_msg.retain = 0;
    topic_msg.dup = 0;
    topic_msg.payload = (void *)msg_pub;
    topic_msg.payload_len = strlen(msg_pub);

    rc = IOT_MQTT_Publish(pclient, g_topic_update, &topic_msg);
    if (rc < 0) {
        IOT_MQTT_Destroy(&pclient);
        EXAMPLE_TRACE("error occur when publish");
        return -1;
    }

    EXAMPLE_TRACE("\n publish message: \n topic: %s\n payload: \%s\n rc = %d", g_topic_update, topic_msg.payload, rc);

    /* Subscribe the specific topic */
    rc = IOT_MQTT_Subscribe(pclient, g_topic_data, IOTX_MQTT_QOS1, _demo_message_arrive, NULL);
    if (rc < 0) {
        IOT_MQTT_Destroy(&pclient);
        EXAMPLE_TRACE("IOT_MQTT_Subscribe() failed, rc = %d", rc);
        return -1;
    }

    IOT_MQTT_Yield(pclient, 200);

    HAL_SleepMs(2000);

    /* Initialize topic information */
    memset(msg_pub, 0x0, 128);
    strcpy(msg_pub, "data: hello! start!");
    memset(&topic_msg, 0x0, sizeof(iotx_mqtt_topic_info_t));
    topic_msg.qos = IOTX_MQTT_QOS1;
    topic_msg.retain = 0;
    topic_msg.dup = 0;
    topic_msg.payload = (void *)msg_pub;
    topic_msg.payload_len = strlen(msg_pub);

    rc = IOT_MQTT_Publish(pclient, g_topic_error, &topic_msg);
    EXAMPLE_TRACE("\n publish message: \n topic: %s\n payload: \%s\n rc = %d", g_topic_error, topic_msg.payload, rc);

    IOT_MQTT_Yield(pclient, 200);

    while(1) {
        /* Generate topic message */
        cnt++;
        msg_len = snprintf(msg_pub, sizeof(msg_pub), "{\"attr_name\":\"temperature\",\"attr_value\":\"%d\"}", cnt);
        if (msg_len < 0) {
            EXAMPLE_TRACE("Error occur! Exit program");
            return -1;
        }

        topic_msg.payload = (void *)msg_pub;
        topic_msg.payload_len = msg_len;

        rc = IOT_MQTT_Publish(pclient, g_topic_error, &topic_msg);
        if (rc < 0) {
            EXAMPLE_TRACE("error occur when publish");
        }
        EXAMPLE_TRACE("packet-id=%u, publish topic msg=%s", (uint32_t)rc, msg_pub);

        /* handle the MQTT packet received from TCP or SSL connection */
        IOT_MQTT_Yield(pclient, 200);

        /* infinite loop if running with 'loop' argument */
        if (user_argc >= 2 && !strcmp("loop", user_argv[1])) {
            HAL_SleepMs(2000);
            cnt = 0;
        }
        HAL_SleepMs(60*1000);
    }

    IOT_MQTT_Yield(pclient, 200);

    IOT_MQTT_Unsubscribe(pclient, g_topic_error);

    IOT_MQTT_Yield(pclient, 200);

    IOT_MQTT_Destroy(&pclient);

    return 0;
}

int linkkit_main(void *paras)
{
    IOT_SetLogLevel(IOT_LOG_CRIT);

    user_argc = 0;
    user_argv = NULL;

    if (paras != NULL) {
        app_main_paras_t *p = (app_main_paras_t *)paras;
        user_argc = p->argc;
        user_argv = p->argv;

        if(user_argc != 4){
            EXAMPLE_TRACE("usage: ./example PK DN DS\n");
            return 0;
        }
    }

    g_pk = user_argv[1];
    g_dn = user_argv[2];
    g_ds = user_argv[3];

    HAL_SetProductKey(g_pk);
    HAL_SetDeviceName(g_dn);
    HAL_SetDeviceSecret(g_ds);

    EXAMPLE_TRACE("pk:  %s, dn:  %s, ds:  %s\n", user_argv[1], user_argv[2], user_argv[3]);
    snprintf(g_topic_update, sizeof(g_topic_update), FMT_TOPIC_UPDATE, g_pk, g_dn);
    snprintf(g_topic_data, sizeof(g_topic_data), FMT_TOPIC_SWITCH, g_pk, g_dn);
    snprintf(g_topic_error, sizeof(g_topic_error), FMT_TOPIC_ERROR, g_pk, g_dn);

    //HAL_SetProductSecret(PRODUCT_SECRET);
    /* Choose Login Server */
    int domain_type = IOTX_CLOUD_REGION_SHANGHAI;
    IOT_Ioctl(IOTX_IOCTL_SET_DOMAIN, (void *)&domain_type);

    /* Choose Login  Method */
    int dynamic_register = 0;
    IOT_Ioctl(IOTX_IOCTL_SET_DYNAMIC_REGISTER, (void *)&dynamic_register);

    mqtt_client();
    IOT_DumpMemoryStats(IOT_LOG_DEBUG);
    IOT_SetLogLevel(IOT_LOG_NONE);

    EXAMPLE_TRACE("out of sample!");

    return 0;
}
