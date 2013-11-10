/*
Copyright (c) 2010,2011,2013 Roger Light <roger@atchoo.org>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of mosquitto nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _MOSQUITTO_INTERNAL_H_
#define _MOSQUITTO_INTERNAL_H_



#include <stdlib.h>

#if defined(WITH_THREADING) 
#  include <pthread.h>
#else
#  include <dummypthread.h>
#endif

#	include <stdint.h>

#include "mosquitto.h"
#include "time_mosq.h"
#ifdef WITH_BROKER
struct mosquitto_client_msg;
#endif

enum mosquitto_msg_direction {
	mosq_md_in = 0,
	mosq_md_out = 1
};

enum mosquitto_msg_state {
	mosq_ms_invalid = 0,
	mosq_ms_publish_qos0 = 1,
	mosq_ms_publish_qos1 = 2,
	mosq_ms_wait_for_puback = 3,
	mosq_ms_publish_qos2 = 4,
	mosq_ms_wait_for_pubrec = 5,
	mosq_ms_resend_pubrel = 6,
	mosq_ms_wait_for_pubrel = 7,
	mosq_ms_resend_pubcomp = 8,
	mosq_ms_wait_for_pubcomp = 9,
	mosq_ms_send_pubrec = 10,
	mosq_ms_queued = 11	//消息等待发送,之所以有这个状态，是因为有最大inflight消息限制，比如max_inflight，也就是说没有稳妥搞定的消息最大条数
};

enum mosquitto_client_state {
	mosq_cs_new = 0,
	mosq_cs_connected ,
	mosq_cs_disconnecting ,
	mosq_cs_connect_async,
	mosq_cs_connect_pending
};

struct _mosquitto_packet{
	uint8_t command;//4 Message Type|1 DUP flag|2 QoS level|1 RETAIN
	uint8_t have_remaining;//是否已经读取完了remaining length字段
	uint8_t remaining_count;// remaining字段包含几个字节
	uint16_t mid;
	uint32_t remaining_mult;
	uint32_t remaining_length;//remaining字段的表示的长度，也就是数据长度
	uint32_t packet_length;
	uint32_t to_process;//还有这么多数据没有读取完成
	uint32_t pos;
	uint8_t *payload;
	struct _mosquitto_packet *next;
};

struct mosquitto_message_all{
	struct mosquitto_message_all *next;
	time_t timestamp;
	enum mosquitto_msg_direction direction;
	enum mosquitto_msg_state state;
	bool dup;
	struct mosquitto_message msg;
};

struct mosquitto {
	int sock;
	char *address;
	char *id;//客户端的id
	char *username;
	char *password;
	uint16_t keepalive;//客户端发送过来的keepalive时间
	bool clean_session;
	enum mosquitto_client_state state;
	time_t last_msg_in;
	time_t last_msg_out;
	time_t ping_t;
	uint16_t last_mid;//这个连接的上一个msgid
	struct _mosquitto_packet in_packet;//客户端发送过来的最后一个包
	struct _mosquitto_packet *current_out_packet;//当前正在发送中的数据包，可能只发送了一部分
	struct _mosquitto_packet *out_packet;//待发送出去的包的链表
	struct mosquitto_message *will;
#if defined(WITH_THREADING) && !defined(WITH_BROKER)
	pthread_mutex_t callback_mutex;
	pthread_mutex_t log_callback_mutex;
	pthread_mutex_t msgtime_mutex;
	pthread_mutex_t out_packet_mutex;
	pthread_mutex_t current_out_packet_mutex;
	pthread_mutex_t state_mutex;
	pthread_mutex_t message_mutex;
	pthread_t thread_id;
#endif
#ifdef WITH_BROKER
	bool is_bridge;
	struct _mqtt3_bridge *bridge;
	struct mosquitto_client_msg *msgs;//这个连接的消息链表,新的放在后面，输入输出消息都放在这里
	struct _mosquitto_acl_user *acl_list;
	struct _mqtt3_listener *listener; //指向我所属的listener的db->config->listeners[i]位置
	time_t disconnect_t;
	int pollfd_index;
	int db_index;//记住我在db->contexts中的下标
	struct _mosquitto_packet *out_packet_last;//快速指向待输出数据列表的索引，mosq->out_packet_last->next = packet

	int auth_result ;
#else
	void *userdata;
	bool in_callback;
	unsigned int message_retry;
	time_t last_retry_check;
	struct mosquitto_message_all *messages;
	void (*on_connect)(struct mosquitto *, void *userdata, int rc);
	void (*on_disconnect)(struct mosquitto *, void *userdata, int rc);
	void (*on_publish)(struct mosquitto *, void *userdata, int mid);
	void (*on_message)(struct mosquitto *, void *userdata, const struct mosquitto_message *message);
	void (*on_subscribe)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos);
	void (*on_unsubscribe)(struct mosquitto *, void *userdata, int mid);
	void (*on_log)(struct mosquitto *, void *userdata, int level, const char *str);
	//void (*on_error)();
	char *host;
	int port;
	int queue_len;
	char *bind_address;
	unsigned int reconnect_delay;
	unsigned int reconnect_delay_max;
	bool reconnect_exponential_backoff;
	bool threaded;
	struct _mosquitto_packet *out_packet_last;
	struct mosquitto_message_all *messages_last;
	int inflight_messages;
	int max_inflight_messages;
#endif
};

#endif
