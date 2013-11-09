/*
Copyright (c) 2009-2013 Roger Light <roger@atchoo.org>
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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <config.h>

#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <read_handle.h>
#include <send_mosq.h>
#include <util_mosq.h>

#ifdef WITH_SYS_TREE
extern uint64_t g_pub_bytes_received;
#endif

int mqtt3_packet_handle(struct mosquitto_db *db, struct mosquitto *context)
{
	if(!context) return MOSQ_ERR_INVAL;

	switch((context->in_packet.command)&0xF0){//高4位为消息类型
		case PINGREQ:
			return _mosquitto_handle_pingreq(context);//简单给客户端发送PINGREQ包就行
		case PINGRESP:
			return _mosquitto_handle_pingresp(context);//不需要额外处理
		case PUBACK:
			return _mosquitto_handle_pubackcomp(context, "PUBACK");//我们给客户端发送一条PUBLISH消息，对方返回一条PUBACK表示收到了
		case PUBCOMP:
			return _mosquitto_handle_pubackcomp(context, "PUBCOMP");//对方给我们返回了一个PUBCOMP，也就是QOS2的第四个包，那我们就可以将这条消息直接给弄掉了
		case PUBLISH:
			return mqtt3_handle_publish(db, context);//处理订阅消息
		case PUBREC:
			return _mosquitto_handle_pubrec(context);//对方跟我说，他已经记录了刚才给他的QOS2消息。等待我发送PUBREL
		case PUBREL:
			return _mosquitto_handle_pubrel(db, context);//客户端发送PUBLIS,我们立即回复PUBREC,现在是该对方发送PUBREL的时候了，接到这个就可以真正发布了
		case CONNECT:
			return mqtt3_handle_connect(db, context);//带密码登陆/重登陆
		case DISCONNECT:
			return mqtt3_handle_disconnect(db, context);//客户端主动断开一个连接,这里只是关闭SOCKET，设置state，其他数据都没有动
		case SUBSCRIBE:
			return mqtt3_handle_subscribe(db, context);//订阅一个topic
		case UNSUBSCRIBE:
			return mqtt3_handle_unsubscribe(db, context);//退订一个topic
		default:
			/* If we don't recognise the command, return an error straight away. */
			return MOSQ_ERR_PROTOCOL;
	}
}

int mqtt3_handle_publish(struct mosquitto_db *db, struct mosquitto *context)
{
	char *topic;
	void *payload = NULL;
	uint32_t payloadlen;
	uint8_t dup, qos, retain;
	uint16_t mid = 0;
	int rc = 0;
	uint8_t header = context->in_packet.command;
	int res = 0;
	struct mosquitto_msg_store *stored = NULL;
	int len;
	char *topic_mount;

	dup = (header & 0x08)>>3;
	qos = (header & 0x06)>>1;
	retain = (header & 0x01);

	if(_mosquitto_read_string(&context->in_packet, &topic)) return 1;//读取TOPIC
	if(strlen(topic) == 0){
		/* Invalid publish topic, disconnect client. */
		_mosquitto_free(topic);
		return 1;
	}
	if(_mosquitto_fix_sub_topic(&topic)){//去掉topic上面多余的斜杠
		_mosquitto_free(topic);
		return 1;
	}
	if(!strlen(topic)){
		_mosquitto_free(topic);
		return 1;
	}
	//检查topic中是否有通配符，不允许publish到通配符地址
	if(_mosquitto_topic_wildcard_len_check(topic) != MOSQ_ERR_SUCCESS){
		/* Invalid publish topic, just swallow it. */
		_mosquitto_free(topic);
		return 1;
	}

	if(qos > 0){
		if(_mosquitto_read_uint16(&context->in_packet, &mid)){
			_mosquitto_free(topic);
			return 1;
		}
	}

	payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
#ifdef WITH_SYS_TREE
	g_pub_bytes_received += payloadlen;
#endif
	if(context->listener && context->listener->mount_point){//追加一个配置的前缀
		len = strlen(context->listener->mount_point) + strlen(topic) + 1;
		topic_mount = _mosquitto_calloc(len, sizeof(char));
		if(!topic_mount){
			_mosquitto_free(topic);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, topic);
		_mosquitto_free(topic);
		topic = topic_mount;
	}

	if(payloadlen){//有数据部分，不是空,检查一下消息大小是否不合格，
		if(db->config->message_size_limit && payloadlen > db->config->message_size_limit){
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
			goto process_bad_message;
		}
		//读消息体
		payload = _mosquitto_calloc(payloadlen+1, sizeof(uint8_t));
		if(_mosquitto_read_bytes(&context->in_packet, payload, payloadlen)){
			_mosquitto_free(topic);
			return 1;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(db, context, topic, MOSQ_ACL_WRITE);
	if(rc == MOSQ_ERR_ACL_DENIED){
		_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
		goto process_bad_message;
	}else if(rc != MOSQ_ERR_SUCCESS){
		_mosquitto_free(topic);
		if(payload) _mosquitto_free(payload);
		return rc;
	}

	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, qos, retain, mid, topic, (long)payloadlen);
	if(qos > 0){//检查这个用户是否曾经发过这条消息,QOS大于0的消息ID只能出现一次
		mqtt3_db_message_store_find(context, mid, &stored);
	}
	if(!stored){
		dup = 0;//创建一个mosquitto_msg_store结构，放到db->msg_store的头部，结构里面存储了这条消息的所有信息
		if(mqtt3_db_message_store(db, context->id, mid, topic, qos, payloadlen, payload, retain, &stored, 0)){
			_mosquitto_free(topic);
			if(payload) _mosquitto_free(payload);
			return 1;
		}
	}else{
		dup = 1;
	}
	switch(qos){
		case 0:
			if(mqtt3_db_messages_queue(db, context->id, topic, qos, retain, stored)) rc = 1;
			break;
		case 1:
			//1级消息可以立即发布出去
			if(mqtt3_db_messages_queue(db, context->id, topic, qos, retain, stored)) rc = 1;
			//发送回包
			if(_mosquitto_send_puback(context, mid)) rc = 1;
			break;
		case 2:
			if(!dup){
				//对于2级的消息，不能立即发布，得跟客户端协商后才行。文档：
				//Log the message to persistent storage, do not make it available to interested
				//parties yet, and return a PUBREC message to the sender.
				//将一条消息插入到context->msg链表后面，设置相关的状态。然后记录这条消息给哪些人发送过等
				res = mqtt3_db_message_insert(db, context, mid, mosq_md_in, qos, retain, stored);
			}else{
				res = 0;
			}
			/* mqtt3_db_message_insert() returns 2 to indicate dropped message
			 * due to queue. This isn't an error so don't disconnect them. */
			if(!res){
				if(_mosquitto_send_pubrec(context, mid)) rc = 1;
			}else if(res == 1){
				rc = 1;
			}
			break;
	}
	_mosquitto_free(topic);
	if(payload) _mosquitto_free(payload);

	return rc;
process_bad_message:
	if(topic) _mosquitto_free(topic);
	if(payload) _mosquitto_free(payload);
	switch(qos){
		case 0:
			return MOSQ_ERR_SUCCESS;
		case 1:
			return _mosquitto_send_puback(context, mid);
		case 2:
			mqtt3_db_message_store_find(context, mid, &stored);
			if(!stored){
				if(mqtt3_db_message_store(db, context->id, mid, NULL, qos, 0, NULL, false, &stored, 0)){
					return 1;
				}
				res = mqtt3_db_message_insert(db, context, mid, mosq_md_in, qos, false, stored);
			}else{
				res = 0;
			}
			if(!res){
				res = _mosquitto_send_pubrec(context, mid);
			}
			return res;
	}
	return 1;
}

