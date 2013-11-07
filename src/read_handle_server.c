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

#include <stdio.h>
#include <string.h>

#include <config.h>

#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <tls_mosq.h>
#include <util_mosq.h>

#ifdef WITH_SYS_TREE
extern unsigned int g_connection_count;
#endif

int mqtt3_handle_connect(struct mosquitto_db *db, struct mosquitto *context)
{
	char *protocol_name = NULL;
	uint8_t protocol_version;
	uint8_t connect_flags;
	char *client_id = NULL;
	char *will_payload = NULL, *will_topic = NULL;
	uint16_t will_payloadlen;
	struct mosquitto_message *will_struct = NULL;
	uint8_t will, will_retain, will_qos, clean_session;
	uint8_t username_flag, password_flag;
	char *username = NULL, *password = NULL;
	int i;
	int rc;
	struct _mosquitto_acl_user *acl_tail;
	int slen;
	struct _clientid_index_hash *find_cih;
	struct _clientid_index_hash *new_cih;

#ifdef WITH_SYS_TREE
	g_connection_count++;
#endif

	/* Don't accept multiple CONNECT commands. */
	if(context->state != mosq_cs_new){//已经connect过了
		mqtt3_context_disconnect(db, context);
		return MOSQ_ERR_PROTOCOL;
	}

	//读取开头的协议名称
	if(_mosquitto_read_string(&context->in_packet, &protocol_name)){
		mqtt3_context_disconnect(db, context);
		return 1;
	}
	if(!protocol_name){
		mqtt3_context_disconnect(db, context);
		return 3;
	}
	if(strcmp(protocol_name, PROTOCOL_NAME)){//协议名必须为"MQIsdp"
		if(db->config->connection_messages == true){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid protocol \"%s\" in CONNECT from %s.",
					protocol_name, context->address);
		}
		_mosquitto_free(protocol_name);
		mqtt3_context_disconnect(db, context);
		return MOSQ_ERR_PROTOCOL;
	}//协议名只是为了检验是否为"MQIsdp"的，只后就没用啦 
	_mosquitto_free(protocol_name);

	if(_mosquitto_read_byte(&context->in_packet, &protocol_version)){//8 个字节的协议号
		mqtt3_context_disconnect(db, context);
		return 1;
	}
	if((protocol_version&0x7F) != PROTOCOL_VERSION){//协议名必须是3版本
		if(db->config->connection_messages == true){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid protocol version %d in CONNECT from %s.",
					protocol_version, context->address);
		}
		_mosquitto_send_connack(context, CONNACK_REFUSED_PROTOCOL_VERSION);
		mqtt3_context_disconnect(db, context);
		return MOSQ_ERR_PROTOCOL;
	}
	if((protocol_version&0x80) == 0x80){//发送这种协议来的，就认为是bridge
		context->is_bridge = true;
	}

	//下面读取各个标志
	if(_mosquitto_read_byte(&context->in_packet, &connect_flags)){
		mqtt3_context_disconnect(db, context);
		return 1;
	}
	clean_session = connect_flags & 0x02;
	will = connect_flags & 0x04;
	will_qos = (connect_flags & 0x18) >> 3;
	will_retain = connect_flags & 0x20;
	password_flag = connect_flags & 0x40;
	username_flag = connect_flags & 0x80;

	if(_mosquitto_read_uint16(&context->in_packet, &(context->keepalive))){
		mqtt3_context_disconnect(db, context);
		return 1;
	}

	//客户端ID是必须有的，flags无法控制
	if(_mosquitto_read_string(&context->in_packet, &client_id)){
		mqtt3_context_disconnect(db, context);
		return 1;
	}

	slen = strlen(client_id);
#ifdef WITH_STRICT_PROTOCOL
	if(slen > 23 || slen == 0){
#else
	if(slen == 0){
#endif
		_mosquitto_free(client_id);
		_mosquitto_send_connack(context, CONNACK_REFUSED_IDENTIFIER_REJECTED);
		mqtt3_context_disconnect(db, context);
		return 1;
	}

	/* clientid_prefixes check */
	if(db->config->clientid_prefixes){//如果配置文件配置了客户端统一前缀clientid_prefixes，那么所有客户端昵称必须一致
		if(strncmp(db->config->clientid_prefixes, client_id, strlen(db->config->clientid_prefixes))){
			_mosquitto_free(client_id);
			_mosquitto_send_connack(context, CONNACK_REFUSED_NOT_AUTHORIZED);
			mqtt3_context_disconnect(db, context);
			return MOSQ_ERR_SUCCESS;
		}
	}

	if(will){//刚开始的时候将Will Message消息发布到Will Topic指代的地方，这里暂时只读取数据
		will_struct = _mosquitto_calloc(1, sizeof(struct mosquitto_message));
		if(!will_struct){
			mqtt3_context_disconnect(db, context);
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}
		if(_mosquitto_read_string(&context->in_packet, &will_topic)){
			mqtt3_context_disconnect(db, context);
			rc = 1;
			goto handle_connect_error;
		}
		if(strlen(will_topic) == 0){
			/* FIXME - CONNACK_REFUSED_IDENTIFIER_REJECTED not really appropriate here. */
			_mosquitto_send_connack(context, CONNACK_REFUSED_IDENTIFIER_REJECTED);
			mqtt3_context_disconnect(db, context);
			rc = 1;
			goto handle_connect_error;
		}
		if(_mosquitto_read_uint16(&context->in_packet, &will_payloadlen)){
			mqtt3_context_disconnect(db, context);
			rc = 1;
			goto handle_connect_error;
		}
		will_payload = _mosquitto_malloc(will_payloadlen);
		if(!will_payload){
			mqtt3_context_disconnect(db, context);
			rc = 1;
			goto handle_connect_error;
		}

		rc = _mosquitto_read_bytes(&context->in_packet, will_payload, will_payloadlen);
		if(rc){
			mqtt3_context_disconnect(db, context);
			rc = 1;
			goto handle_connect_error;
		}
	}

	if(username_flag){//读取用户名密码
		rc = _mosquitto_read_string(&context->in_packet, &username);
		if(rc == MOSQ_ERR_SUCCESS){
			if(password_flag){
				rc = _mosquitto_read_string(&context->in_packet, &password);
				if(rc == MOSQ_ERR_NOMEM){
					rc = MOSQ_ERR_NOMEM;
					goto handle_connect_error;
				}else if(rc == MOSQ_ERR_PROTOCOL){
					/* Password flag given, but no password. Ignore. */
					password_flag = 0;
				}
			}
		}else if(rc == MOSQ_ERR_NOMEM){
			rc = MOSQ_ERR_NOMEM;
			goto handle_connect_error;
		}else{
			/* Username flag given, but no username. Ignore. */
			username_flag = 0;
		}
	}

	if(username_flag){//如果发送了用户名密码，那么进行用户名密码校验
		rc = mosquitto_unpwd_check(db, username, password);
		if(rc == MOSQ_ERR_AUTH){//密码检查失败
			_mosquitto_send_connack(context, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
			mqtt3_context_disconnect(db, context);
			rc = MOSQ_ERR_SUCCESS;
			goto handle_connect_error;
		}else if(rc == MOSQ_ERR_INVAL){
			goto handle_connect_error;
		}
		context->username = username;
		context->password = password;
		username = NULL; /* Avoid free() in error: below. */
		password = NULL;
	}

	//查看系统是否允许匿名使用
	if(!username_flag && db->config->allow_anonymous == false){
		_mosquitto_send_connack(context, CONNACK_REFUSED_NOT_AUTHORIZED);
		mqtt3_context_disconnect(db, context);
		rc = MOSQ_ERR_SUCCESS;
		goto handle_connect_error;
	}

	/* Find if this client already has an entry. This must be done *after* any security checks. */
	HASH_FIND_STR(db->clientid_index_hash, client_id, find_cih);
	if(find_cih){
		i = find_cih->db_context_index;//这个客户端在db->contexts[]数组中的位置
		/* Found a matching client */
		if(db->contexts[i]->sock == -1){//这个肯定是断开连接后重练的
			/* Client is reconnecting after a disconnect */
			/* FIXME - does anything else need to be done here? */
		}else{//这个是肿么回事?
			/* Client is already connected, disconnect old version */
			if(db->config->connection_messages == true){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Client %s already connected, closing old connection.", client_id);
			}
		}
		//清除上一次连接的相关信息，进行初始化，设置为新连接的信息，这里需要考虑离线消息的问题
		db->contexts[i]->clean_session = clean_session;
		mqtt3_context_cleanup(db, db->contexts[i], false);//可能会关闭多点登陆的旧连接

		db->contexts[i]->state = mosq_cs_connected;
		db->contexts[i]->address = _mosquitto_strdup(context->address);
		db->contexts[i]->sock = context->sock;
		db->contexts[i]->listener = context->listener;
		db->contexts[i]->last_msg_in = mosquitto_time();
		db->contexts[i]->last_msg_out = mosquitto_time();
		db->contexts[i]->keepalive = context->keepalive;
		db->contexts[i]->pollfd_index = context->pollfd_index;
		if(context->username){
			db->contexts[i]->username = _mosquitto_strdup(context->username);
		}
		context->sock = -1;
		context->state = mosq_cs_disconnecting;
		//上面这行是什么作用? 这个指针拿掉后，就没了，内存泄露？
		//不是这样的，因为这个函数的上层调用方式为loop_handle_reads_writes()->_mosquitto_packet_read(db, db->contexts[i])
		//也就是这里的context其实是db->contexts数组的某一项，因此这里由于已经知道client_id了，而且其曾经存在于某contexts项
		//因此找到那一项后，将context上的数据拷贝到之前的记录中，然后将当前记录设置为sock = -1。state = mosq_cs_disconnecting
		context = db->contexts[i];//交换使用旧的context
		if(context->msgs){//旧的连接上还有数据挂着···
			//所以需要将状态设置为一个OK的状态，重发上次的数据等，这里要小心重发的问题，别让客户端记录历史数据包
			//里面的代码可能有bug
			mqtt3_db_message_reconnect_reset(context);
		}
	}

	context->id = client_id;
	client_id = NULL;
	context->clean_session = clean_session;
	context->ping_t = 0;

	// Add the client ID to the DB hash table here
	//已经在里面的不需要增加进去了吧
	new_cih = _mosquitto_malloc(sizeof(struct _clientid_index_hash));
	if(!new_cih){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		mqtt3_context_disconnect(db, context);
		rc = MOSQ_ERR_NOMEM;
		goto handle_connect_error;
	}
	new_cih->id = context->id;
	new_cih->db_context_index = context->db_index;
	HASH_ADD_KEYPTR(hh, db->clientid_index_hash, context->id, strlen(context->id), new_cih);

#ifdef WITH_PERSISTENCE
	if(!clean_session){
		db->persistence_changes++;
	}
#endif
	/* Associate user with its ACL, assuming we have ACLs loaded. */
	if(db->acl_list){
		acl_tail = db->acl_list;
		while(acl_tail){
			if(context->username){
				if(acl_tail->username && !strcmp(context->username, acl_tail->username)){
					context->acl_list = acl_tail;
					break;
				}
			}else{
				if(acl_tail->username == NULL){
					context->acl_list = acl_tail;
					break;
				}
			}
			acl_tail = acl_tail->next;
		}
	}else{
		context->acl_list = NULL;
	}

	if(will_struct){
		if(mosquitto_acl_check(db, context, will_topic, MOSQ_ACL_WRITE) != MOSQ_ERR_SUCCESS){
			_mosquitto_send_connack(context, CONNACK_REFUSED_NOT_AUTHORIZED);
			mqtt3_context_disconnect(db, context);
			rc = MOSQ_ERR_SUCCESS;
			goto handle_connect_error;
		}
		context->will = will_struct;
		context->will->topic = will_topic;
		if(will_payload){
			context->will->payload = will_payload;
			context->will->payloadlen = will_payloadlen;
		}else{
			context->will->payload = NULL;
			context->will->payloadlen = 0;
		}
		context->will->qos = will_qos;
		context->will->retain = will_retain;
	}

	if(db->config->connection_messages == true){
		_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s as %s (c%d, k%d).", context->address, context->id, context->clean_session, context->keepalive);
	}

	context->state = mosq_cs_connected;
	//给客户端发送连接成功的CONNACK回包
	return _mosquitto_send_connack(context, CONNACK_ACCEPTED);

handle_connect_error:
	if(client_id) _mosquitto_free(client_id);
	if(username) _mosquitto_free(username);
	if(will_payload) _mosquitto_free(will_payload);
	if(will_topic) _mosquitto_free(will_topic);
	if(will_struct) _mosquitto_free(will_struct);
	return rc;
}

int mqtt3_handle_disconnect(struct mosquitto_db *db, struct mosquitto *context)
{
	if(!context){
		return MOSQ_ERR_INVAL;
	}
	if(context->in_packet.remaining_length != 0){
		return MOSQ_ERR_PROTOCOL;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received DISCONNECT from %s", context->id);
	context->state = mosq_cs_disconnecting;
	mqtt3_context_disconnect(db, context);
	return MOSQ_ERR_SUCCESS;
}


int mqtt3_handle_subscribe(struct mosquitto_db *db, struct mosquitto *context)
{
	int rc = 0;
	int rc2;
	uint16_t mid;
	char *sub;
	uint8_t qos;
	uint8_t *payload = NULL, *tmp_payload;
	uint32_t payloadlen = 0;
	int len;
	char *sub_mount;

	if(!context) return MOSQ_ERR_INVAL;
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received SUBSCRIBE from %s", context->id);
	/* FIXME - plenty of potential for memory leaks here */

	if(_mosquitto_read_uint16(&context->in_packet, &mid)) return 1;

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(_mosquitto_read_string(&context->in_packet, &sub)){
			if(payload) _mosquitto_free(payload);
			return 1;
		}

		if(sub){
			if(_mosquitto_read_byte(&context->in_packet, &qos)){
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}
			if(qos > 2){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Invalid QoS in subscription command from %s, disconnecting.",
					context->address);
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}
			if(_mosquitto_fix_sub_topic(&sub)){
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}
			if(!strlen(sub)){
				_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Empty subscription string from %s, disconnecting.",
					context->address);
				_mosquitto_free(sub);
				if(payload) _mosquitto_free(payload);
				return 1;
			}
			if(context->listener && context->listener->mount_point){
				len = strlen(context->listener->mount_point) + strlen(sub) + 1;
				sub_mount = _mosquitto_calloc(len, sizeof(char));
				if(!sub_mount){
					_mosquitto_free(sub);
					if(payload) _mosquitto_free(payload);
					return MOSQ_ERR_NOMEM;
				}
				snprintf(sub_mount, len, "%s%s", context->listener->mount_point, sub);
				_mosquitto_free(sub);
				sub = sub_mount;

			}
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "\t%s (QoS %d)", sub, qos);

			rc2 = mqtt3_sub_add(db, context, sub, qos, &db->subs);
			if(rc2 == MOSQ_ERR_SUCCESS){
				if(mqtt3_retain_queue(db, context, sub, qos)) rc = 1;
			}else if(rc2 != -1){
				rc = rc2;
			}
			_mosquitto_log_printf(NULL, MOSQ_LOG_SUBSCRIBE, "%s %d %s", context->id, qos, sub);
			_mosquitto_free(sub);

			tmp_payload = _mosquitto_realloc(payload, payloadlen + 1);
			if(tmp_payload){
				payload = tmp_payload;
				payload[payloadlen] = qos;
				payloadlen++;
			}else{
				if(payload) _mosquitto_free(payload);

				return MOSQ_ERR_NOMEM;
			}
		}
	}

	if(_mosquitto_send_suback(context, mid, payloadlen, payload)) rc = 1;
	_mosquitto_free(payload);
	
#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	return rc;
}

int mqtt3_handle_unsubscribe(struct mosquitto_db *db, struct mosquitto *context)
{
	uint16_t mid;
	char *sub;

	if(!context) return MOSQ_ERR_INVAL;
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBSCRIBE from %s", context->id);

	if(_mosquitto_read_uint16(&context->in_packet, &mid)) return 1;

	while(context->in_packet.pos < context->in_packet.remaining_length){
		sub = NULL;
		if(_mosquitto_read_string(&context->in_packet, &sub)){
			return 1;
		}

		if(sub){
			_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "\t%s", sub);
			mqtt3_sub_remove(db, context, sub, &db->subs);
			_mosquitto_log_printf(NULL, MOSQ_LOG_UNSUBSCRIBE, "%s %s", context->id, sub);
			_mosquitto_free(sub);
		}
	}
#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	return _mosquitto_send_command_with_mid(context, UNSUBACK, mid, false);
}

