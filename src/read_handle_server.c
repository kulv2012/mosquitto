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
#include <assert.h>


#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <read_handle.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <util_mosq.h>

#ifdef WITH_SYS_TREE
extern unsigned int g_connection_count;
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
	int rc;
	int slen;

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

	context->clean_session = clean_session;
	context->ping_t = 0;

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
	context->id = client_id;
	client_id = NULL;

	/* clientid_prefixes check */
	if(db->config->clientid_prefixes){//如果配置文件配置了客户端统一前缀clientid_prefixes，那么所有客户端昵称必须一致
		if(strncmp(db->config->clientid_prefixes, context->id, strlen(db->config->clientid_prefixes))){
			_mosquitto_send_connack(context, CONNACK_REFUSED_NOT_AUTHORIZED);
			mqtt3_context_disconnect(db, context);
			return MOSQ_ERR_SUCCESS;
		}
	}

	if(will){//will指的是如果客户端意外断开连接，那么will Message内容的字符串消息会发布到Will Topic指代的地方
		//申请一个message结构，待会填充到context->will上面
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
		//由于需要记录长度，所以不能一次读取_mosquitto_read_string
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
		//设置will-topic的相关信息，mqtt3_context_disconnect会用，判断连接不是主动断开的话会Publis一条消息
		if(mosquitto_acl_check(db, context, will_topic, MOSQ_ACL_WRITE) != MOSQ_ERR_SUCCESS){
			_mosquitto_send_connack(context, CONNACK_REFUSED_NOT_AUTHORIZED);
			mqtt3_context_disconnect(db, context);
			rc = MOSQ_ERR_SUCCESS;
			goto handle_connect_error;
		}
		context->will = will_struct;
		will_struct = NULL ;//设置为空，避免handle_connect_error释放。放到context上面后续释放即可
		context->will->topic = will_topic;
		will_topic = NULL ;
		if(will_payload){
			context->will->payload = will_payload;
			context->will->payloadlen = will_payloadlen;
			will_payload = NULL ;
		}else{
			context->will->payload = NULL;
			context->will->payloadlen = 0;
		}
		context->will->qos = will_qos;
		context->will->retain = will_retain;
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

	context->username = username;
	context->password = password;
	username = NULL; /* Avoid free() in error: below. */
	password = NULL;

	if(username_flag && password_flag){//如果发送了用户名密码，那么进行用户名密码校验
		//放入待验证的客户端链表头部

		struct _mosquitto_auth_list * tmpauth = _mosquitto_calloc(1, sizeof(struct _mosquitto_auth_list));
		if(tmpauth == NULL){
			_mosquitto_send_connack(context, CONNACK_REFUSED_SERVER_UNAVAILABLE);
			mqtt3_context_disconnect(db, context);
			rc = MOSQ_ERR_SUCCESS;
			goto handle_connect_error;
		}
		context->auth_result = CONNACK_REFUSED_NOT_AUTHORIZED ;
		pthread_mutex_lock(&db->auth_list_mutex) ;
		tmpauth->context = context ;
		tmpauth->next = db->waiting_auth_list ;//如果db->waiting_auth_list为空这里也可以没事的
		assert( context->sock != -1) ;
		db->waiting_auth_list = tmpauth; 

		db->contexts[context->db_index] = NULL ;//暂时将这个链接从contexts中移除出来,待验证完成后，放入finished_auth_list
		context->db_index = -1 ;
		pthread_mutex_unlock(&db->auth_list_mutex) ;
		//rc = mosquitto_unpwd_check(db, context->username, context->password);
		return MOSQ_ERR_SUCCESS ;
	}
	//查看系统是否允许匿名使用
	if(!username_flag && db->config->allow_anonymous == false){
		_mosquitto_send_connack(context, CONNACK_REFUSED_NOT_AUTHORIZED);
		mqtt3_context_disconnect(db, context);
		rc = MOSQ_ERR_SUCCESS;
		goto handle_connect_error;
	}
	//没有用户名，那么OK，继续后面的处理
	rc = mqtt3_handle_post_check_unpwd( db, context) ;
	return rc ;

handle_connect_error:
	if(client_id) _mosquitto_free(client_id);
	if(username) _mosquitto_free(username);
	if(password) _mosquitto_free(password);
	if(will_payload) _mosquitto_free(will_payload);
	if(will_topic) _mosquitto_free(will_topic);
	if(will_struct) _mosquitto_free(will_struct);
	return rc;
}

int try_wakeup_finished_auth_connections( struct mosquitto_db *db ){
	int i=0, dbidx = 0 ;
	struct _mosquitto_auth_list * tofree = NULL;

	pthread_mutex_lock(&db->auth_list_mutex) ; 
	struct _mosquitto_auth_list * tmpauth = db->finished_auth_list ;
	db->finished_auth_list = NULL ;
	while( tmpauth ){
		//将链表每个元素还原到contexts数组里面

		assert(tmpauth->context->sock != -1);
		for(i = dbidx ; i < db->context_count; i++){
			if(db->contexts[i] == NULL){
				db->contexts[i] = tmpauth->context ;
				break ;
			}
		}
		if( i == db->context_count){
			struct mosquitto **tmp_contexts = NULL;
			tmp_contexts = _mosquitto_realloc(db->contexts, sizeof(struct mosquitto*)*(db->context_count+1));
			if(tmp_contexts){
				db->context_count += 1; 
				db->contexts = tmp_contexts;
				db->contexts[i] = tmpauth->context;
			}else{
				//到这里，说明contexts[]数组不够了，而且relloac也失败，怎么办，只能丢掉这个连接了。但是下面并没有return -1,而且还去访问了。是个bug
				// Out of memory
				mqtt3_context_cleanup(NULL, tmpauth->context, true);
				tmpauth = tmpauth->next ;
				continue ;
			}

		}
		//已经将这个连接放到contexts数组了。下面需要完成验证的后面部分
		db->contexts[i]->db_index = i ;
		mqtt3_handle_post_check_unpwd(db, db->contexts[i]) ;
		dbidx = i+1 ;
		tofree = tmpauth ;
		tmpauth = tmpauth->next ;
		_mosquitto_free( tofree ) ;
	}

	pthread_mutex_unlock(&db->auth_list_mutex) ;
	return MOSQ_ERR_SUCCESS ;
}

int mqtt3_handle_post_check_unpwd( struct mosquitto_db *db, struct mosquitto *context ){
	int rc = 0;
	int i = 0;
	struct _clientid_index_hash *find_cih;
	struct _clientid_index_hash *new_cih;
	struct _mosquitto_acl_user *acl_tail;

	if(context->auth_result != CONNACK_ACCEPTED){//密码检查失败
		_mosquitto_send_connack(context, CONNACK_REFUSED_BAD_USERNAME_PASSWORD);
		mqtt3_context_disconnect(db, context);
		rc = MOSQ_ERR_SUCCESS;
		goto handle_connect_post_error;
	}

	/* Find if this client already has an entry. This must be done *after* any security checks. */
	HASH_FIND_STR(db->clientid_index_hash, context->id, find_cih);
	if(find_cih){
		i = find_cih->db_context_index;//这个客户端在db->contexts[]数组中的位置
		/* Found a matching client */
		if(db->contexts[i]->sock == -1){//这个肯定是断开连接后重练的
			/* Client is reconnecting after a disconnect */
			/* FIXME - does anything else need to be done here? */
		}else{//这个是肿么回事?
			/* Client is already connected, disconnect old version */
			if(db->config->connection_messages == true){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Client %s already connected, closing old connection.", context->id);
			}
		}
		//清除上一次连接的相关信息，进行初始化，设置为新连接的信息，这里需要考虑离线消息的问题
		assert( db->contexts[i] != context ) ;
		db->contexts[i]->clean_session = context->clean_session;
		mqtt3_context_cleanup(db, db->contexts[i], false);//可能会关闭多点登陆的旧连接


		db->contexts[i]->state = mosq_cs_connected;
		db->contexts[i]->address = _mosquitto_strdup(context->address);
		db->contexts[i]->sock = context->sock;
		db->contexts[i]->listener = context->listener;
		db->contexts[i]->last_msg_in = mosquitto_time();
		db->contexts[i]->last_msg_out = mosquitto_time();
		db->contexts[i]->keepalive = context->keepalive;
		db->contexts[i]->pollfd_index = context->pollfd_index;
		db->contexts[i]->id = _mosquitto_strdup(context->id);
		if(context->username){
			db->contexts[i]->username = _mosquitto_strdup(context->username);
		}
		if(context->password){
			db->contexts[i]->password = _mosquitto_strdup(context->password);
		}

		_mosquitto_free(context->id);//参考mqtt3_context_cleanup，这里必须设置为空，否则db->clientid_index_hash会在那里被清楚
		context->id = NULL;
		context->sock = -1;
		context->clean_session = 1 ;//让其待会在mosquitto_main_loop里面被清空
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

	// Add the client ID to the DB hash table here
	//已经在里面的不需要增加进去了吧,不是，在mqtt3_context_cleanup里面又del掉了···还得加一次
	new_cih = _mosquitto_malloc(sizeof(struct _clientid_index_hash));
	if(!new_cih){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
		mqtt3_context_disconnect(db, context);
		rc = MOSQ_ERR_NOMEM;
		goto handle_connect_post_error;
	}
	new_cih->id = context->id;
	new_cih->db_context_index = context->db_index;
	HASH_ADD_KEYPTR(hh, db->clientid_index_hash, context->id, strlen(context->id), new_cih);

#ifdef WITH_PERSISTENCE
	if(!context->clean_session){
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

	if(db->config->connection_messages == true){
		_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New client connected from %s as %s (c%d, k%d).", context->address, context->id, context->clean_session, context->keepalive);
	}

	context->state = mosq_cs_connected;
	//给客户端发送连接成功的CONNACK回包
	return _mosquitto_send_connack(context, CONNACK_ACCEPTED);

handle_connect_post_error:
	return rc;
}

int mqtt3_handle_disconnect(struct mosquitto_db *db, struct mosquitto *context)
{//只是将这个sock关闭，设置为INVALID，其连接事件等都没有清楚的，设置了stat为mosq_cs_disconnecting
	if(!context){
		return MOSQ_ERR_INVAL;
	}
	if(context->in_packet.remaining_length != 0){
		return MOSQ_ERR_PROTOCOL;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received DISCONNECT from %s", context->id);
	context->state = mosq_cs_disconnecting;//设置主动断开标识，不会发送will-topic
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
	uint8_t *payload = NULL, *tmp_payload;//SUB的返回包为SUBACK，结构为每一行代表对应的一个topic的QOS
	uint32_t payloadlen = 0;
	int len;
	char *sub_mount;

	if(!context) return MOSQ_ERR_INVAL;
	_mosquitto_log_printf(NULL, MOSQ_LOG_DEBUG, "Received SUBSCRIBE from %s", context->id);
	/* FIXME - plenty of potential for memory leaks here */

	if(_mosquitto_read_uint16(&context->in_packet, &mid)) return 1;

	while(context->in_packet.pos < context->in_packet.remaining_length){
		//SUBSCRIBE消息包括msgid，后面就是topic的列表,一个个取就行
		sub = NULL;
		if(_mosquitto_read_string(&context->in_packet, &sub)){
			if(payload) _mosquitto_free(payload);
			return 1;
		}

		if(sub){
			if(_mosquitto_read_byte(&context->in_packet, &qos)){//1个byte的QOS，高位6为空
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
			if(_mosquitto_fix_sub_topic(&sub)){//把重复的斜杠去掉://////some//aa// -> some/aa/
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

			//将当前的这个topic挂到订阅树里面，树的每一层为路径的一段,树的subs代表订阅的客户端链表，children代表子分支链表
			rc2 = mqtt3_sub_add(db, context, sub, qos, &db->subs);
			if(rc2 == MOSQ_ERR_SUCCESS){//订阅成功了
				//下面需要检查一下这个topic上面是不是有retain保留消息需要发送给这个客户端,里面又会处理一遍订阅树，其实可以合并一起处理嘛
				if(mqtt3_retain_queue(db, context, sub, qos)) rc = 1;
			}else if(rc2 != -1){
				rc = rc2;
			}
			_mosquitto_log_printf(NULL, MOSQ_LOG_SUBSCRIBE, "%s %d %s", context->id, qos, sub);
			_mosquitto_free(sub);//释放这个原始的字符串a/b/c

			tmp_payload = _mosquitto_realloc(payload, payloadlen + 1);
			if(tmp_payload){//这是要返回给客户端的QOS列表,一一对应
				payload = tmp_payload;
				payload[payloadlen] = qos;//QOS级别不变？如果本身的topic的级别不够的话怎么办
				payloadlen++;
			}else{
				if(payload) _mosquitto_free(payload);

				return MOSQ_ERR_NOMEM;
			}
			//搞定一条订阅消息，在订阅的topic上已经记录了这个连接，并且payload[]上面也增加了对应连接的qos准备返回
		}
	}

	//发送SUBACK回包
	if(_mosquitto_send_suback(context, mid, payloadlen, payload)) rc = 1;
	_mosquitto_free(payload);
	
#ifdef WITH_PERSISTENCE
	db->persistence_changes++;
#endif

	return rc;
}

int mqtt3_handle_unsubscribe(struct mosquitto_db *db, struct mosquitto *context)
{// 一条条topic的从订阅树中移除当前连接,然后立即给客户端回包
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
			//从订阅树中移除掉这个订阅
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

