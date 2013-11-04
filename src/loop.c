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

#define _GNU_SOURCE

#include <config.h>

#include <assert.h>
#include <poll.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include <time_mosq.h>
#include <util_mosq.h>

#ifndef POLLRDHUP
/* Ignore POLLRDHUP flag on systems where it doesn't exist. */
#define POLLRDHUP 0
#endif

extern bool flag_reload;
#ifdef WITH_PERSISTENCE
extern bool flag_db_backup;
#endif
extern bool flag_tree_print;
extern int run;
#ifdef WITH_SYS_TREE
extern int g_clients_expired;
#endif

static void loop_handle_errors(struct mosquitto_db *db, struct pollfd *pollfds);
static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds);

int mosquitto_main_loop(struct mosquitto_db *db, int *listensock, int listensock_count, int listener_max)
{
	time_t start_time = mosquitto_time();
	time_t last_backup = mosquitto_time();
	time_t last_store_clean = mosquitto_time();
	time_t now;
	int time_count;
	int fdcount;
	sigset_t sigblock, origsig;
	int i;
	struct pollfd *pollfds = NULL;
	int pollfd_count = 0;
	int pollfd_index;

	sigemptyset(&sigblock);
	sigaddset(&sigblock, SIGINT);

	while(run){
#ifdef WITH_SYS_TREE
		mqtt3_db_sys_update(db, db->config->sys_interval, start_time);
#endif

		if(listensock_count + db->context_count > pollfd_count){
			pollfd_count = listensock_count + db->context_count;
			pollfds = _mosquitto_realloc(pollfds, sizeof(struct pollfd)*pollfd_count);
			if(!pollfds){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
				return MOSQ_ERR_NOMEM;
			}
		}

		memset(pollfds, -1, sizeof(struct pollfd)*pollfd_count);

		pollfd_index = 0;
		for(i=0; i<listensock_count; i++){//注册监听sock的pollfd可读事件。也就是新连接事件
			pollfds[pollfd_index].fd = listensock[i];
			pollfds[pollfd_index].events = POLLIN;
			pollfds[pollfd_index].revents = 0;
			pollfd_index++;
		}

		time_count = 0;
		for(i=0; i<db->context_count; i++){//遍历每一个客户端连接,尝试将其加入poll数组中
			if(db->contexts[i]){
				if(time_count > 0){//time_count用来隔1000次循环更新一次now时间
					time_count--;
				}else{
					time_count = 1000;
					now = mosquitto_time();
				}
				db->contexts[i]->pollfd_index = -1;

				if(db->contexts[i]->sock != INVALID_SOCKET){

					/* Local bridges never time out in this fashion. */
					if(!(db->contexts[i]->keepalive) 
							|| db->contexts[i]->bridge
							|| now - db->contexts[i]->last_msg_in < (time_t)(db->contexts[i]->keepalive)*3/2){

						//在进入poll等待之前，先尝试将未发送的数据发送出去
						if(mqtt3_db_message_write(db->contexts[i]) == MOSQ_ERR_SUCCESS){
							pollfds[pollfd_index].fd = db->contexts[i]->sock;
							pollfds[pollfd_index].events = POLLIN | POLLRDHUP;
							pollfds[pollfd_index].revents = 0;
							if(db->contexts[i]->current_out_packet){
								pollfds[pollfd_index].events |= POLLOUT;
							}
							db->contexts[i]->pollfd_index = pollfd_index;
							pollfd_index++;
						}else{//尝试发送失败，连接出问题了
							mqtt3_context_disconnect(db, db->contexts[i]);
						}
					}else{//超过1.5倍的时间，超时关闭连接
						if(db->config->connection_messages == true){
							_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", db->contexts[i]->id);
						}
						/* Client has exceeded keepalive*1.5 */
						mqtt3_context_disconnect(db, db->contexts[i]);//关闭连接，清空数据，后续还可以用.sock=INVALID_SOCKET 
					}
				}else{//db->contexts[i]->sock == INVALID_SOCKET
						if(db->contexts[i]->clean_session == true){
							//这个连接上次由于什么原因，挂了，设置了clean session，所以这里直接彻底清空其结构
							mqtt3_context_cleanup(db, db->contexts[i], true);
							db->contexts[i] = NULL;
						}else if(db->config->persistent_client_expiration > 0){
							//协议规定persistent_client的状态必须永久保存，这里避免连接永远无法删除，增加这个超时选项。
							//也就是如果一个客户端断开连接一段时间了，那么我们会主动干掉他
							/* This is a persistent client, check to see if the
							 * last time it connected was longer than
							 * persistent_client_expiration seconds ago. If so,
							 * expire it and clean up.
							 */
							if(now > db->contexts[i]->disconnect_t+db->config->persistent_client_expiration){
								_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Expiring persistent client %s due to timeout.", db->contexts[i]->id);
#ifdef WITH_SYS_TREE
								g_clients_expired++;
#endif
								db->contexts[i]->clean_session = true;
								mqtt3_context_cleanup(db, db->contexts[i], true);
								db->contexts[i] = NULL;
							}
						}
				}
			}
		}

		//检测消息超时，设置重发标志等,其实没有必要，TCP不会丢包，乱序的
		mqtt3_db_message_timeout_check(db, db->config->retry_interval);

		sigprocmask(SIG_SETMASK, &sigblock, &origsig);
		fdcount = poll(pollfds, pollfd_index, 100);
		//poll返回0代表超时了，没事件。-1代表出错，大于0代表有这么多事件
		sigprocmask(SIG_SETMASK, &origsig, NULL);
		if(fdcount == -1){
			loop_handle_errors(db, pollfds);
		}else{
			loop_handle_reads_writes(db, pollfds);

			for(i=0; i<listensock_count; i++){
				if(pollfds[i].revents & (POLLIN | POLLPRI)){
					while(mqtt3_socket_accept(db, listensock[i]) != -1){
					}
				}
			}
		}
#ifdef WITH_PERSISTENCE
		if(db->config->persistence && db->config->autosave_interval){
			if(db->config->autosave_on_changes){
				if(db->persistence_changes > db->config->autosave_interval){
					mqtt3_db_backup(db, false, false);
					db->persistence_changes = 0;
				}
			}else{
				if(last_backup + db->config->autosave_interval < mosquitto_time()){
					mqtt3_db_backup(db, false, false);
					last_backup = mosquitto_time();
				}
			}
		}
#endif
		if(!db->config->store_clean_interval || last_store_clean + db->config->store_clean_interval < mosquitto_time()){
			mqtt3_db_store_clean(db);
			last_store_clean = mosquitto_time();
		}
#ifdef WITH_PERSISTENCE
		if(flag_db_backup){
			mqtt3_db_backup(db, false, false);
			flag_db_backup = false;
		}
#endif
		if(flag_reload){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Reloading config.");
			mqtt3_config_read(db->config, true);
			mosquitto_security_cleanup(db, true);
			mosquitto_security_init(db, true);
			mosquitto_security_apply(db);
			mqtt3_log_init(db->config->log_type, db->config->log_dest);
			flag_reload = false;
		}
		if(flag_tree_print){
			mqtt3_sub_tree_print(&db->subs, 0);
			flag_tree_print = false;
		}
	}

	if(pollfds) _mosquitto_free(pollfds);
	return MOSQ_ERR_SUCCESS;
}

static void do_disconnect(struct mosquitto_db *db, int context_index)
{
	if(db->config->connection_messages == true){
		if(db->contexts[context_index]->state != mosq_cs_disconnecting){
			_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Socket error on client %s, disconnecting.", db->contexts[context_index]->id);
		}else{
			_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", db->contexts[context_index]->id);
		}
	}
	mqtt3_context_disconnect(db, db->contexts[context_index]);
}

/* Error ocurred, probably an fd has been closed. 
 * Loop through and check them all.
 */
static void loop_handle_errors(struct mosquitto_db *db, struct pollfd *pollfds)
{
	int i;

	for(i=0; i<db->context_count; i++){
		if(db->contexts[i] && db->contexts[i]->sock != INVALID_SOCKET){
			if(pollfds[db->contexts[i]->pollfd_index].revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)){
				do_disconnect(db, i);
			}
		}
	}
}

static void loop_handle_reads_writes(struct mosquitto_db *db, struct pollfd *pollfds)
{
	int i;

	for(i=0; i<db->context_count; i++){
		if(db->contexts[i] && db->contexts[i]->sock != INVALID_SOCKET){
			assert(pollfds[db->contexts[i]->pollfd_index].fd == db->contexts[i]->sock);
			if(pollfds[db->contexts[i]->pollfd_index].revents & POLLOUT){
				//连接可写，则尝试发送数据
				if(_mosquitto_packet_write(db->contexts[i])){
					if(db->config->connection_messages == true){
						if(db->contexts[i]->state != mosq_cs_disconnecting){
							_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Socket write error on client %s, disconnecting.", db->contexts[i]->id);
						}else{
							_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", db->contexts[i]->id);
						}
					}
					/* Write error or other that means we should disconnect */
					mqtt3_context_disconnect(db, db->contexts[i]);
				}
			}
		}
		if(db->contexts[i] && db->contexts[i]->sock != INVALID_SOCKET){
			assert(pollfds[db->contexts[i]->pollfd_index].fd == db->contexts[i]->sock);
			if(pollfds[db->contexts[i]->pollfd_index].revents & POLLIN){
				//连接可读，则读取出书病处理之
				if(_mosquitto_packet_read(db, db->contexts[i])){
					if(db->config->connection_messages == true){
						if(db->contexts[i]->state != mosq_cs_disconnecting){
							_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Socket read error on client %s, disconnecting.", db->contexts[i]->id);
						}else{
							_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", db->contexts[i]->id);
						}
					}
					/* Read error or other that means we should disconnect */
					mqtt3_context_disconnect(db, db->contexts[i]);
				}
			}
		}
		if(db->contexts[i] && db->contexts[i]->sock != INVALID_SOCKET){
			if(pollfds[db->contexts[i]->pollfd_index].revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)){
				do_disconnect(db, i);//连接挂了
			}
		}
	}
}

