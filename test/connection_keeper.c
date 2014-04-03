/*
Copyright (c) 2009,2010, Roger Light <roger@atchoo.org>
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <mosquitto.h>
#include <mosquitto_internal.h>
#include "ae/ae.c"


int on_tcp_write(aeEventLoop *el, int listensock, void *privdata, int mask )  ;


int g_topichashcnt = 500000 ;

aeEventLoop *eventloop ;
struct mosquitto **mosq_cons = NULL;
int maxConn = 0 ;

char* fill_topic_str( char * buf, int randid){
	int gid = randid % g_topichashcnt ;
	//snprintf(buf, 100, "/gid/%d/%d", gid%10000, gid);
	snprintf(buf, 100, "/gid/%d", gid);
	return buf ;
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	char topic[101];

	if(!result){//随机订阅一个topic
		int tmpi = 0 ;
		for(tmpi = 0 ; tmpi < 3; tmpi ++ ){
			fill_topic_str( topic, rand()); 
			mosquitto_subscribe(mosq, NULL, topic, 0);
		}

		int res = aeCreateFileEvent(eventloop, mosq->sock, AE_WRITABLE, on_tcp_write , (void*)mosq) ;
		if( res != 0 ){
			printf("aeCreateFileEvent failed:%d, username:%s\n", res, mosq->username);
			exit(-1);
		}
	}
	printf("my_connect_callback, result[%d]\n", result);
}
void my_subscribe_callback(struct mosquitto *mosq, void *userdata, int mid, int qos_count, const int *granted_qos){
	//mosq->on_subscribe(mosq, mosq->userdata, mid, qos_count, granted_qos);
	printf("my_subscribe_callback called.msgid:[%d]\n", (int)mid);
}

void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	struct userdata *ud;

	assert(obj);
	ud = (struct userdata *)obj;

	if(message->payloadlen){
		printf("my_message_callback:msg[%s]\n", (const char *)message->payload);
	}
}

int on_tcp_read(aeEventLoop *el, int listensock, void *privdata, int mask ) {

	struct mosquitto *mosq = (struct mosquitto *)privdata ;
	int res = mosquitto_loop_read(mosq, 50) ;
	if( res != MOSQ_ERR_SUCCESS){
		return res ;
	}
	mosquitto_loop_misc(mosq);
	if( res != MOSQ_ERR_SUCCESS){
		return res ;
	}
	return MOSQ_ERR_SUCCESS ;
}
int on_tcp_write(aeEventLoop *el, int listensock, void *privdata, int mask ) {

	struct mosquitto *mosq = (struct mosquitto *)privdata ;
	int res = mosquitto_loop_write(mosq, 50) ;
	if( res != MOSQ_ERR_SUCCESS){
		return res ;
	}
	mosquitto_loop_misc(mosq);
	if( res != MOSQ_ERR_SUCCESS){
		return res ;
	}

	if( !mosquitto_want_write(mosq) ) {
		aeDeleteFileEvent(el, mosq->sock, AE_WRITABLE) ;
	}	
	return MOSQ_ERR_SUCCESS ;
}

int serverCron(struct aeEventLoop *eventLoop, long long id, void *clientData){
	char topic[128] ;
	char payload[128] ;
	int tmpcon = rand()%maxConn ;
	struct mosquitto *mosq = mosq_cons[tmpcon] ;
	if( mosq != NULL) {
		memset(topic, 0, sizeof(topic)) ;
		fill_topic_str( topic, rand()); 
		snprintf(payload, 100, "payload_%d", rand());
		mosquitto_publish( mosq, NULL, topic, strlen(payload), payload, 0, 0);
		int res = aeCreateFileEvent(eventloop, mosq->sock, AE_WRITABLE, on_tcp_write , (void*)mosq) ;
		if( res != 0 ){
			printf("aeCreateFileEvent failed:%d, username:%s\n", res, mosq->username);
			exit(-1);
		}
		printf("mosquitto_publish con:%d, topic:%s, data:%s\n", tmpcon, topic, payload);
	}
	return 100 ;
}


int main(int argc, char *argv[])
{// ./fake_user  192.168.1.196 1883 10
	char username[64];
	char password[64] ;
	char *host = argv[1];
	int port = atoi( argv[2] );
	int keepalive = 2*86400;
	bool clean_session = false;
	
	char topic[128];
	memset(topic, 0, 101) ;

	maxConn = atoi(argv[3]) ;
	int pid;

	pid = getpid();
	srand(pid);
	usleep(rand()%1000000) ;
	mosquitto_lib_init();

	mosq_cons = calloc( maxConn, sizeof(struct mosquitto *)) ;

	eventloop = aeCreateEventLoop(600000+1024);
	int servercronid = aeCreateTimeEvent(eventloop, 500, serverCron, NULL, NULL) ;

	int i = 0 ;
	for(i = 0 ; i < maxConn; ++i){
		snprintf(username, 31, "%d_username_%d", pid, i ) ;
		snprintf(password, 31, "%d_password_%d", pid, i ) ;
		mosq_cons[i] = mosquitto_new(username, clean_session, NULL);
		if(!mosq_cons[i]){
			fprintf(stderr, "Error: Out of memory.\n");
			return 1;
		}

		mosquitto_connect_callback_set(mosq_cons[i], my_connect_callback);
		mosquitto_subscribe_callback_set(mosq_cons[i], my_subscribe_callback) ;
		mosquitto_message_callback_set(mosq_cons[i], my_message_callback) ;
		mosquitto_username_pw_set(mosq_cons[i], username, password) ;

		if(mosquitto_connect(mosq_cons[i], host, port, keepalive)){
			fprintf(stderr, "Unable to connect.\n");
			usleep(1000);
			continue ;
		}

		int res = aeCreateFileEvent(eventloop, mosq_cons[i]->sock, AE_READABLE, on_tcp_read , (void*)mosq_cons[i]) ;
		if( res != 0 ){
			printf("aeCreateFileEvent failed:%d, username:%s\n", res, username);
			exit(-1);
		}
		printf("mosquitto_connect %d success. username:%s, pwd:%s\n", i, username, password) ;
	}
	
	int tmperr = MOSQ_ERR_SUCCESS ;
	while( tmperr == MOSQ_ERR_SUCCESS){

			struct timeval tv ;
			getMinWaitTime(eventloop, &tv) ;
			int numevents = aeApiPoll(eventloop, &tv);
			int j = 0 , rnum = 0, wnum = 0;
			for (j = 0; j < numevents; j++) {
				
				aeFileEvent *fe = &eventloop->events[eventloop->fired[j].fd];
				struct mosquitto *mosq = (struct mosquitto *)fe->clientData ;

				int mask = eventloop->fired[j].mask;
				int fd = eventloop->fired[j].fd;
				int rfired = 0, rc = 0 ;
				if (fe->mask & mask & AE_READABLE) {
					++rnum ;
					rfired = 1;
					rc = fe->rfileProc(eventloop,fd,fe->clientData,mask);//_mosquitto_packet_read
				}
				if (fe->mask & mask & AE_WRITABLE) {
					++rnum ;
					rfired = 1;
					rc = fe->wfileProc(eventloop,fd,fe->clientData,mask);
				}
				if( rc != MOSQ_ERR_SUCCESS){
					aeDeleteFileEvent(eventloop, mosq->sock, AE_READABLE);
					aeDeleteFileEvent(eventloop, mosq->sock, AE_WRITABLE);
					int tmpi = 0 ;
					for(tmpi = 0 ; i < maxConn; ++tmpi) { 
						if( mosq == mosq_cons[tmpi]) {
							mosquitto_destroy(mosq);
							mosq_cons[tmpi] = NULL ;
						}
					}
				}

			}
			processTimeEvents(eventloop) ;

	}
	printf("while-end,mosquitto_connect again\n");
	//sleep(10);

	aeDeleteTimeEvent(eventloop, servercronid ) ; 
	for(i = 0 ; i < maxConn; ++i){
		mosquitto_disconnect(mosq_cons[i]);
		mosquitto_destroy(mosq_cons[i]);
	}
	free( (void*)mosq_cons ) ;

	mosquitto_lib_cleanup();

	return 0;
}

