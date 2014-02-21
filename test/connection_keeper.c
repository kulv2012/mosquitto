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

#include <mosquitto.h>
#include <mosquitto_internal.h>

void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	char topic[100];

	if(!result){//随机订阅一个topic
		snprintf(topic, 100, "/gid/%d", rand()%1000);
		mosquitto_subscribe(mosq, NULL, topic, rand()%3);
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
int main(int argc, char *argv[])
{// ./fake_user  192.168.1.196 1883 10
	char username[64];
	char password[64] ;
	char *host = argv[1];
	int port = atoi( argv[2] );
	int keepalive = 3600;
	bool clean_session = false;
	struct mosquitto **mosq_cons = NULL;
	
	char topic[128];
	memset(topic, 0, 101) ;

	int con_count = atoi(argv[3]) ;
	int pid;

	pid = getpid();
	srand(pid);
	usleep(rand()%1000000) ;
	mosquitto_lib_init();

	mosq_cons = calloc( con_count, sizeof(struct mosquitto *)) ;

	int i = 0 ;
	for(i = 0 ; i < con_count; ++i){
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
		printf("mosquitto_connect %d success.\n", i) ;
	}
	
	int tmperr = MOSQ_ERR_SUCCESS ;
	while( tmperr == MOSQ_ERR_SUCCESS){
		int curidx = 0;//rand()%con_count ;
		struct mosquitto * tmp = mosq_cons[curidx] ;
		while(tmperr == MOSQ_ERR_SUCCESS ){
			
			tmperr = mosquitto_loop(tmp, 100, 50) ;
			if( tmperr != MOSQ_ERR_SUCCESS){
				printf("mosquitto_loop return error:%d, errno:%d, errmsg:%s\n", tmperr, errno,strerror(errno) ) ;
				break ;
			}
			memset(topic, 0, sizeof(topic)) ;
			snprintf(topic, 100, "/gid/%d", rand()%1000);
			//mosquitto_publish( tmp, NULL, "/gid/222", 10, "0123456789", rand()%3, 0);
			printf("mosquitto_publish :%s = %s\n", topic, "0123456789");
			//printf("mosquitto_publish [client:%s] :%s = %s\n", tmp->username , topic, "0123456789");
			/*if(rand()%100==0){
			  printf("mosquitto_disconnect\n");
			  mosquitto_disconnect(mosq_cons[0]);
			  break ;
			  }*/
			break ;//
			usleep(10) ;
		}
	}
	printf("while-end,mosquitto_connect again\n");
	//sleep(10);

	for(i = 0 ; i < con_count; ++i){
		mosquitto_disconnect(mosq_cons[i]);
		mosquitto_destroy(mosq_cons[i]);
	}
	free( (void*)mosq_cons ) ;

	mosquitto_lib_cleanup();

	return 0;
}

