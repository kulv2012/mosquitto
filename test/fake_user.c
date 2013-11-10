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

#include <mosquitto.h>

void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
	char topic[100];

	if(!result){//随机订阅一个topic
		snprintf(topic, 100, "fake/%d", getpid()%100);
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
{
	char id[30];
	char username[32];
	char password[32] ;
	char *host = "211.151.86.220";
	int port = 1883;
	int keepalive = 60;
	bool clean_session = false;
	struct mosquitto *mosq = NULL;
	
	void *will_payload = NULL;
	long will_payloadlen = 0;
	int will_qos = 0;
	bool will_retain = false;
	char will_topic[100], topic[100];
	int pid;

	pid = getpid();

	srand(pid);
	snprintf(id, 30, "fake_user_%d", pid);

	mosquitto_lib_init();
	mosq = mosquitto_new(id, clean_session, NULL);
	if(!mosq){
		fprintf(stderr, "Error: Out of memory.\n");
		return 1;
	}

	if(rand()%5 == 0){
		snprintf(will_topic, 100, "fake/wills/%d", rand()%100);
		if(mosquitto_will_set(mosq, will_topic, will_payloadlen, will_payload, will_qos, will_retain)){
			fprintf(stderr, "Error: Problem setting will.\n");
			return 1;
		}
	}
	mosquitto_connect_callback_set(mosq, my_connect_callback);
	mosquitto_subscribe_callback_set(mosq, my_subscribe_callback) ;
	mosquitto_message_callback_set(mosq, my_message_callback) ;
	while(1){
		//clean_session = rand()%10==0?false:true;

		snprintf(username, 31, "username_%d", rand()%10 ) ;
		snprintf(password, 31, "password_%d", rand()%10 ) ;
		mosquitto_username_pw_set(mosq, username, password) ;

		if(mosquitto_connect(mosq, host, port, keepalive)){
			fprintf(stderr, "Unable to connect.\n");
			return 1;
		}
		mosquitto_subscribe(mosq, NULL, "#", 0);

		while(!mosquitto_loop(mosq, 1, 5)){
			if(rand()%100==0){
				snprintf(topic, 100, "fake/%d", rand()%100);
				mosquitto_publish(mosq, NULL, topic, 10, "0123456789", rand()%3, rand()%2);
				printf("mosquitto_publish:%s = %s\n", topic, "0123456789");
			}
			if(rand()%50==0){
				printf("mosquitto_disconnect\n");
				mosquitto_disconnect(mosq);
			}
		}
		printf("while-end,mosquitto_connect again\n");
		//sleep(10);
	}
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;
}

