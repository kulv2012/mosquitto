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
	char username[32];
	char password[32] ;
	char *host = argv[1];
	int port = atoi( argv[2] );
	int keepalive = 60;
	bool clean_session = false;
	struct mosquitto *mosq = NULL;
	
	char topic[100];

	if( argc == 4 ){
		int i = 0 ;
		int count = atoi(argv[3]) ;
		for(i = 0 ; i < count; ++i){
			if(!fork()){
				break ;
			}
		}
	}
	int pid;

	pid = getpid();

	srand(pid);

	usleep(rand()%1000000) ;
	mosquitto_lib_init();
	while(1){
		//clean_session = rand()%10==0?false:true;
		snprintf(username, 31, "username_%d", rand()%10000 ) ;//模拟10000个人
		snprintf(password, 31, "password_%d", rand()%10000 ) ;
		mosq = mosquitto_new(username, clean_session, NULL);
		if(!mosq){
			fprintf(stderr, "Error: Out of memory.\n");
			return 1;
		}

		mosquitto_connect_callback_set(mosq, my_connect_callback);
		mosquitto_subscribe_callback_set(mosq, my_subscribe_callback) ;
		mosquitto_message_callback_set(mosq, my_message_callback) ;

		mosquitto_username_pw_set(mosq, username, password) ;

		if(mosquitto_connect(mosq, host, port, keepalive)){
			fprintf(stderr, "Unable to connect.\n");
			usleep(1000);
			continue ;
		}

		while(!mosquitto_loop(mosq, 100, 50)){
			if(rand()%10==0){
				snprintf(topic, 100, "/gid/%d", rand()%1000);
				mosquitto_publish(mosq, NULL, topic, 10, "0123456789", rand()%3, 0);
				printf("mosquitto_publish:%s = %s\n", topic, "0123456789");
			}
			if(rand()%100==0){
				printf("mosquitto_disconnect\n");
				mosquitto_disconnect(mosq);
			}
		}
		printf("while-end,mosquitto_connect again\n");
		//sleep(10);
		mosquitto_destroy(mosq);
	}
	mosquitto_lib_cleanup();

	return 0;
}

