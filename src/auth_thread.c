#include <stdio.h>
#include <string.h>
#include <assert.h>


#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <util_mosq.h>
#include <pthread.h>



extern int run;


int auth_thread_init(struct mosquitto_db *db){
	int res = 0;
	pthread_mutex_init(&db->auth_list_mutex, NULL);

	res = pthread_create( &db->auth_thread_id, NULL,_mosquitto_auth_thread_main, db) ;
	if( res != 0 ){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "pthread_create() call failed.error[%d] info is %s.", res, strerror(res)) ;
		return -1 ;
	}
	return 0 ;
}


int auth_thread_destroy(struct mosquitto_db *db){

	pthread_join( db->auth_thread_id, NULL) ;
	pthread_mutex_destroy(&db->auth_list_mutex);

	return 0 ;
}


void *_mosquitto_auth_thread_main(void *obj){
	struct mosquitto_db *db = (struct mosquitto_db *)obj ;
	struct mosquitto * context = NULL;
	db= db ;
	while(run){
		struct _mosquitto_auth_list * waitauthlist = NULL ;
		if(db->waiting_auth_list != NULL){//顺便做一次判断，减少锁	
			
			pthread_mutex_lock(&db->auth_list_mutex) ; 
			waitauthlist = db->waiting_auth_list ;
			db->waiting_auth_list = NULL ;//一次全部处理完，避免多次加速，提高效率
			pthread_mutex_unlock(&db->auth_list_mutex) ;
		}
		struct _mosquitto_auth_list *head = waitauthlist ;
		while(waitauthlist){
			context = waitauthlist->context ;
			assert( context->sock != -1 ) ;
			if(strcmp(context->username, context->password) == 0){
				//context->auth_result = CONNACK_REFUSED_BAD_USERNAME_PASSWORD ;
				context->auth_result = CONNACK_ACCEPTED ;
			}
			else {
				context->auth_result = CONNACK_ACCEPTED ;
			}

			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "hello thread, accept client[%s], name[%s], pwd[%s]\n", context->id, context->username, context->password) ;

			waitauthlist = waitauthlist->next ;
		}

		if( head ){//验证完成，将这一部分放入finished_auth_list尾部
			pthread_mutex_lock(&db->auth_list_mutex) ;

			if( db->finished_auth_list == NULL){
				db->finished_auth_list = head ;
			}
			else {//找到最后，放入尾部
				waitauthlist = db->finished_auth_list ;
				while(waitauthlist->next != NULL) {
					waitauthlist =  waitauthlist->next ;
				}
				waitauthlist->next = head ;
			}
			pthread_mutex_unlock(&db->auth_list_mutex) ;
		}
		usleep(1);
	}

	return NULL;
}
