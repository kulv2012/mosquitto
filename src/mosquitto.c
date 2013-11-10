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


/* For initgroups() */
#  define _BSD_SOURCE
#  include <unistd.h>
#  include <grp.h>

#include <pwd.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include "util_mosq.h"

struct mosquitto_db int_db;

bool flag_reload = false;
#ifdef WITH_PERSISTENCE
bool flag_db_backup = false;
#endif
bool flag_tree_print = false;
int run;

int drop_privileges(struct mqtt3_config *config);
void handle_sigint(int signal);
void handle_sigusr1(int signal);
void handle_sigusr2(int signal);

struct mosquitto_db *_mosquitto_get_db(void)
{
	return &int_db;
}

/* mosquitto shouldn't run as root.
 * This function will attempt to change to an unprivileged user and group if
 * running as root. The user is given in config->user.
 * Returns 1 on failure (unknown user, setuid/setgid failure)
 * Returns 0 on success.
 * Note that setting config->user to "root" does not produce an error, but it
 * strongly discouraged.
 */
int drop_privileges(struct mqtt3_config *config)
{
	struct passwd *pwd;
	char err[256];

	if(geteuid() == 0){
		if(config->user){
			pwd = getpwnam(config->user);
			if(!pwd){
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid user '%s'.", config->user);
				return 1;
			}
			if(initgroups(config->user, pwd->pw_gid) == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting groups whilst dropping privileges: %s.", err);
				return 1;
			}
			if(setgid(pwd->pw_gid) == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting gid whilst dropping privileges: %s.", err);
				return 1;
			}
			if(setuid(pwd->pw_uid) == -1){
				strerror_r(errno, err, 256);
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error setting uid whilst dropping privileges: %s.", err);
				return 1;
			}
		}
		if(geteuid() == 0 || getegid() == 0){
			_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Mosquitto should not be run as root/administrator.");
		}
	}
	return MOSQ_ERR_SUCCESS;
}

/* Signal handler for SIGHUP - flag a config reload. */
void handle_sighup(int signal)
{
	flag_reload = true;
}

/* Signal handler for SIGINT and SIGTERM - just stop gracefully. */
void handle_sigint(int signal)
{
	run = 0;
}

/* Signal handler for SIGUSR1 - backup the db. */
void handle_sigusr1(int signal)
{
#ifdef WITH_PERSISTENCE
	flag_db_backup = true;
#endif
}

/* Signal handler for SIGUSR2 - vacuum the db. */
void handle_sigusr2(int signal)
{//vacuum，真空
	flag_tree_print = true;
}


int main(int argc, char *argv[])
{
	int *listensock = NULL;
	int listensock_count = 0;
	int listensock_index = 0;
	struct mqtt3_config config;
	char buf[1024];
	int i, j;
	FILE *pid;
	int listener_max;
	int rc;
	char err[256];


	memset(&int_db, 0, sizeof(struct mosquitto_db));

	mqtt3_config_init(&config);
	rc = mqtt3_config_parse_args(&config, argc, argv);//k: init && load config file, set struct members
	if(rc != MOSQ_ERR_SUCCESS) return rc;
	int_db.config = &config;

	if(config.daemon){//k: fork() goto deamon mode
		switch(fork()){
			case 0:
				break;
			case -1:
				strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error in fork: %s", err);
				return 1;
			default:
				return MOSQ_ERR_SUCCESS;
		}
	}

	if(config.daemon && config.pid_file){//write pid file
		pid = _mosquitto_fopen(config.pid_file, "wt");
		if(pid){
			fprintf(pid, "%d", getpid());
			fclose(pid);
		}else{
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to write pid file.");
			return 1;
		}
	}
	rc = drop_privileges(&config);
	if(rc != MOSQ_ERR_SUCCESS) return rc;

	rc = mqtt3_db_open(&config, &int_db);
	if(rc != MOSQ_ERR_SUCCESS){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Couldn't open database.");
		return rc;
	}

	/* Initialise logging only after initialising the database in case we're
	 * logging to topics */
	mqtt3_log_init(config.log_type, config.log_dest);
	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s (build date %s) starting", VERSION, TIMESTAMP);
	if(config.config_file){
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Config loaded from %s.", config.config_file);
	}else{
		_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Using default config.");
	}

	//安全验证模块，后续可以去掉
	rc = mosquitto_security_module_init(&int_db);
	if(rc) return rc;
	rc = mosquitto_security_init(&int_db, false);
	if(rc) return rc;

	/* Set static $SYS messages */
	snprintf(buf, 1024, "mosquitto version %s", VERSION);
	mqtt3_db_messages_easy_queue(&int_db, NULL, "$SYS/broker/version", 2, strlen(buf), buf, 1);
	snprintf(buf, 1024, "%s", TIMESTAMP);
	mqtt3_db_messages_easy_queue(&int_db, NULL, "$SYS/broker/timestamp", 2, strlen(buf), buf, 1);

	listener_max = -1;
	listensock_index = 0;
	for(i=0; i<config.listener_count; i++){
		if(mqtt3_socket_listen(&config.listeners[i])){
			_mosquitto_free(int_db.contexts);
			mqtt3_db_close(&int_db);
			if(config.pid_file){
				remove(config.pid_file);
			}
			return 1;
		}
		listensock_count += config.listeners[i].sock_count;
		listensock = _mosquitto_realloc(listensock, sizeof(int)*listensock_count);
		if(!listensock){
			_mosquitto_free(int_db.contexts);
			mqtt3_db_close(&int_db);
			if(config.pid_file){
				remove(config.pid_file);
			}
			return 1;
		}
		for(j=0; j<config.listeners[i].sock_count; j++){
			if(config.listeners[i].socks[j] == INVALID_SOCKET){
				_mosquitto_free(int_db.contexts);
				mqtt3_db_close(&int_db);
				if(config.pid_file){
					remove(config.pid_file);
				}
				return 1;
			}
			listensock[listensock_index] = config.listeners[i].socks[j];
			if(listensock[listensock_index] > listener_max){
				listener_max = listensock[listensock_index];
			}
			listensock_index++;
		}
	}

	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);
	signal(SIGHUP, handle_sighup);
	signal(SIGUSR1, handle_sigusr1);
	signal(SIGUSR2, handle_sigusr2);//直接printf一下订阅的树形结构，线上慎用，太大 
	signal(SIGPIPE, SIG_IGN);

	run = 1;

	auth_thread_init( &int_db ) ;

	rc = mosquitto_main_loop(&int_db, listensock, listensock_count, listener_max);


	//等待线程退出
	auth_thread_destroy(&int_db ) ;

	_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s terminating", VERSION);
	mqtt3_log_close();

#ifdef WITH_PERSISTENCE
	if(config.persistence){
		mqtt3_db_backup(&int_db, true, true);
	}
#endif

	for(i=0; i<int_db.context_count; i++){
		if(int_db.contexts[i]){
			mqtt3_context_cleanup(&int_db, int_db.contexts[i], true);
		}
	}
	_mosquitto_free(int_db.contexts);
	int_db.contexts = NULL;
	mqtt3_db_close(&int_db);

	if(listensock){
		for(i=0; i<listensock_count; i++){
			if(listensock[i] != INVALID_SOCKET){
				close(listensock[i]);
			}
		}
		_mosquitto_free(listensock);
	}

	mosquitto_security_module_cleanup(&int_db);

	if(config.pid_file){
		remove(config.pid_file);
		_mosquitto_free(config.pid_file);
		config.pid_file = NULL ;
	}

	mqtt3_config_cleanup(int_db.config);

	return rc;
}

