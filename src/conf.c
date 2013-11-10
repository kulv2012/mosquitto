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


#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#  include <dirent.h>

#  include <netdb.h>
#  include <sys/socket.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include "util_mosq.h"
#include "mqtt3_protocol.h"

struct config_recurse {
	int log_dest;
	int log_dest_set;
	int log_type;
	int log_type_set;
	int max_inflight_messages;
	int max_queued_messages;
};


static int _conf_parse_bool(char **token, const char *name, bool *value, char *saveptr);
static int _conf_parse_int(char **token, const char *name, int *value, char *saveptr);
static int _conf_parse_string(char **token, const char *name, char **value, char *saveptr);
static int _config_read_file(struct mqtt3_config *config, bool reload, const char *file, struct config_recurse *config_tmp, int level, int *lineno);

static int _conf_attempt_resolve(const char *host, const char *text, int log, const char *msg)
{
	struct addrinfo gai_hints;
	struct addrinfo *gai_res;
	int rc;

	memset(&gai_hints, 0, sizeof(struct addrinfo));
	gai_hints.ai_family = PF_UNSPEC;
	gai_hints.ai_flags = AI_ADDRCONFIG;
	gai_hints.ai_socktype = SOCK_STREAM;
	gai_res = NULL;
	rc = getaddrinfo(host, NULL, &gai_hints, &gai_res);
	if(gai_res){
		freeaddrinfo(gai_res);
	}
	if(rc != 0){
		if(rc == EAI_SYSTEM){
			if(errno == ENOENT){
				_mosquitto_log_printf(NULL, log, "%s: Unable to resolve %s %s.", msg, text, host);
			}else{
				_mosquitto_log_printf(NULL, log, "%s: Error resolving %s: %s.", msg, text, strerror(errno));
			}
		}else{
			_mosquitto_log_printf(NULL, log, "%s: Error resolving %s: %s.", msg, text, gai_strerror(rc));
		}
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}

static void _config_init_reload(struct mqtt3_config *config)
{
	int i;
	/* Set defaults */
	if(config->acl_file) _mosquitto_free(config->acl_file);
	config->acl_file = NULL;
	config->allow_anonymous = true;
	config->allow_duplicate_messages = false;
	config->autosave_interval = 1800;
	config->autosave_on_changes = false;
	if(config->clientid_prefixes) _mosquitto_free(config->clientid_prefixes);
	config->connection_messages = true;
	config->clientid_prefixes = NULL;
	if(config->log_fptr){
		fclose(config->log_fptr);
		config->log_fptr = NULL;
	}
	if(config->log_file){
		_mosquitto_free(config->log_file);
		config->log_file = NULL;
	}
	config->log_dest = MQTT3_LOG_STDERR;
	if(config->verbose){
		config->log_type = INT_MAX;
	}else{
		config->log_type = MOSQ_LOG_ERR | MOSQ_LOG_WARNING | MOSQ_LOG_NOTICE | MOSQ_LOG_INFO;
	}
	config->log_timestamp = true;
	if(config->password_file) _mosquitto_free(config->password_file);
	config->password_file = NULL;
	config->persistence = false;
	if(config->persistence_location) _mosquitto_free(config->persistence_location);
	config->persistence_location = NULL;
	if(config->persistence_file) _mosquitto_free(config->persistence_file);
	config->persistence_file = NULL;
	config->persistent_client_expiration = 0;
	config->queue_qos0_messages = false;
	config->retry_interval = 20;
	config->store_clean_interval = 10;
	config->sys_interval = 10;
	config->upgrade_outgoing_qos = false;
	if(config->auth_options){
		for(i=0; i<config->auth_option_count; i++){
			_mosquitto_free(config->auth_options[i].key);
			_mosquitto_free(config->auth_options[i].value);
		}
		_mosquitto_free(config->auth_options);
		config->auth_options = NULL;
		config->auth_option_count = 0;
	}
}

void mqtt3_config_init(struct mqtt3_config *config)
{
	memset(config, 0, sizeof(struct mqtt3_config));
	_config_init_reload(config);
	config->config_file = NULL;
	config->daemon = false;
	config->default_listener.host = NULL;
	config->default_listener.port = 0;
	config->default_listener.max_connections = -1;
	config->default_listener.mount_point = NULL;
	config->default_listener.socks = NULL;
	config->default_listener.sock_count = 0;
	config->default_listener.client_count = 0;
	config->listeners = NULL;
	config->listener_count = 0;
	config->pid_file = NULL;
	config->user = NULL;
	config->auth_plugin = NULL;
	config->verbose = false;
	config->message_size_limit = 0;
}

void mqtt3_config_cleanup(struct mqtt3_config *config)
{
	int i;

	if(config->acl_file) _mosquitto_free(config->acl_file);
	if(config->clientid_prefixes) _mosquitto_free(config->clientid_prefixes);
	if(config->config_file) _mosquitto_free(config->config_file);
	if(config->password_file) _mosquitto_free(config->password_file);
	if(config->persistence_location) _mosquitto_free(config->persistence_location);
	if(config->persistence_file) _mosquitto_free(config->persistence_file);
	if(config->persistence_filepath) _mosquitto_free(config->persistence_filepath);
	if(config->listeners){
		for(i=0; i<config->listener_count; i++){
			if(config->listeners[i].host) _mosquitto_free(config->listeners[i].host);
			if(config->listeners[i].mount_point) _mosquitto_free(config->listeners[i].mount_point);
			if(config->listeners[i].socks) _mosquitto_free(config->listeners[i].socks);
		}
		_mosquitto_free(config->listeners);
	}
	if(config->auth_plugin) _mosquitto_free(config->auth_plugin);
	if(config->auth_options){
		for(i=0; i<config->auth_option_count; i++){
			_mosquitto_free(config->auth_options[i].key);
			_mosquitto_free(config->auth_options[i].value);
		}
		_mosquitto_free(config->auth_options);
		config->auth_options = NULL;
		config->auth_option_count = 0;
	}
	if(config->log_fptr){
		fclose(config->log_fptr);
		config->log_fptr = NULL;
	}
	if(config->log_file){
		_mosquitto_free(config->log_file);
		config->log_file = NULL;
	}
}

static void print_usage(void)
{
	printf("mosquitto version %s (build date %s)\n\n", VERSION, TIMESTAMP);
	printf("mosquitto is an MQTT v3.1 broker.\n\n");
	printf("Usage: mosquitto [-c config_file] [-d] [-h] [-p port]\n\n");
	printf(" -c : specify the broker config file.\n");
	printf(" -d : put the broker into the background after starting.\n");
	printf(" -h : display this help.\n");
	printf(" -p : start the broker listening on the specified port.\n");
	printf("      Not recommended in conjunction with the -c option.\n");
	printf(" -v : verbose mode - enable all logging types. This overrides\n");
	printf("      any logging options given in the config file.\n");
	printf("\nSee http://mosquitto.org/ for more information.\n\n");
}

//k: parse argc/argv, call mqtt3_config_read to load config file
int mqtt3_config_parse_args(struct mqtt3_config *config, int argc, char *argv[])
{
	int i;
	int port_tmp;

	for(i=1; i<argc; i++){
		if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config-file")){
			if(i<argc-1){
				config->config_file = _mosquitto_strdup(argv[i+1]);
				if(!config->config_file){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
					return MOSQ_ERR_NOMEM;
				}

				if(mqtt3_config_read(config, false)){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open configuration file.");
					return MOSQ_ERR_INVAL;
				}
			}else{
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: -c argument given, but no config file specified.");
				return MOSQ_ERR_INVAL;
			}
			i++;
		}else if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--daemon")){
			config->daemon = true;
		}else if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")){
			print_usage();
			return MOSQ_ERR_INVAL;
		}else if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")){
			if(i<argc-1){
				port_tmp = atoi(argv[i+1]);
				if(port_tmp<1 || port_tmp>65535){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port specified (%d).", port_tmp);
					return MOSQ_ERR_INVAL;
				}else{
					if(config->default_listener.port){
						_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Default listener port specified multiple times. Only the latest will be used.");
					}
					config->default_listener.port = port_tmp;
				}
			}else{
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: -p argument given, but no port specified.");
				return MOSQ_ERR_INVAL;
			}
			i++;
		}else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")){
			config->verbose = true;
		}else{
			fprintf(stderr, "Error: Unknown option '%s'.\n",argv[i]);
			print_usage();
			return MOSQ_ERR_INVAL;
		}
	}

	//k: no listen info set ,use old one 
	if(config->listener_count == 0
			|| config->default_listener.host
			|| config->default_listener.port
			|| config->default_listener.max_connections != -1
			|| config->default_listener.mount_point){

		config->listener_count++;
		config->listeners = _mosquitto_realloc(config->listeners, sizeof(struct _mqtt3_listener)*config->listener_count);
		if(!config->listeners){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		if(config->default_listener.port){
			config->listeners[config->listener_count-1].port = config->default_listener.port;
		}else{
			config->listeners[config->listener_count-1].port = 1883;
		}
		if(config->default_listener.host){
			config->listeners[config->listener_count-1].host = config->default_listener.host;
		}else{
			config->listeners[config->listener_count-1].host = NULL;
		}
		if(config->default_listener.mount_point){
			config->listeners[config->listener_count-1].mount_point = config->default_listener.host;
		}else{
			config->listeners[config->listener_count-1].mount_point = NULL;
		}
		config->listeners[config->listener_count-1].max_connections = config->default_listener.max_connections;
		config->listeners[config->listener_count-1].client_count = 0;
		config->listeners[config->listener_count-1].socks = NULL;
		config->listeners[config->listener_count-1].sock_count = 0;
		config->listeners[config->listener_count-1].client_count = 0;
	}

	/* Default to drop to mosquitto user if we are privileged and no user specified. */
	if(!config->user){
		config->user = "mosquitto";
	}
	if(config->verbose){
		config->log_type = INT_MAX;
	}
	return MOSQ_ERR_SUCCESS;
}

int mqtt3_config_read(struct mqtt3_config *config, bool reload)
{
	int rc = MOSQ_ERR_SUCCESS;
	struct config_recurse cr;
	int lineno;

	cr.log_dest = MQTT3_LOG_NONE;
	cr.log_dest_set = 0;
	cr.log_type = MOSQ_LOG_NONE;
	cr.log_type_set = 0;
	cr.max_inflight_messages = 20;
	cr.max_queued_messages = 100;

	if(!config->config_file) return 0;

	if(reload){
		/* Re-initialise appropriate config vars to default for reload. */
		_config_init_reload(config);
	}
	rc = _config_read_file(config, reload, config->config_file, &cr, 0, &lineno);
	if(rc){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error found at %s:%d.", config->config_file, lineno);
		return rc;
	}

#ifdef WITH_PERSISTENCE
	if(config->persistence){
		if(!config->persistence_file){
			config->persistence_file = _mosquitto_strdup("mosquitto.db");
			if(!config->persistence_file) return MOSQ_ERR_NOMEM;
		}
		if(config->persistence_filepath){
			_mosquitto_free(config->persistence_filepath);
		}
		if(config->persistence_location && strlen(config->persistence_location)){
			config->persistence_filepath = _mosquitto_malloc(strlen(config->persistence_location) + strlen(config->persistence_file) + 1);
			if(!config->persistence_filepath) return MOSQ_ERR_NOMEM;
			sprintf(config->persistence_filepath, "%s%s", config->persistence_location, config->persistence_file);
		}else{
			config->persistence_filepath = _mosquitto_strdup(config->persistence_file);
			if(!config->persistence_filepath) return MOSQ_ERR_NOMEM;
		}
	}
#endif
	/* Default to drop to mosquitto user if no other user specified. This must
	 * remain here even though it is covered in mqtt3_parse_args() because this
	 * function may be called on its own. */
	if(!config->user){
		config->user = "mosquitto";
	}

	mqtt3_db_limits_set(cr.max_inflight_messages, cr.max_queued_messages);


	if(cr.log_dest_set){
		config->log_dest = cr.log_dest;
	}
	if(config->verbose){
		config->log_type = MOSQ_LOG_DEBUG | MOSQ_LOG_ERR | MOSQ_LOG_WARNING | MOSQ_LOG_NOTICE | MOSQ_LOG_INFO;
	}else if(cr.log_type_set){
		config->log_type = cr.log_type;
	}
	return MOSQ_ERR_SUCCESS;
}

//k: fopen config file , process line by line
int _config_read_file(struct mqtt3_config *config, bool reload, const char *file, struct config_recurse *cr, int level, int *lineno)
{
	int rc;
	FILE *fptr = NULL;
	char buf[1024];
	char *token;
	int port_tmp;
	char *saveptr = NULL;
	time_t expiration_mult;
	char *key;
	char *conf_file;
	DIR *dh;
	struct dirent *de;
	int len;
	struct _mqtt3_listener *cur_listener = &config->default_listener;
	int lineno_ext;
	
	fptr = _mosquitto_fopen(file, "rt");
	if(!fptr){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open config file %s\n", file);
		return 1;
	}

	*lineno = 0;

	while(fgets(buf, 1024, fptr)){
		(*lineno)++;
		if(buf[0] != '#' && buf[0] != 10 && buf[0] != 13){
			while(buf[strlen(buf)-1] == 10 || buf[strlen(buf)-1] == 13){
				buf[strlen(buf)-1] = 0;
			}
			token = strtok_r(buf, " ", &saveptr);
			if(token){
				if(!strcmp(token, "acl_file")){
					if(reload){
						if(config->acl_file){
							_mosquitto_free(config->acl_file);
							config->acl_file = NULL;
						}
					}
					if(_conf_parse_string(&token, "acl_file", &config->acl_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "address") || !strcmp(token, "addresses")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "allow_anonymous")){
					if(_conf_parse_bool(&token, "allow_anonymous", &config->allow_anonymous, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "allow_duplicate_messages")){
					if(_conf_parse_bool(&token, "allow_duplicate_messages", &config->allow_duplicate_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strncmp(token, "auth_opt_", 9)){
					if(strlen(token) < 12){
						/* auth_opt_ == 9, + one digit key == 10, + one space == 11, + one value == 12 */
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid auth_opt_ config option.");
						return MOSQ_ERR_INVAL;
					}
					key = _mosquitto_strdup(&token[9]);
					if(!key){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory");
						return MOSQ_ERR_NOMEM;
					}else if(strlen(key) == 0){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid auth_opt_ config option.");
						return MOSQ_ERR_INVAL;
					}
					token += 9+strlen(key)+1;
					if(token[0]){
						config->auth_option_count++;
						config->auth_options = _mosquitto_realloc(config->auth_options, config->auth_option_count*sizeof(struct mosquitto_auth_opt));
						if(!config->auth_options){
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						config->auth_options[config->auth_option_count-1].key = key;
						config->auth_options[config->auth_option_count-1].value = _mosquitto_strdup(token);
						if(!config->auth_options[config->auth_option_count-1].value){
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", key);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "auth_plugin")){
					if(reload) continue; // Auth plugin not currently valid for reloading.
					if(_conf_parse_string(&token, "auth_plugin", &config->auth_plugin, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "autosave_interval")){
					if(_conf_parse_int(&token, "autosave_interval", &config->autosave_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->autosave_interval < 0) config->autosave_interval = 0;
				}else if(!strcmp(token, "autosave_on_changes")){
					if(_conf_parse_bool(&token, "autosave_on_changes", &config->autosave_on_changes, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "bind_address")){
					if(reload) continue; // Listener not valid for reloading.
					if(_conf_parse_string(&token, "default listener bind_address", &config->default_listener.host, saveptr)) return MOSQ_ERR_INVAL;
					if(_conf_attempt_resolve(config->default_listener.host, "bind_address", MOSQ_LOG_ERR, "Error")){
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "bridge_cafile")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
				}else if(!strcmp(token, "bridge_capath")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
				}else if(!strcmp(token, "bridge_certfile")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
				}else if(!strcmp(token, "bridge_identity")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS-PSK support not available.");
				}else if(!strcmp(token, "bridge_insecure")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS-PSK support not available.");
				}else if(!strcmp(token, "bridge_keyfile")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge and/or TLS support not available.");
				}else if(!strcmp(token, "cafile")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "capath")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "certfile")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "ciphers")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "clientid")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "cleansession")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "clientid_prefixes")){
					if(reload){
						if(config->clientid_prefixes){
							_mosquitto_free(config->clientid_prefixes);
							config->clientid_prefixes = NULL;
						}
					}
					if(_conf_parse_string(&token, "clientid_prefixes", &config->clientid_prefixes, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "connection")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "connection_messages")){
					if(_conf_parse_bool(&token, token, &config->connection_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "crlfile")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "idle_timeout")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "include_dir")){
					if(level == 0){
						/* Only process include_dir from the main config file. */
						token = strtok_r(NULL, " ", &saveptr);
						dh = opendir(token);
						if(!dh){
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open include_dir '%s'.", token);
							return 1;
						}
						while((de = readdir(dh)) != NULL){
							if(strlen(de->d_name) > 5){
								if(!strcmp(&de->d_name[strlen(de->d_name)-5], ".conf")){
									len = strlen(token)+1+strlen(de->d_name)+1;
									conf_file = _mosquitto_calloc(len+1, sizeof(char));
									if(!conf_file){
										closedir(dh);
										return MOSQ_ERR_NOMEM;
									}
									snprintf(conf_file, len, "%s/%s", token, de->d_name);
									
									rc = _config_read_file(config, reload, conf_file, cr, level+1, &lineno_ext);
									if(rc){
										closedir(dh);
										_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error found at %s:%d.", conf_file, lineno_ext);
										_mosquitto_free(conf_file);
										return rc;
									}
									_mosquitto_free(conf_file);
								}
							}
						}
						closedir(dh);
					}
				}else if(!strcmp(token, "keepalive_interval")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "keyfile")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "listener")){
					if(reload) continue; // Listeners not valid for reloading.
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						config->listener_count++;
						config->listeners = _mosquitto_realloc(config->listeners, sizeof(struct _mqtt3_listener)*config->listener_count);
						if(!config->listeners){
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
							return MOSQ_ERR_NOMEM;
						}
						port_tmp = atoi(token);
						if(port_tmp < 1 || port_tmp > 65535){
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", port_tmp);
							return MOSQ_ERR_INVAL;
						}
						cur_listener = &config->listeners[config->listener_count-1];
						memset(cur_listener, 0, sizeof(struct _mqtt3_listener));
						cur_listener->port = port_tmp;
						token = strtok_r(NULL, " ", &saveptr);
						if(token){
							cur_listener->host = _mosquitto_strdup(token);
						}else{
							cur_listener->host = NULL;
						}
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty listener value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "log_dest")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->log_dest_set = 1;
						if(!strcmp(token, "none")){
							cr->log_dest = MQTT3_LOG_NONE;
						}else if(!strcmp(token, "stdout")){
							cr->log_dest |= MQTT3_LOG_STDOUT;
						}else if(!strcmp(token, "stderr")){
							cr->log_dest |= MQTT3_LOG_STDERR;
						}else if(!strcmp(token, "topic")){
							cr->log_dest |= MQTT3_LOG_TOPIC;
						}else if(!strcmp(token, "file")){
							cr->log_dest |= MQTT3_LOG_FILE;
							if(config->log_fptr || config->log_file){
								_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate \"log_dest file\" value.");
								return MOSQ_ERR_INVAL;
							}
							/* Get remaining string. */
							token = &token[strlen(token)+1];
							while(token[0] == ' '){
								token++;
							}
							if(token){
								config->log_file = _mosquitto_strdup(token);
								if(!config->log_file){
									_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory");
									return MOSQ_ERR_NOMEM;
								}
								config->log_fptr = _mosquitto_fopen(config->log_file, "at");
								if(!config->log_fptr){
									_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open log file %s for writing.", config->log_file);
									return MOSQ_ERR_INVAL;
								}
							}else{
								_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty \"log_dest file\" value in configuration.");
								return MOSQ_ERR_INVAL;
							}
						}else{
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid log_dest value (%s).", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty log_dest value in configuration.");
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "log_timestamp")){
					if(_conf_parse_bool(&token, token, &config->log_timestamp, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "log_type")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->log_type_set = 1;
						if(!strcmp(token, "none")){
							cr->log_type = MOSQ_LOG_NONE;
						}else if(!strcmp(token, "information")){
							cr->log_type |= MOSQ_LOG_INFO;
						}else if(!strcmp(token, "notice")){
							cr->log_type |= MOSQ_LOG_NOTICE;
						}else if(!strcmp(token, "warning")){
							cr->log_type |= MOSQ_LOG_WARNING;
						}else if(!strcmp(token, "error")){
							cr->log_type |= MOSQ_LOG_ERR;
						}else if(!strcmp(token, "debug")){
							cr->log_type |= MOSQ_LOG_DEBUG;
						}else if(!strcmp(token, "subscribe")){
							cr->log_type |= MOSQ_LOG_SUBSCRIBE;
						}else if(!strcmp(token, "unsubscribe")){
							cr->log_type |= MOSQ_LOG_UNSUBSCRIBE;
						}else if(!strcmp(token, "all")){
							cr->log_type = INT_MAX;
						}else{
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid log_type value (%s).", token);
							return MOSQ_ERR_INVAL;
						}
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty log_type value in configuration.");
					}
				}else if(!strcmp(token, "max_connections")){
					if(reload) continue; // Listeners not valid for reloading.
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cur_listener->max_connections = atoi(token);
						if(cur_listener->max_connections < 0) cur_listener->max_connections = -1;
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_connections value in configuration.");
					}
				}else if(!strcmp(token, "max_inflight_messages")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->max_inflight_messages = atoi(token);
						if(cr->max_inflight_messages < 0) cr->max_inflight_messages = 0;
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_inflight_messages value in configuration.");
					}
				}else if(!strcmp(token, "max_queued_messages")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						cr->max_queued_messages = atoi(token);
						if(cr->max_queued_messages < 0) cr->max_queued_messages = 0;
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty max_queued_messages value in configuration.");
					}
				}else if(!strcmp(token, "message_size_limit")){
					if(_conf_parse_int(&token, "message_size_limit", &config->message_size_limit, saveptr)) return MOSQ_ERR_INVAL;
					if(config->message_size_limit < 0 || config->message_size_limit > MQTT_MAX_PAYLOAD){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid message_size_limit value (%d).", config->message_size_limit);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "mount_point")){
					if(reload) continue; // Listeners not valid for reloading.
					if(config->listener_count == 0){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: You must use create a listener before using the mount_point option in the configuration file.");
						return MOSQ_ERR_INVAL;
					}
					if(_conf_parse_string(&token, "mount_point", &cur_listener->mount_point, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "notifications")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "notification_topic")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "password")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "password_file")){
					if(reload){
						if(config->password_file){
							_mosquitto_free(config->password_file);
							config->password_file = NULL;
						}
					}
					if(_conf_parse_string(&token, "password_file", &config->password_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistence") || !strcmp(token, "retained_persistence")){
					if(_conf_parse_bool(&token, token, &config->persistence, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistence_file")){
					if(_conf_parse_string(&token, "persistence_file", &config->persistence_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistence_location")){
					if(_conf_parse_string(&token, "persistence_location", &config->persistence_location, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "persistent_client_expiration")){
					token = strtok_r(NULL, " ", &saveptr);
					if(token){
						switch(token[strlen(token)-1]){
							case 'd':
								expiration_mult = 86400;
								break;
							case 'w':
								expiration_mult = 86400*7;
								break;
							case 'm':
								expiration_mult = 86400*30;
								break;
							case 'y':
								expiration_mult = 86400*365;
								break;
							default:
								_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid persistent_client_expiration duration in configuration.");
								return MOSQ_ERR_INVAL;
						}
						token[strlen(token)-1] = '\0';
						config->persistent_client_expiration = atoi(token)*expiration_mult;
						if(config->persistent_client_expiration <= 0){
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid persistent_client_expiration duration in configuration.");
							return MOSQ_ERR_INVAL;
						}
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty persistent_client_expiration value in configuration.");
					}
				}else if(!strcmp(token, "pid_file")){
					if(reload) continue; // pid file not valid for reloading.
					if(_conf_parse_string(&token, "pid_file", &config->pid_file, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "port")){
					if(reload) continue; // Listener not valid for reloading.
					if(config->default_listener.port){
						_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Default listener port specified multiple times. Only the latest will be used.");
					}
					if(_conf_parse_int(&token, "port", &port_tmp, saveptr)) return MOSQ_ERR_INVAL;
					if(port_tmp < 1 || port_tmp > 65535){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid port value (%d).", port_tmp);
						return MOSQ_ERR_INVAL;
					}
					config->default_listener.port = port_tmp;
				}else if(!strcmp(token, "queue_qos0_messages")){
					if(_conf_parse_bool(&token, token, &config->queue_qos0_messages, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "require_certificate")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "restart_timeout")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "retry_interval")){
					if(_conf_parse_int(&token, "retry_interval", &config->retry_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->retry_interval < 1 || config->retry_interval > 3600){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid retry_interval value (%d).", config->retry_interval);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "round_robin")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "start_type")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "store_clean_interval")){
					if(_conf_parse_int(&token, "store_clean_interval", &config->store_clean_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->store_clean_interval < 0 || config->store_clean_interval > 65535){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid store_clean_interval value (%d).", config->store_clean_interval);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "sys_interval")){
					if(_conf_parse_int(&token, "sys_interval", &config->sys_interval, saveptr)) return MOSQ_ERR_INVAL;
					if(config->sys_interval < 1 || config->sys_interval > 65535){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid sys_interval value (%d).", config->sys_interval);
						return MOSQ_ERR_INVAL;
					}
				}else if(!strcmp(token, "threshold")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "topic")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "try_private")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "upgrade_outgoing_qos")){
					if(_conf_parse_bool(&token, token, &config->upgrade_outgoing_qos, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "use_identity_as_username")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: TLS support not available.");
				}else if(!strcmp(token, "user")){
					if(reload) continue; // Drop privileges user not valid for reloading.
					if(_conf_parse_string(&token, "user", &config->user, saveptr)) return MOSQ_ERR_INVAL;
				}else if(!strcmp(token, "username")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Bridge support not available.");
				}else if(!strcmp(token, "trace_level")
						|| !strcmp(token, "ffdc_output")
						|| !strcmp(token, "max_log_entries")
						|| !strcmp(token, "trace_output")){
					_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: Unsupported rsmb configuration option \"%s\".", token);
				}else{
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unknown configuration variable \"%s\".", token);
					return MOSQ_ERR_INVAL;
				}
			}
		}
	}
	fclose(fptr);

	return MOSQ_ERR_SUCCESS;
}

static int _conf_parse_bool(char **token, const char *name, bool *value, char *saveptr)
{
	*token = strtok_r(NULL, " ", &saveptr);
	if(*token){
		if(!strcmp(*token, "false") || !strcmp(*token, "0")){
			*value = false;
		}else if(!strcmp(*token, "true") || !strcmp(*token, "1")){
			*value = true;
		}else{
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid %s value (%s).", name, *token);
		}
	}else{
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
		return MOSQ_ERR_INVAL;
	}
	
	return MOSQ_ERR_SUCCESS;
}

static int _conf_parse_int(char **token, const char *name, int *value, char *saveptr)
{
	*token = strtok_r(NULL, " ", &saveptr);
	if(*token){
		*value = atoi(*token);
	}else{
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
		return MOSQ_ERR_INVAL;
	}

	return MOSQ_ERR_SUCCESS;
}

static int _conf_parse_string(char **token, const char *name, char **value, char *saveptr)
{
	*token = strtok_r(NULL, " ", &saveptr);
	if(*token){
		if(*value){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Duplicate %s value in configuration.", name);
			return MOSQ_ERR_INVAL;
		}
		*value = _mosquitto_strdup(*token);
		if(!*value){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory");
			return MOSQ_ERR_NOMEM;
		}
	}else{
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty %s value in configuration.", name);
		return MOSQ_ERR_INVAL;
	}
	return MOSQ_ERR_SUCCESS;
}
