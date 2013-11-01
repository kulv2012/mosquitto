/*
Copyright (c) 2011-2013 Roger Light <roger@atchoo.org>
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

#include <config.h>

#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include "util_mosq.h"

static int _aclfile_parse(struct mosquitto_db *db);
static int _unpwd_file_parse(struct mosquitto_db *db);
static int _acl_cleanup(struct mosquitto_db *db, bool reload);
static int _unpwd_cleanup(struct _mosquitto_unpwd **unpwd, bool reload);
static int _psk_file_parse(struct mosquitto_db *db);
#ifdef WITH_TLS
static int _pw_digest(const char *password, const unsigned char *salt, unsigned int salt_len, unsigned char *hash, unsigned int *hash_len);
static int _base64_decode(char *in, unsigned char **decoded, unsigned int *decoded_len);
#endif

int mosquitto_security_init_default(struct mosquitto_db *db, bool reload)
{
	int rc;

	/* Load username/password data if required. */
	if(db->config->password_file){
		rc = _unpwd_file_parse(db);
		if(rc){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error opening password file \"%s\".", db->config->password_file);
			return rc;
		}
	}

	/* Load acl data if required. */
	if(db->config->acl_file){
		rc = _aclfile_parse(db);
		if(rc){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error opening acl file \"%s\".", db->config->acl_file);
			return rc;
		}
	}

	/* Load psk data if required. */
	if(db->config->psk_file){
		rc = _psk_file_parse(db);
		if(rc){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error opening psk file \"%s\".", db->config->psk_file);
			return rc;
		}
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_security_cleanup_default(struct mosquitto_db *db, bool reload)
{
	int rc;
	rc = _acl_cleanup(db, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;
	rc = _unpwd_cleanup(&db->unpwd, reload);
	if(rc != MOSQ_ERR_SUCCESS) return rc;
	return _unpwd_cleanup(&db->psk_id, reload);
}


int _add_acl(struct mosquitto_db *db, const char *user, const char *topic, int access)
{
	struct _mosquitto_acl_user *acl_user=NULL, *user_tail;
	struct _mosquitto_acl *acl, *acl_root=NULL, *acl_tail=NULL;
	char *local_topic;
	char *token = NULL;
	bool new_user = false;
	char *saveptr = NULL;

	if(!db || !topic) return MOSQ_ERR_INVAL;

	local_topic = _mosquitto_strdup(topic);
	if(!local_topic){
		return MOSQ_ERR_NOMEM;
	}

	if(db->acl_list){
		user_tail = db->acl_list;
		while(user_tail){
			if(user == NULL){
				if(user_tail->username == NULL){
					acl_user = user_tail;
					break;
				}
			}else if(user_tail->username && !strcmp(user_tail->username, user)){
				acl_user = user_tail;
				break;
			}
			user_tail = user_tail->next;
		}
	}
	if(!acl_user){
		acl_user = _mosquitto_malloc(sizeof(struct _mosquitto_acl_user));
		if(!acl_user){
			_mosquitto_free(local_topic);
			return MOSQ_ERR_NOMEM;
		}
		new_user = true;
		if(user){
			acl_user->username = _mosquitto_strdup(user);
			if(!acl_user->username){
				_mosquitto_free(local_topic);
				_mosquitto_free(acl_user);
				return MOSQ_ERR_NOMEM;
			}
		}else{
			acl_user->username = NULL;
		}
		acl_user->next = NULL;
		acl_user->acl = NULL;
	}

	/* Tokenise topic */
	if(local_topic[0] == '/'){
		acl_root = _mosquitto_malloc(sizeof(struct _mosquitto_acl));
		if(!acl_root) return MOSQ_ERR_NOMEM;
		acl_tail = acl_root;
		acl_root->child = NULL;
		acl_root->next = NULL;
		acl_root->access = MOSQ_ACL_NONE;
		acl_root->topic = _mosquitto_strdup("/");
		if(!acl_root->topic) return MOSQ_ERR_NOMEM;

		token = strtok_r(local_topic+1, "/", &saveptr);
	}else{
		token = strtok_r(local_topic, "/", &saveptr);
	}

	while(token){
		acl = _mosquitto_malloc(sizeof(struct _mosquitto_acl));
		if(!acl) return MOSQ_ERR_NOMEM;
		acl->child = NULL;
		acl->next = NULL;
		acl->access = MOSQ_ACL_NONE;
		acl->topic = _mosquitto_strdup(token);
		if(!acl->topic) return MOSQ_ERR_NOMEM;
		if(acl_root){
			acl_tail->child = acl;
			acl_tail = acl;
		}else{
			acl_root = acl;
			acl_tail = acl;
		}

		token = strtok_r(NULL, "/", &saveptr);
	}
	if(acl_root){
		acl_tail = acl_root;
		while(acl_tail->child){
			acl_tail = acl_tail->child;
		}
		acl_tail->access = access;
	}else{
		return MOSQ_ERR_INVAL;
	}

	/* Add acl to user acl list */
	if(acl_user->acl){
		acl_tail = acl_user->acl;
		while(acl_tail->next){
			acl_tail = acl_tail->next;
		}
		acl_tail->next = acl_root;
	}else{
		acl_user->acl = acl_root;
	}

	if(new_user){
		/* Add to end of list */
		if(db->acl_list){
			user_tail = db->acl_list;
			while(user_tail->next){
				user_tail = user_tail->next;
			}
			user_tail->next = acl_user;
		}else{
			db->acl_list = acl_user;
		}
	}

	_mosquitto_free(local_topic);
	return MOSQ_ERR_SUCCESS;
}

int _add_acl_pattern(struct mosquitto_db *db, const char *topic, int access)
{
	struct _mosquitto_acl *acl, *acl_root=NULL, *acl_tail=NULL;
	char *local_topic;
	char *token = NULL;
	char *saveptr = NULL;

	if(!db || !topic) return MOSQ_ERR_INVAL;

	local_topic = _mosquitto_strdup(topic);
	if(!local_topic){
		return MOSQ_ERR_NOMEM;
	}

	/* Tokenise topic */
	if(local_topic[0] == '/'){
		acl_root = _mosquitto_malloc(sizeof(struct _mosquitto_acl));
		if(!acl_root) return MOSQ_ERR_NOMEM;
		acl_tail = acl_root;
		acl_root->child = NULL;
		acl_root->next = NULL;
		acl_root->access = MOSQ_ACL_NONE;
		acl_root->topic = _mosquitto_strdup("/");
		if(!acl_root->topic) return MOSQ_ERR_NOMEM;

		token = strtok_r(local_topic+1, "/", &saveptr);
	}else{
		token = strtok_r(local_topic, "/", &saveptr);
	}

	while(token){
		acl = _mosquitto_malloc(sizeof(struct _mosquitto_acl));
		if(!acl) return MOSQ_ERR_NOMEM;
		acl->child = NULL;
		acl->next = NULL;
		acl->access = MOSQ_ACL_NONE;
		acl->topic = _mosquitto_strdup(token);
		if(!acl->topic) return MOSQ_ERR_NOMEM;
		if(acl_root){
			acl_tail->child = acl;
			acl_tail = acl;
		}else{
			acl_root = acl;
			acl_tail = acl;
		}

		token = strtok_r(NULL, "/", &saveptr);
	}

	if(acl_root){
		acl_tail = acl_root;
		while(acl_tail->child){
			acl_tail = acl_tail->child;
		}
		acl_tail->access = access;

		if(db->acl_patterns){
			acl_tail = db->acl_patterns;
			while(acl_tail->next){
				acl_tail = acl_tail->next;
			}
			acl_tail->next = acl_root;
		}else{
			db->acl_patterns = acl_root;
		}
	}else{
		return MOSQ_ERR_INVAL;
	}

	_mosquitto_free(local_topic);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_acl_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access)
{
	char *local_topic;
	char *token;
	struct _mosquitto_acl *acl_root, *acl_tail;
	char *saveptr = NULL;

	if(!db || !context || !topic) return MOSQ_ERR_INVAL;
	if(!db->acl_list && !db->acl_patterns) return MOSQ_ERR_SUCCESS;
	if(context->bridge) return MOSQ_ERR_SUCCESS;
	if(!context->acl_list && !db->acl_patterns) return MOSQ_ERR_ACL_DENIED;

	if(context->acl_list){
		acl_root = context->acl_list->acl;
	}else{
		acl_root = NULL;
	}

	/* Loop through all ACLs for this client. */
	while(acl_root){
		acl_tail = acl_root;

		/* If subscription starts with $SYS, acl_tail->topic must also start with $SYS. */
		if(!strncmp(topic, "$SYS", 4)){
			if(strcmp(acl_tail->topic, "$SYS")){
				acl_root = acl_root->next;
				continue;
			}
		}else{
			/* Topic doesn't start with $SYS */
			if(!strcmp(acl_tail->topic, "#") && !acl_tail->next) return MOSQ_ERR_SUCCESS;
		}

		if(topic[0] == '/'){
			if(strcmp(acl_tail->topic, "/")){
				acl_root = acl_root->next;
				continue;
			}
			acl_tail = acl_tail->child;
		}

		local_topic = _mosquitto_strdup(topic);
		if(!local_topic) return MOSQ_ERR_NOMEM;

		token = strtok_r(local_topic, "/", &saveptr);
		/* Loop through the topic looking for matches to this ACL. */

		/* If subscription starts with $SYS, acl_tail->topic must also start with $SYS. */
		if(!strcmp(token, "$SYS") && strcmp(acl_tail->topic, "$SYS")){
			_mosquitto_free(local_topic);

			acl_root = acl_root->next;
			continue;
		}
		while(token){
			if(acl_tail){
				if(!strcmp(acl_tail->topic, "#") && acl_tail->child == NULL){
					/* We have a match */
					if(access & acl_tail->access){
						/* And access is allowed. */
						_mosquitto_free(local_topic);
						return MOSQ_ERR_SUCCESS;
					}else{
						break;
					}
				}else if(!strcmp(acl_tail->topic, token) || !strcmp(acl_tail->topic, "+")){
					token = strtok_r(NULL, "/", &saveptr);
					if(!token && acl_tail->child == NULL){
						/* We have a match */
						if(access & acl_tail->access){
							/* And access is allowed. */
							_mosquitto_free(local_topic);
							return MOSQ_ERR_SUCCESS;
						}else{
							break;
						}
					}
				}else{
					break;
				}
				acl_tail = acl_tail->child;
			}else{
				break;
			}
		}
		_mosquitto_free(local_topic);

		acl_root = acl_root->next;
	}

	acl_root = db->acl_patterns;
	/* Loop through all pattern ACLs. */
	while(acl_root){
		local_topic = _mosquitto_strdup(topic);
		if(!local_topic) return MOSQ_ERR_NOMEM;

		acl_tail = acl_root;

		if(local_topic[0] == '/'){
			if(strcmp(acl_tail->topic, "/")){
				acl_root = acl_root->next;
				continue;
			}
			acl_tail = acl_tail->child;
		}

		token = strtok_r(local_topic, "/", &saveptr);
		/* Loop through the topic looking for matches to this ACL. */
		while(token){
			if(acl_tail){
				if(!strcmp(acl_tail->topic, "#") && acl_tail->child == NULL){
					/* We have a match */
					if(access & acl_tail->access){
						/* And access is allowed. */
						_mosquitto_free(local_topic);
						return MOSQ_ERR_SUCCESS;
					}else{
						break;
					}
				}else if(!strcmp(acl_tail->topic, "%c")){
					if(!context->id || strcmp(token, context->id)){
						/* No access */
						break;
					}
					token = strtok_r(NULL, "/", &saveptr);
					if(!token && acl_tail->child == NULL){
						/* We have a match */
						if(access & acl_tail->access){
							/* And access is allowed. */
							_mosquitto_free(local_topic);
							return MOSQ_ERR_SUCCESS;
						}else{
							break;
						}
					}
				}else if(!strcmp(acl_tail->topic, "%u")){
					if(!context->username || strcmp(token, context->username)){
						/* No access */
						break;
					}
					token = strtok_r(NULL, "/", &saveptr);
					if(!token && acl_tail->child == NULL){
						/* We have a match */
						if(access & acl_tail->access){
							/* And access is allowed. */
							_mosquitto_free(local_topic);
							return MOSQ_ERR_SUCCESS;
						}else{
							break;
						}
					}
				}else if(!strcmp(acl_tail->topic, token) || !strcmp(acl_tail->topic, "+")){
					token = strtok_r(NULL, "/", &saveptr);
					if(!token && acl_tail->child == NULL){
						/* We have a match */
						if(access & acl_tail->access){
							/* And access is allowed. */
							_mosquitto_free(local_topic);
							return MOSQ_ERR_SUCCESS;
						}else{
							break;
						}
					}
				}else{
					break;
				}
				acl_tail = acl_tail->child;
			}else{
				break;
			}
		}
		_mosquitto_free(local_topic);

		acl_root = acl_root->next;
	}

	return MOSQ_ERR_ACL_DENIED;
}

static int _aclfile_parse(struct mosquitto_db *db)
{
	FILE *aclfile;
	char buf[1024];
	char *token;
	char *user = NULL;
	char *topic;
	char *access_s;
	int access;
	int rc;
	int slen;
	int topic_pattern;
	char *saveptr = NULL;

	if(!db || !db->config) return MOSQ_ERR_INVAL;
	if(!db->config->acl_file) return MOSQ_ERR_SUCCESS;

	aclfile = _mosquitto_fopen(db->config->acl_file, "rt");
	if(!aclfile){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open acl_file \"%s\".", db->config->acl_file);
		return 1;
	}

	// topic [read|write] <topic> 
	// user <user>

	while(fgets(buf, 1024, aclfile)){
		slen = strlen(buf);
		while(slen > 0 && (buf[slen-1] == 10 || buf[slen-1] == 13)){
			buf[slen-1] = '\0';
			slen = strlen(buf);
		}
		if(buf[0] == '#'){
			continue;
		}
		token = strtok_r(buf, " ", &saveptr);
		if(token){
			if(!strcmp(token, "topic") || !strcmp(token, "pattern")){
				if(!strcmp(token, "topic")){
					topic_pattern = 0;
				}else{
					topic_pattern = 1;
				}

				access_s = strtok_r(NULL, " ", &saveptr);
				if(!access_s){
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty topic in acl_file.");
					if(user) _mosquitto_free(user);
					fclose(aclfile);
					return MOSQ_ERR_INVAL;
				}
				token = strtok_r(NULL, " ", &saveptr);
				if(token){
					topic = token;
				}else{
					topic = access_s;
					access_s = NULL;
				}
				if(access_s){
					if(!strcmp(access_s, "read")){
						access = MOSQ_ACL_READ;
					}else if(!strcmp(access_s, "write")){
						access = MOSQ_ACL_WRITE;
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty invalid topic access type in acl_file.");
						if(user) _mosquitto_free(user);
						fclose(aclfile);
						return MOSQ_ERR_INVAL;
					}
				}else{
					access = MOSQ_ACL_READ | MOSQ_ACL_WRITE;
				}
				if(topic_pattern == 0){
					rc = _add_acl(db, user, topic, access);
				}else{
					rc = _add_acl_pattern(db, topic, access);
				}
				if(rc) return rc;
			}else if(!strcmp(token, "user")){
				token = strtok_r(NULL, " ", &saveptr);
				if(token){
					if(user) _mosquitto_free(user);
					user = _mosquitto_strdup(token);
					if(!user){
						fclose(aclfile);
						return MOSQ_ERR_NOMEM;
					}
				}else{
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Missing username in acl_file.");
					if(user) _mosquitto_free(user);
					fclose(aclfile);
					return 1;
				}
			}
		}
	}

	if(user) _mosquitto_free(user);
	fclose(aclfile);

	return MOSQ_ERR_SUCCESS;
}

static void _free_acl(struct _mosquitto_acl *acl)
{
	if(!acl) return;

	if(acl->child){
		_free_acl(acl->child);
	}
	if(acl->next){
		_free_acl(acl->next);
	}
	if(acl->topic){
		_mosquitto_free(acl->topic);
	}
	_mosquitto_free(acl);
}

static int _acl_cleanup(struct mosquitto_db *db, bool reload)
{
	int i;
	struct _mosquitto_acl_user *user_tail;

	if(!db) return MOSQ_ERR_INVAL;
	if(!db->acl_list) return MOSQ_ERR_SUCCESS;

	/* As we're freeing ACLs, we must clear context->acl_list to ensure no
	 * invalid memory accesses take place later.
	 * This *requires* the ACLs to be reapplied after _acl_cleanup()
	 * is called if we are reloading the config. If this is not done, all 
	 * access will be denied to currently connected clients.
	 */
	if(db->contexts){
		for(i=0; i<db->context_count; i++){
			if(db->contexts[i] && db->contexts[i]->acl_list){
				db->contexts[i]->acl_list = NULL;
			}
		}
	}

	while(db->acl_list){
		user_tail = db->acl_list->next;

		_free_acl(db->acl_list->acl);
		if(db->acl_list->username){
			_mosquitto_free(db->acl_list->username);
		}
		_mosquitto_free(db->acl_list);
		
		db->acl_list = user_tail;
	}

	if(db->acl_patterns){
		_free_acl(db->acl_patterns);
		db->acl_patterns = NULL;
	}
	return MOSQ_ERR_SUCCESS;
}

static int _pwfile_parse(const char *file, struct _mosquitto_unpwd **root)
{
	FILE *pwfile;
	struct _mosquitto_unpwd *unpwd;
	char buf[256];
	char *username, *password;
	int len;
	char *saveptr = NULL;

	pwfile = _mosquitto_fopen(file, "rt");
	if(!pwfile){
		_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to open pwfile \"%s\".", file);
		return 1;
	}

	while(!feof(pwfile)){
		if(fgets(buf, 256, pwfile)){
			username = strtok_r(buf, ":", &saveptr);
			if(username){
				unpwd = _mosquitto_calloc(1, sizeof(struct _mosquitto_unpwd));
				if(!unpwd){
					fclose(pwfile);
					return MOSQ_ERR_NOMEM;
				}
				unpwd->username = _mosquitto_strdup(username);
				if(!unpwd->username){
					fclose(pwfile);
					return MOSQ_ERR_NOMEM;
				}
				len = strlen(unpwd->username);
				while(unpwd->username[len-1] == 10 || unpwd->username[len-1] == 13){
					unpwd->username[len-1] = '\0';
					len = strlen(unpwd->username);
				}
				password = strtok_r(NULL, ":", &saveptr);
				if(password){
					unpwd->password = _mosquitto_strdup(password);
					if(!unpwd->password){
						fclose(pwfile);
						return MOSQ_ERR_NOMEM;
					}
					len = strlen(unpwd->password);
					while(len && (unpwd->password[len-1] == 10 || unpwd->password[len-1] == 13)){
						unpwd->password[len-1] = '\0';
						len = strlen(unpwd->password);
					}
				}
				HASH_ADD_KEYPTR(hh, *root, unpwd->username, strlen(unpwd->username), unpwd);
			}
		}
	}
	fclose(pwfile);

	return MOSQ_ERR_SUCCESS;
}

static int _unpwd_file_parse(struct mosquitto_db *db)
{
	int rc;
#ifdef WITH_TLS
	struct _mosquitto_unpwd *u, *tmp;
	char *token;
	unsigned char *salt;
	unsigned int salt_len;
	unsigned char *password;
	unsigned int password_len;
#endif

	if(!db || !db->config) return MOSQ_ERR_INVAL;

	if(!db->config->password_file) return MOSQ_ERR_SUCCESS;

	rc = _pwfile_parse(db->config->password_file, &db->unpwd);
#ifdef WITH_TLS
	if(rc) return rc;

	HASH_ITER(hh, db->unpwd, u, tmp){
		/* Need to decode password into hashed data + salt. */
		if(u->password){
			token = strtok(u->password, "$");
			if(token && !strcmp(token, "6")){
				token = strtok(NULL, "$");
				if(token){
					rc = _base64_decode(token, &salt, &salt_len);
					if(rc){
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to decode password salt for user %s.", u->username);
						return MOSQ_ERR_INVAL;
					}
					u->salt = salt;
					u->salt_len = salt_len;
					token = strtok(NULL, "$");
					if(token){
						rc = _base64_decode(token, &password, &password_len);
						if(rc){
							_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Unable to decode password for user %s.", u->username);
							return MOSQ_ERR_INVAL;
						}
						_mosquitto_free(u->password);
						u->password = (char *)password;
						u->password_len = password_len;
					}else{
						_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s.", u->username);
						return MOSQ_ERR_INVAL;
					}
				}else{
					_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s.", u->username);
					return MOSQ_ERR_INVAL;
				}
			}else{
				_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Invalid password hash for user %s.", u->username);
				return MOSQ_ERR_INVAL;
			}
		}
	}
#endif
	return rc;
}

static int _psk_file_parse(struct mosquitto_db *db)
{
	int rc;
	struct _mosquitto_unpwd *u, *tmp;

	if(!db || !db->config) return MOSQ_ERR_INVAL;

	/* We haven't been asked to parse a psk file. */
	if(!db->config->psk_file) return MOSQ_ERR_SUCCESS;

	rc = _pwfile_parse(db->config->psk_file, &db->psk_id);
	if(rc) return rc;

	HASH_ITER(hh, db->psk_id, u, tmp){
		/* Check for hex only digits */
		if(!u->password){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Empty psk for identity \"%s\".", u->username);
			return MOSQ_ERR_INVAL;
		}
		if(strspn(u->password, "0123456789abcdefABCDEF") < strlen(u->password)){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: psk for identity \"%s\" contains non-hexadecimal characters.", u->username);
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_unpwd_check_default(struct mosquitto_db *db, const char *username, const char *password)
{
	struct _mosquitto_unpwd *u, *tmp;
#ifdef WITH_TLS
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	int rc;
#endif

	if(!db || !username) return MOSQ_ERR_INVAL;
	if(!db->unpwd) return MOSQ_ERR_SUCCESS;

	HASH_ITER(hh, db->unpwd, u, tmp){
		if(!strcmp(u->username, username)){
			if(u->password){
				if(password){
#ifdef WITH_TLS
					rc = _pw_digest(password, u->salt, u->salt_len, hash, &hash_len);
					if(rc == MOSQ_ERR_SUCCESS){
						if(hash_len == u->password_len && !memcmp(u->password, hash, hash_len)){
							return MOSQ_ERR_SUCCESS;
						}else{
							return MOSQ_ERR_AUTH;
						}
					}else{
						return rc;
					}
#else
					if(!strcmp(u->password, password)){
						return MOSQ_ERR_SUCCESS;
					}
#endif
				}else{
					return MOSQ_ERR_AUTH;
				}
			}else{
				return MOSQ_ERR_SUCCESS;
			}
		}
	}

	return MOSQ_ERR_AUTH;
}

static int _unpwd_cleanup(struct _mosquitto_unpwd **root, bool reload)
{
	struct _mosquitto_unpwd *u, *tmp;

	if(!root) return MOSQ_ERR_INVAL;

	HASH_ITER(hh, *root, u, tmp){
		HASH_DEL(*root, u);
		if(u->password) _mosquitto_free(u->password);
		if(u->username) _mosquitto_free(u->username);
#ifdef WITH_TLS
		if(u->salt) _mosquitto_free(u->salt);
#endif
		_mosquitto_free(u);
	}

	*root = NULL;

	return MOSQ_ERR_SUCCESS;
}

/* Apply security settings after a reload.
 * Includes:
 * - Disconnecting anonymous users if appropriate
 * - Disconnecting users with invalid passwords
 * - Reapplying ACLs
 */
int mosquitto_security_apply_default(struct mosquitto_db *db)
{
	struct _mosquitto_acl_user *acl_user_tail;
	bool allow_anonymous;
	int i;

	if(!db) return MOSQ_ERR_INVAL;

	allow_anonymous = db->config->allow_anonymous;
	
	if(db->contexts){
		for(i=0; i<db->context_count; i++){
			if(db->contexts[i]){
				/* Check for anonymous clients when allow_anonymous is false */
				if(!allow_anonymous && !db->contexts[i]->username){
					db->contexts[i]->state = mosq_cs_disconnecting;
					_mosquitto_socket_close(db->contexts[i]);
					continue;
				}
				/* Check for connected clients that are no longer authorised */
				if(mosquitto_unpwd_check_default(db, db->contexts[i]->username, db->contexts[i]->password) != MOSQ_ERR_SUCCESS){
					db->contexts[i]->state = mosq_cs_disconnecting;
					_mosquitto_socket_close(db->contexts[i]);
					continue;
				}
				/* Check for ACLs and apply to user. */
				if(db->acl_list){
  					acl_user_tail = db->acl_list;
					while(acl_user_tail){
						if(acl_user_tail->username){
							if(db->contexts[i]->username){
								if(!strcmp(acl_user_tail->username, db->contexts[i]->username)){
									db->contexts[i]->acl_list = acl_user_tail;
									break;
								}
							}
						}else{
							if(!db->contexts[i]->username){
								db->contexts[i]->acl_list = acl_user_tail;
								break;
							}
						}
						acl_user_tail = acl_user_tail->next;
					}
				}
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_psk_key_get_default(struct mosquitto_db *db, const char *hint, const char *identity, char *key, int max_key_len)
{
	struct _mosquitto_unpwd *u, *tmp;

	if(!db || !hint || !identity || !key) return MOSQ_ERR_INVAL;
	if(!db->psk_id) return MOSQ_ERR_AUTH;

	HASH_ITER(hh, db->psk_id, u, tmp){
		if(!strcmp(u->username, identity)){
			strncpy(key, u->password, max_key_len);
			return MOSQ_ERR_SUCCESS;
		}
	}

	return MOSQ_ERR_AUTH;
}

#ifdef WITH_TLS
int _pw_digest(const char *password, const unsigned char *salt, unsigned int salt_len, unsigned char *hash, unsigned int *hash_len)
{
	const EVP_MD *digest;
	EVP_MD_CTX context;
	char *pass_salt;
	int pass_salt_len;

	digest = EVP_get_digestbyname("sha512");
	if(!digest){
		// FIXME fprintf(stderr, "Error: Unable to create openssl digest.\n");
		return 1;
	}

	pass_salt_len = strlen(password) + salt_len;
	pass_salt = _mosquitto_malloc(pass_salt_len);
	if(!pass_salt){
		// FIXME fprintf(stderr, "Error: Out of memory.\n");
		return 1;
	}
	memcpy(pass_salt, password, strlen(password));
	memcpy(pass_salt+strlen(password), salt, salt_len);
	EVP_MD_CTX_init(&context);
	EVP_DigestInit_ex(&context, digest, NULL);
	EVP_DigestUpdate(&context, pass_salt, pass_salt_len);
	/* hash is assumed to be EVP_MAX_MD_SIZE bytes long. */
	EVP_DigestFinal_ex(&context, hash, hash_len);
	EVP_MD_CTX_cleanup(&context);
	_mosquitto_free(pass_salt);

	return MOSQ_ERR_SUCCESS;
}

int _base64_decode(char *in, unsigned char **decoded, unsigned int *decoded_len)
{
	BIO *bmem, *b64;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(bmem, in, strlen(in));

	if(BIO_flush(bmem) != 1){
		BIO_free_all(bmem);
		return 1;
	}
	*decoded = calloc(strlen(in), 1);
	*decoded_len =  BIO_read(b64, *decoded, strlen(in));
	BIO_free_all(bmem);

	return 0;
}

#endif
