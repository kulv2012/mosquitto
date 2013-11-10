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

#ifndef MQTT3_H
#define MQTT3_H

#include <stdio.h>

#include <mosquitto_internal.h>
#include <mosquitto_plugin.h>
#include <mosquitto.h>
#include "uthash.h"

#ifndef __GNUC__
#define __attribute__(attrib)
#endif

/* Log destinations */
#define MQTT3_LOG_NONE 0x00
#define MQTT3_LOG_FILE 0x02
#define MQTT3_LOG_STDOUT 0x04
#define MQTT3_LOG_STDERR 0x08
#define MQTT3_LOG_TOPIC 0x10
#define MQTT3_LOG_ALL 0xFF

typedef uint64_t dbid_t;

struct _mqtt3_listener {
	int fd;
	char *host;
	uint16_t port;
	int max_connections;
	char *mount_point;//配置项，代表本broker里面的所有topic的前缀。注意跟其他客户端是不可见的。
	int *socks;//由于可能hostname为域名等，一条listener可能需要花费多个sock套接字句柄，所以为数组.所有的sock放在main()的局部变量listensock上面
	int sock_count;//上面socks数组的个数
	int client_count;//这个listener上面的客户连接数目
};

struct mqtt3_config {
	char *config_file;
	char *acl_file;
	bool allow_anonymous;//是否允许免密码登陆使用
	bool allow_duplicate_messages;
	int autosave_interval;//自动保存db文件持久化的间隔时间或者最大累积条数，依赖autosave_on_changes
	bool autosave_on_changes;//如果设置了，那么累积autosave_interval这么多条数据后，会持久化，否则autosave_interval就是保存间隔时间
	char *clientid_prefixes;
	bool connection_messages;
	bool daemon;
	struct _mqtt3_listener default_listener;
	struct _mqtt3_listener *listeners;
	int listener_count;
	int log_dest;
	int log_type;
	bool log_timestamp;
	char *log_file;
	FILE *log_fptr;
	int message_size_limit;
	char *password_file;
	bool persistence;
	char *persistence_location;
	char *persistence_file;
	char *persistence_filepath;
	time_t persistent_client_expiration;
	char *pid_file;
	char *psk_file;
	bool queue_qos0_messages;//如果客户端挂了，qos0的消息是否保存离线记录
	int retry_interval;
	int store_clean_interval;
	int sys_interval;
	bool upgrade_outgoing_qos;//是否允许强制上升QOS，比如客户端要求2，但publisher只要求0，那么如果配置为true，最终以2发送
	char *user;
	bool verbose;
	char *auth_plugin;
	struct mosquitto_auth_opt *auth_options;
	int auth_option_count;
};

struct _mosquitto_subleaf {
	struct _mosquitto_subleaf *prev;
	struct _mosquitto_subleaf *next;
	struct mosquitto *context;//指向订阅的客户端连接，
	int qos;
};

struct _mosquitto_subhier {
	struct _mosquitto_subhier *children;//这个节点的下一级节点链表
	struct _mosquitto_subhier *next;
	struct _mosquitto_subleaf *subs;//一个节点上订阅的客户端链表
	char *topic;
	struct mosquitto_msg_store *retained;//指向db->msg_store上的一条消息，在指向的时候增加了count计数的，所以不会丢掉
};

struct mosquitto_msg_store{//这是服务端记录的消息结构
	struct mosquitto_msg_store *next;
	dbid_t db_id;
	int ref_count;//被多少mosquitto_client_msg客户端消息引用了,如果为0，就可以删除这条消息了
	char *source_id;
	char **dest_ids;//这条消息已经送达的id列表，配置allow_duplicate_messages了的话，这里就有用了
	int dest_id_count;
	uint16_t source_mid;
	struct mosquitto_message msg;
};

struct mosquitto_client_msg{//这是要发送给客户端的消息结构
	struct mosquitto_client_msg *next;
	struct mosquitto_msg_store *store;///指向这条消息的综合结构
	uint16_t mid;
	int qos;
	bool retain;
	time_t timestamp;
	enum mosquitto_msg_direction direction;
	enum mosquitto_msg_state state;
	bool dup;
};

struct _mosquitto_unpwd{
	char *username;
	char *password;
	UT_hash_handle hh;
};

struct _mosquitto_acl{
	struct _mosquitto_acl *child;
	struct _mosquitto_acl *next;
	char *topic;
	int access;
};

struct _mosquitto_acl_user{
	struct _mosquitto_acl_user *next;
	char *username;
	struct _mosquitto_acl *acl;
};

struct _mosquitto_auth_plugin{
	void *lib;
	void *user_data;
	int (*plugin_version)(void);
	int (*plugin_init)(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count);
	int (*plugin_cleanup)(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count);
	int (*security_init)(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload);
	int (*security_cleanup)(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload);
	int (*acl_check)(void *user_data, const char *clientid, const char *username, const char *topic, int access);
	int (*unpwd_check)(void *user_data, const char *username, const char *password);
	int (*psk_key_get)(void *user_data, const char *hint, const char *identity, char *key, int max_key_len);
};

struct _clientid_index_hash{
	/* this is the key */
	char *id;
	/* this is the index where the client ID exists in the db->contexts array */
	int db_context_index;
	UT_hash_handle hh;
};

struct mosquitto_db{
	dbid_t last_db_id;//msg_store上的消息的顺序id
	struct _mosquitto_subhier subs;//树形的订阅关系列表.该链表第一个节点为正常的topic订阅节点，第二个为$SYS系统状态订阅节点
	struct _mosquitto_unpwd *unpwd;
	struct _mosquitto_acl_user *acl_list;
	struct _mosquitto_acl *acl_patterns;
	struct _mosquitto_unpwd *psk_id;
	struct mosquitto **contexts;//注意这个地方会不断变化，所以不要指向这个数组
	struct _clientid_index_hash *clientid_index_hash;//所有客户端id的哈希表,用来快速找到这个客户端在db->contexts数组中的位置的
	int context_count;
	struct mosquitto_msg_store *msg_store;//这里是所有publish的消息，都在这.新消息插入头部
	int msg_store_count;
	struct mqtt3_config *config;
	int persistence_changes;//如果autosave_on_changes设置了，那么这里用来累积计数修改了多少条数据，达到autosave_interval后就会持久化
	struct _mosquitto_auth_plugin auth_plugin;
	int subscription_count;//总订阅量
	int retained_count;
};

enum mqtt3_bridge_direction{
	bd_out = 0,
	bd_in = 1,
	bd_both = 2
};

enum mosquitto_bridge_start_type{
	bst_automatic = 0,
	bst_lazy = 1,
	bst_manual = 2,
	bst_once = 3
};

struct _mqtt3_bridge_topic{
	char *topic;
	int qos;
	enum mqtt3_bridge_direction direction;
	char *local_prefix;
	char *remote_prefix;
	char *local_topic; /* topic prefixed with local_prefix */
	char *remote_topic; /* topic prefixed with remote_prefix */
};

struct bridge_address{
	char *address;
	int port;
};

struct _mqtt3_bridge{
	char *name;
	struct bridge_address *addresses;
	int cur_address;
	int address_count;
	time_t primary_retry;
	bool round_robin;
	char *clientid;
	int keepalive;
	bool clean_session;
	struct _mqtt3_bridge_topic *topics;
	int topic_count;
	bool topic_remapping;
	time_t restart_t;
	char *username;
	char *password;
	bool notifications;
	char *notification_topic;
	enum mosquitto_bridge_start_type start_type;
	int idle_timeout;
	int restart_timeout;
	int threshold;
	bool lazy_reconnect;
	bool try_private;
	bool try_private_accepted;
};

#include <net_mosq.h>

/* ============================================================
 * Main functions
 * ============================================================ */
int mosquitto_main_loop(struct mosquitto_db *db, int *listensock, int listensock_count, int listener_max);
struct mosquitto_db *_mosquitto_get_db(void);

/* ============================================================
 * Config functions
 * ============================================================ */
/* Initialise config struct to default values. */
void mqtt3_config_init(struct mqtt3_config *config);
/* Parse command line options into config. */
int mqtt3_config_parse_args(struct mqtt3_config *config, int argc, char *argv[]);
/* Read configuration data from config->config_file into config.
 * If reload is true, don't process config options that shouldn't be reloaded (listeners etc)
 * Returns 0 on success, 1 if there is a configuration error or if a file cannot be opened.
 */
int mqtt3_config_read(struct mqtt3_config *config, bool reload);
/* Free all config data. */
void mqtt3_config_cleanup(struct mqtt3_config *config);

/* ============================================================
 * Server send functions
 * ============================================================ */
int _mosquitto_send_connack(struct mosquitto *context, int result);
int _mosquitto_send_suback(struct mosquitto *context, uint16_t mid, uint32_t payloadlen, const void *payload);

/* ============================================================
 * Network functions
 * ============================================================ */
int mqtt3_socket_accept(struct mosquitto_db *db, int listensock);
int mqtt3_socket_listen(struct _mqtt3_listener *listener);
int _mosquitto_socket_get_address(int sock, char *buf, int len);

/* ============================================================
 * Read handling functions
 * ============================================================ */
int mqtt3_packet_handle(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_connack(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_connect(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_disconnect(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_publish(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_subscribe(struct mosquitto_db *db, struct mosquitto *context);
int mqtt3_handle_unsubscribe(struct mosquitto_db *db, struct mosquitto *context);

/* ============================================================
 * Database handling
 * ============================================================ */
int mqtt3_db_open(struct mqtt3_config *config, struct mosquitto_db *db);
int mqtt3_db_close(struct mosquitto_db *db);
#ifdef WITH_PERSISTENCE
int mqtt3_db_backup(struct mosquitto_db *db, bool cleanup, bool shutdown);
int mqtt3_db_restore(struct mosquitto_db *db);
#endif
int mqtt3_db_client_count(struct mosquitto_db *db, unsigned int *count, unsigned int *inactive_count);
void mqtt3_db_limits_set(int inflight, int queued);
/* Return the number of in-flight messages in count. */
int mqtt3_db_message_count(int *count);
int mqtt3_db_message_delete(struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir);
int mqtt3_db_message_insert(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, int qos, bool retain, struct mosquitto_msg_store *stored);
int mqtt3_db_message_release(struct mosquitto_db *db, struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir);
int mqtt3_db_message_update(struct mosquitto *context, uint16_t mid, enum mosquitto_msg_direction dir, enum mosquitto_msg_state state);
int mqtt3_db_message_write(struct mosquitto *context);
int mqtt3_db_messages_delete(struct mosquitto *context);
int mqtt3_db_messages_easy_queue(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain);
int mqtt3_db_messages_queue(struct mosquitto_db *db, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored);
int mqtt3_db_message_store(struct mosquitto_db *db, const char *source, uint16_t source_mid, const char *topic, int qos, uint32_t payloadlen, const void *payload, int retain, struct mosquitto_msg_store **stored, dbid_t store_id);
int mqtt3_db_message_store_find(struct mosquitto *context, uint16_t mid, struct mosquitto_msg_store **stored);
/* Check all messages waiting on a client reply and resend if timeout has been exceeded. */
int mqtt3_db_message_timeout_check(struct mosquitto_db *db, unsigned int timeout);
int mqtt3_db_message_reconnect_reset(struct mosquitto *context);
int mqtt3_retain_queue(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int sub_qos);
void mqtt3_db_store_clean(struct mosquitto_db *db);
void mqtt3_db_sys_update(struct mosquitto_db *db, int interval, time_t start_time);
void mqtt3_db_vacuum(void);

/* ============================================================
 * Subscription functions
 * ============================================================ */
int mqtt3_sub_add(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int qos, struct _mosquitto_subhier *root);
int mqtt3_sub_remove(struct mosquitto_db *db, struct mosquitto *context, const char *sub, struct _mosquitto_subhier *root);
int mqtt3_sub_search(struct mosquitto_db *db, struct _mosquitto_subhier *root, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored);
void mqtt3_sub_tree_print(struct _mosquitto_subhier *root, int level);
int mqtt3_subs_clean_session(struct mosquitto_db *db, struct mosquitto *context, struct _mosquitto_subhier *root);

/* ============================================================
 * Context functions
 * ============================================================ */
struct mosquitto *mqtt3_context_init(int sock);
void mqtt3_context_cleanup(struct mosquitto_db *db, struct mosquitto *context, bool do_free);
void mqtt3_context_disconnect(struct mosquitto_db *db, struct mosquitto *context);

/* ============================================================
 * Logging functions
 * ============================================================ */
int mqtt3_log_init(int level, int destinations);
int mqtt3_log_close(void);
int _mosquitto_log_printf(struct mosquitto *mosq, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* ============================================================
 * Bridge functions
 * ============================================================ */

/* ============================================================
 * Security related functions
 * ============================================================ */
int mosquitto_security_module_init(struct mosquitto_db *db);
int mosquitto_security_module_cleanup(struct mosquitto_db *db);

int mosquitto_security_init(struct mosquitto_db *db, bool reload);
int mosquitto_security_apply(struct mosquitto_db *db);
int mosquitto_security_cleanup(struct mosquitto_db *db, bool reload);
int mosquitto_acl_check(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access);
int mosquitto_unpwd_check(struct mosquitto_db *db, const char *username, const char *password);
int mosquitto_psk_key_get(struct mosquitto_db *db, const char *hint, const char *identity, char *key, int max_key_len);

int mosquitto_security_init_default(struct mosquitto_db *db, bool reload);
int mosquitto_security_apply_default(struct mosquitto_db *db);
int mosquitto_security_cleanup_default(struct mosquitto_db *db, bool reload);
int mosquitto_acl_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access);
int mosquitto_unpwd_check_default(struct mosquitto_db *db, const char *username, const char *password);
int mosquitto_psk_key_get_default(struct mosquitto_db *db, const char *hint, const char *identity, char *key, int max_key_len);

/* ============================================================
 * Window service related functions
 * ============================================================ */

#endif
