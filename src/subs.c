/*
Copyright (c) 2010-2013 Roger Light <roger@atchoo.org>
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

/* A note on matching topic subscriptions.
 *
 * Topics can be up to 32767 characters in length. The / character is used as a
 * hierarchy delimiter. Messages are published to a particular topic.
 * Clients may subscribe to particular topics directly, but may also use
 * wildcards in subscriptions.  The + and # characters are used as wildcards.
 * The # wildcard can be used at the end of a subscription only, and is a
 * wildcard for the level of hierarchy at which it is placed and all subsequent
 * levels.
 * The + wildcard may be used at any point within the subscription and is a
 * wildcard for only the level of hierarchy at which it is placed.
 * Neither wildcard may be used as part of a substring.
 * Valid:
 * 	a/b/+
 * 	a/+/c
 * 	a/#
 * 	a/b/#
 * 	#
 * 	+/b/c
 * 	+/+/+
 * Invalid:
 *	a/#/c
 *	a+/b/c
 * Valid but non-matching:
 *	a/b
 *	a/+
 *	+/b
 *	b/c/a
 *	a/b/d
 */

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <mosquitto_broker.h>
#include <memory_mosq.h>
#include <util_mosq.h>

struct _sub_token {
	struct _sub_token *next;
	char *topic;
};

static int _subs_process(struct mosquitto_db *db, struct _mosquitto_subhier *hier, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored, bool set_retain)
{
	int rc = 0;
	int rc2;
	int client_qos, msg_qos;
	uint16_t mid;
	struct _mosquitto_subleaf *leaf;
	bool client_retain;

	leaf = hier->subs;

	if(retain && set_retain){
#ifdef WITH_PERSISTENCE
		if(strncmp(topic, "$SYS", 4)){
			/* Retained messages count as a persistence change, but only if
			 * they aren't for $SYS. */
			db->persistence_changes++;
		}
#endif
		if(hier->retained){
			hier->retained->ref_count--;
			/* FIXME - it would be nice to be able to remove the message from the store at this point if ref_count == 0 */
			db->retained_count--;
		}
		if(stored->msg.payloadlen){
			hier->retained = stored;
			hier->retained->ref_count++;
			db->retained_count++;
		}else{
			hier->retained = NULL;
		}
	}
	while(source_id && leaf){
		if(leaf->context->is_bridge && !strcmp(leaf->context->id, source_id)){
			leaf = leaf->next;
			continue;
		}
		/* Check for ACL topic access. */
		rc2 = mosquitto_acl_check(db, leaf->context, topic, MOSQ_ACL_READ);
		if(rc2 == MOSQ_ERR_ACL_DENIED){
			leaf = leaf->next;
			continue;
		}else if(rc2 == MOSQ_ERR_SUCCESS){
			client_qos = leaf->qos;

			if(db->config->upgrade_outgoing_qos){
				msg_qos = client_qos;
			}else{
				if(qos > client_qos){
					msg_qos = client_qos;
				}else{
					msg_qos = qos;
				}
			}
			if(msg_qos){
				mid = _mosquitto_mid_generate(leaf->context);
			}else{
				mid = 0;
			}
			if(leaf->context->is_bridge){
				/* If we know the client is a bridge then we should set retain
				 * even if the message is fresh. If we don't do this, retained
				 * messages won't be propagated. */
				client_retain = retain;
			}else{
				/* Client is not a bridge and this isn't a stale message so
				 * retain should be false. */
				client_retain = false;
			}
			if(mqtt3_db_message_insert(db, leaf->context, mid, mosq_md_out, msg_qos, client_retain, stored) == 1) rc = 1;
		}else{
			rc = 1;
		}
		leaf = leaf->next;
	}
	return rc;
}

static int _sub_topic_tokenise(const char *subtopic, struct _sub_token **topics)
{//将参数字符串subtopic进行按/分割的段解析，形成一个链表挂到参数topics上面
	struct _sub_token *new_topic, *tail = NULL;
	char *token;
	char *local_subtopic = NULL;
	char *saveptr = NULL;
	char *real_subtopic;

	assert(subtopic);
	assert(topics);

	local_subtopic = _mosquitto_strdup(subtopic);
	if(!local_subtopic) return MOSQ_ERR_NOMEM;
	real_subtopic = local_subtopic;//记住头部，待会师范这个空间。

	if(local_subtopic[0] == '/'){//第一个斜杠也算
		new_topic = _mosquitto_malloc(sizeof(struct _sub_token));
		if(!new_topic) goto cleanup;
		new_topic->next = NULL;
		new_topic->topic = _mosquitto_strdup("/");
		if(!new_topic->topic) goto cleanup;

		*topics = new_topic;
		tail = new_topic;

		local_subtopic++;
	}

	token = strtok_r(local_subtopic, "/", &saveptr);
	while(token){//一节一节的处理，形成一个链表,挂在参数topics上面，供上层使用
		new_topic = _mosquitto_malloc(sizeof(struct _sub_token));
		if(!new_topic) goto cleanup;
		new_topic->next = NULL;
		new_topic->topic = _mosquitto_strdup(token);
		if(!new_topic->topic) goto cleanup;

		if(tail){
			tail->next = new_topic;
			tail = tail->next;
		}else{
			tail = new_topic;
			*topics = tail;
		}
		token = strtok_r(NULL, "/", &saveptr);
	}
	
	_mosquitto_free(real_subtopic);

	return MOSQ_ERR_SUCCESS;

cleanup:
	_mosquitto_free(real_subtopic);

	tail = *topics;
	*topics = NULL;
	while(tail){
		if(tail->topic) _mosquitto_free(tail->topic);
		new_topic = tail->next;
		_mosquitto_free(tail);
		tail = new_topic;
	}
	return 1;
}

static int _sub_add(struct mosquitto_db *db, struct mosquitto *context, int qos, struct _mosquitto_subhier *subhier, struct _sub_token *tokens)
{//递归的查找参数tokens链表代表的路径段，找到其最终的订阅位置然后放到subs链表里面,返回MOSQ_ERR_SUCCESS表示成功，-1表示重复订阅
	struct _mosquitto_subhier *branch, *last = NULL;
	struct _mosquitto_subleaf *leaf, *last_leaf;

	if(!tokens){//tokens为空，那么很简单了，只需要将这个订阅放到当前subhier->subs链表的后面就行了。
		if(context){
			leaf = subhier->subs;//遍历这个节点的叶子
			last_leaf = NULL;
			while(leaf){//扫描一遍，看看是不是有重复订阅的情况，
				//所以这里代价还是比较大的，如果有几千个人订阅这个节点，那么每次新订阅得扫描这么长
				if(!strcmp(leaf->context->id, context->id)){
					/* Client making a second subscription to same topic. Only
					 * need to update QoS. Return -1 to indicate this to the
					 * calling function. */
					leaf->qos = qos;
					return -1;
				}
				last_leaf = leaf;
				leaf = leaf->next;
			}
			leaf = _mosquitto_malloc(sizeof(struct _mosquitto_subleaf));
			if(!leaf) return MOSQ_ERR_NOMEM;
			leaf->next = NULL;
			leaf->context = context;//指向订阅的客户端，那么客户端断开了，这里还是订阅着的
			leaf->qos = qos;
			if(last_leaf){
				last_leaf->next = leaf;
				leaf->prev = last_leaf;
			}else{
				subhier->subs = leaf;
				leaf->prev = NULL;
			}
			db->subscription_count++;
		}
		return MOSQ_ERR_SUCCESS;
	}

	branch = subhier->children;
	while(branch){//扫描一遍当前这个节点的子分支的topic段名称是否相等，相等的话就订阅到其下面，否则需要在末尾增加一个分支
		if(!strcmp(branch->topic, tokens->topic)){
			//找到，递归调用
			return _sub_add(db, context, qos, branch, tokens->next);
		}
		last = branch;
		branch = branch->next;
	}
	//没有找到，那么是一个新的分支，需要新建一个分支，挂入当前的层级的下面作为链表最后一个元素
	branch = _mosquitto_calloc(1, sizeof(struct _mosquitto_subhier));
	if(!branch) return MOSQ_ERR_NOMEM;
	branch->topic = _mosquitto_strdup(tokens->topic);
	if(!branch->topic) return MOSQ_ERR_NOMEM;
	if(!last){
		subhier->children = branch;
	}else{
		last->next = branch;
	}
	//新建了一个节点，然后继续往下深入，每一个段一级
	return _sub_add(db, context, qos, branch, tokens->next);
}

static int _sub_remove(struct mosquitto_db *db, struct mosquitto *context, struct _mosquitto_subhier *subhier, struct _sub_token *tokens)
{
	struct _mosquitto_subhier *branch, *last = NULL;
	struct _mosquitto_subleaf *leaf;

	if(!tokens){
		leaf = subhier->subs;
		while(leaf){
			if(leaf->context==context){
				db->subscription_count--;
				if(leaf->prev){
					leaf->prev->next = leaf->next;
				}else{
					subhier->subs = leaf->next;
				}
				if(leaf->next){
					leaf->next->prev = leaf->prev;
				}
				_mosquitto_free(leaf);
				return MOSQ_ERR_SUCCESS;
			}
			leaf = leaf->next;
		}
		return MOSQ_ERR_SUCCESS;
	}

	branch = subhier->children;
	while(branch){
		if(!strcmp(branch->topic, tokens->topic)){
			_sub_remove(db, context, branch, tokens->next);
			if(!branch->children && !branch->subs && !branch->retained){
				if(last){
					last->next = branch->next;
				}else{
					subhier->children = branch->next;
				}
				_mosquitto_free(branch->topic);
				_mosquitto_free(branch);
			}
			return MOSQ_ERR_SUCCESS;
		}
		last = branch;
		branch = branch->next;
	}
	return MOSQ_ERR_SUCCESS;
}

static int _sub_search(struct mosquitto_db *db, struct _mosquitto_subhier *subhier, struct _sub_token *tokens, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored, bool set_retain)
{
	/* FIXME - need to take into account source_id if the client is a bridge */
	struct _mosquitto_subhier *branch;
	int flag = 0;
	bool sr;

	branch = subhier->children;
	while(branch){
		sr = set_retain;

		if(tokens && tokens->topic && (!strcmp(branch->topic, tokens->topic) || !strcmp(branch->topic, "+"))){
			/* The topic matches this subscription.
			 * Doesn't include # wildcards */
			if(!strcmp(branch->topic, "+")){
				/* Don't set a retained message where + is in the hierarchy. */
				sr = false;
			}
			if(_sub_search(db, branch, tokens->next, source_id, topic, qos, retain, stored, sr) == -1){
				flag = -1;
			}
			if(!tokens->next){
				_subs_process(db, branch, source_id, topic, qos, retain, stored, sr);
			}
		}else if(!strcmp(branch->topic, "#") && !branch->children){
			/* The topic matches due to a # wildcard - process the
			 * subscriptions but *don't* return. Although this branch has ended
			 * there may still be other subscriptions to deal with.
			 */
			_subs_process(db, branch, source_id, topic, qos, retain, stored, false);
			flag = -1;
		}
		branch = branch->next;
	}
	return flag;
}

int mqtt3_sub_add(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int qos, struct _mosquitto_subhier *root)
{//将一个订阅的topic加入到root参数，也就是订阅树&db->subs上面,这里需要区分$SYS还是正常的客户端订阅
	int tree;
	int rc = 0;
	struct _mosquitto_subhier *subhier;
	struct _sub_token *tokens = NULL, *tail;

	assert(root);
	assert(sub);

	if(!strncmp(sub, "$SYS/", 5)){//系统属性等区别对待
		tree = 2;
		if(strlen(sub+5) == 0) return MOSQ_ERR_SUCCESS;
		if(_sub_topic_tokenise(sub+5, &tokens)) return 1;
	}else{
		tree = 0;
		if(strlen(sub) == 0) return MOSQ_ERR_SUCCESS;
		//对/分割的段进行解析，形成链表放到tokens上面
		if(_sub_topic_tokenise(sub, &tokens)) return 1;
	}

	subhier = root->children;//mqtt3_db_open初始化的时候分配了2个节点，一个数据节点和$SYS系统数据节点
	while(subhier){
		if(!strcmp(subhier->topic, "") && tree == 0){
			//正常的数据节点，mqtt3_db_open的时候初始化的
			rc = _sub_add(db, context, qos, subhier, tokens);
			break;
		}else if(!strcmp(subhier->topic, "$SYS") && tree == 2){
			//tree=2，那么只能订阅到$SYS的下面
			rc = _sub_add(db, context, qos, subhier, tokens);
			break;
		}
		subhier = subhier->next;
	}

	while(tokens){//释放内存_sub_topic_tokenise
		tail = tokens->next;
		_mosquitto_free(tokens->topic);
		_mosquitto_free(tokens);
		tokens = tail;
	}
	/* We aren't worried about -1 (already subscribed) return codes. */
	if(rc == -1) rc = MOSQ_ERR_SUCCESS;
	return rc;
}

int mqtt3_sub_remove(struct mosquitto_db *db, struct mosquitto *context, const char *sub, struct _mosquitto_subhier *root)
{//跟mqtt3_sub_add类似
	int rc = 0;
	int tree;
	struct _mosquitto_subhier *subhier;
	struct _sub_token *tokens = NULL, *tail;

	assert(root);
	assert(sub);

	if(!strncmp(sub, "$SYS/", 5)){
		tree = 2;
		if(_sub_topic_tokenise(sub+5, &tokens)) return 1;
	}else{
		tree = 0;
		if(_sub_topic_tokenise(sub, &tokens)) return 1;
	}

	subhier = root->children;
	while(subhier){
		if(!strcmp(subhier->topic, "") && tree == 0){
			rc = _sub_remove(db, context, subhier, tokens);
			break;
		}else if(!strcmp(subhier->topic, "$SYS") && tree == 2){
			rc = _sub_remove(db, context, subhier, tokens);
			break;
		}
		subhier = subhier->next;
	}

	while(tokens){
		tail = tokens->next;
		_mosquitto_free(tokens->topic);
		_mosquitto_free(tokens);
		tokens = tail;
	}

	return rc;
}

int mqtt3_db_messages_queue(struct mosquitto_db *db, const char *source_id, const char *topic, int qos, int retain, struct mosquitto_msg_store *stored)
{//将参数代表的消息发布
	int rc = 0;
	int tree;
	struct _mosquitto_subhier *subhier;
	struct _sub_token *tokens = NULL, *tail;

	assert(db);
	assert(topic);

	if(!strncmp(topic, "$SYS/", 5)){
		tree = 2;
		if(_sub_topic_tokenise(topic+5, &tokens)) return 1;
	}else{
		tree = 0;
		if(_sub_topic_tokenise(topic, &tokens)) return 1;
	}

	subhier = db->subs.children;
	while(subhier){
		if(!strcmp(subhier->topic, "") && tree == 0){
			if(retain){
				/* We have a message that needs to be retained, so ensure that the subscription
				 * tree for its topic exists.
				 */
				_sub_add(db, NULL, 0, subhier, tokens);
			}
			rc = _sub_search(db, subhier, tokens, source_id, topic, qos, retain, stored, true);
			if(rc == -1){
				_subs_process(db, subhier, source_id, topic, qos, retain, stored, true);
				rc = 0;
			}
		}else if(!strcmp(subhier->topic, "$SYS") && tree == 2){
			if(retain){
				/* We have a message that needs to be retained, so ensure that the subscription
				 * tree for its topic exists.
				 */
				_sub_add(db, NULL, 0, subhier, tokens);
			}
			rc = _sub_search(db, subhier, tokens, source_id, topic, qos, retain, stored, true);
			if(rc == -1){
				_subs_process(db, subhier, source_id, topic, qos, retain, stored, true);
				rc = 0;
			}
		}
		subhier = subhier->next;
	}
	while(tokens){
		tail = tokens->next;
		_mosquitto_free(tokens->topic);
		_mosquitto_free(tokens);
		tokens = tail;
	}

	return rc;
}

static int _subs_clean_session(struct mosquitto_db *db, struct mosquitto *context, struct _mosquitto_subhier *root)
{
	int rc = 0;
	struct _mosquitto_subhier *child, *last = NULL;
	struct _mosquitto_subleaf *leaf, *next;

	if(!root) return MOSQ_ERR_SUCCESS;

	leaf = root->subs;
	while(leaf){
		if(leaf->context == context){
			db->subscription_count--;
			if(leaf->prev){
				leaf->prev->next = leaf->next;
			}else{
				root->subs = leaf->next;
			}
			if(leaf->next){
				leaf->next->prev = leaf->prev;
			}
			next = leaf->next;
			_mosquitto_free(leaf);
			leaf = next;
		}else{
			leaf = leaf->next;
		}
	}

	child = root->children;
	while(child){
		_subs_clean_session(db, context, child);
		if(!child->children && !child->subs && !child->retained){
			if(last){
				last->next = child->next;
			}else{
				root->children = child->next;
			}
			_mosquitto_free(child->topic);
			_mosquitto_free(child);
			if(last){
				child = last->next;
			}else{
				child = root->children;
			}
		}else{
			last = child;
			child = child->next;
		}
	}
	return rc;
}

/* Remove all subscriptions for a client.
 */
int mqtt3_subs_clean_session(struct mosquitto_db *db, struct mosquitto *context, struct _mosquitto_subhier *root)
{
	struct _mosquitto_subhier *child;

	child = root->children;
	while(child){
		_subs_clean_session(db, context, child);
		child = child->next;
	}

	return MOSQ_ERR_SUCCESS;
}

void mqtt3_sub_tree_print(struct _mosquitto_subhier *root, int level)
{
	int i;
	struct _mosquitto_subhier *branch;
	struct _mosquitto_subleaf *leaf;

	for(i=0; i<level*2; i++){
		printf(" ");
	}
	printf("%s", root->topic);
	leaf = root->subs;
	while(leaf){
		if(leaf->context){
			printf(" (%s, %d)", leaf->context->id, leaf->qos);
		}else{
			printf(" (%s, %d)", "", leaf->qos);
		}
		leaf = leaf->next;
	}
	if(root->retained){
		printf(" (r)");
	}
	printf("\n");

	branch = root->children;
	while(branch){
		mqtt3_sub_tree_print(branch, level+1);
		branch = branch->next;
	}
}

static int _retain_process(struct mosquitto_db *db, struct mosquitto_msg_store *retained, struct mosquitto *context, const char *sub, int sub_qos)
{//检查权限，生成messageid, 放入context->msg排队处理消息链表尾部,等待处理
	int rc = 0;
	int qos;
	uint16_t mid;

	rc = mosquitto_acl_check(db, context, retained->msg.topic, MOSQ_ACL_READ);
	if(rc == MOSQ_ERR_ACL_DENIED){
		return MOSQ_ERR_SUCCESS;
	}else if(rc != MOSQ_ERR_SUCCESS){
		return rc;
	}

	qos = retained->msg.qos;

	if(qos > sub_qos) qos = sub_qos;
	if(qos > 0){
		mid = _mosquitto_mid_generate(context);
	}else{
		mid = 0;
	}
	//将一条消息插入到context->msg链表后面，设置相关的状态。然后记录这条消息给哪些人发送过等
	return mqtt3_db_message_insert(db, context, mid, mosq_md_out, qos, true, retained);
}

static int _retain_search(struct mosquitto_db *db, struct _mosquitto_subhier *subhier, struct _sub_token *tokens, struct mosquitto *context, const char *sub, int sub_qos, int level)
{//搜索订阅树，看看有没有retained消息，如果有，调用_retain_process，这里处理了通配符。
	//#统配任意多级路径，+通配一级路径
	struct _mosquitto_subhier *branch;
	int flag = 0;

	branch = subhier->children;
	while(branch){
		/* Subscriptions with wildcards in aren't really valid topics to publish to
		 * so they can't have retained messages.
		 */
		if(!strcmp(tokens->topic, "#") && !tokens->next){//当前节点是#通配符，并且tokens段是最后一段了，那么匹配
			/* Set flag to indicate that we should check for retained messages
			 * on "foo" when we are subscribing to e.g. "foo/#" and then exit
			 * this function and return to an earlier _retain_search().
			 */
			flag = -1;
			if(branch->retained){//#通配符，所以当前的节点是满足的
				_retain_process(db, branch->retained, context, sub, sub_qos);
			}
			if(branch->children){//同时后面的所有节点都可以满足，因为tokens还是为#
				_retain_search(db, branch, tokens, context, sub, sub_qos, level+1);
			}
		}else if(strcmp(branch->topic, "+") && (!strcmp(branch->topic, tokens->topic) || !strcmp(tokens->topic, "+"))){
			//1.字符正好相等，或者遇到+号通配1段
			if(tokens->next){//还有下一级，那么往下一级匹配。
				if(_retain_search(db, branch, tokens->next, context, sub, sub_qos, level+1) == -1){
					if(branch->retained){//上面返回-1，所以这里还需要将当前的节点上的订阅发布一下。但不需要再往上回溯了，因为这里是+
						_retain_process(db, branch->retained, context, sub, sub_qos);
					}
				}
			}else{//最后一级了，直接处理结果
				if(branch->retained){
					_retain_process(db, branch->retained, context, sub, sub_qos);
				}
			}
			//比如有这样的 ：a/b/#
			if(!branch->next && tokens->next && !strcmp(tokens->next->topic, "#") && level>0){
				//如果该分支到末尾了并且tokens还没结束，其下一个节点竟然是#，那么，还可以处理一下。那么问题是，这里会不会多次发布了。
				if(branch->retained){
					_retain_process(db, branch->retained, context, sub, sub_qos);
				}
			}
		}

		branch = branch->next;
	}
	return flag;
}

int mqtt3_retain_queue(struct mosquitto_db *db, struct mosquitto *context, const char *sub, int sub_qos)
{//处理一下那些retain遗留保存的数据，如果是新连接，得考虑给他发送这条消息.首先得找到他所对应的订阅树节点,检查节点上是否有数据
	int tree;
	struct _mosquitto_subhier *subhier;
	struct _sub_token *tokens = NULL, *tail;

	assert(db);
	assert(context);
	assert(sub);

	if(!strncmp(sub, "$SYS/", 5)){
		tree = 2;
		if(_sub_topic_tokenise(sub+5, &tokens)) return 1;
	}else{
		tree = 0;
		if(_sub_topic_tokenise(sub, &tokens)) return 1;
	}

	subhier = db->subs.children;
	while(subhier){//根据topic，找到其所合适的节点，然后看看有没有retain数据，如果有就放入该连接的context->msg待发数据队列里面
		if(!strcmp(subhier->topic, "") && tree == 0){
			_retain_search(db, subhier, tokens, context, sub, sub_qos, 0);
			break;
		}else if(!strcmp(subhier->topic, "$SYS") && tree == 2){
			_retain_search(db, subhier, tokens, context, sub, sub_qos, 0);
			break;
		}
		subhier = subhier->next;
	}
	while(tokens){//释放节点内存
		tail = tokens->next;
		_mosquitto_free(tokens->topic);
		_mosquitto_free(tokens);
		tokens = tail;
	}

	return MOSQ_ERR_SUCCESS;
}

