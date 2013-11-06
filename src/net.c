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

#include <config.h>

#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#ifdef __FreeBSD__
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

#ifdef __QNX__
#include <netinet/in.h>
#include <net/netbyte.h>
#include <sys/socket.h>
#endif

#include <mosquitto_broker.h>
#include <mqtt3_protocol.h>
#include <memory_mosq.h>
#include <net_mosq.h>
#include <util_mosq.h>


#ifdef WITH_SYS_TREE
extern unsigned int g_socket_connections;
#endif

int mqtt3_socket_accept(struct mosquitto_db *db, int listensock)
{
	int i;
	int j;
	int new_sock = -1;
	struct mosquitto **tmp_contexts = NULL;
	struct mosquitto *new_context;
	int opt = 1;

	new_sock = accept(listensock, NULL, 0);
	if(new_sock == INVALID_SOCKET) return -1;

#ifdef WITH_SYS_TREE
	g_socket_connections++;
#endif

	/* Set non-blocking */
	opt = fcntl(new_sock, F_GETFL, 0);
	if(opt == -1 || fcntl(new_sock, F_SETFL, opt | O_NONBLOCK) == -1){
		/* If either fcntl fails, don't want to allow this client to connect. */
		close(new_sock);
		return -1;
	}

	//初始化个跟客户端连接的context，里面会设置客户端的IP地址，这里可以考虑不在里面做，accept的时候参数中完成即可
	new_context = mqtt3_context_init(new_sock);
	if(!new_context){
		COMPAT_CLOSE(new_sock);
		return -1;
	}
	for(i=0; i<db->config->listener_count; i++){//循环找每一个listeners，找到我是属于哪个listeners.实际上epoll后就不需要这些东西了
		for(j=0; j<db->config->listeners[i].sock_count; j++){
			if(db->config->listeners[i].socks[j] == listensock){
				new_context->listener = &db->config->listeners[i];//指向我所属的listener
				break;
			}
		}
	}
	if(!new_context->listener){
		COMPAT_CLOSE(new_sock);
		return -1;
	}

	if(new_context->listener->max_connections > 0 && new_context->listener->client_count >= new_context->listener->max_connections){
		_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "Client connection from %s denied: max_connections exceeded.", new_context->address);
		COMPAT_CLOSE(new_sock);
		return -1;
	}
	_mosquitto_log_printf(NULL, MOSQ_LOG_NOTICE, "New connection from %s on port %d.", new_context->address, new_context->listener->port);
	for(i=0; i<db->context_count; i++){//找一个空的contexts结构，指向这一个空连接
		if(db->contexts[i] == NULL){
			db->contexts[i] = new_context;
			break;
		}
	}
	if(i==db->context_count){//没有了，重新realloc一个，这个代价很大的。所以建议申请2倍，保留一些空余的,到一定程度的时候每次增加32个也行
		tmp_contexts = _mosquitto_realloc(db->contexts, sizeof(struct mosquitto*)*(db->context_count+1));
		if(tmp_contexts){
			db->context_count++;
			db->contexts = tmp_contexts;//这样的话，所有人都不能用指向contexts数组某个位置的指针来标识这个连接，比如放到epoll里面去世不行的
			db->contexts[i] = new_context;
		}else{
			//到这里，说明contexts[]数组不够了，而且relloac也失败，怎么办，只能丢掉这个连接了。但是下面并没有return -1,而且还去访问了。是个bug
			// Out of memory
			mqtt3_context_cleanup(NULL, new_context, true);
			return -1 ;//必须return,否则下面会core
		}
	}
	// If we got here then the context's DB index is "i" regardless of how we got here
	new_context->db_index = i;
	new_context->listener->client_count++;


	return new_sock;
}



/* Creates a socket and listens on port 'port'.
 * Returns 1 on failure
 * Returns 0 on success.
 */
int mqtt3_socket_listen(struct _mqtt3_listener *listener)
{
	int sock = -1;
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	char service[10];
	int opt = 1;
	int ss_opt = 1;
	char err[256];

	if(!listener) return MOSQ_ERR_INVAL;

	snprintf(service, 10, "%d", listener->port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;

	//导致下面返回多个链表节的的因素可能有：
	//hostname参数关联的地址有多个，那么每个返回一个节点；比如host为域名的时候，nslookup返回几个ip就有几个
	//service参数指定的服务会吃多个套接字接口类型，那么也返回多个
	if(getaddrinfo(listener->host, service, &hints, &ainfo)) return INVALID_SOCKET;

	listener->sock_count = 0;
	listener->socks = NULL;

	for(rp = ainfo; rp; rp = rp->ai_next){
		if(rp->ai_family == AF_INET){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Opening ipv4 listen socket on port %d.", ntohs(((struct sockaddr_in *)rp->ai_addr)->sin_port));
		}else if(rp->ai_family == AF_INET6){
			_mosquitto_log_printf(NULL, MOSQ_LOG_INFO, "Opening ipv6 listen socket on port %d.", ntohs(((struct sockaddr_in6 *)rp->ai_addr)->sin6_port));
		}else{
			continue;
		}

		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sock == -1){
			strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_WARNING, "Warning: %s", err);
			continue;
		}
		listener->sock_count++;
		listener->socks = _mosquitto_realloc(listener->socks, sizeof(int)*listener->sock_count);
		if(!listener->socks){
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: Out of memory.");
			return MOSQ_ERR_NOMEM;
		}
		listener->socks[listener->sock_count-1] = sock;

		ss_opt = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ss_opt, sizeof(ss_opt));
		ss_opt = 1;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ss_opt, sizeof(ss_opt));


		/* Set non-blocking */
		opt = fcntl(sock, F_GETFL, 0);
		if(opt == -1 || fcntl(sock, F_SETFL, opt | O_NONBLOCK) == -1){
			/* If either fcntl fails, don't want to allow this client to connect. */
			COMPAT_CLOSE(sock);
			return 1;
		}

		if(bind(sock, rp->ai_addr, rp->ai_addrlen) == -1){
			strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: %s", err);
			COMPAT_CLOSE(sock);
			return 1;
		}

		if(listen(sock, 100) == -1){
			strerror_r(errno, err, 256);
			_mosquitto_log_printf(NULL, MOSQ_LOG_ERR, "Error: %s", err);
			COMPAT_CLOSE(sock);
			return 1;
		}
	}
	freeaddrinfo(ainfo);

	/* We need to have at least one working socket. */
	if(listener->sock_count > 0){
		return 0;
	}else{
		return 1;
	}
}

int _mosquitto_socket_get_address(int sock, char *buf, int len)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;

	addrlen = sizeof(addr);
	//获取客户端IP地址,这个明显在accept的时候获取合适嘛
	if(!getpeername(sock, (struct sockaddr *)&addr, &addrlen)){
		if(addr.ss_family == AF_INET){
			if(inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr.s_addr, buf, len)){
				return 0;
			}
		}else if(addr.ss_family == AF_INET6){
			if(inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr, buf, len)){
				return 0;
			}
		}
	}
	return 1;
}
