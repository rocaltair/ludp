#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <arpa/inet.h>

#if (defined(WIN32) || defined(_WIN32))
# include <winsock2.h>
# define socklen_t int
# define EINTR WSAEINTR
# define EWOULDBLOCK WSAEWOULDBLOCK

typedef long ssize_t;

static void startup()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error: %d\n", err);
		exit(1);
	}
}
#else
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <errno.h>
# include <unistd.h>
# define closesocket close
static void startup()
{
}
#endif /* endif for defined windows */

#if LUA_VERSION_NUM < 502
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#endif

#define LUA_BIND_META(L, type_t, ptr, mname) do {                   \
	type_t **my__p = lua_newuserdata(L, sizeof(void *));        \
	*my__p = ptr;                                               \
	luaL_getmetatable(L, mname);                                \
	lua_setmetatable(L, -2);                                    \
} while(0)

#define BUFFER_SIZE (8 * 1024)
#define LUDP_SERVER "ludp{server}"
#define LUDP_CLIENT "ludp{client}"

#define CHECK_SERVER(L, idx)\
	(*(udp_sock_t **) luaL_checkudata(L, idx, LUDP_SERVER))

#define CHECK_CLIENT(L, idx)\
	(*(udp_sock_t **) luaL_checkudata(L, idx, LUDP_CLIENT))

#define CONV_FUNC_MAP(XX)          \
	XX(htonl, uint32_t)        \
	XX(htons, uint16_t)        \
	XX(ntohl, uint32_t)        \
	XX(ntohs, uint16_t)

#define FLAGS_MAP(XX)                                            \
	XX(MSG_OOB, "process out-of-band data")                  \
	XX(MSG_PEEK, "peek at incoming message")                 \
	XX(MSG_WAITALL, "wait for full request or error")        \
	XX(MSG_EOR, "indicates end-of-record")                   \
	XX(MSG_TRUNC, "trunc")                                   \
	XX(MSG_CTRUNC, "ctrunc")                                 \
     	XX(MSG_DONTROUTE, "bypass routing, use direct interface")

typedef struct udp_sock_s {
	int fd;
} udp_sock_t;

#define XX(name, type)                                         \
	static int lua__##name(lua_State *L) {                 \
	        type in = (type)luaL_checknumber(L, 1);        \
	        type ret = name(in);                           \
	        lua_pushnumber(L, (lua_Number)ret);            \
	        return 1;                                      \
	}
	CONV_FUNC_MAP(XX)
#undef XX

static int sockaddr_set(const char * addrstr,
		      int port,
		      struct sockaddr_in * addr)
{
	int nIP = 0;
	if (!addrstr || *addrstr == '\0' 
	    || strcmp(addrstr, "0") == 0
	    || strcmp(addrstr, "0.0.0.0") == 0
	    || strcmp(addrstr, "*") == 0
	    || strcmp(addrstr, "any") == 0) {
		nIP = htonl(INADDR_ANY);
	} else if (strcmp(addrstr, "localhost") == 0) {
		char tmp[] = "127.0.0.1";
		nIP = inet_addr((const char *)tmp);
	} else {
		nIP = inet_addr(addrstr);
	}
	addr->sin_addr.s_addr = nIP;
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	return 0;
}

static void sockaddr_get(const struct sockaddr_storage *address,
			   int addrlen, int *family, char *ip, int *port)
{
	// sizeof ip INET6_ADDRSTRLEN;
	*family = address->ss_family;
	if (address->ss_family == AF_INET) {
		struct sockaddr_in *addrin = (struct sockaddr_in *)address;
		inet_ntop(AF_INET, &(addrin->sin_addr), ip, addrlen);
		*port = ntohs(addrin->sin_port);
	} else if (address->ss_family == AF_INET6) {
		struct sockaddr_in6 *addrin6 = (struct sockaddr_in6 *)address;
		inet_ntop(AF_INET6, &(addrin6->sin6_addr), ip, addrlen);
		*port = ntohs(addrin6->sin6_port);
	}
}

static int lua__sleep(lua_State *L)
{
        int ms = luaL_optinteger(L, 1, 0);
#if (defined(WIN32) || defined(_WIN32))
        Sleep(ms);
#else
        usleep((useconds_t)ms * 1000);
#endif
        lua_pushboolean(L, 1);
        return 1;
}

/* {{ begin of common */

static int luac__isobj(lua_State *L, int objindex)
{
	int ret = 1;
	int top = lua_gettop(L);
	if(lua_getmetatable(L, objindex) == 0) {
		goto finished;
	}
	luaL_getmetatable(L, LUDP_SERVER);
	luaL_getmetatable(L, LUDP_CLIENT);
	if (!lua_rawequal(L, -3, -2) && !lua_rawequal(L, -3, -1)) {
		goto finished;
		ret = 0;
	}
finished:
	lua_settop(L, top);
	return ret;
}

static int lua__common_recvfrom(lua_State *L)
{
	char buffer[BUFFER_SIZE];
	char remote_host[INET6_ADDRSTRLEN + 1];
	int remote_family;
	udp_sock_t *p = *(udp_sock_t **)lua_touserdata(L, 1);
	int flags = luaL_optinteger(L, 2, 0); /* NONE */
	const char *addrstr = luaL_optstring(L, 3, "");
	int port = luaL_optinteger(L, 4, 0);
	int remote_port = port;
	struct sockaddr_in addr;
	struct sockaddr_in *addr_ptr = NULL;
	socklen_t sockaddr_len = 0;
	ssize_t recvlen;


	if (port > 0 && strcmp(addrstr, "") != 0) {
		sockaddr_set(addrstr, port, &addr);
		addr_ptr = &addr;
	} else {
		addr_ptr = &addr;
		sockaddr_len = sizeof(addr);
	}

	if (p == NULL || p->fd < 0 || !luac__isobj(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "server or client obj not found");
		return 2;
	}
        recvlen = recvfrom(p->fd,
			   buffer,
			   sizeof(buffer),
			   flags,
			   (struct sockaddr *)addr_ptr,
			   sockaddr_len > 0 ? &sockaddr_len : NULL);

	if (recvlen < 0) {
		lua_pushnil(L);
#if (defined(WIN32) || defined(_WIN32))
		lua_pushfstring(L, "recvfrom failed");
#else
		lua_pushfstring(L, "recvfrom failed, err:%s", strerror(errno));
#endif /* endif for defined windows */
		return 2;
	}

        sockaddr_get((const struct sockaddr_storage *)addr_ptr,
		     sockaddr_len,
		     &remote_family,
		     (char *)&remote_host,
		     &remote_port);

	lua_pushlstring(L, buffer, (size_t)recvlen);
	lua_pushstring(L, remote_host);
	lua_pushnumber(L, remote_port);
	return 3;
}

static int lua__common_sendto(lua_State *L)
{
	size_t sz;
	udp_sock_t *p = *(udp_sock_t **)lua_touserdata(L, 1);
	const char * buffer = luaL_checklstring(L, 2, &sz);
	int flags = luaL_optinteger(L, 3, 0); /* NONE */
	const char *addrstr = luaL_optstring(L, 4, "");
	int port = luaL_optinteger(L, 5, 0);
	struct sockaddr_in addr;
	struct sockaddr_in *addr_ptr = NULL;
	socklen_t sockaddr_len = 0;
	ssize_t sendlen;

	if (port > 0 && strcmp(addrstr, "") != 0) {
		sockaddr_set(addrstr, port, &addr);
		addr_ptr = &addr;
		sockaddr_len = sizeof(addr);
	}

	if (p == NULL || p->fd < 0 || !luac__isobj(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "server or client obj not found");
		return 2;
	}
	sendlen = sendto(p->fd, buffer, sz, flags, (struct sockaddr *)addr_ptr, sockaddr_len);
	if (sendlen < 0) {
		lua_pushnil(L);
#if (defined(WIN32) || defined(_WIN32))
		lua_pushfstring(L, "send failed");
#else
		lua_pushfstring(L, "send failed:err %s", strerror(errno));
#endif /* endif for defined windows */
		return 2;
	}
	lua_pushnumber(L, sendlen);
	return 1;
}

static int lua__common_close(lua_State *L)
{
	udp_sock_t *p = *(udp_sock_t **)lua_touserdata(L, 1);
	if (p == NULL || p->fd < 0 || !luac__isobj(L, 1)) {
		lua_pushnil(L);
		lua_pushfstring(L, "server or client obj not found");
		return 2;
	}
	closesocket(p->fd);
	p->fd = -1;
	lua_pushboolean(L, 1);
	return 1;
}


/* }} end of common */

/* {{ server */ 
static int lua__server_new(lua_State *L)
{
	udp_sock_t * p = malloc(sizeof(*p));
	if (p == NULL) {
		return 0;
	}
	p->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (p->fd < 0) {
		free(p);
		lua_pushnil(L);
#if (defined(WIN32) || defined(_WIN32))
		lua_pushfstring(L, "create socket server failed");
#else
		lua_pushfstring(L, "create socket server failed, err:%s", strerror(errno));
#endif /* endif for defined windows */
		return 2;
	}
	LUA_BIND_META(L, udp_sock_t, p, LUDP_CLIENT);
	return 1;
}

static int lua__common_bind(lua_State *L)
{
	int fd;
	int bindret;
	struct sockaddr_in addr;
	udp_sock_t * p = *(udp_sock_t **)lua_touserdata(L, 1);
	const char *addrstr = luaL_optstring(L, 2, "0.0.0.0");
	int port = luaL_checkinteger(L, 3);
	if (p == NULL || p->fd < 0 || !luac__isobj(L, 1)) {
		lua_pushnil(L);
		fd = p != NULL ? p->fd : -2;
		lua_pushfstring(L, "server or client obj not found,fd=%d", fd);
		return 2;
	}
	sockaddr_set(addrstr, port, &addr);
	bindret = bind(p->fd, (const struct sockaddr *)&addr, sizeof(addr));
	if (bindret < 0) {
		lua_pushnil(L);
#if (defined(WIN32) || defined(_WIN32))
		lua_pushfstring(L, "Unable to bind to port %s:%d", addrstr, port);
#else
		lua_pushfstring(L, "Unable to bind to port %s:%d.err:%s", addrstr, port, strerror(errno));
#endif /* endif for defined windows */
		return 2;
	}
	lua_pushboolean(L, 1);
	return 1;
}

static int lua__server_gc(lua_State *L)
{
	udp_sock_t * p = CHECK_SERVER(L, 1);
	free(p);
	return 0;
}

static int opencls__server(lua_State *L)
{
	luaL_Reg lmethods[] = {
		{"sendto", lua__common_sendto},
		{"recvfrom", lua__common_recvfrom},
		{"close", lua__common_close},
		{"bind", lua__common_bind},
		{NULL, NULL},
	};
	luaL_newmetatable(L, LUDP_SERVER);
	lua_newtable(L);
	luaL_register(L, NULL, lmethods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction (L, lua__server_gc);
	lua_setfield (L, -2, "__gc");
	return 1;
}

/* }} server */ 

/* {{ begin of client */
static int lua__client_new(lua_State *L)
{
	udp_sock_t * p = malloc(sizeof(*p));
	if (p == NULL) {
		return 0;
	}
	p->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (p->fd < 0) {
		free(p);
		lua_pushnil(L);
#if (defined(WIN32) || defined(_WIN32))
		lua_pushfstring(L, "create socket client failed");
#else
		lua_pushfstring(L, "create socket client failed, err:%s", strerror(errno));
#endif /* endif for defined windows */
		return 2;
	}
	LUA_BIND_META(L, udp_sock_t, p, LUDP_CLIENT);
	return 1;
}

static int lua__client_gc(lua_State *L)
{
	udp_sock_t * p = CHECK_CLIENT(L, 1);
	free(p);
	return 0;
}

static int opencls__client(lua_State *L)
{
	luaL_Reg lmethods[] = {
		{"sendto", lua__common_sendto},
		{"recvfrom", lua__common_recvfrom},
		{"close", lua__common_close},
		{"bind", lua__common_bind},
		{NULL, NULL},
	};
	luaL_newmetatable(L, LUDP_CLIENT);
	lua_newtable(L);
	luaL_register(L, NULL, lmethods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction (L, lua__client_gc);
	lua_setfield (L, -2, "__gc");
	return 1;
}

/* }} end of client */

static int luac__register_flags(lua_State *L)
{
	lua_newtable(L);
#define XX(name, optstr)                  \
        (lua_pushstring(L, #name),        \
        lua_pushnumber(L, name),          \
	lua_settable(L, -3));
	FLAGS_MAP(XX)
#undef XX
	return 1;
}

int luaopen_ludp(lua_State* L)
{
#define XX(name, type) {#name, lua__##name},
	luaL_Reg lfuncs[] = {
		{"new_server", lua__server_new},
		{"new_client", lua__client_new},
		{"sleep", lua__sleep},
		CONV_FUNC_MAP(XX)
		{NULL, NULL},
	};
#undef XX
	startup();
	opencls__server(L);
	opencls__client(L);
	luaL_newlib(L, lfuncs);
	luac__register_flags(L);
	lua_setfield(L, -2, "Flags");	
	return 1;
}