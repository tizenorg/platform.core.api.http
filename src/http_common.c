/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "http.h"
#include "http_private.h"

#include "net_connection.h"

#include <pthread.h>
#include <openssl/err.h>

#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self()

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL;
static bool is_init = false;

bool _http_is_init(void)
{
	return is_init;
}

static void __http_set_init(bool init)
{
	is_init = init;
}

http_method_e _get_method(gchar* method)
{
	if (g_strcmp0(method, "GET") == 0)
		return HTTP_METHOD_GET;
	else if (g_strcmp0(method, "OPTIONS") == 0)
		return HTTP_METHOD_OPTIONS;
	else if (g_strcmp0(method, "HEAD") == 0)
		return HTTP_METHOD_HEAD;
	else if (g_strcmp0(method, "DELETE") == 0)
		return HTTP_METHOD_DELETE;
	else if (g_strcmp0(method, "TRACE") == 0)
		return HTTP_METHOD_TRACE;
	else if (g_strcmp0(method, "POST") == 0)
		return HTTP_METHOD_POST;
	else if (g_strcmp0(method, "PUT") == 0)
		return HTTP_METHOD_PUT;
	else if (g_strcmp0(method, "CONNECT") == 0)
		return HTTP_METHOD_CONNECT;

	return HTTP_METHOD_GET;
}

gchar* _get_http_method(http_method_e method)
{
	gchar* http_method = NULL;

	switch (method) {
	case HTTP_METHOD_OPTIONS:
		http_method = g_strdup("OPTIONS");
		break;

	case HTTP_METHOD_HEAD:
		http_method = g_strdup("HEAD");
		break;

	case HTTP_METHOD_DELETE:
		http_method = g_strdup("DELETE");
		break;

	case HTTP_METHOD_TRACE:
		http_method = g_strdup("TRACE");
		break;

	case HTTP_METHOD_POST:
		http_method = g_strdup("POST");
		break;

	case HTTP_METHOD_PUT:
		http_method = g_strdup("PUT");
		break;

	case HTTP_METHOD_CONNECT:
		http_method = g_strdup("CONNECT");
		break;
	case HTTP_METHOD_GET:
	default:
		http_method = g_strdup("GET");
		break;
	}

	return http_method;
}

http_auth_scheme _get_http_auth_scheme(bool proxy_auth, curl_http_auth_scheme curl_auth_scheme)
{
	http_auth_scheme auth_scheme = HTTP_AUTH_NONE;
	if(proxy_auth) {
		switch (curl_auth_scheme) {
		case _CURL_HTTP_AUTH_NONE:
			auth_scheme = HTTP_AUTH_NONE;
			break;
		case _CURL_HTTP_AUTH_BASIC:
			auth_scheme = HTTP_AUTH_PROXY_BASIC;
			break;
		case _CURL_HTTP_AUTH_DIGEST:
			auth_scheme = HTTP_AUTH_PROXY_MD5;
			break;
		case _CURL_HTTP_AUTH_NTLM:
			auth_scheme = HTTP_AUTH_PROXY_NTLM;
			break;
		default:
			auth_scheme = HTTP_AUTH_NONE;
			break;
		}
	}
	else {
		switch (curl_auth_scheme) {
		case _CURL_HTTP_AUTH_NONE:
			auth_scheme = HTTP_AUTH_NONE;
			break;
		case _CURL_HTTP_AUTH_BASIC:
			auth_scheme = HTTP_AUTH_WWW_BASIC;
			break;
		case _CURL_HTTP_AUTH_DIGEST:
			auth_scheme = HTTP_AUTH_WWW_MD5;
			break;
		case _CURL_HTTP_AUTH_NTLM:
			auth_scheme = HTTP_AUTH_WWW_NTLM;
			break;
		case _CURL_HTTP_AUTH_GSSNEGOTIATE:
			auth_scheme = HTTP_AUTH_WWW_NEGOTIATE;
			break;
		default:
			auth_scheme = HTTP_AUTH_NONE;
			break;
		}
	}

	return auth_scheme;
}

curl_http_auth_scheme _get_http_curl_auth_scheme(http_auth_scheme auth_scheme)
{
	curl_http_auth_scheme curl_auth_scheme = _CURL_HTTP_AUTH_NONE;
	switch (auth_scheme) {
	case HTTP_AUTH_PROXY_BASIC:
	case HTTP_AUTH_WWW_BASIC:
		curl_auth_scheme = _CURL_HTTP_AUTH_BASIC;
		break;
	case HTTP_AUTH_PROXY_MD5:
	case HTTP_AUTH_WWW_MD5:
		curl_auth_scheme = _CURL_HTTP_AUTH_DIGEST;
		break;
	case HTTP_AUTH_PROXY_NTLM:
	case HTTP_AUTH_WWW_NTLM:
		curl_auth_scheme = _CURL_HTTP_AUTH_NTLM;
		break;
	case HTTP_AUTH_WWW_NEGOTIATE:
		curl_auth_scheme = _CURL_HTTP_AUTH_GSSNEGOTIATE;
		break;
	default:
		curl_auth_scheme = _CURL_HTTP_AUTH_NONE;
		break;
	}

	return curl_auth_scheme;
}

void print_curl_multi_errorCode(CURLMcode code)
{
	const char* message = NULL;
	switch (code) {
	case CURLM_CALL_MULTI_PERFORM:
		message = "CURLM_CALL_MULTI_PERFORM";
		break;
	case CURLM_BAD_HANDLE:
		message = "CURLM_BAD_HANDLE";
		break;
	case CURLM_BAD_EASY_HANDLE:
		message = "CURLM_BAD_EASY_HANDLE";
		break;
	case CURLM_OUT_OF_MEMORY:
		message = "CURLM_OUT_OF_MEMORY";
		break;
	case CURLM_INTERNAL_ERROR:
		message = "CURLM_INTERNAL_ERROR";
		break;
	case CURLM_BAD_SOCKET:
		message = "CURLM_BAD_SOCKET";
		break;
	case CURLM_UNKNOWN_OPTION:
		message = "CURLM_UNKNOWN_OPTION";
		break;
	case CURLM_LAST:
		message = "CURLM_LAST";
		break;
	default:
		message = "CURLM_UNKNOWN_ERROR";
		break;
	}

	DBG("CURLMcode(%d): %s", code, message);
}

gchar* parse_values(const gchar* string, int from_index, int to_index)
{
	gchar* str = NULL;
	int cur_index = to_index - from_index;

	str = (gchar*) malloc(cur_index + 1);
	memset(str, '\0', cur_index + 1);

	strncpy(str, (string + from_index), cur_index);
	str[cur_index] ='\0';

	return str;
}

gchar* _get_proxy()
{
	connection_h connection = NULL;
	gchar *proxy_addr = NULL;

	if (connection_create(&connection) < 0) {
		DBG("Fail to create network handle\n");
		return NULL;
	}

	if (connection_get_proxy(connection, CONNECTION_ADDRESS_FAMILY_IPV4, &proxy_addr) < 0) {
		DBG("Fail to get proxy address\n");
		goto CATCH;
	}

CATCH:
	if (connection_destroy(connection) < 0)
		DBG("Fail to destroy network handle\n");

	return proxy_addr;
}

static void locking_function(int mode, int n, const char * file, int line)
{
	if (mode & CRYPTO_LOCK)
		MUTEX_LOCK(mutex_buf[n]);
	else
		MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
	return ((unsigned long)THREAD_ID);
}

int thread_setup(void)
{
	int index = 0;

	mutex_buf = malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
	if (!mutex_buf)
		return 0;

	for (index = 0;  index < CRYPTO_num_locks();  index++)
		MUTEX_SETUP(mutex_buf[index]);

	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);

	return 1;
}

int thread_cleanup(void)
{
	int index;

	if (!mutex_buf)
		return 0;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);

	for (index = 0;  index < CRYPTO_num_locks();  index++)
		MUTEX_CLEANUP(mutex_buf[index]);

	free(mutex_buf);
	mutex_buf = NULL;

	return 1;
}

API int http_init(void)
{
	_retvm_if(_http_is_init(), HTTP_ERROR_INVALID_OPERATION,
			"http is already initialized!!");

	int ret = 0;

	__http_set_init(true);

	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		DBG("curl_global_init failed, so returning!\n");
		return HTTP_ERROR_OPERATION_FAILED;
	}

	ret = thread_setup();
	if (!ret) {
		DBG("ssl thread initialization failed!\n");
		return HTTP_ERROR_OPERATION_FAILED;
	}

	return HTTP_ERROR_NONE;
}

API int http_deinit(void)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http is already deinitialized!!");

	int ret = 0;

	__http_set_init(false);

	ret = thread_cleanup();
	if (!ret) {
		DBG("ssl thread de-initialization failed!\n");
		return HTTP_ERROR_OPERATION_FAILED;
	}

	curl_global_cleanup();

	return HTTP_ERROR_NONE;
}
