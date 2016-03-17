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

http_method_e _get_method(gchar* method)
{
	if (g_strcmp0(method, "GET") == 0) {
		return HTTP_METHOD_GET;
	} else if (g_strcmp0(method, "OPTIONS") == 0) {
		return HTTP_METHOD_OPTIONS;
	} else if (g_strcmp0(method, "HEAD") == 0) {
		return HTTP_METHOD_HEAD;
	} else if (g_strcmp0(method, "DELETE") == 0) {
		return HTTP_METHOD_DELETE;
	} else if (g_strcmp0(method, "TRACE") == 0) {
		return HTTP_METHOD_TRACE;
	} else if (g_strcmp0(method, "POST") == 0) {
		return HTTP_METHOD_POST;
	} else if (g_strcmp0(method, "PUT") == 0) {
		return HTTP_METHOD_PUT;
	} else if (g_strcmp0(method, "CONNECT") == 0) {
		return HTTP_METHOD_CONNECT;
	}

	return HTTP_METHOD_NONE;
}

gchar* _get_http_method(http_method_e method)
{
	gchar* http_method = NULL;

	switch (method) {
	case HTTP_METHOD_GET:
		http_method = g_strdup("GET");
		break;

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

	case HTTP_METHOD_NONE:
	default:
		http_method = NULL;
		break;
	}

	return http_method;
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
	if (connection_destroy(connection) < 0) {
		DBG("Fail to destroy network handle\n");
	}

	return proxy_addr;
}

API int http_init()
{
	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		DBG("curl_global_init failed, so returning!\n");
		return HTTP_ERROR_OPERATION_FAILED;
	}

	return HTTP_ERROR_NONE;
}

API void http_deinit()
{
	curl_global_cleanup();
}
