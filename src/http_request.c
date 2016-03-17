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

API int http_request_set_method(http_transaction_h http_transaction, http_method_e method)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	if (request->method) {
		free(request->method);
		request->method = NULL;
	}

	request->method = _get_http_method(method);

	return HTTP_ERROR_NONE;
}

API int http_request_get_method(http_transaction_h http_transaction, http_method_e *method)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(method == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(method) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	*method =  _get_method(request->method);

	return HTTP_ERROR_NONE;
}

API int http_request_set_version(http_transaction_h http_transaction, http_version_e version)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	request->http_version = version;

	return HTTP_ERROR_NONE;
}

API int http_request_get_version(http_transaction_h http_transaction, http_version_e *version)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(version == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(version) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	*version =  request->http_version;

	return HTTP_ERROR_NONE;
}

API int http_request_set_uri(http_transaction_h http_transaction, const char *host_uri)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(host_uri == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(host_uri) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	request->host_uri = g_strdup(host_uri);

	return HTTP_ERROR_NONE;
}

API int http_request_get_uri(http_transaction_h http_transaction, char **host_uri)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(host_uri == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(host_uri) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	*host_uri = g_strdup(request->host_uri);
	if (*host_uri == NULL) {
		ERR("strdup is failed\n");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}
	DBG("-");

	return HTTP_ERROR_NONE;
}

API int http_request_set_accept_encoding(http_transaction_h http_transaction, const char *encoding)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(encoding == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(encoding) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	request->encoding = g_strdup(encoding);

	return HTTP_ERROR_NONE;
}

API int http_request_get_accept_encoding(http_transaction_h http_transaction, char **encoding)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(encoding == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(encoding) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	*encoding = g_strdup(request->encoding);
	if (*encoding == NULL) {
		ERR("strdup is failed\n");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	return HTTP_ERROR_NONE;
}

API int http_request_set_cookie(http_transaction_h http_transaction, const char *cookie)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(cookie == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(cookie) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	request->cookie = g_strdup(cookie);

	return HTTP_ERROR_NONE;
}

API int http_request_get_cookie(http_transaction_h http_transaction, const char **cookie)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(cookie == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(cookie) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	*cookie = g_strdup(request->cookie);
	if (*cookie == NULL) {
			ERR("strdup is failed\n");
			return HTTP_ERROR_OUT_OF_MEMORY;
	}

	return HTTP_ERROR_NONE;
}

API int http_request_write_body(http_transaction_h http_transaction, const char *body)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(body == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(body) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	request->tot_size += strlen(body);

	g_queue_push_tail(request->body_queue, (gpointer)body);

	return HTTP_ERROR_NONE;
}

int _get_request_body_size(http_transaction_h http_transaction, int *body_size)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(body_size == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(body_size) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	*body_size = request->tot_size;

	return HTTP_ERROR_NONE;
}

int _read_request_body(http_transaction_h http_transaction, char **body)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(body == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(body) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_request_h *request = transaction->request;

	int len = 0;
	int index = 0;
	int body_size = 0;
	int curr_len = 0;
	size_t new_len = 0;
	gchar* ptr = NULL;

	*body = malloc(curr_len + 1);
	if (*body == NULL) {
		DBG("malloc() failed\n");
		return HTTP_ERROR_OPERATION_FAILED;
	}

	len = g_queue_get_length(request->body_queue);

	for (index = 0; index < len; index++) {

		ptr = (gchar*)g_queue_pop_head(request->body_queue);
		body_size = strlen(ptr);

		new_len = curr_len + body_size;
		*body = realloc(*body, new_len + 1);
		if (*body == NULL) {
			DBG("realloc() failed\n");
			return HTTP_ERROR_OPERATION_FAILED;
		}

		memcpy(*body + curr_len, ptr, body_size);

		body[new_len] = '\0';
		curr_len = new_len;
	}

	return HTTP_ERROR_NONE;
}
