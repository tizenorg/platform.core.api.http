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
