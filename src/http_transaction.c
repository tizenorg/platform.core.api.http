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

curl_socket_t __handle_opensocket_cb(void *client_fd, curlsocktype purpose, struct curl_sockaddr *address)
{
	int fd = socket(address->family, address->socktype, address->protocol);
	DBG("socket opened:%d\n", fd);

	return fd;
}

size_t __handle_header_cb(char *buffer, size_t size, size_t nmemb, gpointer user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;
	size_t written = size * nmemb;

	transaction->header_cb(buffer, written);

	return written;
}

size_t __handle_body_cb(char *ptr, size_t size, size_t nmemb, gpointer user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;
	size_t written = size * nmemb;

	transaction->body_cb(ptr, size, nmemb);

	return written;
}

size_t __http_debug_received(CURL* easy_handle, curl_infotype type, char* byte, size_t size, void *user_data)
{
	char log_buffer[_HTTP_DEFAULT_HEADER_SIZE];
	int log_size = 0;

	if (_HTTP_DEFAULT_HEADER_SIZE > size) {
		log_size = size;
	}
	else {
		log_size = _HTTP_DEFAULT_HEADER_SIZE - 1;
	}

	if (type == CURLINFO_TEXT) {
		strncpy(log_buffer, byte, log_size);
		log_buffer[log_size] = '\0';
		DBG("[DEBUG] %s", log_buffer);
	}
	else if (type == CURLINFO_HEADER_IN || type == CURLINFO_HEADER_OUT) {
		//Ignore the body message.
		if (size >= 2 && byte[0] == 0x0D && byte[1] == 0x0A) {
			return 0;
		}
		else {
			strncpy(log_buffer, byte, log_size);
			log_buffer[log_size] = '\0';
			DBG("[DEBUG] %s", log_buffer);
		}
	}

	return 0;
}

int _transaction_submit(gpointer user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;
	__http_session_h *session = transaction->session;
	__http_request_h *request = transaction->request;

	CURLMcode ret = CURLM_OK;
	gchar *proxy_addr = NULL;

	transaction->easy_handle = curl_easy_init();

	if (request->http_version == HTTP_VERSION_1_0) {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
	} else {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
	}

	if (request->host_uri)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_URL, request->host_uri);

	proxy_addr = _get_proxy();
	if (proxy_addr) {
		DBG("Proxy address:%s\n", proxy_addr);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_PROXY, proxy_addr);
		free(proxy_addr);
	}

	if (request->method)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_CUSTOMREQUEST, request->method);

	if (transaction->interface_name)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_INTERFACE, transaction->interface_name);

	if (request->encoding)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_ENCODING, request->encoding);

	//The connection timeout is 30s. (default)
	curl_easy_setopt(transaction->easy_handle, CURLOPT_CONNECTTIMEOUT, _HTTP_DEFAULT_CONNECTION_TIMEOUT);

	if (transaction->timeout > 0) {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_TIMEOUT, transaction->timeout);
	} else if (transaction->timeout == 0) {
		//Set the transaction timeout. The timeout includes connection timeout.
		curl_easy_setopt(transaction->easy_handle, CURLOPT_LOW_SPEED_LIMIT, 1L);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_LOW_SPEED_TIME, 30L);
	}

	if (session->auto_redirect) {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
		DBG("Enabled Auto-Redirection\n");
	} else {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_FOLLOWLOCATION, 0L);
		DBG("Disabled Auto-Redirection\n");
	}

	curl_easy_setopt(transaction->easy_handle, CURLOPT_HEADERFUNCTION, __handle_header_cb);
	curl_easy_setopt(transaction->easy_handle, CURLOPT_HEADERDATA, transaction);

	curl_easy_setopt(transaction->easy_handle, CURLOPT_WRITEFUNCTION, __handle_body_cb);
	curl_easy_setopt(transaction->easy_handle, CURLOPT_WRITEDATA, transaction);

	curl_easy_setopt(transaction->easy_handle, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(transaction->easy_handle, CURLOPT_DEBUGFUNCTION, __http_debug_received);
	curl_easy_setopt(transaction->easy_handle, CURLOPT_ERRORBUFFER, transaction->error);

	curl_easy_setopt(transaction->easy_handle, CURLOPT_OPENSOCKETDATA, &transaction->socket_fd);
	curl_easy_setopt(transaction->easy_handle, CURLOPT_OPENSOCKETFUNCTION, __handle_opensocket_cb);

	curl_easy_setopt(transaction->easy_handle, CURLOPT_PRIVATE, transaction);

	ret = curl_multi_add_handle(session->multi_handle, transaction->easy_handle);
	if (ret == CURLM_OK) {
		DBG("CURLM_OK: Called curl_multi_add_handle().");
	} else {
		print_curl_multi_errorCode(ret);
		ERR("Failed to add easy_handle to curl_multi_add_handle()");
	}

	return HTTP_ERROR_NONE;
}

void* thread_callback(void *user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;

    transaction->thread_loop = g_main_loop_new(NULL, FALSE);

    _transaction_submit(transaction);

	g_main_loop_run(transaction->thread_loop);

	g_main_loop_unref(transaction->thread_loop);
	transaction->thread_loop = NULL;
	DBG("thread exited.\n");

	return NULL;
}

API int http_open_transaction(http_session_h http_session, http_method_e method, http_transaction_header_cb transaction_header_callback,
							http_transaction_body_cb transaction_body_callback, http_transaction_write_cb transaction_write_callback,
							http_transaction_completed_cb transaction_completed_cb, http_transaction_aborted_cb transaction_aborted_cb, http_transaction_h *http_transaction)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");
	_retvm_if(transaction_header_callback == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(transaction_header_callback) is NULL\n");
	_retvm_if(transaction_body_callback == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(transaction_body_callback) is NULL\n");
	_retvm_if(transaction_write_callback == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(transaction_write_callback) is NULL\n");
	_retvm_if(transaction_completed_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(transaction_completed_cb) is NULL\n");
	_retvm_if(transaction_aborted_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(transaction_aborted_cb) is NULL\n");

	__http_transaction_h *transaction = NULL;

	transaction = (__http_transaction_h *)malloc(sizeof(__http_transaction_h));

	transaction->easy_handle = NULL;
	transaction->interface_name = NULL;
	transaction->timeout = 0;
	transaction->error[0] = '\0';

	transaction->header_cb = transaction_header_callback;
	transaction->body_cb = transaction_body_callback;
	transaction->write_cb = transaction_write_callback;
	transaction->completed_cb = transaction_completed_cb;
	transaction->aborted_cb = transaction_aborted_cb;

	transaction->upload_progress_cb = NULL;
	transaction->download_progress_cb = NULL;

	transaction->session = http_session;
	transaction->session->active_transaction_count++;

	transaction->request = (__http_request_h *)malloc(sizeof(__http_request_h));
	transaction->response = (__http_response_h *)malloc(sizeof(__http_response_h));
	transaction->header = (__http_header_h *)malloc(sizeof(__http_header_h));

	transaction->request->host_uri = NULL;

	transaction->request->method = _get_http_method(method);

	transaction->request->encoding = NULL;
	transaction->request->body = NULL;
	transaction->request->http_version = HTTP_VERSION_1_1;

	transaction->thread = NULL;

	*http_transaction = (http_transaction_h)transaction;

	return HTTP_ERROR_NONE;
}

API int http_transaction_submit(http_transaction_h http_transaction)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->thread = g_thread_new("transaction_thread", thread_callback, transaction);

	return HTTP_ERROR_NONE;
}

API int http_transaction_close(http_transaction_h http_transaction)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = NULL;
	__http_session_h *session = NULL;
	__http_header_h *header = NULL;
	__http_request_h *request = NULL;
	__http_response_h *response = NULL;

	transaction = (__http_transaction_h *)http_transaction;
	session = transaction->session;
	request = transaction->request;
	response = transaction->response;
	header = transaction->header;

	if (session) {
		session->active_transaction_count--;
	}

	if (transaction) {

		g_thread_join(transaction->thread);
		transaction->thread = NULL;

		if (transaction->easy_handle != NULL) {
			curl_easy_cleanup(transaction->easy_handle);
			transaction->easy_handle = NULL;
		}

		if (transaction->interface_name != NULL) {
			free(transaction->interface_name);
			transaction->interface_name = NULL;
		}

		transaction->timeout = 0;
		transaction->error[0] = '\0';

		transaction->header_cb = NULL;
		transaction->body_cb = NULL;
		transaction->write_cb = NULL;
		transaction->completed_cb = NULL;
		transaction->aborted_cb = NULL;

		transaction->upload_progress_cb = NULL;
		transaction->download_progress_cb = NULL;

		if (request) {
			if (request->host_uri != NULL) {
				free(request->host_uri);
				request->host_uri = NULL;
			}

			if (request->method != NULL) {
				free(request->method);
				request->method = NULL;
			}

			if (request->encoding != NULL) {
				free(request->encoding);
				request->encoding = NULL;
			}

			if (request->body != NULL) {
				free(request->body);
				request->body = NULL;
			}

			free(request);
		}
		free(response);
		free(header);

		free(transaction);
		transaction = NULL;
	}

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_progress_callbacks(http_transaction_h http_transaction, http_transaction_upload_progress_cb upload_progress_cb,
															http_transaction_download_progress_cb download_progress_cb)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(upload_progress_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(upload_progress_cb) is NULL\n");
	_retvm_if(download_progress_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(download_progress_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->upload_progress_cb = upload_progress_cb;
	transaction->download_progress_cb = download_progress_cb;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_timeout(http_transaction_h http_transaction, int timeout)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->timeout = timeout;

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_timeout(http_transaction_h http_transaction, int *timeout)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(timeout == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(timeout) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	*timeout =  transaction->timeout;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_interface_name(http_transaction_h http_transaction, const char *interface_name)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(interface_name == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(interface_name) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->interface_name = g_strdup(interface_name);

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_interface_name(http_transaction_h http_transaction, char **interface_name)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(interface_name == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(interface_name) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	*interface_name = g_strdup(transaction->interface_name);
	if (*interface_name == NULL) {
		ERR("strdup is failed\n");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	return HTTP_ERROR_NONE;
}
