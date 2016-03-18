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

static __thread GSList *transaction_list = NULL;

void _add_transaction_to_list(http_transaction_h http_transaction)
{
	transaction_list = g_slist_append(transaction_list, http_transaction);
}

void _remove_transaction_from_list(http_transaction_h http_transaction)
{
	transaction_list = g_slist_remove(transaction_list, http_transaction);
	//g_free(http_transaction);
}

void _remove_transaction_list(void)
{
	g_slist_free_full(transaction_list, g_free);
	transaction_list = NULL;
}

int _generate_transaction_id(void)
{
	int transaction_id = 0;

	return transaction_id;
}

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

	__parse_response_header(buffer, written, user_data);
	transaction->header_cb(transaction, buffer, written, transaction->header_user_data);

	return written;
}

size_t __handle_body_cb(char *ptr, size_t size, size_t nmemb, gpointer user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;
	size_t written = size * nmemb;

	transaction->body_cb(transaction, ptr, size, nmemb, transaction->body_user_data);

	return written;
}

size_t __handle_write_cb(char *ptr, size_t size, size_t nmemb, gpointer user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;
	__http_request_h *request = transaction->request;
	size_t recommended_size = size * nmemb;
	size_t body_size = 0;

	transaction->write_cb(transaction, recommended_size, transaction->write_user_data);

	ptr = (gchar*)g_queue_pop_head(request->body_queue);
	if (ptr == NULL) {
		DBG("Sent the last chunk.\n");
		return 0;
	}
	body_size = strlen(ptr);

	return body_size;
}

size_t __http_debug_received(CURL* easy_handle, curl_infotype type, char* byte, size_t size, void *user_data)
{
	char log_buffer[_HTTP_DEFAULT_HEADER_SIZE];
	int log_size = 0;

	if (_HTTP_DEFAULT_HEADER_SIZE > size)
		log_size = size;
	else
		log_size = _HTTP_DEFAULT_HEADER_SIZE - 1;

	if (type == CURLINFO_TEXT) {
		strncpy(log_buffer, byte, log_size);
		log_buffer[log_size] = '\0';
		DBG("[DEBUG] %s", log_buffer);
	} else if (type == CURLINFO_HEADER_IN || type == CURLINFO_HEADER_OUT) {
		/* Ignore the body message. */
		if (size >= 2 && byte[0] == 0x0D && byte[1] == 0x0A) {
			return 0;
		} else {
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
	struct curl_slist* header_list = NULL;
	gchar *field_value = NULL;
	gboolean write_event = FALSE;
	gint body_size = 0;
	gint content_len = 0;

	transaction->easy_handle = curl_easy_init();

	if (request->http_version == HTTP_VERSION_1_0)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
	else
		curl_easy_setopt(transaction->easy_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

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

	header_list = _get_header_list(transaction);
	if (header_list)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_HTTPHEADER, header_list);

	if (request->encoding)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_ENCODING, request->encoding);

	if (request->cookie)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_COOKIE, request->cookie);

	//The connection timeout is 30s. (default)
	curl_easy_setopt(transaction->easy_handle, CURLOPT_CONNECTTIMEOUT, _HTTP_DEFAULT_CONNECTION_TIMEOUT);

	if (transaction->timeout > 0) {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_TIMEOUT, transaction->timeout);
	} else if (transaction->timeout == 0) {
		//Set the transaction timeout. The timeout includes connection timeout.
		curl_easy_setopt(transaction->easy_handle, CURLOPT_LOW_SPEED_LIMIT, 1L);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_LOW_SPEED_TIME, 30L);
	}

	if (!transaction->verify_peer) {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_SSL_VERIFYHOST, 0);

	} else {
			curl_easy_setopt(transaction->easy_handle, CURLOPT_CAPATH, transaction->ca_path);
			DBG("CA path is (%s)", transaction->ca_path);

		curl_easy_setopt(transaction->easy_handle, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_SSL_VERIFYHOST, 2);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_SSL_CIPHER_LIST, "HIGH");
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

	http_transaction_header_get_field_value(transaction, "Content-Length", &field_value);
	if (field_value) {
		content_len = atoi(field_value);

		if (content_len > 0) {
			curl_easy_setopt(transaction->easy_handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)(content_len));
			DBG("Set the Content-Length(%d).", content_len);
		} else if (content_len == 0) {
			curl_easy_setopt(transaction->easy_handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)(content_len));
			curl_easy_setopt(transaction->easy_handle, CURLOPT_COPYPOSTFIELDS, NULL);
			DBG("Set the Content-Length(%d).", content_len);
		}
	} else {
		DBG("The Content-Length is not set.\n");
	}

	_get_request_body_size(transaction, &body_size);

	if (transaction->write_event) {
		if (content_len >= 0 && content_len <= body_size)
			write_event = FALSE;
		else
			write_event = TRUE;
		DBG("The write_event is %d.\n", write_event);
	}

	if ((_get_method(request->method) == HTTP_METHOD_POST) && !write_event) {
		gchar *body = NULL;

		_read_request_body(transaction, &body);

		if (body) {
			curl_easy_setopt(transaction->easy_handle, CURLOPT_COPYPOSTFIELDS, body);
			free(body);
		}
	}

	if (write_event) {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_POST, 1);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_READFUNCTION, __handle_write_cb);
		curl_easy_setopt(transaction->easy_handle, CURLOPT_READDATA, transaction);
	}

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

	DBG("thread exited.\n");

	return NULL;
}



API int http_transaction_submit(http_transaction_h http_transaction)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->thread = g_thread_new("transaction_thread", thread_callback, transaction);

	return HTTP_ERROR_NONE;
}

API int http_transaction_destroy(http_transaction_h http_transaction)
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

	if (session)
		session->active_transaction_count--;

	if (transaction) {
		if (transaction->easy_handle != NULL) {
			curl_easy_cleanup(transaction->easy_handle);
			transaction->easy_handle = NULL;
		}

		if (transaction->interface_name != NULL) {
			free(transaction->interface_name);
			transaction->interface_name = NULL;
		}

		transaction->timeout = 0;
		transaction->verify_peer = 0;

		if (transaction->ca_path) {
			free(transaction->ca_path);
			transaction->ca_path = NULL;
		}
		transaction->error[0] = '\0';

		transaction->header_cb = NULL;
		transaction->body_cb = NULL;
		transaction->write_cb = NULL;
		transaction->completed_cb = NULL;
		transaction->aborted_cb = NULL;
		transaction->progress_cb = NULL;

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

			if (request->cookie != NULL) {
				free(request->cookie);
				request->cookie = NULL;
			}

			if (request->body_queue != NULL)
				g_queue_free(request->body_queue);

			free(request);
		}
		free(response);

		if (header) {
			if (header->header_list != NULL) {
				curl_slist_free_all(header->header_list);
				header->header_list = NULL;
			}

			if (header->hash_table != NULL) {
				g_hash_table_destroy(header->hash_table);
				header->hash_table = NULL;
			}

			free(header);
		}

		_remove_transaction_from_list(transaction);

		g_main_loop_quit((GMainLoop*)transaction->thread_loop);

		g_main_loop_unref(transaction->thread_loop);
		transaction->thread_loop = NULL;

		g_thread_join(transaction->thread);
		transaction->thread = NULL;

		free(transaction);
		transaction = NULL;
	}

	return HTTP_ERROR_NONE;
}

API int http_transaction_pause(http_transaction_h http_transaction, http_pause_state_e pause_state)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(pause_state < HTTP_PAUSE_RECV || pause_state > HTTP_PAUSE_ALL, HTTP_ERROR_INVALID_PARAMETER,
				"Wrong pause state \n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	int ret = 0;

	ret = curl_easy_pause(transaction->easy_handle, pause_state);
	if (ret != 0) {
		ERR("Fail to pause!(%d)", ret);
		return HTTP_ERROR_OPERATION_FAILED;
	}

	return HTTP_ERROR_NONE;
}

API int http_transaction_resume(http_transaction_h http_transaction)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	int ret = 0;

	ret = curl_easy_pause(transaction->easy_handle, CURLPAUSE_CONT);
	if (ret != 0) {
		ERR("Fail to resume!(%d)", ret);
		return HTTP_ERROR_OPERATION_FAILED;
	}

	return HTTP_ERROR_NONE;
}


API int http_transaction_set_progress_cb(http_transaction_h http_transaction, http_transaction_progress_cb progress_cb, void* user_data)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(progress_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(progress_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->progress_cb = progress_cb;
	transaction->progress_user_data = user_data;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_received_header_cb(http_transaction_h http_transaction, http_transaction_header_cb header_cb, void* user_data)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(header_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(header_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->header_cb = header_cb;
	transaction->header_user_data = user_data;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_received_body_cb(http_transaction_h http_transaction, http_transaction_body_cb body_cb, void* user_data)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(body_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(body_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->body_cb = body_cb;
	transaction->body_user_data = user_data;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_uploaded_cb(http_transaction_h http_transaction, http_transaction_write_cb write_cb, void* user_data)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(write_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(write_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->write_cb = write_cb;
	transaction->write_user_data = user_data;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_completed_cb(http_transaction_h http_transaction, http_transaction_completed_cb completed_cb, void* user_data)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(completed_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(completed_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->completed_cb = completed_cb;
	transaction->completed_user_data = user_data;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_aborted_cb(http_transaction_h http_transaction, http_transaction_aborted_cb aborted_cb,  void* user_data)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			 "parameter(http_transaction) is NULL\n");
	_retvm_if(aborted_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(aborted_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->aborted_cb = aborted_cb;

	return HTTP_ERROR_NONE;
}

API int http_transaction_unset_progress_cb(http_transaction_h http_transaction)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	transaction->progress_cb = NULL;

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

API int http_transaction_set_ready_to_write(http_transaction_h http_transaction, bool read_to_write)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->write_event = read_to_write;

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_server_certificate_verification(http_transaction_h http_transaction, bool* verify)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	*verify = transaction->verify_peer;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_server_certificate_verification(http_transaction_h http_transaction, bool verify)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->verify_peer = verify;

	return HTTP_ERROR_NONE;
}

API int http_session_destroy_all_transactions(http_session_h http_session)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");

	GSList *list = NULL;
	__http_session_h *session = (__http_session_h *)http_session;

	for (list = transaction_list; list; list = list->next) {
		__http_transaction_h *transaction = (__http_transaction_h *)list->data;
		if (session->session_id == transaction->session_id) {
			_remove_transaction_from_list(list->data);
			http_transaction_destroy((http_transaction_h) transaction);
		}
	}

	return HTTP_ERROR_NONE;
}

