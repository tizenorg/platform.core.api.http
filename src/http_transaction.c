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

//LCOV_EXCL_START
void _add_transaction_to_list(http_transaction_h http_transaction)
{
	transaction_list = g_slist_append(transaction_list, http_transaction);
}

void _remove_transaction_from_list(http_transaction_h http_transaction)
{
	transaction_list = g_slist_remove(transaction_list, http_transaction);
}

void _remove_transaction_list(void)
{
	g_slist_free_full(transaction_list, g_free);
	transaction_list = NULL;
}
//LCOV_EXCL_STOP

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

size_t __handle_header_cb(gchar *buffer, size_t size, size_t nmemb, gpointer user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;
	__http_header_h *header = transaction->header;

	gchar *temp_header = NULL;
	size_t written = size * nmemb;
	size_t new_len = header->rsp_header_len + written;

	temp_header = header->rsp_header;
	header->rsp_header = realloc(header->rsp_header, new_len + 1);
	if (header->rsp_header == NULL) {
		free(temp_header);
		ERR("realloc() failed\n");
		return -1;
	}

	memcpy(header->rsp_header + header->rsp_header_len, buffer, written);
	header->rsp_header[new_len] = '\0';
	header->rsp_header_len = new_len;

	__parse_response_header(buffer, written, user_data);

	return written;
}

size_t __handle_body_cb(gchar *ptr, size_t size, size_t nmemb, gpointer user_data)
{
	__http_transaction_h *transaction = (__http_transaction_h *)user_data;
	__http_header_h *header = transaction->header;
	size_t written = size * nmemb;

	if (!transaction->header_event) {
		transaction->header_event = TRUE;
		transaction->header_cb(transaction, header->rsp_header, header->rsp_header_len, transaction->header_user_data);
	}

	transaction->body_cb(transaction, ptr, size, nmemb, transaction->body_user_data);

	return written;
}

//LCOV_EXCL_START
size_t __handle_write_cb(gchar *ptr, size_t size, size_t nmemb, gpointer user_data)
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
//LCOV_EXCL_STOP

size_t __http_debug_received(CURL* easy_handle, curl_infotype type, gchar* byte, size_t size, void *user_data)
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

//LCOV_EXCL_START
int http_transaction_set_authentication_info(http_transaction_h http_transaction)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	http_auth_scheme_e auth_scheme = HTTP_AUTH_NONE;

	http_transaction_get_http_auth_scheme(transaction, &auth_scheme);

	switch (auth_scheme) {
	case HTTP_AUTH_PROXY_BASIC:
	case HTTP_AUTH_PROXY_MD5:
	case HTTP_AUTH_PROXY_NTLM:
		http_transaction_header_get_field_value(transaction, _HTTP_PROXY_AUTHENTICATE_HEADER_NAME, &transaction->realm);

		transaction->proxy_auth_type = TRUE;
		break;

	case HTTP_AUTH_WWW_BASIC:
	case HTTP_AUTH_WWW_MD5:
	case HTTP_AUTH_WWW_NEGOTIATE:
	case HTTP_AUTH_WWW_NTLM:
		http_transaction_header_get_field_value(transaction, _HTTP_WWW_AUTHENTICATE_HEADER_NAME, &transaction->realm);

		transaction->proxy_auth_type = FALSE;
		break;

	default:
		break;
	}

	return HTTP_ERROR_NONE;
}
//LCOV_EXCL_STOP

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
	http_auth_scheme_e auth_scheme = HTTP_AUTH_NONE;

	if (!transaction->easy_handle)
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
		curl_easy_setopt(transaction->easy_handle, CURLOPT_ACCEPT_ENCODING, request->encoding);

	if (request->cookie)
		curl_easy_setopt(transaction->easy_handle, CURLOPT_COOKIE, request->cookie);

	/* The connection timeout is 30s. (default) */
	curl_easy_setopt(transaction->easy_handle, CURLOPT_CONNECTTIMEOUT, _HTTP_DEFAULT_CONNECTION_TIMEOUT);

	if (transaction->timeout > 0) {
		curl_easy_setopt(transaction->easy_handle, CURLOPT_TIMEOUT, transaction->timeout);
	} else if (transaction->timeout == 0) {
		/* Set the transaction timeout. The timeout includes connection timeout. */
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

	//LCOV_EXCL_START
	/* Authentication */
	if (transaction->auth_required) {

		curl_http_auth_scheme_e curl_auth_scheme;
		gchar *user_name = NULL;
		gchar *password = NULL;
		gchar *credentials = NULL;
		int credentials_len = 0;

		http_transaction_get_credentials(transaction, &user_name, &password);
		credentials_len = sizeof(gchar) * (strlen(user_name) + 1 + strlen(password) + 1);
		credentials = (gchar *)malloc(credentials_len);
		if (credentials) {
			snprintf(credentials, credentials_len, "%s:%s", (gchar*)user_name, (gchar*)password);
			free(user_name);
			free(password);

			http_transaction_get_http_auth_scheme(transaction, &auth_scheme);

			curl_auth_scheme = _get_http_curl_auth_scheme(auth_scheme);

			if (transaction->proxy_auth_type) {

				curl_easy_setopt(transaction->easy_handle, CURLOPT_PROXYAUTH, curl_auth_scheme);
				curl_easy_setopt(transaction->easy_handle, CURLOPT_PROXYUSERPWD, credentials);

			} else {
				curl_easy_setopt(transaction->easy_handle, CURLOPT_HTTPAUTH, curl_auth_scheme);
				curl_easy_setopt(transaction->easy_handle, CURLOPT_USERPWD, credentials);
			}
			free(credentials);
		}
	}
	//LCOV_EXCL_STOP

	curl_easy_setopt(transaction->easy_handle, CURLOPT_HEADERFUNCTION, __handle_header_cb);
	curl_easy_setopt(transaction->easy_handle, CURLOPT_HEADERDATA, transaction);

	curl_easy_setopt(transaction->easy_handle, CURLOPT_WRITEFUNCTION, __handle_body_cb);
	curl_easy_setopt(transaction->easy_handle, CURLOPT_WRITEDATA, transaction);

	if (http_transaction_header_get_field_value(transaction, "Content-Length", &field_value) == HTTP_ERROR_NONE) {
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

API int http_session_open_transaction(http_session_h http_session, http_method_e method, http_transaction_h *http_transaction)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION, "http isn't initialized");
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER, "parameter(http_session) is NULL\n");

	__http_transaction_h *transaction = NULL;

	transaction = (__http_transaction_h *)malloc(sizeof(__http_transaction_h));
	if (transaction == NULL) {
		ERR("Fail to allocate transaction memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	transaction->easy_handle = NULL;
	transaction->interface_name = NULL;
	transaction->timeout = 0;
	transaction->verify_peer = 1;
	transaction->ca_path = g_strdup(HTTP_DEFAULT_CA_PATH);
	transaction->error[0] = '\0';

	transaction->auth_required = FALSE;
	transaction->realm = NULL;
	transaction->user_name = NULL;
	transaction->password = NULL;
	transaction->proxy_auth_type = FALSE;
	transaction->auth_scheme = HTTP_AUTH_NONE;

	transaction->header_cb = NULL;
	transaction->body_cb = NULL;
	transaction->write_cb = NULL;
	transaction->completed_cb = NULL;
	transaction->aborted_cb = NULL;
	transaction->progress_cb = NULL;

	transaction->session = http_session;
	transaction->session->active_transaction_count++;
	transaction->session_id = 0;

	transaction->request = (__http_request_h *)malloc(sizeof(__http_request_h));
	if (transaction->request == NULL) {
		ERR("Fail to allocate request memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	transaction->response = (__http_response_h *)malloc(sizeof(__http_response_h));
	if (transaction->response == NULL) {
		ERR("Fail to allocate response memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	transaction->header = (__http_header_h *)malloc(sizeof(__http_header_h));
	if (transaction->header == NULL) {
		ERR("Fail to allocate header memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	transaction->header->rsp_header_len = 0;
	transaction->header->rsp_header = malloc(transaction->header->rsp_header_len + 1);
	transaction->header->rsp_header[0] = '\0';
	transaction->header_event = FALSE;

	transaction->request->host_uri = NULL;
	transaction->request->method = _get_http_method(method);
	transaction->request->encoding = NULL;
	transaction->request->cookie = NULL;
	transaction->request->http_version = HTTP_VERSION_1_1;
	transaction->request->body_queue = g_queue_new();
	transaction->request->tot_size = 0;

	transaction->response->status_text = NULL;

	transaction->header->header_list = NULL;
	transaction->header->hash_table = NULL;

	transaction->thread = NULL;
	transaction->thread_loop = NULL;

	*http_transaction = (http_transaction_h)transaction;
	_add_transaction_to_list(transaction);

	return HTTP_ERROR_NONE;
}

API int http_transaction_submit(http_transaction_h http_transaction)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	_retvm_if(transaction->request->host_uri == NULL, HTTP_ERROR_INVALID_OPERATION, "URI isn't set!!");

	transaction->thread = g_thread_new("transaction_thread", thread_callback, transaction);

	return HTTP_ERROR_NONE;
}

API int http_transaction_destroy(http_transaction_h http_transaction)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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

		if (transaction->user_name) {
			free(transaction->user_name);
			transaction->user_name = NULL;
		}

		if (transaction->password) {
			free(transaction->password);
			transaction->password = NULL;
		}

		if (transaction->realm) {
			free(transaction->realm);
			transaction->realm = NULL;
		}

		transaction->auth_required = FALSE;
		transaction->proxy_auth_type = FALSE;
		transaction->auth_scheme = HTTP_AUTH_NONE;

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

		if (response) {

			if (response->status_text != NULL) {
				free(response->status_text);
				response->status_text = NULL;
			}

			free(response);

		}

		if (header) {
			if (header->header_list != NULL) {
				curl_slist_free_all(header->header_list);
				header->header_list = NULL;
			}

			if (header->hash_table != NULL) {

				g_hash_table_remove_all(header->hash_table);

				g_hash_table_destroy(header->hash_table);
				header->hash_table = NULL;
			}

			if (header->rsp_header != NULL) {
				free(header->rsp_header);
				header->rsp_header = NULL;
				header->rsp_header_len = 0;
			}
			free(header);
		}

		_remove_transaction_from_list(transaction);

		if (transaction->thread_loop != NULL) {
			g_main_loop_quit((GMainLoop*)transaction->thread_loop);

			g_main_loop_unref(transaction->thread_loop);
			transaction->thread_loop = NULL;
		}

		if (transaction->thread != NULL) {
			g_thread_join(transaction->thread);
			transaction->thread = NULL;
		}

		free(transaction);
		transaction = NULL;
	}

	return HTTP_ERROR_NONE;
}

//LCOV_EXCL_START
API int http_transaction_pause(http_transaction_h http_transaction, http_pause_type_e pause_type)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(pause_type < HTTP_PAUSE_RECV || pause_type > HTTP_PAUSE_ALL, HTTP_ERROR_INVALID_PARAMETER,
			"Wrong pause state \n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	int ret = 0;

	ret = curl_easy_pause(transaction->easy_handle, pause_type);
	if (ret != 0) {
		ERR("Fail to pause!(%d)", ret);
		return HTTP_ERROR_OPERATION_FAILED;
	}

	return HTTP_ERROR_NONE;
}

API int http_transaction_resume(http_transaction_h http_transaction)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
//LCOV_EXCL_STOP

API int http_transaction_set_progress_cb(http_transaction_h http_transaction, http_transaction_progress_cb progress_cb, void* user_data)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			 "parameter(http_transaction) is NULL\n");
	_retvm_if(aborted_cb == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(aborted_cb) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->aborted_cb = aborted_cb;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_timeout(http_transaction_h http_transaction, int timeout)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->timeout = timeout;

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_timeout(http_transaction_h http_transaction, int *timeout)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
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
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->write_event = read_to_write;

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_server_certificate_verification(http_transaction_h http_transaction, bool* verify)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	*verify = transaction->verify_peer;

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_server_certificate_verification(http_transaction_h http_transaction, bool verify)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->verify_peer = verify;

	return HTTP_ERROR_NONE;
}

API int http_session_destroy_all_transactions(http_session_h http_session)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");

	int ret = 0;
	GSList *list = NULL;
	__http_session_h *session = (__http_session_h *)http_session;

	for (list = transaction_list; list; list = list->next) {
		__http_transaction_h *transaction = (__http_transaction_h *)list->data;
		if (session->session_id == transaction->session_id) {
			_remove_transaction_from_list(list->data);
			ret = http_transaction_destroy((http_transaction_h) transaction);
			if (ret != HTTP_ERROR_NONE) {
				ERR("Fail to destroy transaction!!");
				return HTTP_ERROR_OPERATION_FAILED;
			}
		}
	}

	return HTTP_ERROR_NONE;
}
//LCOV_EXCL_START
API int http_transaction_set_http_auth_scheme(http_transaction_h http_transaction, http_auth_scheme_e auth_scheme)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->auth_scheme = auth_scheme;

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_http_auth_scheme(http_transaction_h http_transaction, http_auth_scheme_e *auth_scheme)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(auth_scheme == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(auth_scheme) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	*auth_scheme =  transaction->auth_scheme;

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_realm(http_transaction_h http_transaction, char **realm)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(realm == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(realm) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	if (transaction->realm == NULL)
		return HTTP_ERROR_INVALID_OPERATION;

	*realm = g_strdup(transaction->realm);
	if (*realm == NULL) {
		ERR("strdup is failed\n");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	return HTTP_ERROR_NONE;
}

API int http_transaction_set_credentials(http_transaction_h http_transaction, const char *user_name, const char *password)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(user_name == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(user_name) is NULL\n");
	_retvm_if(password == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(password) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	transaction->user_name = g_strdup(user_name);
	transaction->password = g_strdup(password);

	return HTTP_ERROR_NONE;
}

API int http_transaction_get_credentials(http_transaction_h http_transaction, char **user_name, char **password)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(user_name == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(user_name) is NULL\n");
	_retvm_if(password == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(password) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;

	*user_name = g_strdup(transaction->user_name);
	if (*user_name == NULL) {
		ERR("strdup is failed\n");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	*password = g_strdup(transaction->password);
	if (*password == NULL) {
		ERR("strdup is failed\n");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}
	return HTTP_ERROR_NONE;
}

API int http_transaction_open_authentication(http_transaction_h http_transaction, http_transaction_h *http_auth_transaction)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_transaction_h *auth_transaction = NULL;

	auth_transaction = (__http_transaction_h *)malloc(sizeof(__http_transaction_h));
	if (auth_transaction == NULL) {
		ERR("Fail to allocate transaction memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	auth_transaction->easy_handle = NULL;
	auth_transaction->interface_name = NULL;
	auth_transaction->ca_path = NULL;
	auth_transaction->error[0] = '\0';

	if (transaction->interface_name)
		auth_transaction->interface_name = g_strdup(transaction->interface_name);
	auth_transaction->timeout = 0;
	auth_transaction->verify_peer = transaction->verify_peer;
	if (transaction->ca_path)
		auth_transaction->ca_path = g_strdup(transaction->ca_path);

	auth_transaction->auth_required = transaction->auth_required;
	auth_transaction->realm = NULL;
	auth_transaction->user_name = NULL;
	auth_transaction->password = NULL;
	auth_transaction->proxy_auth_type = FALSE;
	auth_transaction->auth_scheme = transaction->auth_scheme;
	auth_transaction->write_event = FALSE;

	auth_transaction->header_cb = NULL;
	auth_transaction->header_user_data = NULL;
	auth_transaction->body_cb = NULL;
	auth_transaction->body_user_data = NULL;
	auth_transaction->write_cb = NULL;
	auth_transaction->write_user_data = NULL;
	auth_transaction->completed_cb = NULL;
	auth_transaction->completed_user_data = NULL;
	auth_transaction->aborted_cb = NULL;
	auth_transaction->progress_cb = NULL;
	auth_transaction->progress_user_data = NULL;

	auth_transaction->session = transaction->session;
	auth_transaction->session->active_transaction_count = transaction->session->active_transaction_count;
	auth_transaction->session_id = transaction->session_id;

	auth_transaction->request = (__http_request_h *)malloc(sizeof(__http_request_h));
	if (auth_transaction->request == NULL) {
		free(auth_transaction->interface_name);
		free(auth_transaction->ca_path);
		free(auth_transaction);
		ERR("Fail to allocate request memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	auth_transaction->request->host_uri = NULL;
	auth_transaction->request->method = NULL;

	auth_transaction->response = (__http_response_h *)malloc(sizeof(__http_response_h));
	if (auth_transaction->response == NULL) {
		free(auth_transaction->interface_name);
		free(auth_transaction->ca_path);
		free(auth_transaction->request);
		free(auth_transaction);
		ERR("Fail to allocate response memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	auth_transaction->header = (__http_header_h *)malloc(sizeof(__http_header_h));
	if (auth_transaction->header == NULL) {
		free(auth_transaction->interface_name);
		free(auth_transaction->ca_path);
		free(auth_transaction->request);
		free(auth_transaction->response);
		free(auth_transaction);
		ERR("Fail to allocate header memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	auth_transaction->header->rsp_header_len = 0;
	auth_transaction->header->rsp_header = malloc(auth_transaction->header->rsp_header_len + 1);
	auth_transaction->header->rsp_header[0] = '\0';
	auth_transaction->header_event = FALSE;

	if (transaction->request->host_uri)
		auth_transaction->request->host_uri = g_strdup(transaction->request->host_uri);
	if (transaction->request->method)
		auth_transaction->request->method = g_strdup(transaction->request->method);
	auth_transaction->request->encoding = NULL;
	auth_transaction->request->cookie = NULL;
	auth_transaction->request->http_version = HTTP_VERSION_1_1;
	auth_transaction->request->body_queue = g_queue_new();
	auth_transaction->request->tot_size = 0;

	auth_transaction->header->header_list = NULL;
	auth_transaction->header->hash_table = NULL;

	auth_transaction->thread = NULL;

	*http_auth_transaction = (http_transaction_h)auth_transaction;
	_add_transaction_to_list(auth_transaction);

	http_transaction_set_authentication_info((http_transaction_h)auth_transaction);

	return HTTP_ERROR_NONE;
}
//LCOV_EXCL_STOP
