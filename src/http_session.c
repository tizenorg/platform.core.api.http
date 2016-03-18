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

void _check_curl_multi_status(gpointer user_data)
{
	__http_transaction_h *transaction = NULL;
	__http_session_h *session = (__http_session_h *)user_data;

	CURLMsg* message = NULL;
	int count = 0;
	CURL* curl_easy = NULL;
	char* url = NULL;
	CURLcode curl_code = CURLE_OK;

	message = curl_multi_info_read(session->multi_handle, &count);

	while (message != NULL) {
		if (message->msg == CURLMSG_DONE) {
			curl_easy = message->easy_handle;
			curl_code = message->data.result;
			curl_easy_getinfo(curl_easy, CURLINFO_PRIVATE, &transaction);
			curl_easy_getinfo(curl_easy, CURLINFO_EFFECTIVE_URL, &url);

			DBG("Completed -%s: result(%d)\n", url, curl_code);

			switch (curl_code) {
				case CURLE_OK:
					if (transaction->completed_cb)
						transaction->completed_cb(transaction, transaction->completed_user_data);
					break;
				case CURLE_COULDNT_RESOLVE_HOST:
					if (transaction->aborted_cb)
						transaction->aborted_cb(transaction, HTTP_ERROR_COULDNT_RESOLVE_HOST, transaction->aborted_user_data);
					break;
				case CURLE_COULDNT_CONNECT:
					if (transaction->aborted_cb)
						transaction->aborted_cb(transaction, HTTP_ERROR_COULDNT_CONNECT, transaction->aborted_user_data);
					break;
				case CURLE_SSL_CONNECT_ERROR:
					if (transaction->aborted_cb)
						transaction->aborted_cb(transaction, HTTP_ERROR_SSL_CONNECT_ERROR, transaction->aborted_user_data);
					break;
				case CURLE_OPERATION_TIMEDOUT:
					if (transaction->aborted_cb)
						transaction->aborted_cb(transaction, HTTP_ERROR_OPERATION_TIMEDOUT, transaction->aborted_user_data);
					break;
				default:
					break;
			}

			curl_multi_remove_handle(session->multi_handle, curl_easy);
		}
		message = curl_multi_info_read(session->multi_handle, &count);
	}
}

int _generate_session_id(void)
{
	int session_id = 0;

	return session_id;
}

gboolean timer_expired_callback(gpointer user_data)
{
	__http_session_h* session = (__http_session_h *)user_data;

	CURLMcode ret;

	ret = curl_multi_socket_action(session->multi_handle, CURL_SOCKET_TIMEOUT, 0, &(session->still_running));
	if (ret == CURLM_OK) {
		//DBG("CURLM_OK - Called curl_multi_socket_action()\n");
	} else {
		print_curl_multi_errorCode(ret);
	}

	_check_curl_multi_status(session);

	return FALSE;
}

gboolean _handle_event(int fd, int action, gpointer user_data)
{
	__http_session_h *session = (__http_session_h *)user_data;

	int running_handles = -1;

	CURLMcode ret = CURLM_OK;

	ret = curl_multi_socket_action(session->multi_handle, fd, action, &running_handles);
	if (ret == CURLM_OK) {
		//DBG("CURLM_OK: Called curl_multi_socket_action(%d)\n", action);
	} else {
		print_curl_multi_errorCode(ret);
	}

	_check_curl_multi_status(session);

	if (running_handles > 0) {
		return TRUE;
	} else {
		DBG("last transfer done, kill timeout\n");
		if (session->timer_event) {
			g_source_remove(session->timer_event);
			session->timer_event = 0;
		}
		return FALSE;
	}
}

gboolean __handle_socket_received_event_cb(GIOChannel *channel, GIOCondition condition, gpointer user_data)
{
	int fd, action, ret;

	if (condition & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	//CURL_CSELECT_IN : 1, CURL_CSELECT_OUT: 2
	action = (condition & G_IO_IN ? CURL_CSELECT_IN : 0) | (condition & G_IO_OUT ? CURL_CSELECT_OUT : 0);

	ret = _handle_event(fd, action, user_data);
	if (ret) {
		return TRUE;
	}

	return FALSE;
}

/* Clean up the __http_socket_info_h structure */
static void _remove_socket_info(__http_socket_info_h *sock_info)
{
	if (!sock_info) {
		return;
	}
	if (sock_info->event) {
		g_source_remove(sock_info->event);
		sock_info->event = 0;
	}
	if (sock_info->channel) {
		g_io_channel_unref(sock_info->channel);
		sock_info->channel = NULL;
	}
	g_free(sock_info);
	sock_info = NULL;
}

/* Assign socket information to a __http_socket_info_h structure */
static void _set_socket_info(__http_socket_info_h *sock_info, curl_socket_t fd, CURL *curl_easy, int action, void *user_data)
{
	__http_session_h *session = (__http_session_h *)user_data;
	GIOCondition condition = (action & CURL_POLL_IN ? G_IO_IN : 0) | (action & CURL_POLL_OUT ? G_IO_OUT : 0);

	sock_info->sockfd = fd;
	sock_info->action = action;
	sock_info->easy_handle = curl_easy;
	if (sock_info->event) {
		g_source_remove(sock_info->event);
		sock_info->event = 0;
	}
	sock_info->event = g_io_add_watch(sock_info->channel, condition, __handle_socket_received_event_cb, session);
}

/* Initialize a new Socket Info structure */
static void _add_socket_info(curl_socket_t fd, CURL *curl_easy, int action, void *user_data)
{
	__http_session_h *session = (__http_session_h *)user_data;
	__http_socket_info_h *sock_info = (__http_socket_info_h *)malloc(sizeof(__http_socket_info_h));

	sock_info->session = session;
	sock_info->channel = g_io_channel_unix_new(fd);
	sock_info->event = 0;
	_set_socket_info(sock_info, fd, curl_easy, action, session);
	curl_multi_assign(session->multi_handle, fd, sock_info);
}

int __handle_socket_cb(CURL *curl_easy, curl_socket_t fd, int action, void *user_data, void *socketp)
{
	__http_session_h *session = (__http_session_h *)user_data;
	__http_socket_info_h *sock_info = (__http_socket_info_h*) socketp;

	static const char *actionstr[] = { "none", "IN", "OUT", "INOUT", "REMOVE"};

	DBG("__handle_socket_cb: fd=%d easy_handle=%p action=%s ", fd, curl_easy, actionstr[action]);
	if (action == CURL_POLL_REMOVE) {
		DBG("CURL_POLL_REMOVE\n");
		_remove_socket_info(sock_info);
	} else {
		if (!sock_info) {
			DBG("Adding data: %s%s\n", action & CURL_POLL_IN ? "READ" : "", action & CURL_POLL_OUT ? "WRITE" : "");
			_add_socket_info(fd, curl_easy, action, session);
		} else {
			DBG("Changing action from %d to %d\n", sock_info->action, action);
			_set_socket_info(sock_info, fd, curl_easy, action, session);
		}
	}

	return 0;
}

int __handle_timer_cb(CURLM *curl_multi, long timeout_ms, void *user_data)
{
	__http_session_h* session = (__http_session_h *)user_data;

	session->timer_event = g_timeout_add(timeout_ms , timer_expired_callback , session);

	return 0;
}

API int http_session_create(http_session_mode_e mode, http_session_h *http_session)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");

	__http_session_h *session = NULL;

	session = (__http_session_h *)malloc(sizeof(__http_session_h));
	if (session == NULL) {
		ERR("Fail to allocate session memory!!");
		return HTTP_ERROR_OUT_OF_MEMORY;
	}

	session->multi_handle = curl_multi_init();
	session->session_id = _generate_session_id();
	session->active_transaction_count = 0;
	session->session_mode = mode;
	session->auto_redirect = FALSE;

	curl_multi_setopt(session->multi_handle, CURLMOPT_SOCKETFUNCTION, __handle_socket_cb);
	curl_multi_setopt(session->multi_handle, CURLMOPT_SOCKETDATA, session);
	curl_multi_setopt(session->multi_handle, CURLMOPT_TIMERFUNCTION, __handle_timer_cb);
	curl_multi_setopt(session->multi_handle, CURLMOPT_TIMERDATA, session);

	if (mode == HTTP_SESSION_MODE_PIPELINING) {
		curl_multi_setopt(session->multi_handle, CURLMOPT_PIPELINING, 1L);
	}

	*http_session = (http_session_h)session;

	return HTTP_ERROR_NONE;
}

API int http_session_destroy(http_session_h http_session)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");

	__http_session_h *session = (__http_session_h *)http_session;

	if (session->multi_handle) {
		curl_multi_cleanup(session->multi_handle);
		session->multi_handle = NULL;
	}

	session->active_transaction_count = 0;
	session->still_running = 0;
	session->auto_redirect = FALSE;

	free(session);

	return HTTP_ERROR_NONE;
}

API int http_session_set_auto_redirection(http_session_h http_session, bool auto_redirection)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");

	__http_session_h *session = (__http_session_h *)http_session;

	session->auto_redirect = auto_redirection;

	return HTTP_ERROR_NONE;
}

API int http_session_get_auto_redirection(http_session_h http_session, bool *auto_redirect)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");
	_retvm_if(auto_redirect == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(auto_redirect) is NULL\n");

	__http_session_h *session = (__http_session_h *)http_session;

	*auto_redirect =  session->auto_redirect;

	return HTTP_ERROR_NONE;
}

API int http_session_get_active_transaction_count(http_session_h http_session, int *active_transaction_count)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");
	_retvm_if(active_transaction_count == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(active_transaction_count) is NULL\n");

	__http_session_h *session = (__http_session_h *)http_session;

	*active_transaction_count = session->active_transaction_count;

	return HTTP_ERROR_NONE;
}

API int http_session_get_max_transaction_count(http_session_h http_session, int *transaction_count)
{
	_retvm_if(http_session == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_session) is NULL\n");
	_retvm_if(transaction_count == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(transaction_count) is NULL\n");

	__http_session_h *session = (__http_session_h *)http_session;

	if (session->session_mode == HTTP_SESSION_MODE_NORMAL) {
		*transaction_count =  _MAX_HTTP_TRANSACTIONS_PER_SESSION_NORMAL;
	} else if (session->session_mode == HTTP_SESSION_MODE_PIPELINING) {
		*transaction_count =  _MAX_HTTP_TRANSACTIONS_PER_SESSION_PIPE;
	} else {
		*transaction_count =  -1;
	}

	return HTTP_ERROR_NONE;
}
