/*
* Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __HTTP_PRIVATE_H__
#define __HTTP_PRIVATE_H__

#define LOG_TAG	"CAPI_NETWORK_HTTP"

#include <string.h>
#include <glib.h>
#include <gio/gio.h>
#include <curl/curl.h>
#include <dlog.h>

#include "http.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#ifndef DEPRECATED_API
#define DEPRECATED_API __attribute__ ((deprecated))
#endif

#define DBG(fmt, args...)	LOGD(fmt, ##args)
#define WARN(fmt, args...)	LOGW(fmt, ##args)
#define ERR(fmt, args...)	LOGE(fmt, ##args)
#define SDBG(fmt, args...)	SECURE_LOGD(fmt, ##args)
#define SERR(fmt, args...)	SECURE_LOGE(fmt, ##args)

#define _warn_if(expr, fmt, arg...) do { \
		if (expr) { \
			WARN(fmt, ##arg); \
		} \
	} while (0)

#define _ret_if(expr) do { \
		if (expr) { \
			return; \
		} \
	} while (0)

#define _retv_if(expr, val) do { \
		if (expr) { \
			return (val); \
		} \
	} while (0)

#define _retm_if(expr, fmt, arg...) do { \
		if (expr) { \
			ERR(fmt, ##arg); \
			return; \
		} \
	} while (0)

#define _retvm_if(expr, val, fmt, arg...) do { \
		if (expr) { \
			ERR(fmt, ##arg); \
			return (val); \
		} \
	} while (0)

static const int _HTTP_DEFAULT_CONNECTION_TIMEOUT = 30;
static const int _HTTP_DEFAULT_HEADER_SIZE = 1024;
static const int _MAX_HTTP_TRANSACTIONS_PER_SESSION_NORMAL = 1;
static const int _MAX_HTTP_TRANSACTIONS_PER_SESSION_PIPE = 5;

typedef struct {
	struct curl_slist *header_list;
	GHashTable *hash_table;
} __http_header_h;

typedef struct {
	gchar *host_uri;
	gchar *method;
	gchar *encoding;
	gchar *body;
	http_version_e http_version;
} __http_request_h;

typedef struct {
	gchar *status_text;
	http_status_code_e status_code;
} __http_response_h;

typedef struct {
	CURLM *multi_handle;
	guint timer_event;
	int still_running;
	int active_transaction_count;
	gboolean auto_redirect;
	http_session_mode_e session_mode;
} __http_session_h;

typedef struct {
	CURL *easy_handle;
	gchar *interface_name;
	int timeout;
	gchar error[CURL_ERROR_SIZE];

	int socket_fd;
	/*Transaction Callbacks */
	http_transaction_header_cb header_cb;
	http_transaction_body_cb body_cb;
	http_transaction_write_cb write_cb;
	http_transaction_completed_cb completed_cb;
	http_transaction_aborted_cb aborted_cb;
	/*Progress Callbacks */
	http_transaction_upload_progress_cb upload_progress_cb;
	http_transaction_download_progress_cb download_progress_cb;

	__http_session_h *session;
	__http_request_h *request;
	__http_response_h *response;
	__http_header_h *header;

	GThread *thread;
	GMainLoop *thread_loop;
} __http_transaction_h;

typedef struct {
	curl_socket_t sockfd;
	CURL *easy_handle;
	int action;
	guint event;

	GIOChannel *channel;
	__http_session_h *session;
} __http_socket_info_h;


void print_curl_multi_errorCode(CURLMcode code);
gchar* _get_http_method(http_method_e method);
http_method_e _get_method(gchar* method);
gchar* _get_proxy();
struct curl_slist* _get_header_list(http_transaction_h http_transaction);

#ifdef __cplusplus
 }
#endif

#endif /* __HTTP_PRIVATE_H__ */
