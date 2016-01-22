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

typedef struct {
	CURLM *multi_handle;
	guint timer_event;
	int still_running;
	int active_transaction_count;
	gboolean auto_redirect;
	http_session_mode_e session_mode;
} __http_session_h;

typedef struct {
	gchar *proxy_addr;
	gchar *host_uri;
	gchar *method;
	gchar *encoding;
	gchar *interface_name;
	int timeout;
	http_version_e http_version;
	gchar error[CURL_ERROR_SIZE];

	int socket_fd;
	CURL *easy_handle;
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

	GThread *thread;
	GMainLoop *thread_loop;
} __http_transaction_h;

typedef struct {
	GIOChannel* channel;
	GSource* source;
	int action;

	__http_session_h *session;
} __http_socket_info_h;

#ifdef __cplusplus
 }
#endif

#endif /* __HTTP_PRIVATE_H__ */
