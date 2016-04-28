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

#define HTTP_PREFIX_SIZE 5
#define HTTP_VERSION_SIZE 3
#define HTTP_STATUS_CODE_SIZE 3
#define HTTP_REASON_PHRASE_SIZE 1024

#define HTTP_DEFAULT_CA_PATH "/etc/ssl/certs"

static const int _HTTP_DEFAULT_CONNECTION_TIMEOUT = 30;
static const int _HTTP_DEFAULT_HEADER_SIZE = 1024;
static const int _MAX_HTTP_TRANSACTIONS_PER_SESSION_NORMAL = 1;
static const int _MAX_HTTP_TRANSACTIONS_PER_SESSION_PIPE = 5;


#define _HTTP_PROXY_AUTHENTICATE_HEADER_NAME "Proxy-Authenticate"
#define _HTTP_WWW_AUTHENTICATE_HEADER_NAME "WWW-Authenticate"
#define _HTTP_CONTENT_LENGTH_HEADER_NAME "Content-Length"

typedef enum {
	_CURL_HTTP_AUTH_NONE = 0,			//none
	_CURL_HTTP_AUTH_BASIC = 1,			// The constant for basic authentication
	_CURL_HTTP_AUTH_DIGEST = 2,			// The constant for digest authentication
	_CURL_HTTP_AUTH_GSSNEGOTIATE = 4,	// The constant for gss-negotiate authentication
	_CURL_HTTP_AUTH_NTLM = 8			// The constant for ntlm authentication
} curl_http_auth_scheme;

typedef struct {
	struct curl_slist *header_list;
	GHashTable *hash_table;
	gchar *rsp_header;
	gint rsp_header_len;
} __http_header_h;

typedef struct {
	gchar *host_uri;
	gchar *method;
	gchar *encoding;
	gchar *cookie;
	GQueue* body_queue;
	gint tot_size;
	http_version_e http_version;
} __http_request_h;

typedef struct {
	gchar *status_text;
	http_status_code_e status_code;
	http_version_e version;
} __http_response_h;

typedef struct {
	CURLM *multi_handle;
	int session_id;
	guint timer_event;
	int still_running;
	int active_transaction_count;
	gboolean auto_redirect;
	http_session_mode_e session_mode;
} __http_session_h;

typedef struct {
	CURL *easy_handle;
	int session_id;
	int transaction_id;
	gchar *interface_name;
	int timeout;
	int write_event;
	bool verify_peer;
	gchar *ca_path;
	gchar error[CURL_ERROR_SIZE];

	/*Authentication Info*/
	bool auth_required;
	bool proxy_auth_type;
	http_auth_scheme auth_scheme;
	gchar* realm;
	/*Credential Info*/
	gchar* user_name;
	gchar* password;

	int socket_fd;
	/*Transaction Callbacks and User data*/
	http_transaction_progress_cb progress_cb;
	void* progress_user_data;
	http_transaction_header_cb header_cb;
	void* header_user_data;
	bool header_event;
	http_transaction_body_cb body_cb;
	void* body_user_data;
	http_transaction_write_cb write_cb;
	void* write_user_data;
	http_transaction_completed_cb completed_cb;
	void* completed_user_data;
	http_transaction_aborted_cb aborted_cb;
	void *aborted_user_data;

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
bool _http_is_init(void);
gchar* _get_http_method(http_method_e method);
http_method_e _get_method(gchar* method);
gchar* _get_proxy();
struct curl_slist* _get_header_list(http_transaction_h http_transaction);

int _get_request_body_size(http_transaction_h http_transaction, int *body_size);
int _read_request_body(http_transaction_h http_transaction, char **body);
void __parse_response_header(char *buffer, size_t written, gpointer user_data);
int _generate_session_id(void);
int _generate_transaction_id(void);
void _add_transaction_to_list(http_transaction_h http_transaction);
void _remove_transaction_from_list(http_transaction_h http_transaction);
void _remove_transaction_list(void);
curl_http_auth_scheme _get_http_curl_auth_scheme(http_auth_scheme auth_scheme);
http_auth_scheme _get_http_auth_scheme(bool proxy_auth, curl_http_auth_scheme curl_auth_scheme);
gchar* parse_values(const char* string, int from_index, int to_index);

#ifdef __cplusplus
 }
#endif

#endif /* __HTTP_PRIVATE_H__ */
