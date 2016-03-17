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


#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include "http.h"

static GMainLoop *mainloop = NULL;

#define DBG	printf

FILE* fp1 = NULL;
FILE* fp2 = NULL;

http_session_h session_handle = NULL;
http_transaction_h transaction_handle1 = NULL;
http_transaction_h transaction_handle2 = NULL;
int count = 0;

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int add_http_header(http_transaction_h transaction_handle)
{
	http_header_add_field(transaction_handle, "Connection", "close");
	//http_header_add_field(transaction_handle, "Accept-Charset", "ISO-8859-1,UTF-8;q=0.7,*;q=0.7");
	//http_header_add_field(transaction_handle, "Cache-Control", "no-cache");
	//http_header_add_field(transaction_handle, "Accept-Language", "en-us;q=0.3");

	return 0;
}

int remove_http_header(http_transaction_h transaction_handle)
{
	http_header_remove_field(transaction_handle, "Connection");
	//http_header_remove_field(transaction_handle, "Accept-Charset");
	//http_header_remove_field(transaction_handle, "Cache-Control");
	//http_header_remove_field(transaction_handle, "Accept-Language");

	return 0;
}

void print_response_header(http_transaction_h transaction_handle)
{
	char* uri = NULL;
	char* status_text = NULL;
	http_status_code_e status_code;
	http_version_e version;

	DBG("########################## Result #########################################\n");

	http_request_get_uri(transaction_handle, &uri);
	http_response_get_version(transaction_handle, &version);
	http_response_get_status_code(transaction_handle, &status_code);
	http_response_get_status_text(transaction_handle, &status_text);

	DBG("URI(%s) HTTP version (%d) Status Code (%d) Status message (%s)\n", uri, version, status_code, status_text);
}

void close_transaction(http_transaction_h transaction_handle)
{
	remove_http_header(transaction_handle);

	http_transaction_close(transaction_handle);

	//transaction_handle = NULL;
}

void delete_session(http_session_h session)
{
	http_transaction_close_all(session_handle);

	http_delete_session(session_handle);
	session_handle = NULL;
	http_deinit();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////Callbacks////////////////////////////////////////////////////////////////////////////
void transaction_header_cb(http_transaction_h transaction_handle, char *header, size_t header_len, void *user_data)
{
	DBG("########################## transaction_header_cb(%p)#########################################\n", transaction_handle);

}

void transaction_body_cb(http_transaction_h transaction_handle, char *body, size_t size, size_t nmemb, void *user_data)
{
	DBG("########################## transaction_body_cb(%p)#########################################\n", transaction_handle);
	int written = size * nmemb;
	DBG("Received: %d\n", written);
	//if (written) {
		//fwrite(body, size, nmemb, fp1);
	//}
}

void transaction_write_cb(http_transaction_h transaction_handle, int recommended_chunk_size, void *user_data)
{
	DBG("########################## transaction_write_cb(%p)#########################################\n", transaction_handle);

	DBG("recommended_chunk_size:%d\n", recommended_chunk_size);
}

void transaction_completed_cb(http_transaction_h transaction_handle, void *user_data)
{
	DBG("########################## transaction_completed_cb(%p)#########################################\n", transaction_handle);

	char *uri = NULL;

	http_request_get_uri(transaction_handle, &uri);
	DBG("Completed uri: %s\n", uri);
	print_response_header(transaction_handle);
	count--;

	if (count == 0)
		g_main_loop_quit((GMainLoop*)mainloop);
}

void transaction_aborted_cb(http_transaction_h transaction_handle, int reason, void *user_data)
{
	DBG("########################## transaction_aborted_cb(%p)#########################################\n", transaction_handle);

	close_transaction(transaction_handle);
	count--;

	if (count == 0)
		g_main_loop_quit((GMainLoop*)mainloop);
}

http_transaction_h create_http_request(http_session_h session_handle, gchar* host_url)
{
	http_transaction_h transaction_handle = NULL;

	//http_session_set_auto_redirection(session_handle, TRUE);

	http_open_transaction(session_handle, HTTP_METHOD_GET, &transaction_handle);

	http_request_set_uri(transaction_handle, host_url);
	add_http_header(transaction_handle);
	count++;

	return transaction_handle;
}

int submit_http_request(http_transaction_h transaction_handle)
{
	http_transaction_submit(transaction_handle);

	return 0;
}

int main()
{
	DBG("########################## main:Enter#########################################\n");

	mainloop = g_main_loop_new(NULL, FALSE);

	http_init();

	http_create_session(&session_handle, HTTP_SESSION_MODE_NORMAL);

	transaction_handle1 = create_http_request(session_handle, "https://www.google.com");
	transaction_handle2 = create_http_request(session_handle, "http://www.naver.com");

	http_transaction_set_server_certificate_verification(transaction_handle1, 0);
	http_transaction_set_received_header_cb(transaction_handle1, transaction_header_cb, NULL);
	http_transaction_set_received_body_cb(transaction_handle1, transaction_body_cb, NULL);
	http_transaction_set_uploaded_cb(transaction_handle1, transaction_write_cb, NULL);
	http_transaction_set_completed_cb(transaction_handle1, transaction_completed_cb, NULL);
	http_transaction_set_aborted_cb(transaction_handle1, transaction_aborted_cb, NULL);

	http_transaction_set_received_header_cb(transaction_handle2, transaction_header_cb, NULL);
	http_transaction_set_received_body_cb(transaction_handle2, transaction_body_cb, NULL);
	http_transaction_set_uploaded_cb(transaction_handle2, transaction_write_cb, NULL);
	http_transaction_set_completed_cb(transaction_handle2, transaction_completed_cb, NULL);
	http_transaction_set_aborted_cb(transaction_handle2, transaction_aborted_cb, NULL);

	DBG("transaction1(%p), transaction2(%p)\n", transaction_handle1, transaction_handle2);
	submit_http_request(transaction_handle1);
	submit_http_request(transaction_handle2);

	g_main_loop_run(mainloop);

	http_transaction_close_all(session_handle);
	delete_session(session_handle);

	DBG("########################## main:Exit#########################################\n");
	return 0;
}
