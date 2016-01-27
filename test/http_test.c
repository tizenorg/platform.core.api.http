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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////Request 1 Callbacks////////////////////////////////////////////////////////////////////////////
void transaction_header_cb(char *header, size_t header_len)
{
	DBG("########################## 1:transaction_header_cb#########################################\n");

	if (!fp1)
		fp1 = fopen ("./google.html", "w+");

}

void transaction_body_cb(char *body, size_t size, size_t nmemb)
{
	DBG("########################## 1:transaction_body_cb#########################################\n");
	//DBG("Body:%s\n", body);
	int written = size * nmemb;

	if (written) {
		fwrite(body, size, nmemb, fp1);
	}
}

void transaction_write_cb(int recommended_chunk_size)
{
	DBG("########################## 1:transaction_write_cb#########################################\n");

	DBG("recommended_chunk_size:%d\n", recommended_chunk_size);
}

void transaction_completed_cb(void)
{
	DBG("########################## 1:transaction_completed_cb#########################################\n");

	fclose(fp1);

	//g_main_loop_quit((GMainLoop*)mainloop);
}

void transaction_aborted_cb(int reason)
{
	DBG("########################## 1:transaction_aborted_cb#########################################\n");

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////Request 2 Callbacks////////////////////////////////////////////////////////////////////////////
void transaction_header_callback(char *header, size_t header_len)
{
	DBG("########################## 2: transaction_header_callback#########################################\n");

	if (!fp2)
		fp2 = fopen ("./ibnlive.html", "w+");

}

void transaction_body_callback(char *body, size_t size, size_t nmemb)
{
	DBG("########################## 2: transaction_body_callback#########################################\n");
	//DBG("Body:%s\n", body);
	int written = size * nmemb;

	if (written) {
		fwrite(body, size, nmemb, fp2);
	}
}

void transaction_write_callback(int recommended_chunk_size)
{
	DBG("########################## 2:transaction_write_callback#########################################\n");

	DBG("recommended_chunk_size:%d\n", recommended_chunk_size);
}

void transaction_completed_callback(void)
{
	DBG("########################## 2:transaction_completed_callback #########################################\n");

	fclose(fp2);

	g_main_loop_quit((GMainLoop*)mainloop);
}

void transaction_aborted_callback(int reason)
{
	DBG("########################## 2:transaction_aborted_callback#########################################\n");

}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

http_transaction_h create_http_request(http_session_h session_handle, gchar* host_url, http_transaction_header_cb header_cb, http_transaction_body_cb body_cb, http_transaction_write_cb write_cb,
							http_transaction_completed_cb completed_cb, http_transaction_aborted_cb aborted_cb)
{
	http_transaction_h transaction_handle = NULL;

	http_session_set_auto_redirection(session_handle, TRUE);

	http_open_transaction(session_handle, HTTP_METHOD_GET, (http_transaction_header_cb)header_cb,
						(http_transaction_body_cb)body_cb, (http_transaction_write_cb)write_cb, (http_transaction_completed_cb)completed_cb,
						(http_transaction_aborted_cb)aborted_cb, &transaction_handle);

	http_request_set_uri(transaction_handle, host_url);

	return transaction_handle;
}

int submit_http_request(http_transaction_h transaction_handle)
{
	http_transaction_submit(transaction_handle);

	return 0;
}

int main()
{
	http_session_h session_handle = NULL;
	http_transaction_h transaction_handle1 = NULL;
	http_transaction_h transaction_handle2 = NULL;


	DBG("########################## main:Enter#########################################\n");

	mainloop = g_main_loop_new(NULL, FALSE);

	http_init();

	http_create_session(&session_handle, HTTP_SESSION_MODE_NORMAL);

	transaction_handle1 = create_http_request(session_handle, "http://www.google.com", transaction_header_cb, transaction_body_cb,
														transaction_write_cb, transaction_completed_cb, transaction_aborted_cb);
	transaction_handle2 = create_http_request(session_handle, "http://www.ibnlive.com", transaction_header_callback, transaction_body_callback,
														transaction_write_callback, transaction_completed_callback, transaction_aborted_callback);

	submit_http_request(transaction_handle1);
	submit_http_request(transaction_handle2);

	g_main_loop_run(mainloop);

	http_transaction_close(transaction_handle1);
	transaction_handle1 = NULL;
	http_transaction_close(transaction_handle2);
	transaction_handle1 = NULL;
	http_delete_session(session_handle);
	session_handle = NULL;
	http_deinit();

	g_main_loop_unref(mainloop);

	DBG("########################## main:Exit#########################################\n");
	return 0;
}
