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

#define ERR(x, y) printf("[ERR] %s(%d)\n", x, y)
#define PRG(x, y) printf("[PRG] %s(%p)\n", x, y)
#define DBG	printf
#define MAX_URI_LEN 1024

FILE* fp1 = NULL;
FILE* fp2 = NULL;

/////////////////Callbacks////////////////////////////////////////////////////////////////////////////
void __transaction_header_cb(http_transaction_h http_transaction, char *header, size_t header_len, void *user_data)
{
	PRG("transaction_header_cb", http_transaction);
}

void __transaction_body_cb(http_transaction_h http_transaction, char *body, size_t size, size_t nmemb, void *user_data)
{
	PRG("transaction_body_cb", http_transaction);
	int written = size * nmemb;
	DBG("Received: %d\n", written);
}

void __transaction_write_cb(http_transaction_h http_transaction, int recommended_chunk_size, void *user_data)
{
	PRG("transaction_write_cb", http_transaction);
	DBG("recommended_chunk_size:%d\n", recommended_chunk_size);
}

void __transaction_completed_cb(http_transaction_h http_transaction, void *user_data)
{
	PRG("transaction_completed_cb", http_transaction);

	http_status_code_e status = 0;
	int ret;

	ret = http_transaction_response_get_status_code(http_transaction, &status);

	DBG("Status(%d)\n", status);
	ret = http_transaction_destroy(http_transaction);
	if (ret == HTTP_ERROR_NONE) DBG("Success to destroy transaction\n");
	else DBG("Fail to destroy transaction\n");
}

void __transaction_aborted_cb(http_transaction_h http_transaction, int reason, void *user_data)
{
	PRG("transaction_aborted_cb", http_transaction);
	DBG("aborted reason: %d\n", reason);
}

void _register_callbacks(http_transaction_h transaction)
{
	http_transaction_set_received_header_cb(transaction, __transaction_header_cb, NULL);
	http_transaction_set_received_body_cb(transaction, __transaction_body_cb, NULL);
	http_transaction_set_uploaded_cb(transaction, __transaction_write_cb, NULL);
	http_transaction_set_completed_cb(transaction, __transaction_completed_cb, NULL);
	http_transaction_set_aborted_cb(transaction, __transaction_aborted_cb, NULL);
}

int test_http_init(void)
{
	int ret = http_init();
	if (ret == HTTP_ERROR_NONE)
		return 1;
	else return 0;
}

int test_http_deinit(void)
{
	int ret = http_deinit();
	if (ret == HTTP_ERROR_NONE)
		return 1;
	else return 0;
}

int test_simple_get(void)
{
	char uri[1024];
	int ret;
	http_session_h session = NULL;
	http_transaction_h transaction = NULL;

	printf("Input uri: ");
	ret = scanf("%1023s", uri);

	ret = http_session_create(HTTP_SESSION_MODE_NORMAL, &session);
	if (ret != 0) {
		ERR("Fail to create session", ret);
		return 0;
	}

	ret = http_session_open_transaction(session, HTTP_METHOD_GET, &transaction);
	if (ret != 0) {
		ERR("Fail to open transaction", ret);
		return 0;
	}

	ret = http_transaction_request_set_uri(transaction, uri);
	if (ret != 0) {
		ERR("Fail to set URI", ret);
		return 0;
	}

	_register_callbacks(transaction);
	http_transaction_submit(transaction);

	return 1;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
    int rv;
    char a[10];

    printf("Event received from stdin\n");

    rv = read(0, a, 10);

    if (rv <= 0 || a[0] == '0')
        exit(1);

    if (a[0] == '\n' || a[0] == '\r') {
        printf("\n\n Network Connection API Test App\n\n");
        printf("Options..\n");
        printf("1       - Initialize\n");
        printf("2       - Deinitialize\n");
        printf("3       - Simple GET\n");
        printf("4       - \n");
        printf("5       - \n");
        printf("6       - \n");
        printf("0       - Exit \n");
        printf("ENTER  - Show options menu.......\n");
    }

    switch (a[0]) {
    case '1':
        rv = test_http_init();
        break;
    case '2':
    	rv = test_http_deinit();
        break;
    case '3':
    	rv = test_simple_get();
        break;
    case '4':
        break;
    case '5':
        break;
    case '6':
        break;
    }

    if (rv == 1)
        printf("Operation succeeded!\n");
    else
        printf("Operation failed!\n");

    return true;
}

int main(int argc, char **argv)
{
    GMainLoop *mainloop;

#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init();
#endif
    mainloop = g_main_loop_new(NULL, false);

    GIOChannel *channel = g_io_channel_unix_new(0);
    g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL), test_thread, NULL);
    printf("Test Thread created...\n");
    g_main_loop_run(mainloop);

    return 0;
}



