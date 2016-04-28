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

#include <math.h>

#include "http.h"
#include "http_private.h"

static int __convert_status_code(gchar *status_code)
{
	int i = 0;
	int converted_digit = 0;
	int converted_status_code = 0;

	for (i = HTTP_STATUS_CODE_SIZE - 1; i >= 0; i--) {
		converted_digit = g_ascii_digit_value(status_code[i]);
		converted_status_code += converted_digit * pow(10, HTTP_STATUS_CODE_SIZE - i - 1);
	}

	return converted_status_code;
}

void __parse_response_header(gchar *buffer, size_t written, gpointer user_data)
{
	__http_transaction_h* transaction = (__http_transaction_h *)user_data;
	__http_response_h*response = (__http_response_h *)transaction->response;

	gchar status_code[HTTP_STATUS_CODE_SIZE] = {0, };
	gchar* start = NULL;
	gchar* end = NULL;

	if (strncmp(buffer, "HTTP/", HTTP_PREFIX_SIZE) == 0) {
		if (strncmp(buffer + HTTP_PREFIX_SIZE, "1.0", HTTP_VERSION_SIZE) == 0)
			response->version = HTTP_VERSION_1_0;
		else if (strncmp(buffer + HTTP_PREFIX_SIZE, "1.1", HTTP_VERSION_SIZE) == 0)
			response->version = HTTP_VERSION_1_1;

		start = buffer + HTTP_PREFIX_SIZE + HTTP_VERSION_SIZE + 1;
		strncpy(status_code, start, HTTP_STATUS_CODE_SIZE);

		start += HTTP_STATUS_CODE_SIZE + 1;
		end = start + strcspn(start, "\n");

		while (end > start && (end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
			end--;

		response->status_code = __convert_status_code(status_code);
		response->status_text = g_strndup(start, end - start);

		DBG("reason_pharse: %s", response->status_text);
	} else {
		gchar *field_name = NULL;
		gchar *field_value = NULL;
		gchar *curpos = NULL;
		int pos = 0, len = 0;

		len = strlen(buffer);
		curpos = strchr(buffer, ':');
		if (curpos == NULL) {
			return;
		}
		pos = curpos - buffer + 1;

		field_name = parse_values(buffer, 0, pos - 1);
		field_value = parse_values(buffer, pos + 1, len);

		http_transaction_header_add_field(transaction, field_name, field_value);
		free(field_name);
		free(field_value);
	}
}

API int http_transaction_response_get_status_code(http_transaction_h http_transaction, http_status_code_e *status_code)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(status_code == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(status_code) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_response_h* response = (__http_response_h *)transaction->response;

	*status_code  = response->status_code;

	return HTTP_ERROR_NONE;
}

API int http_transaction_response_get_status_text(http_transaction_h http_transaction, char **status_text)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(status_text == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(status_text) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_response_h* response = (__http_response_h *)transaction->response;

	*status_text = g_strdup(response->status_text);

	return HTTP_ERROR_NONE;
}

API int http_transaction_response_get_version(http_transaction_h http_transaction, http_version_e *version)
{
	_retvm_if(_http_is_init() == false, HTTP_ERROR_INVALID_OPERATION,
			"http isn't initialized");
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(version == NULL, HTTP_ERROR_INVALID_PARAMETER,
				"parameter(version) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_response_h* response = (__http_response_h *)transaction->response;

	*version = response->version;

	return HTTP_ERROR_NONE;
}
