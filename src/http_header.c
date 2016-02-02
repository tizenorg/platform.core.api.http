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

struct curl_slist* _get_header_list(http_transaction_h http_transaction)
{
	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_header_h *header = transaction->header;

	gchar* header_str = NULL;
	GHashTableIter iter;
	gpointer key = NULL;
	gpointer value = NULL;
	gint size = 0;

	size = g_hash_table_size(header->hash_table);
	DBG("Header table Size: %d\n", size);

	g_hash_table_iter_init(&iter, header->hash_table);

	while(g_hash_table_iter_next (&iter, &key, &value)) {
		header_str = (gchar *)malloc(sizeof(gchar) * (strlen(key) + 1 + 1 + strlen(value) + 1) );
		sprintf(header_str, "%s: %s", (gchar*)key, (gchar*)value);
		DBG("Header Field: %s\n", header_str);
		header->header_list = curl_slist_append(header->header_list, header_str);
		free(header_str);
	}

	return header->header_list;
}

API int http_header_add_field(http_transaction_h http_transaction, const char *field_name, const char* field_value)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(field_name == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(field_name) is NULL\n");
	_retvm_if(field_value == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(field_value) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_header_h *header = transaction->header;

	if (!header->hash_table) {
		header->hash_table = g_hash_table_new(g_str_hash, g_str_equal);
	}

	g_hash_table_insert(header->hash_table, (char*)field_name, (char*)field_value);

	return HTTP_ERROR_NONE;
}

API int http_header_remove_field(http_transaction_h http_transaction, const char *field_name)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(field_name == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(field_name) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_header_h *header = transaction->header;

	g_hash_table_remove(header->hash_table, field_name);

	return HTTP_ERROR_NONE;
}

API int http_header_get_field_value(http_transaction_h http_transaction, const char *field_name, char **field_value)
{
	_retvm_if(http_transaction == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(http_transaction) is NULL\n");
	_retvm_if(field_name == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(field_name) is NULL\n");
	_retvm_if(field_value == NULL, HTTP_ERROR_INVALID_PARAMETER,
			"parameter(field_value) is NULL\n");

	__http_transaction_h *transaction = (__http_transaction_h *)http_transaction;
	__http_header_h *header = transaction->header;

	*field_value = g_hash_table_lookup(header->hash_table, field_name);

	return HTTP_ERROR_NONE;
}
