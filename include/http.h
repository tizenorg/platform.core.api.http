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

#ifndef __TIZEN_NETWORK_HTTP_H__
#define __TIZEN_NETWORK_HTTP_H__

#include <tizen.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file http.h
 */

/**
 * @addtogroup CAPI_NETWORK_HTTP_MANAGER_MODULE
 * @{
 */

/**
 * @brief The Http handle.
 * @since_tizen 3.0
 */
typedef void * http_session_h;
typedef void * http_transaction_h;

/**
 * @}
 */

/**
 * @brief Enumeration for the http session.
 * @since_tizen 3.0
 */
typedef enum {
	HTTP_SESSION_MODE_NORMAL,           /**< The Normal Mode */
	HTTP_SESSION_MODE_PIPELINING,       /**< The Pipelining mode */
} http_session_mode_e;

/**
 * @brief Enumeration for the http method.
 * @since_tizen 3.0
 */
typedef enum {
	HTTP_METHOD_NONE = 0x0,
	HTTP_METHOD_GET = 0x40,         /**< The HTTP GET Method */
	HTTP_METHOD_OPTIONS = 0x41,     /**< The HTTP OPTIONS Method */
	HTTP_METHOD_HEAD = 0x42,        /**< The HTTP HEAD Method */
	HTTP_METHOD_DELETE = 0x43,      /**< The HTTP DELETE Method */
	HTTP_METHOD_TRACE = 0x44,       /**< The HTTP TRACE Method */
	HTTP_METHOD_POST = 0x60,        /**< The HTTP POST Method */
	HTTP_METHOD_PUT = 0x61,         /**< The HTTP PUT Method */
	HTTP_METHOD_CONNECT = 0x70,     /**< The HTTP CONNECT Method */
} http_method_e;

/**
 * @brief Enumeration for the http version.
 * @since_tizen 3.0
 */
typedef enum {
	HTTP_VERSION_1_0,   /**< %Http version 1.0 */
	HTTP_VERSION_1_1    /**< %Http version 1.1 */
} http_version_e;

/**
 * @brief Enumeration for transfer pause state
 * @since_tizen 3.0
 */
typedef enum {
	HTTP_PAUSE_RECV = 1 << 0,   /**< Pause receiving data */
	HTTP_PAUSE_SEND = 1 << 2,    /**< Pause sending data */
	HTTP_PAUSE_ALL =  HTTP_PAUSE_RECV |  HTTP_PAUSE_SEND  /**< %Pause both directions */
} http_pause_state_e;

/**
 * @brief Enumeration for the http error code.
 * @since_tizen 3.0
 */
typedef enum {
    HTTP_ERROR_NONE = TIZEN_ERROR_NONE,  /**< Successful */
    HTTP_ERROR_NOT_PERMITTED = TIZEN_ERROR_NOT_PERMITTED,  /**< Operation not permitted */
    HTTP_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid parameter */
    HTTP_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,  /**< Out of memory */
    HTTP_ERROR_RESOURCE_BUSY = TIZEN_ERROR_RESOURCE_BUSY,  /**< Resource busy */
    HTTP_ERROR_NOT_ENABLED =  0x0501,  /**< Not enabled */
    HTTP_ERROR_OPERATION_FAILED = 0x0502,  /**< Operation failed */
    HTTP_ERROR_INVALID_OPERATION = TIZEN_ERROR_INVALID_OPERATION, /**< Invalid operation */
    HTTP_ERROR_NOT_SUPPORTED = TIZEN_ERROR_NOT_SUPPORTED, /**< API is not supported */
    HTTP_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED,  /**< Permission denied */
} http_error_code_e;

/**
 * @brief Enumeration for the http status code.
 * @since_tizen 3.0
 */
typedef enum {
	HTTP_STATUS_UNDEFINED = 0,                                          /**< The undefined status */
	HTTP_STATUS_CONTINUE = 100,                                         /**< The status code: 100 Continue */
	HTTP_STATUS_SWITCHING_PROTOCOLS = 101,                              /**< The status code: 101 Switching Protocols */
	HTTP_STATUS_OK = 200,                                               /**< The status code: 200 OK */
	HTTP_STATUS_CREATED = 201,                                          /**< The status code: 201 Created */
	HTTP_STATUS_ACCEPTED = 202,                                         /**< The status code: 202 Accepted */
	HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,                    /**< The status code: 203 Non-Authoritative Information */
	HTTP_STATUS_NO_CONTENT = 204,                                       /**< The status code: 204 No %Content */
	HTTP_STATUS_RESET_CONTENT = 205,                                    /**< The status code: 205 Reset %Content */
	HTTP_STATUS_PARTIAL_CONTENT = 206,                                  /**< The status code: 206 Partial %Content */

	HTTP_STATUS_MULTIPLE_CHOICE = 300,                                  /**< The status code: 300 Multiple Choices */
	HTTP_STATUS_MOVED_PERMANENTLY = 301,                                /**< The status code: 301 Moved Permanently */
	HTTP_STATUS_MOVED_TEMPORARILY = 302,                                /**< The status code: 302 Found */
	HTTP_STATUS_SEE_OTHER = 303,                                        /**< The status code: 303 See Other */
	HTTP_STATUS_NOT_MODIFIED = 304,                                     /**< The status code: 304 Not Modified */
	HTTP_STATUS_USE_PROXY = 305,                                        /**< The status code: 305 Use Proxy */

	HTTP_STATUS_BAD_REQUEST = 400,                                      /**< The status code: 400 Bad Request */
	HTTP_STATUS_UNAUTHORIZED = 401,                                     /**< The status code: 401 Unauthorized */
	HTTP_STATUS_PAYMENT_REQUIRED = 402,                                 /**< The status code: 402 Payment Required */
	HTTP_STATUS_FORBIDDEN = 403,                                        /**< The status code: 403 Forbidden */
	HTTP_STATUS_NOT_FOUND = 404,                                        /**< The status code: 404 Not Found */
	HTTP_STATUS_METHOD_NOT_ALLOWED = 405,                               /**< The status code: 405 Method Not Allowed */
	HTTP_STATUS_NOT_ACCEPTABLE = 406,                                   /**< The status code: 406 Not Acceptable */
	HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,                    /**< The status code: 407 Proxy Authentication Required */
	HTTP_STATUS_REQUEST_TIME_OUT = 408,                                 /**< The status code: 408 Request Timeout (not used) */
	HTTP_STATUS_CONFLICT = 409,                                         /**< The status code: 409 Conflict */
	HTTP_STATUS_GONE = 410,                                             /**< The status code: 410 Gone */
	HTTP_STATUS_LENGTH_REQUIRED = 411,                                  /**< The status code: 411 Length Required */
	HTTP_STATUS_PRECONDITION_FAILED = 412,                              /**< The status code: 412 Precondition Failed */
	HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,                         /**< The status code: 413 Request Entity Too Large (not used) */
	HTTP_STATUS_REQUEST_URI_TOO_LARGE = 414,                            /**< The status code: 414 Request-URI Too Long (not used) */
	HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,                           /**< The status code: 415 Unsupported %Media Type */

	HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,                            /**< The status code: 500 Internal Server Error */
	HTTP_STATUS_NOT_IMPLEMENTED = 501,                                  /**< The status code: 501 Not Implemented */
	HTTP_STATUS_BAD_GATEWAY = 502,                                      /**< The status code: 502 Bad Gateway */
	HTTP_STATUS_SERVICE_UNAVAILABLE = 503,                              /**< The status code: 503 Service Unavailable */
	HTTP_STATUS_GATEWAY_TIME_OUT = 504,                                 /**< The status code: 504 Gateway Timeout */
	HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505                        /**< The status code: 505 HTTP Version Not Supported */
} http_status_code_e;

/**
 * @brief Called when the http header is received.
 * @since_tizen 3.0
 * @details Called when the http header is received.
 * @param[in]  header  header information of Http Transaction
 * @param[in]  header_len  length of the Http Transaction header
 */
typedef void (*http_transaction_header_cb)(http_transaction_h transaction, char *header, size_t header_len, void *user_data);

/**
 * @brief Called when the http response is received.
 * @since_tizen 3.0
 * @details Called when the http response is received.
 * @param[in]  body		response information of Http Transaction
 * @param[in]  size		Size in bytes of each element to be written
 * @param[in]  count	Number of elements, each one with a size of size bytes
 */
typedef void (*http_transaction_body_cb)(http_transaction_h transaction, char *body, size_t size, size_t count, void *user_data);

/**
 * @brief Called when the http ready to write event is received.
 * @since_tizen 3.0
 * @details Called when the http ready to write event is received.
 * @param[in]  recommended_chunk_size  recommended chunk length of the Http transaction
 */
typedef void (*http_transaction_write_cb)(http_transaction_h transaction, int recommended_chunk_size, void *user_data);

/**
 * @brief Called when the http transaction is completed.
 * @since_tizen 3.0
 * @details Called when the http transaction is completed.
 */
typedef void (*http_transaction_completed_cb)(http_transaction_h transaction, void *user_data);

/**
 * @brief Called when the http transaction is aborted.
 * @since_tizen 3.0
 * @details Called when the http transaction is aborted.
 * @param[in] reason aborted reason code
 */
typedef void (*http_transaction_aborted_cb)(http_transaction_h transaction, int reason, void *user_data);

/**
 * @brief Called to notify when the content body of the response message is being downloaded.
 * @since_tizen 3.0
 * @details Called to notify when the content body of the response message is being downloaded.
 * @param[in] currentLength current length of the downloaded data (in bytes)
 * @param[in] totalLength total length of the data (in bytes) to download
 */
typedef void (*http_transaction_progress_cb)(http_transaction_h transaction, double dltotla, double dlnow, double ultotal, double ulnow, void *user_data);

/**
 * @addtogroup CAPI_NETWORK_HTTP_MODULE
 * @{
 */

/**
 * @brief Initialize the Http module.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/internet
 * @details Initialize the Http module.
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_init(void);

/**
 * @brief Deinitialize the Http module.
 * @since_tizen 3.0
 * @details Deinitialize the Http module.
 */
int http_deinit(void);

/**
 * @}
 */

/**
 * @addtogroup CAPI_NETWORK_HTTP_SESSION_MODULE
 * @{
 */

/**
 * @brief Create the Http Session.
 * @since_tizen 3.0
 * @details Create the Http Session.
 * @param[out]  http_session  http session handle
 * @param[in]  mode  http session mode
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_create_session(http_session_h *http_session, http_session_mode_e mode);

/**
 * @brief Delete the Http Session.
 * @since_tizen 3.0
 * @details Delete the Http Session.
 * @param[in]  http_session  http session handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_delete_session(http_session_h http_session);

/**
 * @brief  Sets the value to redirect the HTTP request automatically.
 * @since_tizen 3.0
 * @details Sets the value to redirect the HTTP request automatically.
 * @param[in]  http_session  http session handle
 * @param[in]  auto_redirect set value of auto redirect
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_session_set_auto_redirection(http_session_h http_session, bool enable);

/**
 * @brief Get the auto redirection for the HTTP request.
 * @since_tizen 3.0
 * @details Get the auto redirection for the HTTP request.
 * @param[in]  http_session  http session handle
 * @param[out]  auto_redirect get value of auto redirect
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_session_get_auto_redirection(http_session_h http_session, bool *auto_redirect);

/**
 * @brief Gets the number of active transactions in the current session.
 * @since_tizen 3.0
 * @details Gets the number of active transactions in the current session.
 * @param[in]  http_session  http session handle
 * @param[out]  active_transaction_count  active transaction count
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_session_get_active_transaction_count(http_session_h http_session, int *active_transaction_count);

/**
 * @brief Gets the maximum number of transactions for the current session.
 * @since_tizen 3.0
 * @details Gets the maximum number of transactions for the current session.
 * @param[in]  http_session  http session handle
 * @param[out]  transaction_count  maximum transaction count
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_session_get_max_transaction_count(http_session_h http_session, int *transaction_count);
/**
 * @}
 */

/**
 * @addtogroup CAPI_NETWORK_HTTP_TRANSACTION_MODULE
 * @{
 */

/**
 * @brief Open Http Transaction from the Http Session.
 * @since_tizen 3.0
 * @details Open Http Transaction from the Http Session.
 * @param[in]  http_session  http session handle
 * @param[in]  method  http method
 * @param[in]  transaction_header_callback  Header callback
 * @param[in]  transaction_body_callback  Body callback
 * @param[in]  transaction_write_callback  write callback
 * @param[in]  transaction_completed_cb  completed callback
 * @param[in]  transaction_aborted_cb  aborted callback
 * @param[out]  http_transaction  http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_open_transaction(http_session_h http_session, http_method_e method, http_transaction_h *http_transaction);

/**
 * @brief Submit the Http request.
 * @since_tizen 3.0
 * @details Submit the Http request.
 * @param[in]  http_transaction  The http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_submit(http_transaction_h http_transaction);

/**
 * @brief Close the Http Transaction.
 * @since_tizen 3.0
 * @details Close the Http Transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_close(http_transaction_h http_transaction);

/*
 * @brief Registers callback called when receive header.
 * @since_tizen 3.0
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  header_cb  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_received_header_cb(http_transaction_h transaction, http_transaction_header_cb header_cb, void* user_data);

/*
 * @brief Registers callback called when receive body.
 * @since_tizen 3.0
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  body_cb  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_received_body_cb(http_transaction_h transaction, http_transaction_body_cb body_cb, void* user_data);

/*
 * @brief Registers callback called when write data.
 * @since_tizen 3.0
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  write_cb  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_uploaded_cb(http_transaction_h transaction, http_transaction_write_cb write_cb, void* user_data);

/*
 * @brief Registers callback called when transaction is completed.
 * @since_tizen 3.0
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  completed_cb  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_completed_cb(http_transaction_h transaction, http_transaction_completed_cb completed_cb, void* user_data);

/*
 * @brief Registers callback called when transaction is aborted.
 * @since_tizen 3.0
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  header_cb  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_aborted_cb(http_transaction_h http_transaction, http_transaction_aborted_cb aborted_cb, void* user_data);


/*
 * @brief Close all transaction.
 * @since_tizen 3.0
 * @param[in]  http_session  The http session handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #HTTP_ERROR_OPERATION_fAILED  Operation failed
 */
int http_transaction_close_all(http_session_h session);


/**
 * @brief Register the progress callbacks.
 * @since_tizen 3.0
 * @details Sets the progress callbacks.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in] progress_cb download callback
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_progress_cb(http_transaction_h http_transaction, http_transaction_progress_cb progress_cb, void* user_data);

/**
 * @brief Sets the timeout in seconds that is the timeout for waiting the transaction. @n
 * A timeout value of zero means an infinite timeout.
 * @since_tizen 3.0
 * @details Sets the timeout in seconds that is the timeout for waiting the transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  timeout  timeout in seconds
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_timeout(http_transaction_h http_transaction, int timeout);

/**
 * @brief Get the time out in seconds for the transaction.
 * @since_tizen 3.0
 * @details Get the time out in seconds for the transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  timeout  timeout in seconds
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_get_timeout(http_transaction_h http_transaction, int *timeout);

/**
 * @brief Sets a user object to the instance of HTTP transaction.
 * @since_tizen 3.0
 * @details Sets a user object to the instance of HTTP transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  user_object user object
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_user_object(http_transaction_h http_transaction, void *user_object);

/**
 * @brief Gets a user object that is set to the instance of HTTP transaction.
 * @since_tizen 3.0
 * @details Gets a user object that is set to the instance of HTTP transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  user_object  user object
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_get_user_object(http_transaction_h http_transaction, void **user_object);

/**
 * @brief Resumes the transaction after the http_transaction_cert_verifcation_required_cb event is invoked.
 * @since_tizen 3.0
 * @details Resumes the transaction after the http_transaction_cert_verifcation_required_cb event is invoked.
 * @param[in]  http_transaction  The http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_resume(http_transaction_h http_transaction);

/**
 * @brief Pauses the transaction after the http_transaction_cert_verifcation_required_cb event is invoked.
 * @since_tizen 3.0
 * @details Pauses the transaction after the http_transaction_cert_verifcation_required_cb event is invoked.
 * @param[in]  http_transaction  The http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_pause(http_transaction_h http_transaction, http_pause_state_e pause_state);

/**
 * @brief Sets ready to write event for a transaction.
 * @since_tizen 3.0
 * @details Sets ready to write event for a transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out] read_to_write enable/disable ready to write
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_ready_to_write(http_transaction_h http_transaction, bool read_to_write);

/**
 * @brief Set the interface name.
 * @since_tizen 3.0
 * @details Set the interface name.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in] interface_name  interface name
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_interface_name(http_transaction_h http_transaction, const char *interface_name);

/**
 * @brief Get the interface name.
 * @since_tizen 3.0
 * @details Get the interface name.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  interface_name  interface name
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_get_interface_name(http_transaction_h http_transaction, char **interface_name);

/**
 * @brief Sets the flag to verify a server certificate.
 * @since_tizen 3.0
 * @details Get the interface name.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  verify flag to verify a server certificate.
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_set_server_certificate_verification(http_transaction_h http_transaction, bool verify);

/**
 * @brief Gets the flag to verify a server certificate.
 * @since_tizen 3.0
 * @details Get the interface name.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  verify flag to verify a server certificate.
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_transaction_get_server_certificate_verification(http_transaction_h http_transaction, bool* verify);

/**
 * @brief Adds a named field, which is a <@c fieldName, @c fieldValue> pair, to the current instance of Http Transaction.
 * @since_tizen 3.0
 * @details Adds a named field, which is a <@c fieldName, @c fieldValue> pair, to the current instance of Http Transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  field_name  Http Header Field name
 * @param[in]  field_name  Http Header Field value
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_header_add_field(http_transaction_h http_transaction, const char *field_name, const char* field_value);

/**
 * @brief Remove the named field, which is a <@c fieldName, @c fieldValue> pair, from the current instance of Http Transaction.
 * @since_tizen 3.0
 * @details Remove the named field, which is a <@c fieldName, @c fieldValue> pair, from the current instance of Http Transaction.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  field_name  Http Header Field name
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_header_remove_field(http_transaction_h http_transaction, const char *field_name);

/**
 * @brief Get the Http Header Field value.
 * @since_tizen 3.0
 * @details Get the Http Header Field value.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  field_name  Http Header Field name
 * @param[out]  field_value  Http Header Field value
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_header_get_field_value(http_transaction_h http_transaction, const char *field_name, char **field_value);

/**
 * @}
 */

/**
 * @addtogroup CAPI_NETWORK_HTTP_REQUEST_MODULE
 * @{
 */

/**
 * @brief Sets an HTTP method of the request header.
 * @since_tizen 3.0
 * @details Sets an HTTP method of the request header.
 * @param[in]  http_transaction  The http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_set_method(http_transaction_h http_transaction, http_method_e method);

/**
 * @brief Get the Http method.
 * @since_tizen 3.0
 * @details Get the Http method.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  method method
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_get_method(http_transaction_h http_transaction, http_method_e *method);

/**
 * @brief Sets an HTTP version of the request header.
 * @since_tizen 3.0
 * @details Sets an HTTP version of the request header.
 * @param[in]  http_transaction  The http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_set_version(http_transaction_h http_transaction, http_version_e version);

/**
 * @brief Get the Http version.
 * @since_tizen 3.0
 * @details Get the Http version.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  version version
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_get_version(http_transaction_h http_transaction, http_version_e *version);

/**
 * @brief Sets a URI of the request header.
 * @since_tizen 3.0
 * @details Sets a URI of the request header.
 * @param[in]  http_transaction  The http transaction handle
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_set_uri(http_transaction_h http_transaction, const char *host_uri);

/**
 * @brief Get the uri.
 * @since_tizen 3.0
 * @details Get the uri.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  host_uri  host uri
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_get_uri(http_transaction_h http_transaction, char **host_uri);

/**
 * @brief Sets the Accept-Encoding header field of HttpRequest.
 * @since_tizen 3.0
 * @details Sets the Accept-Encoding header field of HttpRequest.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  encoding  encoding
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_set_accept_encoding(http_transaction_h http_transaction, const char *encoding);

/**
 * @brief Get the Accept-Encoding header field of HttpRequest.
 * @since_tizen 3.0
 * @details Get the Accept-Encoding header field of HttpRequest.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  encoding  encoding
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_get_accept_encoding(http_transaction_h http_transaction, char **encoding);

int http_request_set_cookie(http_transaction_h http_transaction, const char *cookie);
int http_request_get_cookie(http_transaction_h http_transaction, const char **cookie);

/**
 * @brief Sets the request message body.
 * @since_tizen 3.0
 * @details Sets the request message body.
 * @param[in]  http_transaction  The http transaction handle
 * @param[in]  body  message body data
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_request_write_body(http_transaction_h http_transaction, const char *body);

/**
 * @}
 */

/**
 * @addtogroup CAPI_NETWORK_HTTP_RESPONSE_MODULE
 * @{
 */

/**
 * @brief Get the Http status code from Http Response.
 * @since_tizen 3.0
 * @details Get the Http status code from Http Response.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  status_code http status code
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_response_get_status_code(http_transaction_h http_transaction, http_status_code_e *status_code);

/**
 * @brief Get the Http status text from Http Response.
 * @since_tizen 3.0
 * @details Get the Http status text from Http Response.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  status_text http status text
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_response_get_status_text(http_transaction_h http_transaction, char **status_text);

/**
 * @brief Get the Http version from Http Response.
 * @since_tizen 3.0
 * @details Get the Http version from Http Response.
 * @param[in]  http_transaction  The http transaction handle
 * @param[out]  version version
 * @return 0 on success, otherwise negative error value
 * @retval  #HTTP_ERROR_NONE  Successful
 * @retval  #HTTP_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int http_response_get_version(http_transaction_h http_transaction, http_version_e *version);

/**
 * @}
 */

#ifdef __cplusplus
 }
#endif

#endif /* __TIZEN_NETWORK_HTTP_H__ */
