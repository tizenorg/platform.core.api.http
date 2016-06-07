/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TIZEN_NETWORK_HTTP_DOC_H__
#define __TIZEN_NETWORK_HTTP_DOC_H__

/**
 * @ingroup CAPI_NETWORK_FRAMEWORK
 * @defgroup CAPI_NETWORK_HTTP_MODULE  HTTP
 * @brief The HTTP API provides functions for communication with server according to HTTP protocol.
 *
 * @section CAPI_NETWORK_HTTP_MODULE_HEADER Required Header
 *   \#include <http.h>
 *
 * @section CAPI_NETWORK_HTTP_MODULE Overview
 * The HTTP API provides functions for communication with server according to HTTP protocol.
 * Using the HTTP APIs, you can implement features that allow the users of your application to:
 * - Manage HTTP session
 * - Manage HTTP transaction
 * - Send/Recieve HTTP request/response
 * 
 * @if WEARABLE
 * @section CAPI_NETWORK_HTTP_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.internet \n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 * @ endif
 *
 */

/**
 * @ingroup CAPI_NETWORK_HTTP_MODULE
 * @defgroup CAPI_NETWORK_HTTP_SESSION_MODULE  HTTP Session
 * @brief The HTTP Session API provides functions for managing HTTP session.
 *
 * @section CAPI_NETWORK_HTTP_SESSION_MODULE_HEADER Required Header
 *   \#include <http.h>
 *
 * @section CAPI_NETWORK_HTTP_SESSION_MODULE_OVERVEW Overview
 * The HTTP Session API provides functions for managing HTTP session.
 * Using the HTTP Session, you can implement features that allow the users of your application to:
 * - Create / Delete HTTP session
 * - Get activated transaction count
 * - Manage redirection
 * 
 * @if WEARABLE
 * @section CAPI_NETWORK_HTTP_SESSION_MODULE_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.internet \n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 * @ endif
 *
 */

/**
 * @ingroup CAPI_NETWORK_HTTP_SESSION_MODULE
 * @defgroup CAPI_NETWORK_HTTP_TRANSACTION_MODULE  HTTP Transaction
 * @brief The HTTP Transaction API provides functions for managing HTTP transactions.
 *
 * @section CAPI_NETWORK_HTTP_TRANSACTION_MODULE_HEADER Required Header
 *   \#include <http.h>
 *
 * @section CAPI_NETWORK_HTTP_TRANSACTION_MODULE_OVERVIEW Overview
 * It allows managing HTTP transactions.
 * Using the HTTP Transaction, you can implement features that allow the users of your application to:
 * - Open/Close transactions
 * - Pause/Resume transactions
 * - Transfer HTTP request
 * - Get/Set transaction options such as interface, verification and timeout
 * 
 * @if WEARABLE
 * @section CAPI_NETWORK_HTTP_TRANSACTION_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.internet \n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 * @ endif
 *
 */

/**
 * @ingroup CAPI_NETWORK_HTTP_TRANSACTION_MODULE
 * @defgroup CAPI_NETWORK_HTTP_REQUEST_MODULE  HTTP Request
 * @brief It manages HTTP request.
 *
 * @section CAPI_NETWORK_HTTP_REQUEST_MODULE_HEADER  Required Header
 *   \#include <http.h>
 *
 * @section CAPI_NETWORK_HTTP_REQUEST_MODULE_OVERVIEW Overview
 * It manages HTTP request message.
 * - Set/Get uri, method
 * - Make body for POST/PUT Method
 * It supports other request options according to the HTTP protocol.
 * 
 * @if WEARABLE
 * @section CAPI_NETWORK_HTTP_REQUEST_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.internet\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 * @ endif
 *
 */

/**
 * @ingroup CAPI_NETWORK_HTTP_TRANSACTION_MODULE
 * @defgroup CAPI_NETWORK_HTTP_RESPONSE_MODULE  HTTP Response
 * @brief It manages HTTP response.
 *
 * @section CAPI_NETWORK_HTTP_RESPONSE_MODULE_HEADER  Required Header
 *   \#include <http.h>
 *
 * @section CAPI_NETWORK_HTTP_RESPONSE_MODULE_OVERVIEW Overview
 * It manages HTTP response message.
 * - Get status code and reason phrase from response message
 * 
 * @if WEARABLE
 * @section CAPI_NETWORK_HTTP_RESPONSE_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.internet \n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 * @ endif
 *
 */

/**
 * @ingroup CAPI_NETWORK_HTTP_TRANSACTION_MODULE
 * @defgroup CAPI_NETWORK_HTTP_HEADER_MODULE  HTTP Header
 * @brief It manages custom header
 *
 * @section CAPI_NETWORK_HTTP_HEADER_MODULE_HEADER  Required Header
 *   \#include <http.h>
 *
 * @section CAPI_NETWORK_HTTP_HEADER_MODULE_OVERVIEW Overview
 * It manages custom header
 * 
 * @if WEARABLE
 * @section CAPI_NETWORK_HTTP_HEADER_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.internet \n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 * @ endif
 *
 */

#endif /* __TIZEN_NETWORK_HTTP_DOC_H__ */
