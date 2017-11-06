/** \addtogroup platform */
/** @{*/
/* gxos Microcontroller Library
 * Copyright (c) 2006-2013 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef gxos_PREPROCESSOR_H
#define gxos_PREPROCESSOR_H


/** gxos_CONCAT
 *  Concatenate tokens together
 *
 *  @note
 *  Expands tokens before concatenation
 *
 *  @code
 *  // Creates a unique label based on the line number
 *  int gxos_CONCAT(UNIQUE_LABEL_, __LINE__) = 1;
 *  @endcode
 */
#define gxos_CONCAT(a, b) gxos_CONCAT_(a, b)
#define gxos_CONCAT_(a, b) a##b

/** gxos_STRINGIFY
 *  Converts tokens into strings
 *
 *  @note
 *  Expands tokens before stringification
 *
 *  @code
 *  // Creates a string based on the parameters
 *  const char *c = gxos_STRINGIFY(This is a ridiculous way to create a string)
 *  @endcode
 */
#define gxos_STRINGIFY(a) gxos_STRINGIFY_(a)
#define gxos_STRINGIFY_(a) #a


#endif

/** @}*/
