
/** \addtogroup hal */
/** @{*/
/* gxos Microcontroller Library
 * Copyright (c) 2014-2015 ARM Limited
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
#ifndef gxos_BUFFER_H
#define gxos_BUFFER_H

#include <stddef.h>

/** Generic buffer structure
 */
typedef struct buffer_s {
    void    *buffer; /**< the pointer to a buffer */
    size_t   length; /**< the buffer length */
    size_t   pos;    /**< actual buffer position */
    uint8_t  width;  /**< The buffer unit width (8, 16, 32, 64), used for proper *buffer casting */
} buffer_t;

#endif

/** @}*/
