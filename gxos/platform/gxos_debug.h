
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
#ifndef gxos_DEBUG_H
#define gxos_DEBUG_H
#if DEVICE_STDIO_MESSAGES
#include <stdio.h>
#include <stdarg.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


/** Output a debug message
 *
 * @param format printf-style format string, followed by variables
 */
static inline void debug(const char *format, ...) {
#if DEVICE_STDIO_MESSAGES && !defined(NDEBUG)
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
#endif
}


/** Conditionally output a debug message
 *
 * NOTE: If the condition is constant false (== 0) and the compiler optimization
 * level is greater than 0, then the whole function will be compiled away.
 *
 * @param condition output only if condition is true (!= 0)
 * @param format printf-style format string, followed by variables
 */
static inline void debug_if(int condition, const char *format, ...) {
#if DEVICE_STDIO_MESSAGES && !defined(NDEBUG)
    if (condition) {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
    }
#endif
}


#ifdef __cplusplus
}
#endif

#endif

/** @}*/
