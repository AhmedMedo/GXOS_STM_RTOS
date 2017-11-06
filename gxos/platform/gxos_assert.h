
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
#ifndef gxos_ASSERT_H
#define gxos_ASSERT_H

#include "gxos_preprocessor.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Internal gxos assert function which is invoked when gxos_ASSERT macro failes.
 *  This function is active only if NDEBUG is not defined prior to including this
 *  assert header file.
 *  In case of gxos_ASSERT failing condition, error() is called with the assertation message.
 *  @param expr Expresion to be checked.
 *  @param file File where assertation failed.
 *  @param line Failing assertation line number.
 */
void gxos_assert_internal(const char *expr, const char *file, int line);

#ifdef __cplusplus
}
#endif

#ifdef NDEBUG
#define gxos_ASSERT(expr) ((void)0)

#else
#define gxos_ASSERT(expr)                                \
do {                                                     \
    if (!(expr)) {                                       \
        gxos_assert_internal(#expr, __FILE__, __LINE__); \
    }                                                    \
} while (0)
#endif


/** gxos_STATIC_ASSERT
 *  Declare compile-time assertions, results in compile-time error if condition is false
 *
 *  The assertion acts as a declaration that can be placed at file scope, in a
 *  code block (except after a label), or as a member of a C++ class/struct/union.
 *
 *  @note
 *  Use of gxos_STATIC_ASSERT as a member of a struct/union is limited:
 *  - In C++, gxos_STATIC_ASSERT is valid in class/struct/union scope.
 *  - In C, gxos_STATIC_ASSERT is not valid in struct/union scope, and
 *    gxos_STRUCT_STATIC_ASSERT is provided as an alternative that is valid
 *    in C and C++ class/struct/union scope.
 *
 *  @code
 *  gxos_STATIC_ASSERT(gxos_LIBRARY_VERSION >= 120,
 *          "The gxos library must be at least version 120");
 *
 *  int main() {
 *      gxos_STATIC_ASSERT(sizeof(int) >= sizeof(char),
 *              "An int must be larger than a char");
 *  }
 *  @endcode
 */
#if defined(__cplusplus) && (__cplusplus >= 201103L || __cpp_static_assert >= 200410L)
#define gxos_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#elif !defined(__cplusplus) && __STDC_VERSION__ >= 201112L
#define gxos_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)
#elif defined(__cplusplus) && defined(__GNUC__) && defined(__GXX_EXPERIMENTAL_CXX0X__) \
    && (__GNUC__*100 + __GNUC_MINOR__) > 403L
#define gxos_STATIC_ASSERT(expr, msg) __extension__ static_assert(expr, msg)
#elif !defined(__cplusplus) && defined(__GNUC__) && !defined(__CC_ARM) \
    && (__GNUC__*100 + __GNUC_MINOR__) > 406L
#define gxos_STATIC_ASSERT(expr, msg) __extension__ _Static_assert(expr, msg)
#elif defined(__ICCARM__)
#define gxos_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#else
#define gxos_STATIC_ASSERT(expr, msg) \
    enum {gxos_CONCAT(gxos_ASSERTION_AT_, __LINE__) = sizeof(char[(expr) ? 1 : -1])}
#endif

/** gxos_STRUCT_STATIC_ASSERT
 *  Declare compile-time assertions, results in compile-time error if condition is false
 *
 *  Unlike gxos_STATIC_ASSERT, gxos_STRUCT_STATIC_ASSERT can and must be used
 *  as a member of a C/C++ class/struct/union.
 *
 *  @code
 *  struct thing {
 *      gxos_STATIC_ASSERT(2 + 2 == 4,
 *              "Hopefully the universe is mathematically consistent");
 *  };
 *  @endcode
 */
#define gxos_STRUCT_STATIC_ASSERT(expr, msg) int : (expr) ? 0 : -1


#endif

/** @}*/
