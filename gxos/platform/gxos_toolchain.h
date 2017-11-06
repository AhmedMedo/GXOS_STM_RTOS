
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
#ifndef gxos_TOOLCHAIN_H
#define gxos_TOOLCHAIN_H

#include "gxos_preprocessor.h"


// Warning for unsupported compilers
#if !defined(__GNUC__)   /* GCC        */ \
 && !defined(__CC_ARM)   /* ARMCC      */ \
 && !defined(__clang__)  /* LLVM/Clang */ \
 && !defined(__ICCARM__) /* IAR        */
#warning "This compiler is not yet supported."
#endif


// Attributes

/** gxos_PACKED
 *  Pack a structure, preventing any padding from being added between fields.
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *
 *  gxos_PACKED(struct) foo {
 *      char x;
 *      int y;
 *  };
 *  @endcode
 */
#ifndef gxos_PACKED
#if defined(__ICCARM__)
#define gxos_PACKED(struct) __packed struct
#else
#define gxos_PACKED(struct) struct __attribute__((packed))
#endif
#endif

/** gxos_ALIGN(N)
 *  Declare a variable to be aligned on an N-byte boundary.
 *
 *  @note
 *  IAR does not support alignment greater than word size on the stack
 *  
 *  @code
 *  #include "gxos_toolchain.h"
 *
 *  gxos_ALIGN(16) char a;
 *  @endcode
 */
#ifndef gxos_ALIGN
#if defined(__ICCARM__)
#define gxos_ALIGN(N) _Pragma(gxos_STRINGIFY(data_alignment=N))
#else
#define gxos_ALIGN(N) __attribute__((aligned(N)))
#endif
#endif

/** gxos_UNUSED
 *  Declare a function argument to be unused, suppressing compiler warnings
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *
 *  void foo(gxos_UNUSED int arg) {
 *
 *  }
 *  @endcode
 */
#ifndef gxos_UNUSED
#if defined(__GNUC__) || defined(__clang__) || defined(__CC_ARM)
#define gxos_UNUSED __attribute__((__unused__))
#else
#define gxos_UNUSED
#endif
#endif

/** gxos_WEAK
 *  Mark a function as being weak.
 *  
 *  @note
 *  weak functions are not friendly to making code re-usable, as they can only
 *  be overridden once (and if they are multiply overridden the linker will emit
 *  no warning). You should not normally use weak symbols as part of the API to
 *  re-usable modules.
 *  
 *  @code
 *  #include "gxos_toolchain.h"
 *  
 *  gxos_WEAK void foo() {
 *      // a weak implementation of foo that can be overriden by a definition
 *      // without  __weak
 *  }
 *  @endcode
 */
#ifndef gxos_WEAK
#if defined(__ICCARM__)
#define gxos_WEAK __weak
#else
#define gxos_WEAK __attribute__((weak))
#endif
#endif

/** gxos_PURE
 *  Hint to the compiler that a function depends only on parameters
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *
 *  gxos_PURE int foo(int arg){
 *      // no access to global variables
 *  }
 *  @endcode
 */
#ifndef gxos_PURE
#if defined(__GNUC__) || defined(__clang__) || defined(__CC_ARM)
#define gxos_PURE __attribute__((const))
#else
#define gxos_PURE
#endif
#endif

/** gxos_NOINLINE
 *  Declare a function that must not be inlined.
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *  
 *  gxos_NOINLINE void foo() {
 *  
 *  }
 *  @endcode
 */
#ifndef gxos_NOINLINE
#if defined(__GNUC__) || defined(__clang__) || defined(__CC_ARM)
#define gxos_NOINLINE __attribute__((noinline))
#elif defined(__ICCARM__)
#define gxos_NOINLINE _Pragma("inline=never")
#else
#define gxos_NOINLINE
#endif
#endif

/** gxos_FORCEINLINE
 *  Declare a function that must always be inlined. Failure to inline
 *  such a function will result in an error.
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *  
 *  gxos_FORCEINLINE void foo() {
 *  
 *  }
 *  @endcode
 */
#ifndef gxos_FORCEINLINE
#if defined(__GNUC__) || defined(__clang__) || defined(__CC_ARM)
#define gxos_FORCEINLINE static inline __attribute__((always_inline))
#elif defined(__ICCARM__)
#define gxos_FORCEINLINE _Pragma("inline=forced") static
#else
#define gxos_FORCEINLINE static inline
#endif
#endif

/** gxos_NORETURN
 *  Declare a function that will never return.
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *  
 *  gxos_NORETURN void foo() {
 *      // must never return
 *      while (1) {}
 *  }
 *  @endcode
 */
#ifndef gxos_NORETURN
#if defined(__GNUC__) || defined(__clang__) || defined(__CC_ARM)
#define gxos_NORETURN __attribute__((noreturn))
#elif defined(__ICCARM__)
#define gxos_NORETURN __noreturn
#else
#define gxos_NORETURN
#endif
#endif

/** gxos_UNREACHABLE
 *  An unreachable statement. If the statement is reached,
 *  behaviour is undefined. Useful in situations where the compiler
 *  cannot deduce the unreachability of code.
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *
 *  void foo(int arg) {
 *      switch (arg) {
 *          case 1: return 1;
 *          case 2: return 2;
 *          ...
 *      }
 *      gxos_UNREACHABLE;
 *  }
 *  @endcode
 */
#ifndef gxos_UNREACHABLE
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__CC_ARM)
#define gxos_UNREACHABLE __builtin_unreachable()
#else
#define gxos_UNREACHABLE while (1)
#endif
#endif

/** gxos_DEPRECATED("message string")
 *  Mark a function declaration as deprecated, if it used then a warning will be
 *  issued by the compiler possibly including the provided message. Note that not
 *  all compilers are able to display the message.
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *  
 *  gxos_DEPRECATED("don't foo any more, bar instead")
 *  void foo(int arg);
 *  @endcode
 */
#ifndef gxos_DEPRECATED
#if defined(__CC_ARM)
#define gxos_DEPRECATED(M) __attribute__((deprecated))
#elif defined(__GNUC__) || defined(__clang__)
#define gxos_DEPRECATED(M) __attribute__((deprecated(M)))
#else
#define gxos_DEPRECATED(M)
#endif
#endif

/** gxos_DEPRECATED_SINCE("version", "message string")
 *  Mark a function declaration as deprecated, noting that the declaration was
 *  deprecated on the specified version. If the function is used then a warning
 *  will be issued by the compiler possibly including the provided message.
 *  Note that not all compilers are able to display this message.
 *
 *  @code
 *  #include "gxos_toolchain.h"
 *
 *  gxos_DEPRECATED_SINCE("gxos-os-5.1", "don't foo any more, bar instead")
 *  void foo(int arg);
 *  @endcode
 */
#define gxos_DEPRECATED_SINCE(D, M) gxos_DEPRECATED(M " [since " D "]")

/** gxos_CALLER_ADDR()
 * Returns the caller of the current function.
 *
 * @note
 * This macro is only implemented for GCC and ARMCC.
 *
 * @code
 * #include "gxos_toolchain.h"
 *
 * printf("This function was called from %p", gxos_CALLER_ADDR());
 * @endcode
 *
 * @return Address of the calling function
 */
#ifndef gxos_CALLER_ADDR
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__CC_ARM)
#define gxos_CALLER_ADDR() __builtin_extract_return_addr(__builtin_return_address(0))
#elif defined(__CC_ARM)
#define gxos_CALLER_ADDR() __builtin_return_address(0)
#else
#define gxos_CALLER_ADDR() (NULL)
#endif
#endif

#ifndef gxos_SECTION
#if (defined(__GNUC__) || defined(__clang__)) || defined(__CC_ARM)
#define gxos_SECTION(name) __attribute__ ((section (name)))
#elif defined(__ICCARM__)
#define gxos_SECTION(name) _Pragma(gxos_STRINGIFY(location=name))
#else
#error "Missing gxos_SECTION directive"
#endif
#endif

#ifndef gxos_PRINTF
#if defined(__GNUC__) || defined(__CC_ARM)
#define gxos_PRINTF(format_idx, first_param_idx) __attribute__ ((__format__(__printf__, format_idx, first_param_idx)))
#else
#define gxos_PRINTF(format_idx, first_param_idx)
#endif
#endif

#ifndef gxos_PRINTF_METHOD
#if defined(__GNUC__) || defined(__CC_ARM)
#define gxos_PRINTF_METHOD(format_idx, first_param_idx) __attribute__ ((__format__(__printf__, format_idx+1, first_param_idx+1)))
#else
#define gxos_PRINTF_METHOD(format_idx, first_param_idx)
#endif
#endif

#ifndef gxos_SCANF
#if defined(__GNUC__) || defined(__CC_ARM)
#define gxos_SCANF(format_idx, first_param_idx) __attribute__ ((__format__(__scanf__, format_idx, first_param_idx)))
#else
#define gxos_SCANF(format_idx, first_param_idx)
#endif
#endif

#ifndef gxos_SCANF_METHOD
#if defined(__GNUC__) || defined(__CC_ARM)
#define gxos_SCANF_METHOD(format_idx, first_param_idx) __attribute__ ((__format__(__scanf__, format_idx+1, first_param_idx+1)))
#else
#define gxos_SCANF_METHOD(format_idx, first_param_idx)
#endif
#endif

// FILEHANDLE declaration
#if defined(TOOLCHAIN_ARM)
#include <rt_sys.h>
#endif

#ifndef FILEHANDLE
typedef int FILEHANDLE;
#endif

// Backwards compatibility
#ifndef WEAK
#define WEAK gxos_WEAK
#endif

#ifndef PACKED
#define PACKED gxos_PACKED()
#endif

#ifndef EXTERN
#define EXTERN extern
#endif

#endif

/** @}*/
