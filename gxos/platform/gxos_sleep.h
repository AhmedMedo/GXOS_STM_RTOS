
/** \addtogroup platform */
/** @{*/
/* gxos Microcontroller Library
 * Copyright (c) 2006-2017 ARM Limited
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
#ifndef gxos_SLEEP_H
#define gxos_SLEEP_H

#include "sleep_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Send the microcontroller to sleep
 *
 * @note This function can be a noop if not implemented by the platform.
 * @note This function will be a noop in debug mode (debug build profile when gxos_DEBUG is defined).
 * @note This function will be a noop while uVisor is in use.
 *
 * The processor is setup ready for sleep, and sent to sleep using __WFI(). In this mode, the
 * system clock to the core is stopped until a reset or an interrupt occurs. This eliminates
 * dynamic power used by the processor, memory systems and buses. The processor, peripheral and
 * memory state are maintained, and the peripherals continue to work and can generate interrupts.
 *
 * The processor can be woken up by any internal peripheral interrupt or external pin interrupt.
 *
 * @note
 *  The gxos interface semihosting is disconnected as part of going to sleep, and can not be restored.
 * Flash re-programming and the USB serial port will remain active, but the gxos program will no longer be
 * able to access the LocalFileSystem
 */
__INLINE static void sleep(void)
{
#if !(defined(FEATURE_UVISOR) && defined(TARGET_UVISOR_SUPPORTED))
#ifndef gxos_DEBUG
#if DEVICE_SLEEP
    hal_sleep();
#endif /* DEVICE_SLEEP */
#endif /* gxos_DEBUG */
#endif /* !(defined(FEATURE_UVISOR) && defined(TARGET_UVISOR_SUPPORTED)) */
}

/** Send the microcontroller to deep sleep
 *
 * @note This function can be a noop if not implemented by the platform.
 * @note This function will be a noop in debug mode (debug build profile when gxos_DEBUG is defined)
 * @note This function will be a noop while uVisor is in use.
 *
 * This processor is setup ready for deep sleep, and sent to sleep using __WFI(). This mode
 * has the same sleep features as sleep plus it powers down peripherals and clocks. All state
 * is still maintained.
 *
 * The processor can only be woken up by an external interrupt on a pin or a watchdog timer.
 *
 * @note
 *  The gxos interface semihosting is disconnected as part of going to sleep, and can not be restored.
 * Flash re-programming and the USB serial port will remain active, but the gxos program will no longer be
 * able to access the LocalFileSystem
 */
__INLINE static void deepsleep(void)
{
#if !(defined(FEATURE_UVISOR) && defined(TARGET_UVISOR_SUPPORTED))
#ifndef gxos_DEBUG
#if DEVICE_SLEEP
    hal_deepsleep();
#endif /* DEVICE_SLEEP */
#endif /* gxos_DEBUG */
#endif /* !(defined(FEATURE_UVISOR) && defined(TARGET_UVISOR_SUPPORTED)) */
}

#ifdef __cplusplus
}
#endif

#endif

/** @}*/
