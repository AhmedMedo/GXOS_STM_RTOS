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
#ifndef gxos_H
#define gxos_H

#define gxos_LIBRARY_VERSION 147

#if gxos_CONF_RTOS_PRESENT
// RTOS present, this is valid only for gxos OS 5
#define gxos_MAJOR_VERSION 5
#define gxos_MINOR_VERSION 5
#define gxos_PATCH_VERSION 3

#else
// gxos 2
#define gxos_MAJOR_VERSION 2
#define gxos_MINOR_VERSION 0
#define gxos_PATCH_VERSION gxos_LIBRARY_VERSION
#endif

#define gxos_ENCODE_VERSION(major, minor, patch) ((major)*10000 + (minor)*100 + (patch))
#define gxos_VERSION gxos_ENCODE_VERSION(gxos_MAJOR_VERSION, gxos_MINOR_VERSION, gxos_PATCH_VERSION)

#if gxos_CONF_RTOS_PRESENT
#include "rtos/rtos.h"
#endif

#if gxos_CONF_NSAPI_PRESENT
#include "netsocket/nsapi.h"
#include "netsocket/nsapi_ppp.h"
#endif

#if gxos_CONF_EVENTS_PRESENT
#include "events/gxos_events.h"
#endif

#if gxos_CONF_FILESYSTEM_PRESENT
#include "filesystem/gxos_filesystem.h"
#endif

#include "platform/gxos_toolchain.h"
#include "platform/platform.h"
#include "platform/gxos_application.h"

// Useful C libraries
#include <math.h>
#include <time.h>

// gxos Debug libraries
#include "platform/gxos_error.h"
#include "platform/gxos_interface.h"
#include "platform/gxos_assert.h"
#include "platform/gxos_debug.h"

// gxos Peripheral components
#include "drivers/DigitalIn.h"
#include "drivers/DigitalOut.h"
#include "drivers/DigitalInOut.h"
#include "drivers/BusIn.h"
#include "drivers/BusOut.h"
#include "drivers/BusInOut.h"
#include "drivers/PortIn.h"
#include "drivers/PortInOut.h"
#include "drivers/PortOut.h"
#include "drivers/AnalogIn.h"
#include "drivers/AnalogOut.h"
#include "drivers/PwmOut.h"
#include "drivers/Serial.h"
#include "drivers/SPI.h"
#include "drivers/SPISlave.h"
#include "drivers/I2C.h"
#include "drivers/I2CSlave.h"
#include "drivers/Ethernet.h"
#include "drivers/CAN.h"
#include "drivers/RawSerial.h"
#include "drivers/UARTSerial.h"
#include "drivers/FlashIAP.h"

// gxos Internal components
#include "drivers/Timer.h"
#include "drivers/Ticker.h"
#include "drivers/Timeout.h"
#include "drivers/LowPowerTimeout.h"
#include "drivers/LowPowerTicker.h"
#include "drivers/LowPowerTimer.h"
#include "platform/LocalFileSystem.h"
#include "drivers/InterruptIn.h"
#include "platform/gxos_wait_api.h"
#include "hal/sleep_api.h"
#include "platform/gxos_sleep.h"
#include "platform/gxos_rtc_time.h"
#include "platform/gxos_poll.h"
#include "platform/ATCmdParser.h"
#include "platform/FileSystemHandle.h"
#include "platform/FileHandle.h"
#include "platform/DirHandle.h"

// gxos Non-hardware components
#include "platform/Callback.h"
#include "platform/FunctionPointer.h"

using namespace gxos;
using namespace std;

#endif
