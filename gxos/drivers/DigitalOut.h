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
#ifndef gxos_DIGITALOUT_H
#define gxos_DIGITALOUT_H

#include "platform/platform.h"
#include "hal/gpio_api.h"
#include "platform/gxos_critical.h"

namespace gxos {
/** \addtogroup drivers */

/** A digital output, used for setting the state of a pin
 *
 * @note Synchronization level: Interrupt safe
 *
 * Example:
 * @code
 * // Toggle a LED
 * #include "gxos.h"
 *
 * DigitalOut led(LED1);
 *
 * int main() {
 *     while(1) {
 *         led = !led;
 *         wait(0.2);
 *     }
 * }
 * @endcode
 * @ingroup drivers
 */
class DigitalOut {

public:
    /** Create a DigitalOut connected to the specified pin
     *
     *  @param pin DigitalOut pin to connect to
     */
    DigitalOut(PinName pin) : gpio() {
        // No lock needed in the constructor
        gpio_init_out(&gpio, pin);
    }

    /** Create a DigitalOut connected to the specified pin
     *
     *  @param pin DigitalOut pin to connect to
     *  @param value the initial pin value
     */
    DigitalOut(PinName pin, int value) : gpio() {
        // No lock needed in the constructor
        gpio_init_out_ex(&gpio, pin, value);
    }

    /** Set the output, specified as 0 or 1 (int)
     *
     *  @param value An integer specifying the pin output value,
     *      0 for logical 0, 1 (or any other non-zero value) for logical 1
     */
    void write(int value) {
        // Thread safe / atomic HAL call
        gpio_write(&gpio, value);
    }

    /** Return the output setting, represented as 0 or 1 (int)
     *
     *  @returns
     *    an integer representing the output setting of the pin,
     *    0 for logical 0, 1 for logical 1
     */
    int read() {
        // Thread safe / atomic HAL call
        return gpio_read(&gpio);
    }

    /** Return the output setting, represented as 0 or 1 (int)
     *
     *  @returns
     *    Non zero value if pin is connected to uc GPIO
     *    0 if gpio object was initialized with NC
     */
    int is_connected() {
        // Thread safe / atomic HAL call
        return gpio_is_connected(&gpio);
    }

    /** A shorthand for write()
     * \sa DigitalOut::write()
     */
    DigitalOut& operator= (int value) {
        // Underlying write is thread safe
        write(value);
        return *this;
    }

    /** A shorthand for write()
     * \sa DigitalOut::write()
     */
    DigitalOut& operator= (DigitalOut& rhs) {
        core_util_critical_section_enter();
        write(rhs.read());
        core_util_critical_section_exit();
        return *this;
    }

    /** A shorthand for read()
     * \sa DigitalOut::read()
     */
    operator int() {
        // Underlying call is thread safe
        return read();
    }

protected:
    gpio_t gpio;
};

} // namespace gxos

#endif
