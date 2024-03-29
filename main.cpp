#include "gxos.h"
#include "rtos.h"
#include "SWO.h"
Serial pc(SERIAL_TX, SERIAL_RX);
SWO_Channel swo("channel");

void print_char(char c = '*')
{
    swo.printf("%c", c);
    fflush(stdout);
}

DigitalOut led1(LED1);

void print_thread(void const *argument)
{
    while (true) {
        Thread::wait(1000);
        print_char();
    }
}

int main()
{
    swo.printf("\n\n*** RTOS basic example ***\n");
    Thread thread(print_thread, NULL, osPriorityNormal, DEFAULT_STACK_SIZE);
    while (true) {
        led1 = !led1;
        Thread::wait(500);
    }
}
