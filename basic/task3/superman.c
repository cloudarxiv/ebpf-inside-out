/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <unistd.h>

int main() 
{
    printf("Pid: %d\n", getpid());
    while (1) {
        printf("I am Superman\n");
        sleep(1);
    }
    return 0;
}