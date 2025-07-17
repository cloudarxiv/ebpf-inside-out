#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// This is a simple program that prints "Hello Superman" every second

int main() {
    printf("Pid: %d\n", getpid());
    while (1) {
        printf("I am Superman\n");
        sleep(1); // Sleep for 1 second to avoid flooding the output
    }
    return 0;
}