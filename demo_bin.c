#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    long addr, size, *ptr;
    int choice;
    printf("libc stdout leak: %p\n", stdout);
    while(1)
    {
        puts("1. create buffer");
        puts("2. arbitrary write");
        puts("3. exit");
        printf("choice: ");
        scanf("%d", &choice);
        if(choice == 1)
        {
            ptr = malloc(0xe0);
            printf("new buffer at address: %p\n", ptr);
            printf("data: ");
            read(0, ptr, 0xe0);
        }
        else if(choice == 2)
        {
            printf("addr: ");
            scanf("%ld", &addr);
            printf("data: ");
            read(0, (long *)addr, 8);
        }
        else exit(0);
    }
}