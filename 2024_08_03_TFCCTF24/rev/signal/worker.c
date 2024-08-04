#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

char const* alpha = "abcdef0123456789";

int main(int argc, char** argv) {
    char flag[32];
    time_t start = (time_t)atoi(argv[1]);
    int step = atoi(argv[2]);
    time_t now = start;

    printf("start: %ld step: %d\n", start, step);

    for ( ; ; ) {
        srand(now);
        for (int i = 0; i < 32; i++)
            flag[i] = alpha[rand() & 0xf];
        if (memcmp(flag, "b11e8", 5) == 0) {
            if (memcmp(&flag[10], "b27dc", 5) == 0) {
                printf("[%s]\n", flag);
                if (memcmp(&flag[10], "b27dcf82e70c4bad63a3eb", 22) == 0) {
                    printf("%s\n", flag); // TFCCTF{b11e807f65b27dcf82e70c4bad63a3eb}
                    break;
                }
            }
        }
        now -= step;
    }
    return 0;
}