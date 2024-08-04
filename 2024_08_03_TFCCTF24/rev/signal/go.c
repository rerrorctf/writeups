#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#define NUM_WORKERS (16)

void* worker(void *arg) {
    time_t start = (time_t)arg;
    char cmd[512];
    sprintf(cmd, "./worker %ld %d", start, NUM_WORKERS);
    int rc = system(cmd);
    (void)rc;
    pthread_exit(0);
}

int main(int argc, char** argv) {
    pthread_t threads[NUM_WORKERS];

    time_t now = time(0);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_create(&threads[i], 0, worker, (void*)(now - i));
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(threads[i], 0);
    }

    return 0;
}