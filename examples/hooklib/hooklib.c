#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor))
void init(void) {
    FILE *fp = fopen("/tmp/go-ptrace-hook.log", "a");
    if (!fp) {
        return;
    }
    fprintf(fp, "[hooklib] constructor called at pid %d\n", getpid());
    fclose(fp);
}

__attribute__((destructor))
void fini(void) {
    FILE *fp = fopen("/tmp/go-ptrace-hook.log", "a");
    if (!fp) {
        return;
    }
    fprintf(fp, "[hooklib] destructor called at pid %d\n", getpid());
    fclose(fp);
}
