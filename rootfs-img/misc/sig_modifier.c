#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define SIG_LENGTH 4
#define SIG_OFFSET 440

const char SIGNATURE[SIG_LENGTH] = { 0x6d, 0xc8, 0x7c, 0x07 };

void usage() {
    printf("Please input 1 parameter to the image file.\n");
}

int main(int argc, char** argv) {
    if(argc != 2) {
        usage();
        return -1;
    }

    char* file = argv[1];
    int fd = open(file, O_WRONLY);
    if(fd == -1) {
        perror("open ");
        return -1;
    }

    int res = lseek(fd, SIG_OFFSET, SEEK_SET);
    if(res == -1) {
        perror("lseek ");
        return -1;
    }

    res = write(fd, SIGNATURE, SIG_LENGTH);
    if(res == -1) {
        perror("write ");
        return -1;
    }

    printf("Signature modified.\n");
    return 0;
}