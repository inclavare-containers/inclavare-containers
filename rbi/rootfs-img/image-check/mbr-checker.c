#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define MBR_LENGTH 512
#define SIG_OFFSET 0x1b8
#define SIG_LENGTH 0x4

const char MBR_RECORD[MBR_LENGTH] = {\
0xfa, 0xb8, 0x00, 0x10, 0x8e, 0xd0, 0xbc, 0x00, 0xb0, 0xb8, 0x00, 0x00, 0x8e, 0xd8, 0x8e, 0xc0, \
0xfb, 0xbe, 0x00, 0x7c, 0xbf, 0x00, 0x06, 0xb9, 0x00, 0x02, 0xf3, 0xa4, 0xea, 0x21, 0x06, 0x00, \
0x00, 0xbe, 0xbe, 0x07, 0x38, 0x04, 0x75, 0x0b, 0x83, 0xc6, 0x10, 0x81, 0xfe, 0xfe, 0x07, 0x75, \
0xf3, 0xeb, 0x16, 0xb4, 0x02, 0xb0, 0x01, 0xbb, 0x00, 0x7c, 0xb2, 0x80, 0x8a, 0x74, 0x01, 0x8b, \
0x4c, 0x02, 0xcd, 0x13, 0xea, 0x00, 0x7c, 0x00, 0x00, 0xeb, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8f, 0xc1, 0x15, 0x75, 0x00, 0x00, 0x00, 0x00, \
0x01, 0x30, 0x83, 0x03, 0xe0, 0xff, 0x00, 0x18, 0x00, 0x00, 0x00, 0xe0, 0x0b, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xaa};

void usage() {
    perror("Must have 1 parameter: \n\
    -   image file.\n");
}

int main(int argc, char** argv) {
    if(argc != 2) {
        usage();
        return -1;
    }

    char* filename = argv[1];
    int fd = open(filename, O_RDONLY);
    if(fd == -1) {
        perror("open ");
        return -1;
    }

    char mbr_read[MBR_LENGTH] = {0};
    int res = read(fd, &mbr_read, 512);
    if(res == -1) {
        perror("read ");
        return -1;
    }

    for(int i = 0 ; i < 512; i++) {
        //printf("%c ", mbr_read[i]);
    }

    for(int i = 0 ; i < SIG_OFFSET; i++) {
        if(mbr_read[i] == MBR_RECORD[i])
            continue; 
        printf("Mbr Unmatched.\n");
        printf("addr %.2x: read %.2x, need %.2x\n", i, mbr_read[i], MBR_RECORD[i]);
        return -1;
    }

    for(int i = SIG_OFFSET + SIG_LENGTH ; i < MBR_LENGTH; i++) {
        if(mbr_read[i] == MBR_RECORD[i])
            continue; 
        printf("Mbr Unmatched.\n");
        printf("addr %.2x: read %.2x, need %.2x\n", i, mbr_read[i], MBR_RECORD[i]);
        return -1;
    }

    printf("Mbr matched.\n");
    return 0;
}