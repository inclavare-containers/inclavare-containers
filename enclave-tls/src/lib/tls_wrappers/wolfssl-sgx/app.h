#include "sgx_urts.h"           /* Manages Enclave */
#include <sys/types.h>          /* for send/recv */
#include <sys/socket.h>         /* for send/recv */

#include "wolfssl_enclave_u.h"  /* contains untrusted wrapper functions used to call enclave functions */

extern void *memmem(void *start, unsigned int s_len, void *find, unsigned int f_len);
#define BENCH_RSA
#define ENCLAVE_FILENAME "wolfssl_enclave.signed.so"
enum BenchmarkBounds {
        /* these numbers are lower then default wolfSSL one to collect benchmark values faster for GUI */
        numBlocks = 10,         /* how many megs to test */
        ntimes = 30             /* how many itteration to run RSA decrypt/encrypt */
};
