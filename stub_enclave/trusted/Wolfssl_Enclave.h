#ifndef _BENCHMARK_ENCLAVE_H_
#define _BENCHMARK_ENCLAVE_H_

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
int sprintf(char* buf, const char *fmt, ...);
double current_time(void);

#if defined(__cplusplus)
}
#endif

#endif /* !_BENCHMARK_ENCLAVE_H_ */
