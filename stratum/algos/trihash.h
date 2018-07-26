#ifndef TRIHASH_H
#define TRIHASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void trihash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
