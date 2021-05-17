#ifndef _BCRYPTO_BASE58_H
#define _BCRYPTO_BASE58_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

int
bcrypto_base58_encode(char **str, size_t *str_len,
                      const uint8_t *data, size_t data_len);

int
bcrypto_base58_decode(uint8_t **data, size_t *data_len,
                      const char *str, size_t str_len);

int
bcrypto_base58_test(const char *str, size_t str_len);

#ifdef __cplusplus
}
#endif

#endif
