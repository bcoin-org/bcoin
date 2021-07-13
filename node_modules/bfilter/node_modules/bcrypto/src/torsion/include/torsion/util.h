#ifndef _TORSION_UTIL_H
#define _TORSION_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Symbol Aliases
 */

#define cleanse torsion_cleanse

/*
 * Util
 */

void
cleanse(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _TORSION_UTIL_H */
