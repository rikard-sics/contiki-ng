#pragma once

#include "uipopt.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#if UIP_BYTE_ORDER != UIP_LITTLE_ENDIAN
#error "Compiler byte order differs from UIP byte order"
#endif

#ifndef htobe16
#define htobe16(x) __builtin_bswap16(x)
#endif
#ifndef htole16
#define htole16(x) (uint16_t)(x)
#endif
#ifndef be16toh
#define be16toh(x) __builtin_bswap16(x)
#endif
#ifndef le16toh
#define le16toh(x) (uint16_t)(x)
#endif

#ifndef htobe32
#define htobe32(x) __builtin_bswap32(x)
#endif
#ifndef htole32
#define htole32(x) (uint32_t)(x)
#endif
#ifndef be32toh
#define be32toh(x) __builtin_bswap32(x)
#endif
#ifndef le32toh
#define le32toh(x) (uint32_t)(x)
#endif

#ifndef htobe64
#define htobe64(x) __builtin_bswap64(x)
#endif
#ifndef htole64
#define htole64(x) (uint64_t)(x)
#endif
#ifndef be64toh
#define be64toh(x) __builtin_bswap64(x)
#endif
#ifndef le64toh
#define le64toh(x) (uint64_t)(x)
#endif

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#if UIP_BYTE_ORDER == UIP_LITTLE_ENDIAN
#error "Compiler byte order differs from UIP byte order"
#endif

#ifndef htobe16
#define htobe16(x) (uint16_t)(x)
#endif
#ifndef htole16
#define htole16(x) __builtin_bswap16(x)
#endif
#ifndef be16toh
#define be16toh(x) (uint16_t)(x)
#endif
#ifndef le16toh
#define le16toh(x) __builtin_bswap16(x)
#endif

#ifndef htobe32
#define htobe32(x) (uint32_t)(x)
#endif
#ifndef htole32
#define htole32(x) __builtin_bswap32(x)
#endif
#ifndef be32toh
#define be32toh(x) (uint32_t)(x)
#endif
#ifndef le32toh
#define le32toh(x) __builtin_bswap32(x)
#endif

#ifndef htobe64
#define htobe64(x) (uint64_t)(x)
#endif
#ifndef htole64
#define htole64(x) __builtin_bswap64(x)
#endif
#ifndef be64toh
#define be64toh(x) (uint64_t)(x)
#endif
#ifndef le64toh
#define le64toh(x) __builtin_bswap64(x)
#endif

#else
#error "Unknown byte order"
#endif

/* BSD Names */

#ifndef betoh16
#define betoh16(x) be16toh(x)
#endif
#ifndef betoh32
#define betoh32(x) be32toh(x)
#endif
#ifndef betoh64
#define betoh64(x) be64toh(x)
#endif
#ifndef letoh16
#define letoh16(x) le16toh(x)
#endif
#ifndef letoh32
#define letoh32(x) le32toh(x)
#endif
#ifndef letoh64
#define letoh64(x) le64toh(x)
#endif
