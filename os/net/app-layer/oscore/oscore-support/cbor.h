#ifndef _CBOR_H
#define _CBOR_H
#include <stddef.h>
#include <inttypes.h>

int cbor_put_text(uint8_t **buffer, char *text, uint8_t text_len);

int cbor_put_array(uint8_t **buffer, uint8_t elements);

int cbor_put_bytes(uint8_t **buffer, uint8_t *bytes, uint8_t bytes_len);

int cbor_put_map(uint8_t **buffer, uint8_t elements);

int cbor_put_unsigned(uint8_t **buffer, uint8_t value);

#endif /* _cbor_H */
