#ifndef _OSCORE_CONTEXT_H
#define _OSCORE_CONTEXT_H

#include <inttypes.h>
#include "coap-constants.h"
#include "coap-endpoint.h"

#define CONTEXT_KEY_LEN 16
#define CONTEXT_INIT_VECT_LEN 13
#define CONTEXT_SEQ_LEN sizeof(uint32_t)

#define OSCORE_SEQ_MAX (((uint64_t)1 << 40) - 1)

typedef struct oscore_sender_ctx_t oscore_sender_ctx_t;
typedef struct oscore_recipient_ctx_t oscore_recipient_ctx_t;
typedef struct oscore_ctx_t oscore_ctx_t;
typedef struct token_seq_t token_seq_t;
typedef struct ep_ctx_t ep_ctx_t;

struct oscore_sender_ctx_t {
  uint8_t sender_key[CONTEXT_KEY_LEN];
  uint8_t token[COAP_TOKEN_LEN];
  uint32_t seq;
  uint8_t *sender_id;
  uint8_t sender_id_len;
  uint8_t token_len;
};

struct oscore_recipient_ctx_t {
  uint32_t last_seq;
  uint32_t highest_seq;
  uint32_t sliding_window;
  uint32_t rollback_sliding_window;
  uint32_t rollback_last_seq;
  oscore_recipient_ctx_t *recipient_context; /* This field facilitates easy integration of OSCOAP multicast */
  uint8_t recipient_key[CONTEXT_KEY_LEN];
  uint8_t *recipient_id;
  uint8_t recipient_id_len;
  uint8_t replay_window_size;
  uint8_t initial_state;
};

struct oscore_ctx_t {
  /* uint8_t   ContextId[CONTEXT_ID_LEN]; */
  uint8_t *master_secret;
  uint8_t *master_salt;
  uint8_t common_iv[CONTEXT_INIT_VECT_LEN];
  oscore_sender_ctx_t *sender_context;
  oscore_recipient_ctx_t *recipient_context;
  oscore_ctx_t *next_context;
  uint8_t master_secret_len;
  uint8_t master_salt_len;
  uint8_t alg;
};

struct token_seq_t {
  uint8_t token[8];
  uint8_t token_len;
  uint32_t seq;
  token_seq_t *next;
};

struct ep_ctx_t {
  coap_endpoint_t *ep;
  oscore_ctx_t *ctx;
  ep_ctx_t *next;
};
void oscore_ctx_store_init();

oscore_ctx_t *oscore_derrive_ctx(uint8_t *master_secret, uint8_t master_secret_len, uint8_t *master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t hkdf_alg,
                                 uint8_t *sid, uint8_t sid_len, uint8_t *rid, uint8_t rid_len, uint8_t replay_window);

int oscore_free_ctx(oscore_ctx_t *ctx);

oscore_ctx_t *oscore_find_ctx_by_rid(uint8_t *rid, uint8_t rid_len);
oscore_ctx_t *oscore_find_ctx_by_token(uint8_t *token, uint8_t token_len);

/* Token <=> SEQ association */
void oscore_token_seq_store_init();
uint8_t get_seq_from_token(uint8_t *token, uint8_t token_len, uint32_t *seq);
uint8_t set_seq_from_token(uint8_t *token, uint8_t token_len, uint32_t seq);
void remove_seq_from_token(uint8_t *token, uint8_t token_len);

/* URI <=> CTX association */
void oscore_ep_ctx_store_init();
uint8_t oscore_ep_ctx_set_association(coap_endpoint_t *ep, oscore_ctx_t *ctx);
oscore_ctx_t *oscore_get_context_from_ep(coap_endpoint_t *ep);

#endif /* _OSCORE_CONTEXT_H */
