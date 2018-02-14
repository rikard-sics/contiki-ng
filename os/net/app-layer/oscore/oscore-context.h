#ifndef _OSCORE_CONTEXT_H
#define _OSCORE_CONTEXT_H

void oscore_ctx_store_init();
	
static uint8_t compose_info(uint8_t* buffer, uint8_t alg, uint8_t* id, uint8_t id_len, uint8_t out_len);

oscore_ctx_t* oscore_derrive_ctx(uint8_t* master_secret, uint8_t master_secret_len, uint8_t* master_salt, uint8_t master_salt_len, uint8_t alg, uint8_t hkdf_alg,
       	uint8_t* sid, uint8_t sid_len, uint8_t* rid, uint8_t rid_len, uint8_t replay_window);
	
int oscore_free_ctx(oscore_ctx_t *ctx);
	
oscore_ctx_t* oscore_find_ctx_by_rid(uint8_t* rid, uint8_t rid_len);
oscore_ctx_t* oscore_find_ctx_by_token(uint8_t* token, uint8_t token_len);

/* Token <=> SEQ association */
void init_token_seq_store();
uint8_t get_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t* seq);
uint8_t set_seq_from_token(uint8_t* token, uint8_t token_len, uint32_t seq);
void remove_seq_from_token(uint8_t* token, uint8_t token_len);

/* URI <=> RID association */
void oscore_init_uri_rid_store();
uint8_t oscore_set_uri_rid_association(uint8_t *rid, uint8_t rid_len, uint8_t *uri, uint8_t uri_len);
oscore_ctx_t* oscore_get_context_from_uri(uint8_t *uri, uint8_t uri_len);
	
#endif /* _OSCORE_CONTEXT_H */
