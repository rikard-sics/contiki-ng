//TODO add copyright statement

#include <stdio.h>

#include "contiki.h"
#include "contiki-net.h"
#include "contiki-lib.h"
#include "lib/assert.h"

#include "oscore-test-vectors.h"
#include "unit-test/unit-test.h"
#include "oscore.h" 
#include "oscore-context.h" 
#include "coap-endpoint.h"
#include "cose.h"

PROCESS(test_process, "6top protocol APIs test");
AUTOSTART_PROCESSES(&test_process);

static void
test_setup(void)
{
  oscore_init_client();
}

void t_printf_hex(uint8_t *hex, int len){
	for ( int i = 0; i < len; i++){
		printf("%02X ", hex[i]);
	}
	printf("\n");
}

UNIT_TEST_REGISTER(test_validate_sender_seq,
                   "validate_sender_seq()");
UNIT_TEST(test_validate_sender_seq)
{

  UNIT_TEST_BEGIN();
  cose_encrypt0_t cose[1];
  uint8_t seq_0[1] = { 0x00 };
  uint8_t seq_1[1] = { 0x01 };
  uint8_t seq_3[1] = { 0x03 };
  uint8_t seq_5[1] = { 0x05 };
  uint8_t seq_8[1] = { 0x08 };
  uint8_t seq_50[1] = { 0x32 };
  uint8_t seq_60[1] = { 0x3C };
  uint8_t seq_under_max[8] = { 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE }; /* ((1 << 40) - 2)*/
  uint8_t seq_max[8] = { 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; /* ((1 << 40) - 1)*/
  uint8_t seq_over_max[8] = { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 }; /* ((1 << 40)) */
  

  oscore_ctx_t *ctx  = oscore_derive_ctx(master_secret, master_secret_len, master_salt, master_salt_len, 10, sender_id, sender_id_len, recipient_id, recipient_id_len, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  UNIT_TEST_ASSERT(ctx != NULL);

  oscore_recipient_ctx_t *r_ctx = ctx->recipient_context;
  
  cose_encrypt0_set_partial_iv(cose, seq_0, sizeof(seq_0));  
   
  uint8_t ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Test seq 1. */
  cose_encrypt0_set_partial_iv(cose, seq_1, sizeof(seq_1));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Test seq 1 again (replay). */
  cose_encrypt0_set_partial_iv(cose, seq_1, sizeof(seq_1));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);

  
  /* Test seq 5, then seq 3. Test replay window. */
  cose_encrypt0_set_partial_iv(cose, seq_5, sizeof(seq_5));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_3, sizeof(seq_3));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Test seq 60, 50 (within replay window), then seq 8, outside replay window -> reject seq. */
  cose_encrypt0_set_partial_iv(cose, seq_60, sizeof(seq_60));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_50, sizeof(seq_50));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_8, sizeof(seq_8));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);

  cose_encrypt0_set_partial_iv(cose, seq_under_max, sizeof(seq_max));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  cose_encrypt0_set_partial_iv(cose, seq_max, sizeof(seq_max));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);
  
  cose_encrypt0_set_partial_iv(cose, seq_over_max, sizeof(seq_over_max));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret != 1);

  oscore_free_ctx(ctx);

  UNIT_TEST_END();
}

UNIT_TEST_REGISTER(test_rollback_seq,
                   "rollback_seq()");
UNIT_TEST(test_rollback_seq)
{

  UNIT_TEST_BEGIN();
  cose_encrypt0_t cose[1];
  uint8_t seq_0[1] = { 0x00 };
  uint8_t seq_1[1] = { 0x01 };
  uint8_t seq_2[1] = { 0x0F };
  uint8_t seq_3[1] = { 0x12 };

  oscore_ctx_t *ctx  = oscore_derive_ctx(master_secret, master_secret_len, master_salt, master_salt_len, 10, sender_id, sender_id_len, recipient_id, recipient_id_len, NULL, 0, OSCORE_DEFAULT_REPLAY_WINDOW);
  UNIT_TEST_ASSERT(ctx != NULL);

  oscore_recipient_ctx_t *r_ctx = ctx->recipient_context;
  
  /* Set seq 0. */
  cose_encrypt0_set_partial_iv(cose, seq_0, sizeof(seq_0));  
  uint8_t ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Set seq 1. */
  cose_encrypt0_set_partial_iv(cose, seq_1, sizeof(seq_1));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Set seq 2. */
  cose_encrypt0_set_partial_iv(cose, seq_2, sizeof(seq_2));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Save parameters to test after rollback. */
  uint32_t sliding_window = r_ctx->sliding_window; 
  uint64_t last_seq = r_ctx->last_seq;
  uint64_t highest_seq = r_ctx->highest_seq;

  /* Set seq 3. */
  cose_encrypt0_set_partial_iv(cose, seq_3, sizeof(seq_3));  
  ret = oscore_validate_sender_seq(r_ctx, cose);
  UNIT_TEST_ASSERT(ret == 1);

  /* Roll back seq. */
  oscore_roll_back_seq(r_ctx);
  UNIT_TEST_ASSERT(sliding_window == r_ctx->sliding_window); 
  UNIT_TEST_ASSERT( last_seq == r_ctx->last_seq);
  UNIT_TEST_ASSERT( highest_seq == r_ctx->highest_seq);

  UNIT_TEST_END();
}

PROCESS_THREAD(test_process, ev, data)
{

  PROCESS_BEGIN();
  test_setup();
  printf("Run unit-test\n");
  printf("---\n");
  UNIT_TEST_RUN(test_validate_sender_seq);
  UNIT_TEST_RUN(test_rollback_seq);
  printf("=check-me= DONE\n");
  PROCESS_END();
}


