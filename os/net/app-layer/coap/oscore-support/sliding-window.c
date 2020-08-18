#include "sliding-window.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "oscore"
#ifdef LOG_CONF_LEVEL_OSCORE
#define LOG_LEVEL LOG_CONF_LEVEL_OSCORE
#else
#define LOG_LEVEL LOG_LEVEL_WARN
#endif

bool oscore_sliding_window_init(oscore_sliding_window_t* w, uint8_t replay_window_size)
{
    if (replay_window_size > OSCORE_MAX_REPLAY_WINDOW_SIZE)
    {
        LOG_ERR("Invalid replay window size\n");
        return false;
    }

    w->largest_seq = -1;
    w->recent_seq = 0;
    w->replay_window_size = replay_window_size;
    w->rollback_largest_seq = 0;
    w->sliding_window = 0;
    w->rollback_sliding_window = -1;
    //w->initialized = false;

    return true;
}

void oscore_sliding_window_rollback(oscore_sliding_window_t* w)
{
    LOG_DBG("Rolling back seq (window %"PRIu32" = %"PRIi32") (seq %"PRIi64" = %"PRIi64")\n",
    w->sliding_window, w->rollback_sliding_window,
    w->largest_seq, w->rollback_largest_seq);

 // if(w->rollback_sliding_window != -1){
    w->sliding_window = w->rollback_sliding_window;
 //   w->rollback_sliding_window = -1;
//  }
  
 // if( w->rollback_largest_seq !=  -1) {
    w->largest_seq = w->rollback_largest_seq;
//    w->rollback_largest_seq = -1;
//  }
}

bool oscore_sliding_window_validate(oscore_sliding_window_t* w, uint64_t incoming_seq)
{
  LOG_DBG("incoming SEQ %" PRIi64 "\n", incoming_seq);

  /* Save the current state for potential rollback */
  w->rollback_largest_seq = w->largest_seq;
  w->rollback_sliding_window = w->sliding_window;

  /* Special case since we do not use unsigned int for seq */
  /* if(!w->initialized) {
      w->initialized = 1;
      int shift = incoming_seq - w->largest_seq;
      w->sliding_window = w->sliding_window << shift;
      w->sliding_window = w->sliding_window | 1;
      w->largest_seq = incoming_seq;
      w->recent_seq = incoming_seq;
      return 1;
  }
  */

  if(incoming_seq >= OSCORE_SEQ_MAX) {
    LOG_WARN("OSCORE Replay protection, SEQ %" PRIi64 " larger than SEQ_MAX %" PRIi64 ".\n",
      incoming_seq, OSCORE_SEQ_MAX);
    return false;
  }

  if(incoming_seq > w->largest_seq) {
    /* Update the replay window */
    int shift = incoming_seq - w->largest_seq;
    w->sliding_window = w->sliding_window << shift;
    w->sliding_window = w->sliding_window | 1;
    w->largest_seq = incoming_seq;

  } else if(incoming_seq == w->largest_seq) {
      LOG_WARN("OSCORE Replay protection, replayed SEQ incoming_seq (%" PRIi64 ") == w->largest_seq (%" PRIi64 ").\n",
        incoming_seq, w->largest_seq);
      return false;

  } else { /* seq < recipient_seq */
    if(incoming_seq + w->replay_window_size < w->largest_seq) {
      LOG_WARN("OSCORE Replay protection, SEQ outside of replay window "
        "(incoming_seq %" PRIi64 " + replay_window_size %" PRIu8 " < largest_seq %" PRId64 ").\n",
        incoming_seq, w->replay_window_size, w->largest_seq);
      return false;
    }

    /* seq+replay_window_size > recipient_seq */
    int shift = w->largest_seq - incoming_seq;
    uint32_t pattern = 1 << shift;
    uint32_t verifier = w->sliding_window & pattern;
    verifier = verifier >> shift;
    if(verifier == 1) {
      LOG_WARN("OSCORE Replay protection, replayed SEQ (sliding_window=%" PRIu32 ", pattern=%" PRIu32 ", shift=%d).\n",
        w->sliding_window, pattern, shift);
      return false;
    }
    w->sliding_window = w->sliding_window | pattern;
  }

  /* Update the last seen seq */
  w->recent_seq = incoming_seq;

  return true;
}
