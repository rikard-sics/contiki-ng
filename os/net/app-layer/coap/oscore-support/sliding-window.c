#include "sliding-window.h"

#include "assert.h"

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
    if (replay_window_size == 0 || replay_window_size > OSCORE_MAX_REPLAY_WINDOW_SIZE)
    {
        LOG_ERR("Invalid replay window size %" PRIu8 "\n", replay_window_size);
        return false;
    }

    w->largest_seq = OSCORE_INVALID_SEQ;
    w->rollback_largest_seq = w->largest_seq;
    
    w->sliding_window = 0;
    w->rollback_sliding_window = w->sliding_window;

    w->replay_window_size = replay_window_size;

    w->recent_seq = OSCORE_INVALID_SEQ;

    //w->initialized = false;

    return true;
}

void oscore_sliding_window_rollback(oscore_sliding_window_t* w)
{
    LOG_DBG("Rolling back seq (window %"PRIu32" = %"PRIu32") (seq %"PRIu64" = %"PRIu64")\n",
    w->sliding_window, w->rollback_sliding_window,
    w->largest_seq, w->rollback_largest_seq);

    w->sliding_window = w->rollback_sliding_window;
    w->largest_seq = w->rollback_largest_seq;
}

bool oscore_sliding_window_test(const oscore_sliding_window_t* w, uint64_t seq)
{
    /* Check that seq is within the sliding window */
    if (w->largest_seq == OSCORE_INVALID_SEQ)
    {
        /* no sliding window yet */
        return false;
    }
    if (seq > w->largest_seq)
    {
        /* too big */
        return false;
    }
    if (seq + w->replay_window_size < w->largest_seq)
    {
        /* too small */
        return false;
    }

    const int64_t shift = w->largest_seq - seq;

    return (w->sliding_window & (1 << shift)) != 0;
}

void oscore_sliding_window_set(oscore_sliding_window_t* w, uint64_t seq)
{
    if (w->largest_seq == OSCORE_INVALID_SEQ) {
        /* Set the 0th bit */
        w->sliding_window = (1 << 0);

        w->largest_seq = seq;
    }
    else if (seq > w->largest_seq) {
        const int64_t shift = seq - w->largest_seq;

        /* Move the window along so the 0th bit is this new seq */
        w->sliding_window <<= shift;

        /* Set the 0th bit */
        w->sliding_window |= (1 << 0);

        w->largest_seq = seq;

    } else {
        assert(seq + w->replay_window_size >= w->largest_seq);

        const int64_t shift = w->largest_seq - seq;

        w->sliding_window |= (1 << shift);
    }
}

bool oscore_sliding_window_validate(oscore_sliding_window_t* w, uint64_t incoming_seq)
{
    LOG_DBG("incoming SEQ %" PRIi64 "\n", incoming_seq);

    /* Save the current state for potential rollback */
    w->rollback_largest_seq = w->largest_seq;
    w->rollback_sliding_window = w->sliding_window;

    if(incoming_seq >= OSCORE_SEQ_MAX) {
        LOG_WARN("OSCORE Replay protection, SEQ %" PRIu64 " larger than SEQ_MAX %" PRIu64 ".\n",
          incoming_seq, OSCORE_SEQ_MAX);
        return false;
    }

    if(incoming_seq > w->largest_seq || w->largest_seq == OSCORE_INVALID_SEQ) {
        oscore_sliding_window_set(w, incoming_seq);

    } else if(incoming_seq == w->largest_seq) {
        LOG_WARN("OSCORE Replay protection, replayed SEQ incoming_seq (%" PRIu64 ") == w->largest_seq (%" PRIu64 ").\n",
            incoming_seq, w->largest_seq);
        return false;

    } else { /* seq < recipient_seq */
        if(incoming_seq + w->replay_window_size < w->largest_seq) {
            LOG_WARN("OSCORE Replay protection, SEQ outside of replay window "
                "(incoming_seq %" PRIu64 " + replay_window_size %" PRIu8 " < largest_seq %" PRIu64 ").\n",
                incoming_seq, w->replay_window_size, w->largest_seq);
            return false;
        }

        /* seq+replay_window_size > recipient_seq */
        const bool set = oscore_sliding_window_test(w, incoming_seq);
        if(set) {
            LOG_WARN("OSCORE Replay protection, replayed SEQ %"PRIu64" (sliding_window=%" PRIu32 ").\n",
                incoming_seq, w->sliding_window);
            return false;
        } else {
            oscore_sliding_window_set(w, incoming_seq);
        }
    }

    /* Update the last seen seq */
    w->recent_seq = incoming_seq;

    return true;
}
