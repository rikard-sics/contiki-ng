#ifndef _OSCORE_SLIDING_WINDOW_H
#define _OSCORE_SLIDING_WINDOW_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include "cc.h"

#define OSCORE_SEQ_MAX (((uint64_t)1 << 40) - 1)

typedef struct {
    uint32_t sliding_window;
    int32_t rollback_sliding_window;

    int64_t largest_seq;
    int64_t rollback_largest_seq;

    uint64_t recent_seq;
    
    uint8_t replay_window_size;

    //bool initialized;

} oscore_sliding_window_t;

#define OSCORE_MAX_REPLAY_WINDOW_SIZE (CC_FIELD_SIZEOF(oscore_sliding_window_t, sliding_window) * CHAR_BIT)

#ifndef OSCORE_DEFAULT_REPLAY_WINDOW
#define OSCORE_DEFAULT_REPLAY_WINDOW OSCORE_MAX_REPLAY_WINDOW_SIZE
#endif

_Static_assert(OSCORE_DEFAULT_REPLAY_WINDOW >= 1, "OSCORE Replay window too small");
_Static_assert(OSCORE_DEFAULT_REPLAY_WINDOW <= OSCORE_MAX_REPLAY_WINDOW_SIZE, "OSCORE Replay window too large");

bool oscore_sliding_window_init(oscore_sliding_window_t* window, uint8_t replay_window_size);

/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fail. */
void oscore_sliding_window_rollback(oscore_sliding_window_t* window);

bool oscore_sliding_window_validate(oscore_sliding_window_t* window, uint64_t incoming_seq);

#endif /* _OSCORE_SLIDING_WINDOW_H */
