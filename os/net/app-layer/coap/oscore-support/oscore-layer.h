#pragma once

#include "oscore-context.h"

typedef struct {
  const char *next_hop_uri;   /* Proxy-Uri for this layer */
  oscore_ctx_t *ctx;          /* OSCORE context for this hop */
} oscore_layer_t;
