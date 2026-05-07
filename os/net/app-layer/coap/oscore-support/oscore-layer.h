#pragma once

#include "oscore-context.h"

typedef struct {
  const char *forward_to_uri; /* Proxy-Uri to embed in this layer's plaintext */
  oscore_ctx_t *ctx;          /* OSCORE context for this hop */
} oscore_layer_t;

typedef struct {
  oscore_layer_t *layers;
  uint8_t num_layers;
} oscore_path_t;

void oscore_ep_path_set(const coap_endpoint_t *ep, oscore_path_t *path);
oscore_path_t *oscore_ep_path_get(const coap_endpoint_t *ep);
