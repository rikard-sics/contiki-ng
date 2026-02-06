#include <string.h>
#include "oscore-layer.h"
#include "coap-log.h"

#define LOG_MODULE "oscore-path"
#define LOG_LEVEL LOG_LEVEL_DBG

#define MAX_PATHS 2

typedef struct {
  const coap_endpoint_t *ep;
  oscore_path_t *path;
  uint8_t in_use;
} oscore_path_assoc_t;

static oscore_path_assoc_t path_table[MAX_PATHS];

void
oscore_ep_path_set(const coap_endpoint_t *ep, oscore_path_t *path)
{
  if (!ep || !path) {
    return;
  }

  // Overwrite existing
  for (int i = 0; i < MAX_PATHS; i++) {
    if (path_table[i].in_use && path_table[i].ep == ep) {
      path_table[i].path = path;
      return;
    }
  }

  // Insert new 
  for (int i = 0; i < MAX_PATHS; i++) {
    if (!path_table[i].in_use) {
      path_table[i].ep = ep;
      path_table[i].path = path;
      path_table[i].in_use = 1;
      LOG_DBG("Stored OSCORE path for endpoint\n");
      return;
    }
  }

  LOG_ERR("OSCORE path table full\n");
}

oscore_path_t *
oscore_ep_path_get(const coap_endpoint_t *ep)
{
  if (!ep) {
    return NULL;
  }

  for (int i = 0; i < MAX_PATHS; i++) {
    if (path_table[i].in_use && path_table[i].ep == ep) {
      return path_table[i].path;
    }
  }

  return NULL;
}
