#pragma once

#include "strformat.h"
#include <stddef.h>

strformat_result _ftoa(const strformat_context_t *ctxt, double value, size_t* written);
