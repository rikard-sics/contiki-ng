/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB (RISE), Stockholm, Sweden
 * Copyright (c) 2020, Industrial Systems Institute (ISI), Patras, Greece
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *         edhoc-log header
 *
 * \author
 *         Lidia Pocero <pocero@isi.gr>, Peter A Jonsson, Rikard Höglund, Marco Tiloca
 */
#ifndef EDHOC_LOG_H_
#define EDHOC_LOG_H_

#include "edhoc-msgs.h"

#define LOG_EDHOC_MSG_1(level, msg1) do {         \
    if(level <= (LOG_LEVEL)) {                   \
      edhoc_msgs_log_msg_1(msg1);                \
    }                                            \
  } while(0)

#define LOG_EDHOC_MSG_2(level, msg2) do {         \
    if(level <= (LOG_LEVEL)) {                   \
      edhoc_msgs_log_msg_2(msg2);                \
    }                                            \
  } while(0)

#define LOG_EDHOC_MSG_3(level, msg3) do {         \
    if(level <= (LOG_LEVEL)) {                   \
      edhoc_msgs_log_msg_3(msg3);                \
    }                                            \
  } while(0)

#define LOG_ERR_EDHOC_MSG_1(msg1) LOG_EDHOC_MSG_1(LOG_LEVEL_ERR, msg1)
#define LOG_WARN_EDHOC_MSG_1(msg1) LOG_EDHOC_MSG_1(LOG_LEVEL_WARN, msg1)
#define LOG_INFO_EDHOC_MSG_1(msg1) LOG_EDHOC_MSG_1(LOG_LEVEL_INFO, msg1)
#define LOG_DBG_EDHOC_MSG_1(msg1) LOG_EDHOC_MSG_1(LOG_LEVEL_DBG, msg1)
#define LOG_PRINT_EDHOC_MSG_1(msg1) LOG_EDHOC_MSG_1(LOG_LEVEL_PRINT, msg1)

#define LOG_ERR_EDHOC_MSG_2(msg2) LOG_EDHOC_MSG_2(LOG_LEVEL_ERR, msg2)
#define LOG_WARN_EDHOC_MSG_2(msg2) LOG_EDHOC_MSG_2(LOG_LEVEL_WARN, msg2)
#define LOG_INFO_EDHOC_MSG_2(msg2) LOG_EDHOC_MSG_2(LOG_LEVEL_INFO, msg2)
#define LOG_DBG_EDHOC_MSG_2(msg2) LOG_EDHOC_MSG_2(LOG_LEVEL_DBG, msg2)
#define LOG_PRINT_EDHOC_MSG_2(msg2) LOG_EDHOC_MSG_2(LOG_LEVEL_PRINT, msg2)

#define LOG_ERR_EDHOC_MSG_3(msg3) LOG_EDHOC_MSG_3(LOG_LEVEL_ERR, msg3)
#define LOG_WARN_EDHOC_MSG_3(msg3) LOG_EDHOC_MSG_3(LOG_LEVEL_WARN, msg3)
#define LOG_INFO_EDHOC_MSG_3(msg3) LOG_EDHOC_MSG_3(LOG_LEVEL_INFO, msg3)
#define LOG_DBG_EDHOC_MSG_3(msg3) LOG_EDHOC_MSG_3(LOG_LEVEL_DBG, msg3)
#define LOG_PRINT_EDHOC_MSG_3(msg3) LOG_EDHOC_MSG_3(LOG_LEVEL_PRINT, msg3)

#endif /* EDHOC_LOG_H_ */
