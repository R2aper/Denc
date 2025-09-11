#ifndef THREAD_PROCES_H
#define THREAD_PROCES_H

#include <stddef.h>
#include <stdint.h>

typedef struct string string;

#define NUM_THREAD 4

typedef struct thread_data_t {
  unsigned char *buffer;
  size_t start;
  size_t end;
  uint64_t start_pos;
  const string *key;
  // uint32_t iv_value;

} thread_data_t;

// @brief thread function for encrypting given buffer
//
// @param arg thread_data_t parametr
// @return NULL
void *process_chunk(void *arg);

#endif // THREAD_PROCES_H
