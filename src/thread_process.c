#include "thread_process.h"

#include <estd/estring.h>

void *process_chunk(void *arg) {
  thread_data_t *data = (thread_data_t *)arg;
  size_t key_index = 0;

  for (size_t i = data->start; i < data->end; i++) {
    unsigned long global_pos = data->start_pos + (i - data->start);
    key_index = (global_pos + i) % string_length(data->key);
    data->buffer[i] ^= string_at(data->key, key_index, NULL);
  }

  return NULL;
}
