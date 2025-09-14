#include "thread_process.h"

#include <estd/estring.h>
#include <stdlib.h>
#include <threads.h>

#include "global.h"

int process_chunk(void *arg) {
  thread_data_t *data = (thread_data_t *)arg;
  size_t key_index = 0;
  uint32_t global_pos = 0;
  easy_error err = OK;

  for (size_t i = data->start; i < data->end; i++) {
    global_pos = data->start_pos + (i - data->start);
    key_index = global_pos % string_length(data->key);
    char key_char = string_at(data->key, key_index, &err);
    if (err != OK)
      return err;

    data->buffer[i] ^= key_char ^ data->iv[global_pos % IV_SIZE];
  }

  return 0;
}

int multithreading_processing(const string *key, unsigned char *buffer,
                              int num_thread, size_t bytes_read,
                              const unsigned char *iv, uint32_t pos) {
  thrd_t threads[num_thread];
  thread_data_t thread_data[num_thread];
  size_t chunk_size = bytes_read / num_thread;

  // Processing chunks
  for (int i = 0; i < num_thread; i++) {
    thread_data[i].buffer = buffer;
    thread_data[i].start = i * chunk_size;
    thread_data[i].end =
        (i == num_thread - 1) ? bytes_read : (i + 1) * chunk_size;
    thread_data[i].start_pos = pos + i * chunk_size;
    thread_data[i].key = key;
    thread_data[i].iv = iv;

    if (thrd_create(&threads[i], process_chunk, &thread_data[i]) != 0)
      return EXIT_THREAD_CREATE_ERROR;
  }

  // Join all threads
  for (int i = 0; i < num_thread; i++) {
    int res = 0;
    if (thrd_join(threads[i], &res) != 0)
      return EXIT_THREAD_JOIN_ERROR;
    if (res != 0)
      return res; // Propagate error from thread
  }

  return EXIT_SUCCESS;
}
