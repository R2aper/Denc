#include "thread_process.h"

#include <estd/estring.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "global.h"

/// @brief Macros for getting number of CPU THREADS
#ifdef WIN32
#define GET_NUM_THREADS(num_thread)                                            \
  SYSTEM_INFO sysinfo;                                                         \
  GetSystemInfo(&sysinfo);                                                     \
  num_thread = sysinfo.dwNumberOfProcessors
#else
#define GET_NUM_THREADS(num_thread) num_thread = sysconf(_SC_NPROCESSORS_ONLN)
#endif

int process_chunk(void *arg) {
  thread_data_t *data = (thread_data_t *)arg;
  size_t key_index = 0;
  uint64_t global_pos = 0;
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
                              const uint8_t *iv, uint64_t pos) {
  int tmp;
  GET_NUM_THREADS(tmp);

  if (num_thread <= 0 || num_thread > tmp)
    num_thread = tmp;

  printf("%d\n", num_thread);

  // I hate you cl compiler
  thrd_t threads[
#ifdef _MSC_VER
      NUM_THREAD
#else
      num_thread
#endif
  ];

  thread_data_t thread_data[
#ifdef _MSC_VER
      NUM_THREAD
#else
      num_thread
#endif
  ];

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
