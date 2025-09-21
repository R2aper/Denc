#include "thread_process.h"

#include <estd/eerror.h>
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
#define GET_NUM_THREADS(num_threads)                                           \
  SYSTEM_INFO sysinfo;                                                         \
  GetSystemInfo(&sysinfo);                                                     \
  num_threads = sysinfo.dwNumberOfProcessors
#else
#define GET_NUM_THREADS(num_threads) num_threads = sysconf(_SC_NPROCESSORS_ONLN)
#endif

easy_error process_chunk(void *arg) {
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

result_t multithreading_processing(const string *key, unsigned char *buffer,
                                   int num_threads, size_t bytes_read,
                                   const uint8_t *iv, uint64_t pos) {
  result_t result = {0, NULL};
  int tmp = 0;
  GET_NUM_THREADS(tmp);

  if (num_threads <= 0 || num_threads > tmp)
    num_threads = tmp;

  thrd_t *threads = (thrd_t *)malloc(sizeof(thrd_t) * num_threads);
  thread_data_t *thread_data =
      (thread_data_t *)malloc(sizeof(thread_data_t) * num_threads);

  size_t chunk_size = bytes_read / num_threads;

  // Processing chunks
  for (int i = 0; i < num_threads; i++) {
    thread_data[i].buffer = buffer;
    thread_data[i].start = i * chunk_size;
    thread_data[i].end =
        (i == num_threads - 1) ? bytes_read : (i + 1) * chunk_size;
    thread_data[i].start_pos = pos + i * chunk_size;
    thread_data[i].key = key;
    thread_data[i].iv = iv;

    if (thrd_create(&threads[i], process_chunk, &thread_data[i]) != 0) {
      free(threads);
      free(thread_data);
      RETURN_RESULT(result, EXIT_THREAD_CREATE_ERROR,
                    "Error while creating thread");
    }
  }

  // Join all threads
  for (int i = 0; i < num_threads; i++) {
    int res = 0;
    if (thrd_join(threads[i], &res) != 0) {
      free(threads);
      free(thread_data);
      RETURN_RESULT(result, EXIT_THREAD_JOIN_ERROR,
                    "Error while joining threads");
    }

    if (res != 0) { // Propagate error from thread
      free(threads);
      free(thread_data);
      RETURN_RESULT(result, res, easy_error_message(res));
    }
  }

  free(threads);
  free(thread_data);
  return result;
}
