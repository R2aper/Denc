#include "thread_process.h"

#include <estd/efile.h>
#include <estd/estring.h>
#include <stdlib.h>

#include "global.h"

int encrypt_decrypt(const string *key, freader *source, fwriter *output) {
  if (!key || is_empty(key) || !source || !output)
    return EXIT_ALGORITHM_FAILED;

  size_t key_index = 0;
  unsigned char buffer[BUFFER_SIZE];
  size_t bytes_read = 0;
  uint64_t pos = 0;

  easy_error err = OK;
  while ((bytes_read = read_bytes(source, buffer, 1, BUFFER_SIZE, &err)) > 0 &&
         err == OK) {
    if (bytes_read < 1024) { // Too small for multithreading

      for (size_t i = 0; i < bytes_read; i++) {
        buffer[i] ^= string_at(key, key_index, &err);
        key_index = (i + pos) % string_length(key);

        pos++;
      }

    } else {
      int result =
          multithreading_processing(key, buffer, NUM_THREAD, bytes_read, pos);

      if (result != EXIT_SUCCESS)
        return result;

      pos += bytes_read;
    }

    write_bytes(output, buffer, 1, bytes_read, &err);
  }

  return EXIT_SUCCESS;
}
