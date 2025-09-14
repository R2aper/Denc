#include "thread_process.h"

#include <estd/efile.h>
#include <estd/estring.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>

#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "global.h"

#define GET_IV_VALUE(iv) iv[0] | (iv[1] << 8) | (iv[2] << 16) | (iv[3] << 24)
#define ITERATE_HASH(hash) hash = (hash * 1103515245 + 12345) % 2147483648;

int get_random_bytes(void *buf, int32_t len) {
#ifdef _WIN32
  HCRYPTPROV hProv;
  if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT)) {
    return -1;
  }
  if (!CryptGenRandom(hProv, len, (BYTE *)buf)) {
    CryptReleaseContext(hProv, 0);
    return -1;
  }
  CryptReleaseContext(hProv, 0);
  return 0;
#else // Assuming Linux/Unix-like
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    return -1;
  }

  ssize_t bytes_read = 0;
  while (bytes_read < len) {
    ssize_t result = read(fd, (uint8_t *)buf + bytes_read, len - bytes_read);
    if (result < 0) {
      close(fd);
      return -1;
    }
    bytes_read += result;
  }

  close(fd);
  return 0;
#endif
}

static easy_error read_salt_and_iv(freader *source, uint8_t *salt,
                                   uint8_t *iv) {
  if (!source || !salt || !iv)
    return INVALID_ARGUMENT;

  easy_error err = OK;
  size_t read = 0;

  read = read_bytes(source, salt, 1, SALT_SIZE, &err);
  if (err != OK && read != SALT_SIZE)
    return (err != OK) ? err : EXIT_ERROR_READING_SALT_IV;

  read = read_bytes(source, iv, 1, IV_SIZE, &err);
  if (err != OK && read != IV_SIZE)
    return (err != OK) ? err : EXIT_ERROR_READING_SALT_IV;

  return OK;
}

static easy_error write_salt_and_iv(fwriter *output, const uint8_t *salt,
                                    const uint8_t *iv) {
  if (!output || !salt || !iv)
    return INVALID_ARGUMENT;

  easy_error err = OK;

  write_bytes(output, salt, 1, SALT_SIZE, &err);
  if (err != OK)
    return err;

  write_bytes(output, iv, 1, IV_SIZE, &err);
  if (err != OK)
    return err;

  return OK;
}

uint32_t ced_hash_fnv1a(const void *key, size_t length) {
  const uint32_t offset_basis = 2166136261;
  const uint32_t prime = 16777619;

  uint32_t hash = offset_basis;
  const uint8_t *data = (const uint8_t *)key;

  for (size_t i = 0; i < length; ++i) {
    hash ^= data[i];
    hash *= prime;
  }

  return hash;
}

static inline int init_salt_and_iv(uint8_t *salt, uint8_t *iv) {
  if (get_random_bytes(salt, SALT_SIZE) != 0) {
    return -1;
  }

  if (get_random_bytes(iv, IV_SIZE) != 0)
    return -1;

  return 0;
}

static inline string *derive_key_with_salt(const string *password,
                                           const uint8_t *salt,
                                           size_t key_size) {
  string *key = NULL,
         *salted_password = string_from_cstr(string_cstr(password));
  if (!salted_password)
    return NULL;

  for (size_t i = 0; i < SALT_SIZE; i++) {
    if (string_appendc(salted_password, salt[i]) != OK) {
      string_free_(salted_password);
      return NULL;
    }
  }

  uint64_t hash = ced_hash_fnv1a(string_cstr(salted_password),
                                 string_length(salted_password));
  string_free_(salted_password);

  key = string_init_empty();
  if (!key)
    return NULL;

  for (size_t i = 0; i < key_size; i++) {
    for (int j = 0; j < 100; j++)
      ITERATE_HASH(hash);

    if (string_appendc(key, (char)(hash % 256)) != OK) {
      string_free_(key);
      return NULL;
    }
  }

  return key;
}

int encrypt(const string *password, freader *source, fwriter *output,
            int num_threads) {
  if (!password || !password->data || is_empty(password))
    return EXIT_PASSWORD_ERROR;

  if (!source || !output)
    return EXIT_FILE_ERROR;

  easy_error err = OK;
  string *key = NULL;

  uint8_t salt[SALT_SIZE], iv[IV_SIZE];
  if (init_salt_and_iv(salt, iv) != 0) {
    puts("ADADD");
    return EXIT_ALGORITHM_FAILED;
  }

  key = derive_key_with_salt(password, salt, KEY_SIZE);
  if (!key)
    return EXIT_COULDNT_CREATE_KEY;

  err = write_salt_and_iv(output, salt, iv);
  if (err != OK)
    return EXIT_ERROR_WRITING_SALT_IV;

  uint64_t pos = 0;

  size_t bytes_read;
  uint8_t buffer[BUFFER_SIZE];

  while ((bytes_read = read_bytes(source, buffer, 1, BUFFER_SIZE, &err)) > 0 &&
         err == OK) {
    if (bytes_read < 1024) { // Too small for multithreading

      for (size_t i = 0; i < bytes_read; i++) {
        size_t key_index = (pos + i) % string_length(key);
        char key_char = string_at(key, key_index, &err);
        if (err != OK)
          break;

        buffer[i] ^= key_char ^ iv[(pos + i) % IV_SIZE];
      }

    } else {
      int result = multithreading_processing(key, buffer, num_threads,
                                             bytes_read, iv, pos);

      if (result != 0) {
        string_free_(key);
        return result;
      }
    }

    if (err != OK) // Error from single-threaded loop
      break;

    write_bytes(output, buffer, 1, bytes_read, &err);
    if (err != OK)
      break;

    pos += bytes_read;
  }

  if (key)
    string_free_(key);

  return (err == OK) ? EXIT_SUCCESS : err;
}

int decrypt(const string *password, freader *source, fwriter *output,
            int num_threads) {
  if (!password || !password->data || is_empty(password))
    return EXIT_PASSWORD_ERROR;

  if (!source || !output)
    return EXIT_FILE_ERROR;

  easy_error err = OK;
  string *key = NULL;

  uint8_t salt[SALT_SIZE], iv[IV_SIZE];
  err = read_salt_and_iv(source, salt, iv);
  if (err != OK)
    return EXIT_ERROR_READING_SALT_IV;

  key = derive_key_with_salt(password, salt, KEY_SIZE);
  if (!key)
    return EXIT_COULDNT_CREATE_KEY;

  uint64_t pos = 0;

  size_t bytes_read;
  uint8_t buffer[BUFFER_SIZE];

  while ((bytes_read = read_bytes(source, buffer, 1, BUFFER_SIZE, &err)) > 0 &&
         err == OK) {
    if (bytes_read < 1024) { // Too small for multithreading

      for (size_t i = 0; i < bytes_read; i++) {
        size_t key_index = (pos + i) % string_length(key);
        char key_char = string_at(key, key_index, &err);
        if (err != OK)
          break;

        buffer[i] ^= key_char ^ iv[(pos + i) % IV_SIZE];
      }

    } else {

      int result = multithreading_processing(key, buffer, num_threads,
                                             bytes_read, iv, pos);

      if (result != 0) {
        string_free_(key);
        return result;
      }
    }

    if (err != OK) // Error from single-threaded loop
      break;

    write_bytes(output, buffer, 1, bytes_read, &err);
    if (err != OK)
      break;

    pos += bytes_read;
  }

  if (key)
    string_free_(key);

  return (err == OK) ? EXIT_SUCCESS : err;
}
