#include "thread_process.h"

#include <estd/efile.h>
#include <estd/estring.h>
#include <estd/hash.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "global.h"

int get_random_bytes(void *buf, int32_t len) {
#ifdef _WIN32
  HCRYPTPROV hProv;
  if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT))
    return -1;

  if (!CryptGenRandom(hProv, len, (BYTE *)buf)) {
    CryptReleaseContext(hProv, 0);
    return -1;
  }
  CryptReleaseContext(hProv, 0);
#else // Assuming Linux/Unix-like
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;

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
#endif
  return 0;
}

// Read before decrypting
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

// Write before encrypting
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

static inline int init_salt_and_iv(uint8_t *salt, uint8_t *iv) {
  if (get_random_bytes(salt, SALT_SIZE) != 0) {
    return -1;
  }

  if (get_random_bytes(iv, IV_SIZE) != 0)
    return -1;

  return 0;
}

// Function to XOR two byte arrays
static inline void xor_bytes(uint8_t *a, const uint8_t *b, size_t len) {
  for (size_t i = 0; i < len; i++)
    a[i] ^= b[i];
}

// HMAC(key, message) implementation using  sha256_hash
static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                        size_t data_len, uint8_t out[SHA256_HASH_SIZE]) {
  uint8_t k_prime[SHA256_BLOCK_SIZE];
  memset(k_prime, 0, SHA256_BLOCK_SIZE);

  // If key is longer than block size, hash it
  if (key_len > SHA256_BLOCK_SIZE) {
    sha256_hash(key, key_len, k_prime);
  } else {
    memcpy(k_prime, key, key_len);
  }

  uint8_t o_key_pad[SHA256_BLOCK_SIZE];
  uint8_t i_key_pad[SHA256_BLOCK_SIZE];
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
    o_key_pad[i] = 0x5c ^ k_prime[i];
    i_key_pad[i] = 0x36 ^ k_prime[i];
  }

  // Inner hash
  sha256_buff inner_buff;
  sha256_init(&inner_buff);
  sha256_update(&inner_buff, i_key_pad, SHA256_BLOCK_SIZE);
  sha256_update(&inner_buff, data, data_len);
  sha256_finalize(&inner_buff);
  uint8_t inner_hash[SHA256_HASH_SIZE];
  sha256_read(&inner_buff, inner_hash);

  // Outer hash
  sha256_buff outer_buff;
  sha256_init(&outer_buff);
  sha256_update(&outer_buff, o_key_pad, SHA256_BLOCK_SIZE);
  sha256_update(&outer_buff, inner_hash, SHA256_HASH_SIZE);
  sha256_finalize(&outer_buff);
  sha256_read(&outer_buff, out);
}

// PBKDF2 implementation using HMAC-SHA256
static void pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                               const uint8_t *salt, size_t salt_len,
                               uint32_t iterations, uint8_t *out_key) {
  uint8_t U[SHA256_HASH_SIZE];
  uint8_t T[SHA256_HASH_SIZE];
  uint8_t salt_and_block[SALT_SIZE + 4];

  memcpy(salt_and_block, salt, salt_len);
  // BE encoding of block number (1)
  salt_and_block[salt_len] = 0;
  salt_and_block[salt_len + 1] = 0;
  salt_and_block[salt_len + 2] = 0;
  salt_and_block[salt_len + 3] = 1;

  // First iteration
  hmac_sha256(password, password_len, salt_and_block, salt_len + 4, U);
  memcpy(T, U, SHA256_HASH_SIZE);

  // Subsequent iterations
  for (uint32_t i = 1; i < iterations; i++) {
    hmac_sha256(password, password_len, U, SHA256_HASH_SIZE, U);
    xor_bytes(T, U, SHA256_HASH_SIZE);
  }

  memcpy(out_key, T, KEY_SIZE > SHA256_HASH_SIZE ? SHA256_HASH_SIZE : KEY_SIZE);
}

// Generate key from password and salt
static inline string *derive_key_with_salt(const string *password,
                                           const uint8_t *salt) {
  uint8_t key_bytes[KEY_SIZE];

  pbkdf2_hmac_sha256((const uint8_t *)string_cstr(password),
                     string_length(password), salt, SALT_SIZE,
                     PBKDF2_ITERATIONS, key_bytes);

  string *key = string_init_empty();
  if (!key)
    return NULL;

  for (size_t i = 0; i < KEY_SIZE; i++) {
    if (string_appendc(key, key_bytes[i]) != OK) {
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
  if (init_salt_and_iv(salt, iv) != 0)
    return EXIT_ALGORITHM_FAILED;

  key = derive_key_with_salt(password, salt);
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

  key = derive_key_with_salt(password, salt);
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
