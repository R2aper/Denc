#include <estd/argparser.h>
#include <estd/efile.h>

#include "encrypt.h"
#include "global.h"
#include "thread_process.h"

#define CHECK_ERROR(error, what_to_free)                                       \
  if (error != OK) {                                                           \
    fprintf(stderr, "%s\n", easy_error_message(error));                        \
    what_to_free;                                                              \
    return error;                                                              \
  }

void usage(void) {
  puts(
      "Usage: denc [OPTIONS]... [FILE]\n"
      "Encrypt/Decrypt given file with key using xor\n"
      "\n"
      "Options:\n"
      "-p, --password <path to password file>\t Provide key that would be used "
      "for "
      "encryption/decryption\n"
      "-e, --encypt\t\t\t\t Encrypt file\n"
      "-d, --decrypt\t\t\t\t Decrypt file\n"
      "-o, --output\t\t\t\t Set output file\n"
      "-h, --help\t\t\t\t Display this help and exit");
}

static inline easy_error add_arguments(cmd_parser *parser) {
  easy_error err = OK;

  err = cmd_parser_add(parser, "-h", "--help", FLAG);
  if (err != OK)
    return err;

  err = cmd_parser_add(parser, "-p", "--password", SINGLE_OPTION);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-o", "--output", SINGLE_OPTION);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-e", "--encrypt", FLAG);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-d", "--decrypt", FLAG);
  if (err != OK)
    return err;

  return OK;
}

int main(int argc, char *argv[]) {
  easy_error error = OK;
  string *password = NULL;
  freader *input_file = NULL, *password_file = NULL;
  fwriter *output_file = NULL;

  const string *path_to_password_file = NULL, *path_to_output_file_given = NULL,
               *path_to_input_file = NULL;

  bool password_flag = false, output_flag = false, help_flag = false,
       encrypt_flag = false, decrypt_flag = false;

  string *path_to_output_file =
      NULL; // This would be not NULL if user didn't pass output file

  PROGRAM_MODE mode = 0;

  // Creating parser
  cmd_parser *parser = cmd_parser_create();
  if (!parser) {
    fprintf(stderr, "Error of creating parser!\n");
    return ALLOCATION_FAILED;
  }

  // Adding arguments
  error = add_arguments(parser);
  CHECK_ERROR(error, cmd_parser_free(parser))

  // Parse command line
  error = cmd_parser_parse(parser, argc, argv);
  if (error != OK) {
    fprintf(stderr, "Fatal! %s", easy_error_message(error));
    if (parser->arg_error)
      fprintf(stderr, ": %s\n", string_cstr(parser->arg_error));

    cmd_parser_free(parser);
    return error;
  }

  help_flag = cmd_is_set(parser, "-h", &error);
  CHECK_ERROR(error, cmd_parser_free(parser))
  if (help_flag) {
    usage();
    cmd_parser_free(parser);
    return 0;
  }

  encrypt_flag = cmd_is_set(parser, "-e", &error);
  CHECK_ERROR(error, cmd_parser_free(parser))

  decrypt_flag = cmd_is_set(parser, "-d", &error);
  CHECK_ERROR(error, cmd_parser_free(parser))

  if (encrypt_flag && decrypt_flag) {
    fprintf(stderr, "Fatal! provide both encrypt and decrypt flag mode!\n");
    cmd_parser_free(parser);
    return EXIT_INVALID_MODE;

  } else if (!encrypt_flag && !decrypt_flag) {
    fprintf(stderr, "Fatal! No flag mode provide!\n");
    cmd_parser_free(parser);
    return EXIT_INVALID_MODE;
  }

  mode = (encrypt_flag) ? ENCRYPT : DECRYPT;

  // Getting input file
  const grow *positional_args = cmd_get_pos_args(parser, &error);
  CHECK_ERROR(error, cmd_parser_free(parser));

  // No input file provided
  if (grow_size(positional_args) == 0) {
    fprintf(stderr, "Fatal! No file to encrypt/decrypt provided!\n");
    cmd_parser_free(parser);
    return EXIT_NO_INPUT_FILE_PROVIDED;

    // Provided more that 1 input file
  } else if (grow_size(positional_args) > 1) {
    fprintf(stderr, "Fatal! Too many input files: ");
    for (size_t i = 0; i < grow_size(positional_args) && error == OK; i++) {
      const string *arg = grow_get(positional_args, i, &error);
      fprintf(stderr, " %s, ", string_cstr(arg));
    }

    cmd_parser_free(parser);
    return EXIT_MORE_THAN_ONE_INPUT_FILE;
  }

  path_to_input_file = grow_get(positional_args, 0, &error);
  CHECK_ERROR(error, cmd_parser_free(parser));

  // Getting password
  password_flag = cmd_is_set(parser, "-p", &error);
  CHECK_ERROR(error, cmd_parser_free(parser))
  if (password_flag) {
    path_to_password_file = cmd_get_value(parser, "-p", &error);
    CHECK_ERROR(error, cmd_parser_free(parser))

  } else {
    fprintf(stderr, "Fatal! No password file provided!\n");
    cmd_parser_free(parser);
    return EXIT_NO_PASSWORD_FILE_PROVIDED;
  }

  // Getting output file
  output_flag = cmd_is_set(parser, "-o", &error);
  CHECK_ERROR(error, cmd_parser_free(parser))

  if (output_flag) {
    path_to_output_file_given = cmd_get_value(parser, "-o", &error);
    CHECK_ERROR(error, cmd_parser_free(parser))

  } else {
    path_to_output_file = string_from_cstr(string_cstr(path_to_input_file));
    error = string_append(path_to_output_file, ".x"); // add .x extension

    CHECK_ERROR(error, cmd_parser_free(parser);
                string_free_(path_to_output_file));
  }

  // Opening files
  // FIX: Rewrite this shit
  input_file = openr(string_cstr(path_to_input_file), READ_BIN, &error);
  CHECK_ERROR(
      error, cmd_parser_free(parser);
      if (path_to_output_file) { string_free_(path_to_output_file); })

  output_file =
      openw(string_cstr((path_to_output_file) ? path_to_output_file
                                              : path_to_output_file_given),
            WRITE_BIN, &error);
  CHECK_ERROR(
      error, cmd_parser_free(parser); closer(input_file);
      if (path_to_output_file) { string_free_(path_to_output_file); })

  password_file = openr(string_cstr(path_to_password_file), READ_BIN, &error);
  CHECK_ERROR(
      error, cmd_parser_free(parser); closer(input_file); closew(output_file);
      closer(password_file);
      if (path_to_output_file) { string_free_(path_to_output_file); })

  password = read_file(password_file, &error);
  CHECK_ERROR(
      error, cmd_parser_free(parser); closer(input_file); closew(output_file);
      closer(password_file);
      if (path_to_output_file) { string_free_(path_to_output_file); })

  int result = encrypt_decrypt(password, input_file, output_file, mode);

  cmd_parser_free(parser);
  closew(output_file);
  closer(input_file);
  closer(password_file);
  string_free_(password);
  if (path_to_output_file)
    string_free_(path_to_output_file);

  return result;
}
