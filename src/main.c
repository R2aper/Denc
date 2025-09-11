#include <estd/argparser.h>
#include <estd/eerror.h>
#include <estd/efile.h>
#include <estd/estring.h>
#include <estd/grow.h>
#include <stdlib.h>

#define EXIT_NO_KEY_FILE_PROVIDED 1
#define EXIT_NO_INPUT_FILE_PROVIDED 2
#define EXIT_MORE_THAN_ONE_INPUT_FILE 3
#define EXIT_ALGORITHM_FAILED 4

#define CHECK_ERROR(error, what_to_free)                                       \
  if (error != OK) {                                                           \
    fprintf(stderr, "%s\n", easy_error_message(error));                        \
    what_to_free;                                                              \
    return error;                                                              \
  }

void usage(void) {
  puts("Usage: denc [OPTIONS]... [FILE]\n"
       "Encrypt/Decrypt given file with key using xor\n"
       "\n"
       "Options:\n"
       "-k, --key <path to key file>\t Provide key that would be used for "
       "encryption/decryption\n"
       "-o, --output\t Set output file\n"
       "-h, --help\t Display this help and exit");
}

int encrypt_decrypt(const string *key, freader *source, fwriter *output) {
  size_t key_index = 0;

  int bytes = 0;
  easy_error error = OK;
  while ((bytes = file_getc(source)) != EOF) {
    char encrypt_byte = bytes ^ string_at(key, key_index, &error);
    if (error != OK)
      return EXIT_ALGORITHM_FAILED;

    file_putc(encrypt_byte, output);
    key_index = (key_index + 1) % string_length(key);
  }

  return EXIT_SUCCESS;
}

static inline easy_error add_arguments(cmd_parser *parser) {
  easy_error err = OK;

  err = cmd_parser_add(parser, "-h", "--help", FLAG);
  if (err != OK)
    return err;

  err = cmd_parser_add(parser, "-k", "--key", SINGLE_OPTION);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-o", "--output", SINGLE_OPTION);
  if (err != OK)
    return err;

  return OK;
}

int main(int argc, char *argv[]) {
  easy_error error = OK;
  string *key = NULL;
  freader *input_file = NULL, *key_file = NULL;
  fwriter *output_file = NULL;

  const string *path_to_key_file = NULL, *path_to_output_file_given = NULL,
               *path_to_input_file = NULL;

  bool key_flag = false, output_flag = false, help_flag = false;

  string *path_to_output_file =
      NULL; // This would be not NULL if user didn't pass output file

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

  // Getting key
  key_flag = cmd_is_set(parser, "-k", &error);
  CHECK_ERROR(error, cmd_parser_free(parser))
  if (key_flag) {
    path_to_key_file = cmd_get_value(parser, "-k", &error);
    CHECK_ERROR(error, cmd_parser_free(parser))

  } else {
    fprintf(stderr, "Fatal! No key file provided!\n");
    cmd_parser_free(parser);
    return EXIT_NO_KEY_FILE_PROVIDED;
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

  key_file = openr(string_cstr(path_to_key_file), READ, &error);
  CHECK_ERROR(
      error, cmd_parser_free(parser); closer(input_file); closew(output_file);
      closer(key_file);
      if (path_to_output_file) { string_free_(path_to_output_file); })

  key = read_file(key_file, &error);
  CHECK_ERROR(
      error, cmd_parser_free(parser); closer(input_file); closew(output_file);
      closer(key_file);
      if (path_to_output_file) { string_free_(path_to_output_file); })

  int result = encrypt_decrypt(key, input_file, output_file);

  cmd_parser_free(parser);
  closew(output_file);
  closer(input_file);
  closer(key_file);
  string_free_(key);
  if (path_to_output_file)
    string_free_(path_to_output_file);

  return result;
}
