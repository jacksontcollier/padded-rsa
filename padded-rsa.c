#include "padded-rsa.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

const char* rsa_enc_dec_arg_options = "k:i:o";
const char* rsa_keygen_arg_options = "p:s:n";

RSAEncDecOptions* new_RSAEncDecOptions()
{
  RSAEncDecOptions* options = malloc(sizeof(RSAEncDecOptions));

  options->key_file = NULL;
  options->in_file = NULL;
  options->out_file = NULL;
  options->print = print_RSAEncDecOptions;

  return options;
}

RSAEncDecOptions* parse_RSAEncDecOptions(const int argc, char * const argv[])
{
  int option;
  RSAEncDecOptions* rsa_options = new_RSAEncDecOptions();

  while ((option = getopt(argc, argv, rsa_enc_dec_arg_options)) != -1) {
    switch(option) {
      case 'k':
        rsa_options->key_file = optarg;
        break;
      case 'i':
        rsa_options->in_file = optarg;
        break;
      case 'o':
        rsa_options->out_file = optarg;
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);
    }
  }

  if (rsa_options->key_file == NULL || rsa_options->in_file == NULL ||
      rsa_options->out_file == NULL) {
    fprintf(stderr, "-k -i -o options are reqquired\n");
    exit(1);
  }

  return rsa_options;
}

void print_RSAEncDecOptions(const RSAEncDecOptions* options)
{
  printf("key file: %s\n", options->key_file);
  printf("input file: %s\n", options->in_file);
  printf("output file: %s\n", options->out_file);
}

RSAKeygenOptions* new_RSAKeygenOptions()
{
  RSAKeygenOptions *options = malloc(sizeof(RSAKeygenOptions));

  options->public_key_file = NULL;
  options->secret_key_file = NULL;
  options->num_bits = 0;
  options->print = print_RSAKeygenOptions;

  return options;
}

RSAKeygenOptions* parse_RSAKeygenOptions(const int argc, char * const argv[])
{
  int option;
  RSAKeygenOptions* keygen_options = new_RSAKeygenOptions();

  while ((option = getopt(argc, argv, rsa_keygen_arg_options)) != -1) {
    switch(option) {
      case 'p':
        keygen_options->public_key_file = optarg;
        break;
      case 's':
        keygen_options->secret_key_file = optarg;
        break;
      case 'n':
        sscanf(optarg, "%ld", &keygen_options->num_bits);
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);
    }
  }

  if (keygen_options->public_key_file == NULL ||
      keygen_options->secret_key_file == NULL) {
    fprintf(stderr, "-p -s -n options are required\n");
    exit(1);
  }

  return keygen_options;
}

void print_RSAKeygenOptions(const RSAKeygenOptions* options)
{
  printf("public key file: %s\n", options->public_key_file);
  printf("secret key file: %s\n", options->secret_key_file);
  printf("number of bits: %ld\n", options->num_bits);
}

RSAKey* new_RSAKey()
{
  RSAKey* rsa_key = malloc(sizeof(RSAKey));

  rsa_key->d = BN_new();
  rsa_key->e = BN_new();
  rsa_key->N = BN_new();

  return rsa_key;
}

RSAKey* gen_RSAKey(int num_bits)
{
  RSAKey* rsa_key = new_RSAKey();
  BIGNUM* p = BN_new();
  BIGNUM* q = BN_new();

  BN_generate_prime_ex(p, num_bits, //
}

