#include "padded-rsa.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>

const char* rsa_enc_dec_arg_options = "k:i:o:";
const char* rsa_keygen_arg_options = "p:s:n:";


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
    fprintf(stderr, "-k -i -o options are required\n");
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
        sscanf(optarg, "%ld", &(keygen_options->num_bits));
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

  if (!rsa_key) return NULL;

  rsa_key->d = BN_new();
  rsa_key->e = BN_new();
  rsa_key->N = BN_new();
  rsa_key->num_bits = 0;

  if (!rsa_key->d || !rsa_key->e || !rsa_key->N) {
    goto handle_new_RSAKey_error;
  }

  if (!BN_dec2bn(&rsa_key->e, "3")) {
    goto handle_new_RSAKey_error;
  }

  return rsa_key;

  handle_new_RSAKey_error:
    if (rsa_key->d) BN_clear_free(rsa_key->d);
    if (rsa_key->e) BN_clear_free(rsa_key->e);
    if (rsa_key->N) BN_clear_free(rsa_key->N);
    if (rsa_key) free(rsa_key);
    return NULL;
}

void free_RSAKey(RSAKey* rsa_key)
{
  if (rsa_key) {
    if (rsa_key->d) BN_clear_free(rsa_key->d);
    if (rsa_key->e) BN_clear_free(rsa_key->e);
    if (rsa_key->N) BN_clear_free(rsa_key->N);
    free(rsa_key);
  }
}


RSAKey* gen_RSAKey(int num_bits)
{
  RSAKey* rsa_key = new_RSAKey();
  BIGNUM* p = BN_new();
  BIGNUM* q = BN_new();

  if (!rsa_key || !p || !q) {
    goto handle_gen_RSAKey_error;
  }

  rsa_key->num_bits = (unsigned long) num_bits;

  if (!BN_generate_prime_ex(p, num_bits / 2, 0, NULL, NULL, NULL) ||
      !BN_generate_prime_ex(q, num_bits / 2, 0, NULL, NULL, NULL)) {
    goto handle_gen_RSAKey_error;
  }

  BN_CTX* bn_ctx = BN_CTX_new();

  if (!bn_ctx || !BN_mul(rsa_key->N, p, q, bn_ctx)) {
    goto handle_gen_RSAKey_error;
  }

  BIGNUM* phi_N = calc_phi_N(p, q, bn_ctx);

  if (!phi_N || !calc_d(rsa_key->d, rsa_key->e, phi_N, bn_ctx)) {
    goto handle_gen_RSAKey_error;
  }

  return rsa_key;

  handle_gen_RSAKey_error:
    if (rsa_key) free_RSAKey(rsa_key);
    if (p) BN_clear_free(p);
    if (q) BN_clear_free(q);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    if (phi_N) BN_clear_free(phi_N);
    return NULL;
}

void print_RSAKey(FILE* fout, unsigned long num_bits, const char* N,
                  const char* key)
{
  fprintf(fout, "%ld\n", num_bits);
  fprintf(fout, "%s\n", N);
  fprintf(fout, "%s\n", key);
}

BIGNUM* calc_phi_N(const BIGNUM* p, const BIGNUM* q, BN_CTX* bn_ctx)
{
  BIGNUM* p_minus_one = BN_new();
  BIGNUM* q_minus_one = BN_new();
  BIGNUM* phi_N = BN_new();

  if (!p_minus_one || !q_minus_one || !phi_N) {
    goto handle_calc_phi_N_error;
  }

  if (!BN_sub(p_minus_one, p, BN_value_one()) ||
      !BN_sub(q_minus_one, q, BN_value_one()) ||
      !BN_mul(phi_N, p_minus_one, q_minus_one, bn_ctx)) {
    goto handle_calc_phi_N_error;
  }

  BN_clear_free(p_minus_one);
  BN_clear_free(q_minus_one);

  return phi_N;

  handle_calc_phi_N_error:
    if (p_minus_one) BN_clear_free(p_minus_one);
    if (q_minus_one) BN_clear_free(q_minus_one);
    if (phi_N) BN_clear_free(phi_N);
    return NULL;
}

int calc_d(BIGNUM* d, const BIGNUM* e, const BIGNUM* phi_N, BN_CTX* bn_ctx)
{
  return BN_mod_inverse(d, e, phi_N, bn_ctx) != NULL;
}

void print_openssl_err_and_exit()
{
  fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
  exit(1);
}

