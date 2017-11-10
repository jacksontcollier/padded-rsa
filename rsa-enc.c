#include "padded-rsa.h"

int main(int argc, char** argv)
{
  RSAEncDecOptions* rsa_options = parse_RSAEncDecOptions(argc, argv);

  FILE* public_key_fin = fopen(rsa_options->key_file, "r");
  PublicRSAKey* public_rsa_key = read_file_PublicRSAKey(public_key_fin);
  fclose(public_key_fin);

  FILE* m_fin = fopen(rsa_options->in_file, "r");
  BIGNUM* m = read_file_bn(m_fin);
  fclose(m_fin);

  BIGNUM* ciphertext = padded_rsa_encrypt(m, public_rsa_key->N,
      public_rsa_key->e, public_rsa_key->num_bits);

  if (!ciphertext) print_openssl_err_and_exit();

  FILE* ciphertext_fout = fopen(rsa_options->out_file, "w");

  write_file_bn(ciphertext, ciphertext_fout);
  fclose(ciphertext_fout);

  return 0;
}
