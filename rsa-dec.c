#include "padded-rsa.h"

int main(int argc, char** argv)
{
  RSAEncDecOptions* rsa_options = parse_RSAEncDecOptions(argc, argv);

  FILE* secret_key_fin = fopen(rsa_options->key_file, "r");
  SecretRSAKey* secret_rsa_key = read_file_SecretRSAKey(secret_key_fin);
  fclose(secret_key_fin);

  FILE* c_fin = fopen(rsa_options->in_file, "r");
  BIGNUM* c = read_file_bn(c_fin);
  fclose(c_fin);

  BIGNUM* m = padded_rsa_decrypt(c, secret_rsa_key->N, secret_rsa_key->d,
      secret_rsa_key->num_bits);

  if (!m) print_openssl_err_and_exit();

  FILE* m_fout = fopen(rsa_options->out_file, "w");
  write_file_bn(m, m_fout);
  fclose(m_fout);

  return 0;
}
