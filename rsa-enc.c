#include "padded-rsa.h"

int main(int argc, char** argv)
{
  RSAEncDecOptions* rsa_options = parse_RSAEncDecOptions(argc, argv);
  rsa_options->print(rsa_options);

  return 0;
}
