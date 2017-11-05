#include "padded-rsa.h"

int main(int argc, char** argv)
{
  RSAKeygenOptions* keygen_options = parse_RSAKeygenOptions(argc, argv);
  keygen_options->print(keygen_options);

  return 0;
}
