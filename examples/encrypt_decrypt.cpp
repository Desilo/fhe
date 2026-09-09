#include <iostream>

#include "engine/engine.h"

void encrypt_and_decrypt() {
  auto engine = desilo::fhe::create_default_engine();

  const auto secret_key = engine->create_secret_key();
  const auto public_key = engine->create_public_key(secret_key);

  const auto slot_count = engine->get_slot_count();
  std::vector<double> message(slot_count);
  for (int i = 0; i < slot_count; i++) {
    message[i] = i + 1;
  }

  std::cout << "message: " << std::endl;
  for (int i = 0; i < 10; i++) {
    std::cout << message[i] << " ";
  }
  std::cout << "..." << std::endl;

  const auto ciphertext = engine->encrypt(message, public_key);
  const auto decrypted = engine->decrypt(ciphertext, secret_key);

  std::cout << "decrypted: " << std::endl;
  for (int i = 0; i < 10; i++) {
    std::cout << decrypted[i] << " ";
  }
  std::cout << "..." << std::endl;

  delete engine;
  delete secret_key;
  delete public_key;
  delete ciphertext;
}

int main() {
  encrypt_and_decrypt();
  return 0;
}
