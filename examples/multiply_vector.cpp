#include <iostream>

#include "engine/engine.h"

void multiply_vector() {
  auto engine = desilo::fhe::create_default_engine();

  const auto secret_key = engine->create_secret_key();
  const auto public_key = engine->create_public_key(secret_key);

  const auto slot_count = engine->get_slot_count();
  std::vector<double> message(slot_count);
  for (int i = 0; i < slot_count; i++) {
    message[i] = (i % 10) / 10.;
  }

  std::cout << "message: " << std::endl;
  for (int i = 0; i < 10; i++) {
    std::cout << message[i] << " ";
  }
  std::cout << "..." << std::endl;

  const auto ciphertext = engine->encrypt(message, public_key);
  const auto multiplied = engine->multiply(ciphertext, message);
  const auto decrypted = engine->decrypt(multiplied, secret_key);

  std::cout << "decrypted: " << std::endl;
  for (int i = 0; i < 10; i++) {
    std::cout << decrypted[i] << " ";
  }
  std::cout << "..." << std::endl;

  delete engine;
  delete secret_key;
  delete public_key;
  delete ciphertext;
  delete multiplied;
}

int main() {
  multiply_vector();
  return 0;
}
