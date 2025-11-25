#ifndef DIFFIE_HELLMAN_HPP
#define DIFFIE_HELLMAN_HPP

#include <cstdint>
#include <random>
#include <vector>

class DiffieHellman {
 public:
  DiffieHellman(uint64_t prime, uint64_t generator)
      : _prime(prime), _generator(generator), _priv(0), _pub(0) {}

  void generate_private_key() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, _prime - 2);
    _priv = dist(gen);
  }

  void generate_public_key() { _pub = modexp(_generator, _priv, _prime); }

  uint64_t public_key() const { return _pub; }

  uint64_t compute_shared(uint64_t other_public) const {
    // (Comprobación simple)
    return modexp(other_public, _priv, _prime);
  }

  static uint64_t modexp(uint64_t base, uint64_t exp, uint64_t mod) {
    __uint128_t result = 1;
    __uint128_t b = base % mod;
    while (exp > 0) {
      if (exp & 1) result = (result * b) % mod;
      b = (b * b) % mod;
      exp >>= 1;
    }
    return static_cast<uint64_t>(result);
  }

  static std::vector<uint8_t> to_bytes(uint64_t value) {
    std::vector<uint8_t> out;
    while (value > 0) {
      out.insert(out.begin(), static_cast<uint8_t>(value & 0xFF));
      value >>= 8;
    }
    if (out.empty()) out.push_back(0);
    return out;
  }
  uint64_t get_private_key() const { return _priv; }

 private:
  uint64_t _prime;
  uint64_t _generator;
  uint64_t _priv;
  uint64_t _pub;
};

#endif