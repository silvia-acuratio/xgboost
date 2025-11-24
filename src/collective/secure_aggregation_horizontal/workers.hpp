// Workers.hpp
#ifndef WORKERS_HPP
#define WORKERS_HPP

#include <cstdint>
#include <vector>

// 1. Movemos la estructura aquí para que ambos la conozcan
struct DHExchangeResult {
  uint64_t localPriv;
  uint64_t localPub;
  uint64_t remotePub;
  bool ok;
};

// 2. Declaramos las funciones (prototipos)
DHExchangeResult servidorA();
DHExchangeResult clienteB();

// 3. Declaramos la función auxiliar PRG
// Nota: La implementación irá en uno de los .cpp o en un utils.cpp
std::vector<double> PRG(uint64_t seed, size_t length);

#endif