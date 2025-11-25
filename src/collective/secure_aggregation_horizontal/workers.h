// Workers.h
#ifndef WORKERS_H
#define WORKERS_H

#include <cstdint>
#include <vector>

// 1. Movemos la estructura aquí para que ambos la conozcan
struct DHExchangeResult {
  double localPriv;
  double localPub;
  double remotePub;
  double sharedSecret;
  bool ok;
};

// 2. Declaramos las funciones (prototipos)
DHExchangeResult servidorA();
DHExchangeResult clienteB();

// 3. Declaramos la función auxiliar PRG
// Nota: La implementación irá en uno de los .cpp o en un utils.cpp
std::vector<double> PRG(uint64_t seed, size_t length);

#endif