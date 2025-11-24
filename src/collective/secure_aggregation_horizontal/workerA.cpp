#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <thread>
#include <vector>

#include "DiffieHellman.hpp"
#include "workers.hpp"

static constexpr uint64_t PRIME_DH = 0xffffffffffffffc5ULL;
static constexpr uint64_t GENERATOR_DH = 5ULL;

std::vector<double> PRG(uint64_t seed, size_t length) {
  std::vector<double> out;
  std::mt19937_64 gen(seed);
  std::uniform_real_distribution<double> dist(0.0, 255.0);
  out.reserve(length);
  for (size_t i = 0; i < length; ++i) out.push_back(dist(gen));
  return out;
}

DHExchangeResult servidorA() {
  DHExchangeResult result{0, 0, 0, false};

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return result;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(4000);
  inet_pton(AF_INET, "100.85.102.20", &addr.sin_addr);

  if (bind(sockfd, (sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(sockfd);
    return result;
  }
  if (listen(sockfd, 1) < 0) {
    perror("listen");
    close(sockfd);
    return result;
  }
  std::cout << "[A] Esperando conexion en 100.85.102.20:4000\n";

  sockaddr_in cli{};
  socklen_t clen = sizeof(cli);
  int csock = accept(sockfd, (sockaddr *)&cli, &clen);
  if (csock < 0) {
    perror("accept");
    close(sockfd);
    return result;
  }

  char ipbuf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &cli.sin_addr, ipbuf, sizeof(ipbuf));
  std::cout << "[A] Conectado cliente desde " << ipbuf << "\n";

  DiffieHellman dhA(PRIME_DH, GENERATOR_DH);
  dhA.generate_private_key();
  dhA.generate_public_key();
  uint64_t pubA = dhA.public_key();

  uint64_t netPubB;
  ssize_t r = read(csock, &netPubB, sizeof(netPubB));
  if (r != sizeof(netPubB)) {
    std::cerr << "[A] Error leyendo clave publica B\n";
    close(csock);
    close(sockfd);
    return result;
  }
  uint64_t pubB = be64toh(netPubB);
  std::cout << "[A] Clave Publica de B recibida.\n";

  uint64_t netPubA = htobe64(pubA);
  if (write(csock, &netPubA, sizeof(netPubA)) != sizeof(netPubA)) {
    std::cerr << "[A] Error enviando clave publica A\n";
    close(csock);
    close(sockfd);
    return result;
  }

  const char *msg = "OK_A";
  write(csock, msg, strlen(msg));

  close(csock);
  close(sockfd);
  std::cout << "[A] Socket cerrado.\n";

  result.localPriv = dhA.get_private_key();  // añadir getter si no existe
  result.localPub = pubA;
  result.remotePub = pubB;
  result.ok = true;
  return result;
}
