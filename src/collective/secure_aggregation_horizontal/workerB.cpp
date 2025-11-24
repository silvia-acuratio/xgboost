#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
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

DHExchangeResult clienteB() {
  DHExchangeResult result{0, 0, 0, false};

  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return result;
  }

  sockaddr_in serv{};
  serv.sin_family = AF_INET;
  serv.sin_port = htons(4000);
  inet_pton(AF_INET, "100.85.102.20", &serv.sin_addr);

  if (connect(sockfd, (sockaddr *)&serv, sizeof(serv)) != 0) {
    perror("connect");
    close(sockfd);
    return result;
  }
  std::cout << "[B] Conectado a servidor A\n";

  DiffieHellman dhB(PRIME_DH, GENERATOR_DH);
  dhB.generate_private_key();
  dhB.generate_public_key();
  uint64_t pubB = dhB.public_key();

  uint64_t netPubB = htobe64(pubB);
  if (write(sockfd, &netPubB, sizeof(netPubB)) != sizeof(netPubB)) {
    std::cerr << "[B] Error enviando clave publica B\n";
    close(sockfd);
    return result;
  }

  uint64_t netPubA;
  ssize_t r = read(sockfd, &netPubA, sizeof(netPubA));
  if (r != sizeof(netPubA)) {
    std::cerr << "[B] Error leyendo clave publica A\n";
    close(sockfd);
    return result;
  }
  uint64_t pubA = be64toh(netPubA);
  std::cout << "[B] Clave Publica de A recibida.\n";

  char buffer[32]{};
  read(sockfd, buffer, sizeof(buffer) - 1);
  std::cout << "[B] Mensaje posterior: " << buffer << "\n";

  close(sockfd);
  std::cout << "[B] Socket cerrado.\n";

  uint64_t shared = DiffieHellman::modexp(result.remotePub, result.localPriv, PRIME_DH);
  std::cout << "[B] Secreto compartido (hex): 0x" << std::hex << shared << std::dec << "\n";
  result.localPriv = dhB.get_private_key();  // añadir getter
  result.localPub = pubB;
  result.remotePub = pubA;
  result.ok = true;
  result.sharedSecret = shared;
  return result;
}
