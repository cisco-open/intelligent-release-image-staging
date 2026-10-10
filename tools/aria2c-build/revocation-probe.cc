// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: GPL-2.0-or-later
// Exercise the exact native revocation reader without a network or daemon.
#include "BtPeerRevocations.h"
#include <iostream>
#include <memory>
#include <openssl/pem.h>

static std::unique_ptr<X509, decltype(&X509_free)> certificate(const char* path)
{
  std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_file(path, "r"), BIO_free);
  return {input ? PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr) : nullptr,
          X509_free};
}

int main(int argc, char** argv)
{
  if (argc != 4) return 2;
  auto local = certificate(argv[3]);
  aria2::BtPeerRevocations reader(argv[1], argv[2], local.get());
  std::string path;
  while (std::getline(std::cin, path)) {
    auto peer = certificate(path.c_str());
    bool allowed = reader.allowed(peer.get());
    auto status = reader.status();
    std::cout << "{\"allowed\":" << (allowed ? "true" : "false")
              << ",\"state\":\"" << status.state << "\",\"revision\":"
              << status.revision << ",\"own_revoked\":"
              << (status.ownRevoked ? "true" : "false") << "}" << std::endl;
  }
}
