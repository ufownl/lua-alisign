#include "sign.hpp"
#include "scope_guard.hpp"
#include <string>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/sha.h>

namespace alisign {

namespace {

void cook_key(const char* key, std::string& out) {
  for (size_t i = 0; key[i]; ++i) {
    if (i % 64 == 0) {
      out += '\n';
    }
    out += key[i];
  }
}

std::string cook_private_key(const char* private_key) {
  std::string result;
  result.reserve(2048);
  result += "-----BEGIN RSA PRIVATE KEY-----";
  cook_key(private_key, result);
  result += "\n-----END RSA PRIVATE KEY-----";
  return result;
}

std::string cook_public_key(const char* public_key) {
  std::string result;
  result.reserve(512);
  result = "-----BEGIN PUBLIC KEY-----";
  cook_key(public_key, result);
  result += "\n-----END PUBLIC KEY-----";
  return result;
}

}

std::vector<uint8_t> sign(const uint8_t* data, size_t data_len,
                          const char* sign_type, const char* private_key) {
  auto cooked_key = cook_private_key(private_key);
  auto bio = BIO_new_mem_buf(cooked_key.c_str(), -1);
  if (!bio) {
    return std::vector<uint8_t>{};
  }
  auto bio_g = make_scope_guard([&] { BIO_free_all(bio); });
  auto rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
  if (!rsa) {
    return std::vector<uint8_t>{};
  }
  auto rsa_g = make_scope_guard([&] { RSA_free(rsa); });
  if (std::strcmp(sign_type, "RSA") == 0) {
    uint8_t buf[SHA_DIGEST_LENGTH];
    std::vector<uint8_t> result(RSA_size(rsa));
    uint32_t sign_len;
    if (RSA_sign(NID_sha1, SHA1(data, data_len, buf), SHA_DIGEST_LENGTH,
                 result.data(), &sign_len, rsa)) {
      result.resize(sign_len);
      return result;
    }
  } else if (std::strcmp(sign_type, "RSA2") == 0) {
    uint8_t buf[SHA256_DIGEST_LENGTH];
    std::vector<uint8_t> result(RSA_size(rsa));
    uint32_t sign_len;
    if (RSA_sign(NID_sha256, SHA256(data, data_len, buf), SHA256_DIGEST_LENGTH,
                 result.data(), &sign_len, rsa)) {
      result.resize(sign_len);
      return result;
    }
  }
  return std::vector<uint8_t>{};
}

int verify_sign(const uint8_t* data, size_t data_len,
                const uint8_t* sign, size_t sign_len,
                const char* sign_type, const char* public_key) {
  auto cooked_key = cook_public_key(public_key);
  auto bio = BIO_new_mem_buf(cooked_key.c_str(), -1);
  if (!bio) {
    return 0;
  }
  auto bio_g = make_scope_guard([&] { BIO_free_all(bio); });
  auto rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
  if (!rsa) {
    return 0;
  }
  auto rsa_g = make_scope_guard([&] { RSA_free(rsa); });
  if (std::strcmp(sign_type, "RSA") == 0) {
    uint8_t buf[SHA_DIGEST_LENGTH];
    return RSA_verify(NID_sha1, SHA1(data, data_len, buf), SHA_DIGEST_LENGTH,
                      sign, sign_len, rsa);
  } else if (std::strcmp(sign_type, "RSA2") == 0) {
    uint8_t buf[SHA256_DIGEST_LENGTH];
    return RSA_verify(NID_sha256, SHA256(data, data_len, buf),
                      SHA256_DIGEST_LENGTH, sign, sign_len, rsa);
  }
  return 0;
}

}
