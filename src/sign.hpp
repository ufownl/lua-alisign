#ifndef ALISIGN_SIGN_HPP
#define ALISIGN_SIGN_HPP

#include <vector>
#include <stdint.h>
#include <stddef.h>

namespace alisign {

std::vector<uint8_t> sign(const uint8_t* data, size_t data_len,
                          const char* sign_type, const char* private_key);

int verify_sign(const uint8_t* data, size_t data_len,
                const uint8_t* sign, size_t sign_len,
                const char* sign_type, const char* public_key);

}

#endif  // ALISIGN_SIGN_HPP
