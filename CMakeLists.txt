cmake_minimum_required(VERSION 3.19)
project(ethsignminitrezor C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

set(CFILES src/main.c
        src/ecdsa.c
        src/bignum.c
        src/hmac_drbg.c
        src/memzero.c
        src/rand.c
        src/rfc6979.c
        src/secp256k1.c
        src/sha2.c
        )

add_executable(ethsignminitrezor ${CFILES})