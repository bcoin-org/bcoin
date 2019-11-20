{
  "variables": {
    "bcrypto_byteorder%":
      "<!(python -c 'from __future__ import print_function; import sys; print(sys.byteorder)')",
  },
  "targets": [{
    "target_name": "bcrypto",
    "sources": [
      "./src/aead/aead.c",
      "./src/aes/aes.c",
      "./src/blake2b/blake2b.c",
      "./src/blake2s/blake2s.c",
      "./src/chacha20/chacha20.c",
      "./src/dsa/dsa.c",
      "./src/ecdsa/ecdsa.c",
      "./src/ed25519/ed25519.c",
      "./src/ed448/arch_32/f_impl.c",
      "./src/ed448/curve448.c",
      "./src/ed448/curve448_tables.c",
      "./src/ed448/eddsa.c",
      "./src/ed448/f_generic.c",
      "./src/ed448/scalar.c",
      "./src/murmur3/murmur3.c",
      "./src/pbkdf2/pbkdf2.c",
      "./src/poly1305/poly1305.c",
      "./src/random/random.c",
      "./src/rsa/rsa.c",
      "./src/scrypt/insecure_memzero.c",
      "./src/scrypt/sha256.c",
      "./src/scrypt/scrypt.c",
      "./src/secp256k1/src/secp256k1.c",
      "./src/secp256k1/contrib/lax_der_parsing.c",
      "./src/secp256k1/contrib/lax_der_privatekey_parsing.c",
      "./src/siphash/siphash.c",
      "./src/keccak/keccak.c",
      "./src/aead.cc",
      "./src/aes.cc",
      "./src/bcrypto.cc",
      "./src/blake2b.cc",
      "./src/blake2s.cc",
      "./src/chacha20.cc",
      "./src/cipherbase.cc",
      "./src/dsa.cc",
      "./src/dsa_async.cc",
      "./src/ecdsa.cc",
      "./src/ed25519.cc",
      "./src/ed448.cc",
      "./src/hash160.cc",
      "./src/hash256.cc",
      "./src/keccak.cc",
      "./src/md4.cc",
      "./src/md5.cc",
      "./src/murmur3.cc",
      "./src/pbkdf2.cc",
      "./src/pbkdf2_async.cc",
      "./src/poly1305.cc",
      "./src/random.cc",
      "./src/ripemd160.cc",
      "./src/rsa.cc",
      "./src/rsa_async.cc",
      "./src/scrypt.cc",
      "./src/scrypt_async.cc",
      "./src/secp256k1.cc",
      "./src/sha1.cc",
      "./src/sha224.cc",
      "./src/sha256.cc",
      "./src/sha384.cc",
      "./src/sha512.cc",
      "./src/siphash.cc",
      "./src/whirlpool.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wno-unknown-warning-option",
      "-Wno-maybe-uninitialized",
      "-Wno-cast-function-type",
      "-Wno-unused-result",
      "-Wno-nonnull-compare",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99",
      "-Wno-unused-parameter"
    ],
    "cflags_cc+": [
      "-std=c++0x",
      "-Wno-maybe-uninitialized",
      "-Wno-cast-function-type",
      "-Wno-unused-parameter",
      "-Wno-unknown-warning-option",
      "-Wno-unused-const-variable",
      "-Wno-undefined-internal"
    ],
    "include_dirs": [
      "/usr/local/include",
      "<!(node -e \"require('nan')\")"
    ],
    "defines": [
      "ENABLE_MODULE_RECOVERY=1",
      "ENABLE_MODULE_SCHNORRSIG=1"
    ],
    "variables": {
      "conditions": [
        ["OS!='win'", {
          "cc": "<!(echo $CC)"
        }],
        ["OS=='win'", {
          "conditions": [
            ["target_arch=='ia32'", {
              "openssl_root%": "C:/OpenSSL-Win32"
            }, {
              "openssl_root%": "C:/OpenSSL-Win64"
            }]
          ]
        }],
        ["OS=='win'", {
          "with_gmp%": "false"
        }, {
          "with_gmp%": "<!(utils/has_lib.sh gmp)"
        }]
      ]
    },
    "conditions": [
      ["target_arch=='x64' and OS!='win' and cc=='clang'", {
        "cflags": [
          "-msse4.1"
        ]
      }],
      ["bcrypto_byteorder=='little'", {
        "defines": [
          "BCRYPTO_LITTLE_ENDIAN"
        ]
      }, {
        "defines": [
          "BCRYPTO_BIG_ENDIAN"
        ]
      }],
      ["target_arch=='x64' and OS!='win'", {
        "defines": [
          "BCRYPTO_POLY1305_64BIT",
          "BCRYPTO_SIPHASH_64BIT",
          "BCRYPTO_USE_ASM",
          "BCRYPTO_USE_SSE",
          "BCRYPTO_USE_SSE41",
          "HAVE___INT128=1",
          "USE_ASM_X86_64=1",
          "USE_FIELD_5X52=1",
          "USE_FIELD_5X52_INT128=1",
          "USE_SCALAR_4X64=1"
        ]
      }, {
        "defines": [
          "BCRYPTO_POLY1305_32BIT",
          "BCRYPTO_ED25519_NO_INLINE_ASM",
          "USE_FIELD_10X26=1",
          "USE_SCALAR_8X32=1"
        ]
      }],
      ["OS=='win'", {
        "libraries": [
          "-l<(openssl_root)/lib/libeay32.lib"
        ],
        "include_dirs": [
          "<(openssl_root)/include"
        ]
      }, {
        "include_dirs": [
          "<(node_root_dir)/deps/openssl/openssl/include"
        ]
      }],
      ["with_gmp=='true'", {
        "defines": [
          "HAVE_LIBGMP=1",
          "USE_NUM_GMP=1",
          "USE_FIELD_INV_NUM=1",
          "USE_SCALAR_INV_NUM=1"
        ],
        "libraries": [
          "-lgmp"
        ]
      }, {
        "defines": [
          "USE_NUM_NONE=1",
          "USE_FIELD_INV_BUILTIN=1",
          "USE_SCALAR_INV_BUILTIN=1"
        ]
      }],
      ["OS=='mac'", {
        "libraries": [
          "-L/usr/local/lib"
        ],
        "xcode_settings": {
          "MACOSX_DEPLOYMENT_TARGET": "10.7",
          "OTHER_CPLUSPLUSFLAGS": [
            "-stdlib=libc++"
          ]
        }
      }]
    ]
  }]
}
