{
  "targets": [{
    "target_name": "bcrypto",
    "sources": [
      "./src/base58/base58.c",
      "./src/bech32/bech32.c",
      "./src/cash32/cash32.c",
      "./src/murmur3/murmur3.c",
      "./src/torsion/src/aead.c",
      "./src/torsion/src/chacha20.c",
      "./src/torsion/src/drbg.c",
      "./src/torsion/src/dsa.c",
      "./src/torsion/src/ecc.c",
      "./src/torsion/src/hash.c",
      "./src/torsion/src/kdf.c",
      "./src/torsion/src/poly1305.c",
      "./src/torsion/src/rsa.c",
      "./src/torsion/src/salsa20.c",
      "./src/torsion/src/siphash.c",
      "./src/torsion/src/util.c",
      "./src/bcrypto.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wextra",
      "-Wno-implicit-fallthrough",
      "-Wno-nonnull-compare",
      "-Wno-unknown-warning",
      "-Wno-unknown-warning-option",
      "-Wno-unused-function",
      "-O3"
    ],
    "cflags_c": [
      "-std=c89",
      "-pedantic",
      "-Wshadow",
      "-Wno-declaration-after-statement",
      "-Wno-long-long",
      "-Wno-overlength-strings"
    ],
    "include_dirs": [
      "./src/torsion/include"
    ],
    "variables": {
      "with_secp256k1%": "true",
      "conditions": [
        ["OS=='win'", {
          "with_gmp%": "false"
        }, {
          "with_gmp%": "<!(./utils/has_gmp.sh)"
        }]
      ]
    },
    "conditions": [
      ["node_byteorder=='big'", {
        "defines": [
          "WORDS_BIGENDIAN"
        ]
      }],
      ["target_arch=='x64' and OS!='win'", {
        "defines": [
          "TORSION_USE_64BIT",
          "TORSION_USE_ASM"
        ]
      }],
      ["with_gmp=='true'", {
        "defines": [
          "TORSION_USE_GMP",
        ],
        "libraries": [
          "-lgmp"
        ]
      }, {
        "sources": [
          "./src/torsion/src/mini-gmp.c"
        ],
        "cflags_c": [
          "-Wno-unused-parameter",
          "-Wno-sign-compare"
        ]
      }],
      ["OS!='win' and node_use_openssl=='true' and nodedir.find('electron')==-1", {
        "defines": [
          "TORSION_USE_OPENSSL"
        ]
      }],
      ["OS=='win'", {
        "msbuild_settings": {
          "ClCompile": {
            "ObjectFileName": "$(IntDir)/%(Directory)/%(Filename)"
          },
          "Link": {
            "ImageHasSafeExceptionHandlers": "false"
          }
        }
      }],
      ["with_secp256k1=='true'", {
        "defines": [
          "BCRYPTO_USE_SECP256K1",
          # "BCRYPTO_USE_SECP256K1_LATEST",
          # "ECMULT_GEN_PREC_BITS=4",
          # "ECMULT_WINDOW_SIZE=15",
          "USE_ENDOMORPHISM",
          "ENABLE_MODULE_ECDH",
          "ENABLE_MODULE_ELLIGATOR",
          "ENABLE_MODULE_EXTRA",
          "ENABLE_MODULE_RECOVERY",
          "ENABLE_MODULE_SCHNORRLEG"
          # "ENABLE_MODULE_SCHNORRSIG"
        ],
        "sources": [
          "./src/secp256k1/src/secp256k1.c",
          "./src/secp256k1/contrib/lax_der_parsing.c"
        ],
        # "include_dirs": [
        #   "./src/secp256k1",
        #   "./src/secp256k1/include",
        #   "./src/secp256k1/src"
        # ],
        "conditions": [
          ["target_arch=='x64' and OS!='win'", {
            "defines": [
              "HAVE___INT128",
              "USE_ASM_X86_64",
              "USE_FIELD_5X52",
              "USE_SCALAR_4X64"
            ]
          }, {
            "defines": [
              "USE_FIELD_10X26",
              "USE_SCALAR_8X32"
            ]
          }],
          ["with_gmp=='true'", {
            "defines": [
              "HAVE_LIBGMP",
              "USE_NUM_GMP",
              "USE_FIELD_INV_NUM",
              "USE_SCALAR_INV_NUM"
            ]
          }, {
            "defines": [
              "USE_NUM_NONE",
              "USE_FIELD_INV_BUILTIN",
              "USE_SCALAR_INV_BUILTIN"
            ]
          }]
        ]
      }]
    ]
  }]
}
