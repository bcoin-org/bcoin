{
  "variables": {
    "with_secp256k1%": "true"
  },
  "targets": [
    {
      "target_name": "torsion",
      "type": "static_library",
      "sources": [
        "./deps/torsion/src/aead.c",
        "./deps/torsion/src/asn1.c",
        "./deps/torsion/src/cipher.c",
        "./deps/torsion/src/drbg.c",
        "./deps/torsion/src/dsa.c",
        "./deps/torsion/src/ecc.c",
        "./deps/torsion/src/encoding.c",
        "./deps/torsion/src/entropy/env.c",
        "./deps/torsion/src/entropy/hw.c",
        "./deps/torsion/src/entropy/sys.c",
        "./deps/torsion/src/hash.c",
        "./deps/torsion/src/ies.c",
        "./deps/torsion/src/internal.c",
        "./deps/torsion/src/kdf.c",
        "./deps/torsion/src/mac.c",
        "./deps/torsion/src/mpi.c",
        "./deps/torsion/src/rand.c",
        "./deps/torsion/src/rsa.c",
        "./deps/torsion/src/stream.c",
        "./deps/torsion/src/util.c"
      ],
      "include_dirs": [
        "./deps/torsion/include"
      ],
      "direct_dependent_settings": {
        "include_dirs": [
          "./deps/torsion/include"
        ]
      },
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-std=c89",
            "-pedantic",
            "-Wcast-align",
            "-Wno-implicit-fallthrough",
            "-Wno-long-long",
            "-Wno-overlength-strings",
            "-Wshadow"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "MACOSX_DEPLOYMENT_TARGET": "10.7",
            "GCC_C_LANGUAGE_STANDARD": "c89",
            "WARNING_CFLAGS": [
              "-pedantic",
              "-Wcast-align",
              "-Wno-implicit-fallthrough",
              "-Wno-long-long",
              "-Wno-overlength-strings",
              "-Wshadow"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings=": [
            4146, # negation of unsigned integer
            4244, # implicit integer demotion
            4267, # implicit size_t demotion
            4334  # implicit 32->64 bit shift
          ]
        }],
        ["OS in 'mac linux freebsd openbsd solaris aix'", {
          "defines": [
            "TORSION_HAVE_PTHREAD"
          ]
        }]
      ]
    },
    {
      "target_name": "secp256k1",
      "type": "static_library",
      "sources": [
        "./deps/secp256k1/contrib/lax_der_parsing.c",
        "./deps/secp256k1/src/secp256k1.c"
      ],
      "include_dirs": [
        "./deps/secp256k1",
        "./deps/secp256k1/include",
        "./deps/secp256k1/src"
      ],
      "direct_dependent_settings": {
        "include_dirs": [
          "./deps/secp256k1/contrib",
          "./deps/secp256k1/include"
        ]
      },
      "defines": [
        "USE_NUM_NONE=1",
        "USE_FIELD_INV_BUILTIN=1",
        "USE_SCALAR_INV_BUILTIN=1",
        "ECMULT_WINDOW_SIZE=15",
        "ECMULT_GEN_PREC_BITS=4",
        "USE_ENDOMORPHISM=1",
        "ENABLE_MODULE_ECDH=1",
        "ENABLE_MODULE_RECOVERY=1",
        "ENABLE_MODULE_EXTRAKEYS=1",
        "ENABLE_MODULE_SCHNORRSIG=1",
        "ENABLE_MODULE_SCHNORRLEG=1",
        "ENABLE_MODULE_ELLIGATOR=1",
        "ENABLE_MODULE_EXTRA=1"
      ],
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-std=c89",
            "-pedantic",
            "-Wcast-align",
            "-Wnested-externs",
            "-Wno-long-long",
            "-Wno-nonnull-compare", # GCC only
            "-Wno-overlength-strings",
            "-Wno-unknown-warning", # GCC
            "-Wno-unknown-warning-option", # Clang
            "-Wno-unused-function",
            "-Wshadow",
            "-Wstrict-prototypes"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "GCC_C_LANGUAGE_STANDARD": "c89",
            "WARNING_CFLAGS": [
              "-pedantic",
              "-Wcast-align",
              "-Wnested-externs",
              "-Wno-long-long",
              "-Wno-overlength-strings",
              "-Wno-unused-function",
              "-Wshadow",
              "-Wstrict-prototypes"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings=": [
            4244, # implicit integer demotion
            4267, # implicit size_t demotion
            4334  # implicit 32->64 bit shift
          ]
        }],
        ["node_byteorder == 'big'", {
          "defines": [
            "SECP256K1_BIG_ENDIAN"
          ]
        }, {
          "defines": [
            "SECP256K1_LITTLE_ENDIAN"
          ]
        }],
        ["target_arch == 'x64' and OS != 'win'", {
          "defines": [
            "USE_ASM_X86_64=1",
            "USE_FORCE_WIDEMUL_INT128=1"
          ]
        }, {
          "defines": [
            "USE_FORCE_WIDEMUL_INT64=1"
          ]
        }]
      ]
    },
    {
      "target_name": "bcrypto",
      "dependencies": [
        "torsion"
      ],
      "sources": [
        "./src/bcrypto.c"
      ],
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-std=c99",
            "-Wcast-align",
            "-Wshadow"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "GCC_C_LANGUAGE_STANDARD": "c99",
            "WARNING_CFLAGS": [
              "-Wcast-align",
              "-Wshadow"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings=": [
            4244, # implicit integer demotion
            4267  # implicit size_t demotion
          ]
        }],
        ["with_secp256k1 == 'true'", {
          "dependencies": [
            "secp256k1"
          ],
          "defines": [
            "BCRYPTO_USE_SECP256K1"
          ]
        }]
      ]
    }
  ]
}
