{
  "variables": {
    "mrmr_byteorder%":
      "<!(python -c 'from __future__ import print_function; import sys; print(sys.byteorder)')",
  },
  "targets": [{
    "target_name": "mrmr",
    "sources": [
      "./src/murmur3.cc",
      "./src/mrmr.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wno-cast-function-type",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99"
    ],
    "cflags_cc+": [
      "-std=c++0x"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "conditions": [
      ["mrmr_byteorder=='little'", {
        "defines": [
          "MRMR_LITTLE_ENDIAN"
        ]
      }, {
        "defines": [
          "MRMR_BIG_ENDIAN"
        ]
      }]
    ]
  }]
}
