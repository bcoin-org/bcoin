{
  "targets": [
    {
      "target_name": "snappy",
      "type": "static_library",
      "sources": [
        "deps/leveldb/deps/snappy/snappy-c.cc",
        "deps/leveldb/deps/snappy/snappy-sinksource.cc",
        "deps/leveldb/deps/snappy/snappy-stubs-internal.cc",
        "deps/leveldb/deps/snappy/snappy.cc"
      ],
      "include_dirs": [
        "deps/config",
        "deps/leveldb/deps/snappy"
      ],
      "direct_dependent_settings": {
        "include_dirs": [
          "deps/config",
          "deps/leveldb/deps/snappy"
        ],
        "conditions": [
          ["OS in 'mac ios linux android freebsd openbsd solaris'", {
            "defines": [
              "HAVE_SYS_UIO_H=1"
            ]
          }]
        ]
      },
      "defines": [
        "SNAPPY_HAVE_SSSE3=0",
        "SNAPPY_HAVE_BMI2=0"
      ],
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-Wno-sign-compare"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "WARNING_CFLAGS": [
              "-Wno-sign-compare"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings": [
            4018,
            4244,
            4267,
            4355,
            4506,
            4530,
            4722,
            4996
          ]
        }],
        ["OS == 'win'", {
          "defines": [
            "HAVE_WINDOWS_H=1"
          ]
        }, {
          "defines": [
            "HAVE_SYS_RESOURCE_H=1",
            "HAVE_SYS_TIME_H=1",
            "HAVE_UNISTD_H=1"
          ]
        }],
        ["OS == 'mac' or OS == 'ios'", {
          "defines": [
            "HAVE_SYS_MMAN_H=1",
            "HAVE_SYS_UIO_H=1",
            "HAVE_BUILTIN_EXPECT=1",
            "HAVE_BUILTIN_CTZ=1",
            "HAVE_FUNC_MMAP=1",
            "HAVE_FUNC_SYSCONF=1"
          ]
        }],
        ["OS == 'linux' or OS == 'android'", {
          "defines": [
            "HAVE_BYTESWAP_H=1",
            "HAVE_SYS_MMAN_H=1",
            "HAVE_SYS_UIO_H=1",
            "HAVE_BUILTIN_EXPECT=1",
            "HAVE_BUILTIN_CTZ=1",
            "HAVE_FUNC_MMAP=1",
            "HAVE_FUNC_SYSCONF=1"
          ]
        }],
        ["OS == 'freebsd'", {
          "defines": [
            "HAVE_SYS_ENDIAN_H=1",
            "HAVE_SYS_MMAN_H=1",
            "HAVE_SYS_UIO_H=1",
            "HAVE_BUILTIN_EXPECT=1",
            "HAVE_BUILTIN_CTZ=1",
            "HAVE_FUNC_MMAP=1",
            "HAVE_FUNC_SYSCONF=1"
          ]
        }],
        ["OS == 'openbsd'", {
          "defines": [
            "HAVE_SYS_ENDIAN_H=1",
            "HAVE_SYS_MMAN_H=1",
            "HAVE_SYS_UIO_H=1",
            "HAVE_BUILTIN_EXPECT=1",
            "HAVE_BUILTIN_CTZ=1",
            "HAVE_FUNC_MMAP=1",
            "HAVE_FUNC_SYSCONF=1"
          ]
        }],
        ["OS == 'solaris'", {
          "defines": [
            "HAVE_SYS_MMAN_H=1",
            "HAVE_SYS_UIO_H=1",
            "HAVE_BUILTIN_EXPECT=1",
            "HAVE_BUILTIN_CTZ=1",
            "HAVE_FUNC_MMAP=1",
            "HAVE_FUNC_SYSCONF=1"
          ]
        }],
        ["node_byteorder == 'big'", {
          "defines": [
            "SNAPPY_IS_BIG_ENDIAN=1"
          ]
        }]
      ]
    },
    {
      "target_name": "leveldb",
      "type": "static_library",
      "dependencies": [
        "snappy"
      ],
      "sources": [
        "deps/leveldb/db/builder.cc",
        "deps/leveldb/db/c.cc",
        "deps/leveldb/db/db_impl.cc",
        "deps/leveldb/db/db_iter.cc",
        "deps/leveldb/db/dbformat.cc",
        "deps/leveldb/db/dumpfile.cc",
        "deps/leveldb/db/filename.cc",
        "deps/leveldb/db/log_reader.cc",
        "deps/leveldb/db/log_writer.cc",
        "deps/leveldb/db/memtable.cc",
        "deps/leveldb/db/repair.cc",
        "deps/leveldb/db/table_cache.cc",
        "deps/leveldb/db/version_edit.cc",
        "deps/leveldb/db/version_set.cc",
        "deps/leveldb/db/write_batch.cc",
        "deps/leveldb/table/block_builder.cc",
        "deps/leveldb/table/block.cc",
        "deps/leveldb/table/filter_block.cc",
        "deps/leveldb/table/format.cc",
        "deps/leveldb/table/iterator.cc",
        "deps/leveldb/table/merger.cc",
        "deps/leveldb/table/table_builder.cc",
        "deps/leveldb/table/table.cc",
        "deps/leveldb/table/two_level_iterator.cc",
        "deps/leveldb/util/arena.cc",
        "deps/leveldb/util/bloom.cc",
        "deps/leveldb/util/cache.cc",
        "deps/leveldb/util/coding.cc",
        "deps/leveldb/util/comparator.cc",
        "deps/leveldb/util/crc32c.cc",
        "deps/leveldb/util/env.cc",
        "deps/leveldb/util/filter_policy.cc",
        "deps/leveldb/util/hash.cc",
        "deps/leveldb/util/logging.cc",
        "deps/leveldb/util/options.cc",
        "deps/leveldb/util/status.cc",
        "deps/leveldb/helpers/memenv/memenv.cc"
      ],
      "include_dirs": [
        "deps/leveldb/include",
        "deps/leveldb"
      ],
      "direct_dependent_settings": {
        "include_dirs": [
          "deps/leveldb/include"
        ]
      },
      "defines": [
        "LEVELDB_COMPILE_LIBRARY",
        "HAVE_CRC32C=0",
        "HAVE_SNAPPY=1"
      ],
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-Wno-implicit-fallthrough"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "WARNING_CFLAGS": [
              "-Wno-implicit-fallthrough"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings": [
            4018,
            4244,
            4267,
            4355,
            4506,
            4530,
            4722,
            4996
          ]
        }],
        ["OS == 'win'", {
          "defines": [
            "LEVELDB_PLATFORM_WINDOWS=1",
            "HAVE_FDATASYNC=0",
            "HAVE_FULLFSYNC=0",
            "_UNICODE",
            "UNICODE"
          ],
          "sources": [
            "deps/leveldb/util/env_windows.cc"
          ]
        }, {
          "defines": [
            "LEVELDB_PLATFORM_POSIX=1",
            "HAVE_UNISTD_H=1"
          ],
          "sources": [
            "deps/leveldb/util/env_posix.cc"
          ]
        }],
        ["OS == 'mac' or OS == 'ios'", {
          "defines": [
            "HAVE_FDATASYNC=0",
            "HAVE_FULLFSYNC=1"
          ]
        }],
        ["OS == 'linux' or OS == 'android'", {
          "defines": [
            "HAVE_FDATASYNC=1",
            "HAVE_FULLFSYNC=0"
          ]
        }],
        ["OS == 'freebsd'", {
          "defines": [
            "HAVE_FDATASYNC=1",
            "HAVE_FULLFSYNC=0"
          ]
        }],
        ["OS == 'openbsd'", {
          "defines": [
            "HAVE_FDATASYNC=1",
            "HAVE_FULLFSYNC=0"
          ]
        }],
        ["OS == 'solaris'", {
          "defines": [
            "HAVE_FDATASYNC=1",
            "HAVE_FULLFSYNC=0"
          ]
        }],
        ["OS not in 'win mac ios linux android freebsd openbsd solaris'", {
          "defines": [
            "HAVE_FDATASYNC=0",
            "HAVE_FULLFSYNC=0"
          ]
        }],
        ["node_byteorder == 'big'", {
          "defines": [
            "LEVELDB_IS_BIG_ENDIAN=1"
          ]
        }, {
          "defines": [
            "LEVELDB_IS_BIG_ENDIAN=0"
          ]
        }]
      ]
    },
    {
      "target_name": "leveldown",
      "dependencies": [
        "leveldb"
      ],
      "sources": [
        "src/binding.cc"
      ]
    }
  ]
}
