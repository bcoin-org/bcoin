/*!
 * cipher.c - ciphers for libtorsion
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/libtorsion
 *
 * Parts of this software are based on openssl/openssl:
 *   Based on code entered into the public domain by Vincent Rijmen.
 *   https://github.com/openssl/openssl/blob/master/crypto/aes/aes_core.c
 *
 * Parts of this software are based on joyent/node-bcrypt-pbkdf:
 *   Copyright (c) 2016, Joyent Inc
 *   https://github.com/joyent/node-bcrypt-pbkdf
 *
 * Parts of this software are based on aead/camellia:
 *   Copyright (c) 2016, Andreas Auernhammer (MIT License).
 *   https://github.com/aead/camellia
 *
 * Parts of this software are based on aead/serpent:
 *   Copyright (c) 2016, Andreas Auernhammer (MIT License).
 *   https://github.com/aead/camellia
 *
 * Parts of this software are based on indutny/des.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/des.js
 *
 * Parts of this software are based on dgryski/go-idea:
 *   Copyright (c) 2013-2017, Damian Gryski. All rights reserved.
 *   https://github.com/dgryski/go-idea
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <torsion/cipher.h>
#include <torsion/util.h>
#include "bf.h"
#include "bio.h"

/*
 * Constants
 */

/* Shifted by four. */
static const uint32_t poly_table[9] = {
  0x00001b, /* 8 */
  0x000087, /* 16 */
  0x000425, /* 32 */
  0x000000,
  0x000125, /* 64 */
  0x000000,
  0x000000,
  0x000000,
  0x080043  /* 128 */
};

/*
 * AES
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 *   http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 *   https://github.com/openssl/openssl/blob/master/crypto/aes/aes_core.c
 */

#define TE0 aes_TE0
#define TE1 aes_TE1
#define TE2 aes_TE2
#define TE3 aes_TE3
#define TD0 aes_TD0
#define TD1 aes_TD1
#define TD2 aes_TD2
#define TD3 aes_TD3
#define TD4 aes_TD4
#define RCON aes_RCON

static const uint32_t TE0[256] = {
  0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d,
  0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554,
  0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d,
  0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a,
  0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87,
  0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b,
  0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea,
  0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b,
  0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a,
  0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f,
  0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108,
  0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f,
  0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e,
  0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5,
  0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d,
  0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f,
  0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e,
  0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb,
  0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce,
  0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497,
  0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c,
  0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed,
  0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b,
  0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a,
  0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16,
  0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594,
  0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81,
  0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3,
  0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a,
  0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504,
  0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163,
  0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d,
  0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f,
  0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739,
  0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47,
  0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395,
  0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f,
  0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883,
  0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c,
  0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76,
  0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e,
  0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4,
  0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6,
  0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b,
  0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7,
  0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0,
  0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25,
  0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818,
  0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72,
  0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651,
  0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21,
  0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85,
  0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa,
  0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12,
  0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0,
  0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9,
  0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133,
  0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7,
  0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920,
  0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a,
  0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17,
  0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8,
  0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11,
  0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a
};

static const uint32_t TE1[256] = {
  0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b,
  0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5,
  0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b,
  0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676,
  0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d,
  0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0,
  0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf,
  0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0,
  0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626,
  0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc,
  0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1,
  0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515,
  0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3,
  0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a,
  0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2,
  0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575,
  0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a,
  0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0,
  0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3,
  0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484,
  0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded,
  0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b,
  0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939,
  0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf,
  0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb,
  0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585,
  0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f,
  0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8,
  0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f,
  0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5,
  0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121,
  0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2,
  0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec,
  0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717,
  0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d,
  0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373,
  0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc,
  0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888,
  0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414,
  0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb,
  0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a,
  0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c,
  0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262,
  0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979,
  0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d,
  0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9,
  0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea,
  0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808,
  0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e,
  0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6,
  0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f,
  0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a,
  0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666,
  0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e,
  0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9,
  0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e,
  0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111,
  0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494,
  0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9,
  0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf,
  0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d,
  0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868,
  0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f,
  0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616
};

static const uint32_t TE2[256] = {
  0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b,
  0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5,
  0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b,
  0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76,
  0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d,
  0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0,
  0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af,
  0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0,
  0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26,
  0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc,
  0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1,
  0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15,
  0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3,
  0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a,
  0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2,
  0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75,
  0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a,
  0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0,
  0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3,
  0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384,
  0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed,
  0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b,
  0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239,
  0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf,
  0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb,
  0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185,
  0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f,
  0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8,
  0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f,
  0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5,
  0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221,
  0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2,
  0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec,
  0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17,
  0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d,
  0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673,
  0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc,
  0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88,
  0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814,
  0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb,
  0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a,
  0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c,
  0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462,
  0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279,
  0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d,
  0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9,
  0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea,
  0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008,
  0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e,
  0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6,
  0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f,
  0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a,
  0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66,
  0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e,
  0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9,
  0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e,
  0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211,
  0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394,
  0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9,
  0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df,
  0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d,
  0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068,
  0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f,
  0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16
};

static const uint32_t TE3[256] = {
  0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6,
  0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491,
  0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56,
  0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec,
  0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa,
  0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb,
  0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45,
  0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b,
  0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c,
  0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83,
  0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9,
  0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a,
  0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d,
  0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f,
  0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf,
  0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea,
  0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34,
  0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b,
  0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d,
  0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713,
  0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1,
  0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6,
  0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72,
  0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85,
  0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed,
  0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411,
  0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe,
  0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b,
  0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05,
  0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1,
  0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342,
  0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf,
  0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3,
  0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e,
  0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a,
  0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6,
  0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3,
  0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b,
  0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28,
  0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad,
  0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14,
  0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8,
  0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4,
  0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2,
  0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da,
  0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049,
  0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf,
  0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810,
  0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c,
  0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197,
  0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e,
  0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f,
  0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc,
  0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c,
  0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069,
  0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927,
  0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322,
  0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733,
  0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9,
  0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5,
  0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a,
  0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0,
  0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e,
  0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c
};

static const uint32_t TD0[256] = {
  0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96,
  0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393,
  0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25,
  0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f,
  0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1,
  0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6,
  0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da,
  0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844,
  0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd,
  0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4,
  0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45,
  0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94,
  0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7,
  0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a,
  0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5,
  0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c,
  0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1,
  0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a,
  0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75,
  0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051,
  0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46,
  0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff,
  0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77,
  0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb,
  0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000,
  0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e,
  0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927,
  0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a,
  0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e,
  0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16,
  0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d,
  0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8,
  0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd,
  0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34,
  0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163,
  0xd731dcca, 0x42638510, 0x13972240, 0x84c61120,
  0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d,
  0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0,
  0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422,
  0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef,
  0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36,
  0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4,
  0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662,
  0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5,
  0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3,
  0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b,
  0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8,
  0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6,
  0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6,
  0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0,
  0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815,
  0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f,
  0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df,
  0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f,
  0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e,
  0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713,
  0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89,
  0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c,
  0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf,
  0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86,
  0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f,
  0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541,
  0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190,
  0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742
};

static const uint32_t TD1[256] = {
  0x5051f4a7, 0x537e4165, 0xc31a17a4, 0x963a275e,
  0xcb3bab6b, 0xf11f9d45, 0xabacfa58, 0x934be303,
  0x552030fa, 0xf6ad766d, 0x9188cc76, 0x25f5024c,
  0xfc4fe5d7, 0xd7c52acb, 0x80263544, 0x8fb562a3,
  0x49deb15a, 0x6725ba1b, 0x9845ea0e, 0xe15dfec0,
  0x02c32f75, 0x12814cf0, 0xa38d4697, 0xc66bd3f9,
  0xe7038f5f, 0x9515929c, 0xebbf6d7a, 0xda955259,
  0x2dd4be83, 0xd3587421, 0x2949e069, 0x448ec9c8,
  0x6a75c289, 0x78f48e79, 0x6b99583e, 0xdd27b971,
  0xb6bee14f, 0x17f088ad, 0x66c920ac, 0xb47dce3a,
  0x1863df4a, 0x82e51a31, 0x60975133, 0x4562537f,
  0xe0b16477, 0x84bb6bae, 0x1cfe81a0, 0x94f9082b,
  0x58704868, 0x198f45fd, 0x8794de6c, 0xb7527bf8,
  0x23ab73d3, 0xe2724b02, 0x57e31f8f, 0x2a6655ab,
  0x07b2eb28, 0x032fb5c2, 0x9a86c57b, 0xa5d33708,
  0xf2302887, 0xb223bfa5, 0xba02036a, 0x5ced1682,
  0x2b8acf1c, 0x92a779b4, 0xf0f307f2, 0xa14e69e2,
  0xcd65daf4, 0xd50605be, 0x1fd13462, 0x8ac4a6fe,
  0x9d342e53, 0xa0a2f355, 0x32058ae1, 0x75a4f6eb,
  0x390b83ec, 0xaa4060ef, 0x065e719f, 0x51bd6e10,
  0xf93e218a, 0x3d96dd06, 0xaedd3e05, 0x464de6bd,
  0xb591548d, 0x0571c45d, 0x6f0406d4, 0xff605015,
  0x241998fb, 0x97d6bde9, 0xcc894043, 0x7767d99e,
  0xbdb0e842, 0x8807898b, 0x38e7195b, 0xdb79c8ee,
  0x47a17c0a, 0xe97c420f, 0xc9f8841e, 0x00000000,
  0x83098086, 0x48322bed, 0xac1e1170, 0x4e6c5a72,
  0xfbfd0eff, 0x560f8538, 0x1e3daed5, 0x27362d39,
  0x640a0fd9, 0x21685ca6, 0xd19b5b54, 0x3a24362e,
  0xb10c0a67, 0x0f9357e7, 0xd2b4ee96, 0x9e1b9b91,
  0x4f80c0c5, 0xa261dc20, 0x695a774b, 0x161c121a,
  0x0ae293ba, 0xe5c0a02a, 0x433c22e0, 0x1d121b17,
  0x0b0e090d, 0xadf28bc7, 0xb92db6a8, 0xc8141ea9,
  0x8557f119, 0x4caf7507, 0xbbee99dd, 0xfda37f60,
  0x9ff70126, 0xbc5c72f5, 0xc544663b, 0x345bfb7e,
  0x768b4329, 0xdccb23c6, 0x68b6edfc, 0x63b8e4f1,
  0xcad731dc, 0x10426385, 0x40139722, 0x2084c611,
  0x7d854a24, 0xf8d2bb3d, 0x11aef932, 0x6dc729a1,
  0x4b1d9e2f, 0xf3dcb230, 0xec0d8652, 0xd077c1e3,
  0x6c2bb316, 0x99a970b9, 0xfa119448, 0x2247e964,
  0xc4a8fc8c, 0x1aa0f03f, 0xd8567d2c, 0xef223390,
  0xc787494e, 0xc1d938d1, 0xfe8ccaa2, 0x3698d40b,
  0xcfa6f581, 0x28a57ade, 0x26dab78e, 0xa43fadbf,
  0xe42c3a9d, 0x0d507892, 0x9b6a5fcc, 0x62547e46,
  0xc2f68d13, 0xe890d8b8, 0x5e2e39f7, 0xf582c3af,
  0xbe9f5d80, 0x7c69d093, 0xa96fd52d, 0xb3cf2512,
  0x3bc8ac99, 0xa710187d, 0x6ee89c63, 0x7bdb3bbb,
  0x09cd2678, 0xf46e5918, 0x01ec9ab7, 0xa8834f9a,
  0x65e6956e, 0x7eaaffe6, 0x0821bccf, 0xe6ef15e8,
  0xd9bae79b, 0xce4a6f36, 0xd4ea9f09, 0xd629b07c,
  0xaf31a4b2, 0x312a3f23, 0x30c6a594, 0xc035a266,
  0x37744ebc, 0xa6fc82ca, 0xb0e090d0, 0x1533a7d8,
  0x4af10498, 0xf741ecda, 0x0e7fcd50, 0x2f1791f6,
  0x8d764dd6, 0x4d43efb0, 0x54ccaa4d, 0xdfe49604,
  0xe39ed1b5, 0x1b4c6a88, 0xb8c12c1f, 0x7f466551,
  0x049d5eea, 0x5d018c35, 0x73fa8774, 0x2efb0b41,
  0x5ab3671d, 0x5292dbd2, 0x33e91056, 0x136dd647,
  0x8c9ad761, 0x7a37a10c, 0x8e59f814, 0x89eb133c,
  0xeecea927, 0x35b761c9, 0xede11ce5, 0x3c7a47b1,
  0x599cd2df, 0x3f55f273, 0x791814ce, 0xbf73c737,
  0xea53f7cd, 0x5b5ffdaa, 0x14df3d6f, 0x867844db,
  0x81caaff3, 0x3eb968c4, 0x2c382434, 0x5fc2a340,
  0x72161dc3, 0x0cbce225, 0x8b283c49, 0x41ff0d95,
  0x7139a801, 0xde080cb3, 0x9cd8b4e4, 0x906456c1,
  0x617bcb84, 0x70d532b6, 0x74486c5c, 0x42d0b857
};

static const uint32_t TD2[256] = {
  0xa75051f4, 0x65537e41, 0xa4c31a17, 0x5e963a27,
  0x6bcb3bab, 0x45f11f9d, 0x58abacfa, 0x03934be3,
  0xfa552030, 0x6df6ad76, 0x769188cc, 0x4c25f502,
  0xd7fc4fe5, 0xcbd7c52a, 0x44802635, 0xa38fb562,
  0x5a49deb1, 0x1b6725ba, 0x0e9845ea, 0xc0e15dfe,
  0x7502c32f, 0xf012814c, 0x97a38d46, 0xf9c66bd3,
  0x5fe7038f, 0x9c951592, 0x7aebbf6d, 0x59da9552,
  0x832dd4be, 0x21d35874, 0x692949e0, 0xc8448ec9,
  0x896a75c2, 0x7978f48e, 0x3e6b9958, 0x71dd27b9,
  0x4fb6bee1, 0xad17f088, 0xac66c920, 0x3ab47dce,
  0x4a1863df, 0x3182e51a, 0x33609751, 0x7f456253,
  0x77e0b164, 0xae84bb6b, 0xa01cfe81, 0x2b94f908,
  0x68587048, 0xfd198f45, 0x6c8794de, 0xf8b7527b,
  0xd323ab73, 0x02e2724b, 0x8f57e31f, 0xab2a6655,
  0x2807b2eb, 0xc2032fb5, 0x7b9a86c5, 0x08a5d337,
  0x87f23028, 0xa5b223bf, 0x6aba0203, 0x825ced16,
  0x1c2b8acf, 0xb492a779, 0xf2f0f307, 0xe2a14e69,
  0xf4cd65da, 0xbed50605, 0x621fd134, 0xfe8ac4a6,
  0x539d342e, 0x55a0a2f3, 0xe132058a, 0xeb75a4f6,
  0xec390b83, 0xefaa4060, 0x9f065e71, 0x1051bd6e,
  0x8af93e21, 0x063d96dd, 0x05aedd3e, 0xbd464de6,
  0x8db59154, 0x5d0571c4, 0xd46f0406, 0x15ff6050,
  0xfb241998, 0xe997d6bd, 0x43cc8940, 0x9e7767d9,
  0x42bdb0e8, 0x8b880789, 0x5b38e719, 0xeedb79c8,
  0x0a47a17c, 0x0fe97c42, 0x1ec9f884, 0x00000000,
  0x86830980, 0xed48322b, 0x70ac1e11, 0x724e6c5a,
  0xfffbfd0e, 0x38560f85, 0xd51e3dae, 0x3927362d,
  0xd9640a0f, 0xa621685c, 0x54d19b5b, 0x2e3a2436,
  0x67b10c0a, 0xe70f9357, 0x96d2b4ee, 0x919e1b9b,
  0xc54f80c0, 0x20a261dc, 0x4b695a77, 0x1a161c12,
  0xba0ae293, 0x2ae5c0a0, 0xe0433c22, 0x171d121b,
  0x0d0b0e09, 0xc7adf28b, 0xa8b92db6, 0xa9c8141e,
  0x198557f1, 0x074caf75, 0xddbbee99, 0x60fda37f,
  0x269ff701, 0xf5bc5c72, 0x3bc54466, 0x7e345bfb,
  0x29768b43, 0xc6dccb23, 0xfc68b6ed, 0xf163b8e4,
  0xdccad731, 0x85104263, 0x22401397, 0x112084c6,
  0x247d854a, 0x3df8d2bb, 0x3211aef9, 0xa16dc729,
  0x2f4b1d9e, 0x30f3dcb2, 0x52ec0d86, 0xe3d077c1,
  0x166c2bb3, 0xb999a970, 0x48fa1194, 0x642247e9,
  0x8cc4a8fc, 0x3f1aa0f0, 0x2cd8567d, 0x90ef2233,
  0x4ec78749, 0xd1c1d938, 0xa2fe8cca, 0x0b3698d4,
  0x81cfa6f5, 0xde28a57a, 0x8e26dab7, 0xbfa43fad,
  0x9de42c3a, 0x920d5078, 0xcc9b6a5f, 0x4662547e,
  0x13c2f68d, 0xb8e890d8, 0xf75e2e39, 0xaff582c3,
  0x80be9f5d, 0x937c69d0, 0x2da96fd5, 0x12b3cf25,
  0x993bc8ac, 0x7da71018, 0x636ee89c, 0xbb7bdb3b,
  0x7809cd26, 0x18f46e59, 0xb701ec9a, 0x9aa8834f,
  0x6e65e695, 0xe67eaaff, 0xcf0821bc, 0xe8e6ef15,
  0x9bd9bae7, 0x36ce4a6f, 0x09d4ea9f, 0x7cd629b0,
  0xb2af31a4, 0x23312a3f, 0x9430c6a5, 0x66c035a2,
  0xbc37744e, 0xcaa6fc82, 0xd0b0e090, 0xd81533a7,
  0x984af104, 0xdaf741ec, 0x500e7fcd, 0xf62f1791,
  0xd68d764d, 0xb04d43ef, 0x4d54ccaa, 0x04dfe496,
  0xb5e39ed1, 0x881b4c6a, 0x1fb8c12c, 0x517f4665,
  0xea049d5e, 0x355d018c, 0x7473fa87, 0x412efb0b,
  0x1d5ab367, 0xd25292db, 0x5633e910, 0x47136dd6,
  0x618c9ad7, 0x0c7a37a1, 0x148e59f8, 0x3c89eb13,
  0x27eecea9, 0xc935b761, 0xe5ede11c, 0xb13c7a47,
  0xdf599cd2, 0x733f55f2, 0xce791814, 0x37bf73c7,
  0xcdea53f7, 0xaa5b5ffd, 0x6f14df3d, 0xdb867844,
  0xf381caaf, 0xc43eb968, 0x342c3824, 0x405fc2a3,
  0xc372161d, 0x250cbce2, 0x498b283c, 0x9541ff0d,
  0x017139a8, 0xb3de080c, 0xe49cd8b4, 0xc1906456,
  0x84617bcb, 0xb670d532, 0x5c74486c, 0x5742d0b8
};

static const uint32_t TD3[256] = {
  0xf4a75051, 0x4165537e, 0x17a4c31a, 0x275e963a,
  0xab6bcb3b, 0x9d45f11f, 0xfa58abac, 0xe303934b,
  0x30fa5520, 0x766df6ad, 0xcc769188, 0x024c25f5,
  0xe5d7fc4f, 0x2acbd7c5, 0x35448026, 0x62a38fb5,
  0xb15a49de, 0xba1b6725, 0xea0e9845, 0xfec0e15d,
  0x2f7502c3, 0x4cf01281, 0x4697a38d, 0xd3f9c66b,
  0x8f5fe703, 0x929c9515, 0x6d7aebbf, 0x5259da95,
  0xbe832dd4, 0x7421d358, 0xe0692949, 0xc9c8448e,
  0xc2896a75, 0x8e7978f4, 0x583e6b99, 0xb971dd27,
  0xe14fb6be, 0x88ad17f0, 0x20ac66c9, 0xce3ab47d,
  0xdf4a1863, 0x1a3182e5, 0x51336097, 0x537f4562,
  0x6477e0b1, 0x6bae84bb, 0x81a01cfe, 0x082b94f9,
  0x48685870, 0x45fd198f, 0xde6c8794, 0x7bf8b752,
  0x73d323ab, 0x4b02e272, 0x1f8f57e3, 0x55ab2a66,
  0xeb2807b2, 0xb5c2032f, 0xc57b9a86, 0x3708a5d3,
  0x2887f230, 0xbfa5b223, 0x036aba02, 0x16825ced,
  0xcf1c2b8a, 0x79b492a7, 0x07f2f0f3, 0x69e2a14e,
  0xdaf4cd65, 0x05bed506, 0x34621fd1, 0xa6fe8ac4,
  0x2e539d34, 0xf355a0a2, 0x8ae13205, 0xf6eb75a4,
  0x83ec390b, 0x60efaa40, 0x719f065e, 0x6e1051bd,
  0x218af93e, 0xdd063d96, 0x3e05aedd, 0xe6bd464d,
  0x548db591, 0xc45d0571, 0x06d46f04, 0x5015ff60,
  0x98fb2419, 0xbde997d6, 0x4043cc89, 0xd99e7767,
  0xe842bdb0, 0x898b8807, 0x195b38e7, 0xc8eedb79,
  0x7c0a47a1, 0x420fe97c, 0x841ec9f8, 0x00000000,
  0x80868309, 0x2bed4832, 0x1170ac1e, 0x5a724e6c,
  0x0efffbfd, 0x8538560f, 0xaed51e3d, 0x2d392736,
  0x0fd9640a, 0x5ca62168, 0x5b54d19b, 0x362e3a24,
  0x0a67b10c, 0x57e70f93, 0xee96d2b4, 0x9b919e1b,
  0xc0c54f80, 0xdc20a261, 0x774b695a, 0x121a161c,
  0x93ba0ae2, 0xa02ae5c0, 0x22e0433c, 0x1b171d12,
  0x090d0b0e, 0x8bc7adf2, 0xb6a8b92d, 0x1ea9c814,
  0xf1198557, 0x75074caf, 0x99ddbbee, 0x7f60fda3,
  0x01269ff7, 0x72f5bc5c, 0x663bc544, 0xfb7e345b,
  0x4329768b, 0x23c6dccb, 0xedfc68b6, 0xe4f163b8,
  0x31dccad7, 0x63851042, 0x97224013, 0xc6112084,
  0x4a247d85, 0xbb3df8d2, 0xf93211ae, 0x29a16dc7,
  0x9e2f4b1d, 0xb230f3dc, 0x8652ec0d, 0xc1e3d077,
  0xb3166c2b, 0x70b999a9, 0x9448fa11, 0xe9642247,
  0xfc8cc4a8, 0xf03f1aa0, 0x7d2cd856, 0x3390ef22,
  0x494ec787, 0x38d1c1d9, 0xcaa2fe8c, 0xd40b3698,
  0xf581cfa6, 0x7ade28a5, 0xb78e26da, 0xadbfa43f,
  0x3a9de42c, 0x78920d50, 0x5fcc9b6a, 0x7e466254,
  0x8d13c2f6, 0xd8b8e890, 0x39f75e2e, 0xc3aff582,
  0x5d80be9f, 0xd0937c69, 0xd52da96f, 0x2512b3cf,
  0xac993bc8, 0x187da710, 0x9c636ee8, 0x3bbb7bdb,
  0x267809cd, 0x5918f46e, 0x9ab701ec, 0x4f9aa883,
  0x956e65e6, 0xffe67eaa, 0xbccf0821, 0x15e8e6ef,
  0xe79bd9ba, 0x6f36ce4a, 0x9f09d4ea, 0xb07cd629,
  0xa4b2af31, 0x3f23312a, 0xa59430c6, 0xa266c035,
  0x4ebc3774, 0x82caa6fc, 0x90d0b0e0, 0xa7d81533,
  0x04984af1, 0xecdaf741, 0xcd500e7f, 0x91f62f17,
  0x4dd68d76, 0xefb04d43, 0xaa4d54cc, 0x9604dfe4,
  0xd1b5e39e, 0x6a881b4c, 0x2c1fb8c1, 0x65517f46,
  0x5eea049d, 0x8c355d01, 0x877473fa, 0x0b412efb,
  0x671d5ab3, 0xdbd25292, 0x105633e9, 0xd647136d,
  0xd7618c9a, 0xa10c7a37, 0xf8148e59, 0x133c89eb,
  0xa927eece, 0x61c935b7, 0x1ce5ede1, 0x47b13c7a,
  0xd2df599c, 0xf2733f55, 0x14ce7918, 0xc737bf73,
  0xf7cdea53, 0xfdaa5b5f, 0x3d6f14df, 0x44db8678,
  0xaff381ca, 0x68c43eb9, 0x24342c38, 0xa3405fc2,
  0x1dc37216, 0xe2250cbc, 0x3c498b28, 0x0d9541ff,
  0xa8017139, 0x0cb3de08, 0xb4e49cd8, 0x56c19064,
  0xcb84617b, 0x32b670d5, 0x6c5c7448, 0xb85742d0
};

static const uint8_t TD4[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
  0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
  0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
  0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
  0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
  0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
  0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
  0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
  0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
  0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint32_t RCON[10] = {
  0x01000000, 0x02000000, 0x04000000, 0x08000000,
  0x10000000, 0x20000000, 0x40000000, 0x80000000,
  0x1b000000, 0x36000000
};

void
aes_init(aes_t *ctx, unsigned int bits, const unsigned char *key) {
  aes_init_encrypt(ctx, bits, key);
  aes_init_decrypt(ctx);
}

void
aes_init_encrypt(aes_t *ctx, unsigned int bits, const unsigned char *key) {
  uint32_t *K = ctx->enckey;
  uint32_t word;
  int i = 0;

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  switch (bits) {
    case 128: {
      ctx->rounds = 10;

      K[0] = read32be(key +  0);
      K[1] = read32be(key +  4);
      K[2] = read32be(key +  8);
      K[3] = read32be(key + 12);

      for (;;) {
        word = K[3];

        K[4] = K[0]
          ^ (TE2[(word >> 16) & 0xff] & 0xff000000)
          ^ (TE3[(word >>  8) & 0xff] & 0x00ff0000)
          ^ (TE0[(word >>  0) & 0xff] & 0x0000ff00)
          ^ (TE1[(word >> 24) & 0xff] & 0x000000ff)
          ^ RCON[i];

        K[5] = K[1] ^ K[4];
        K[6] = K[2] ^ K[5];
        K[7] = K[3] ^ K[6];

        if (++i == 10)
          break;

        K += 4;
      }

      break;
    }

    case 192: {
      ctx->rounds = 12;

      K[0] = read32be(key +  0);
      K[1] = read32be(key +  4);
      K[2] = read32be(key +  8);
      K[3] = read32be(key + 12);
      K[4] = read32be(key + 16);
      K[5] = read32be(key + 20);

      for (;;) {
        word = K[5];

        K[6] = K[0]
          ^ (TE2[(word >> 16) & 0xff] & 0xff000000)
          ^ (TE3[(word >>  8) & 0xff] & 0x00ff0000)
          ^ (TE0[(word >>  0) & 0xff] & 0x0000ff00)
          ^ (TE1[(word >> 24) & 0xff] & 0x000000ff)
          ^ RCON[i];

        K[7] = K[1] ^ K[6];
        K[8] = K[2] ^ K[7];
        K[9] = K[3] ^ K[8];

        if (++i == 8)
          break;

        K[10] = K[4] ^ K[ 9];
        K[11] = K[5] ^ K[10];

        K += 6;
      }

      break;
    }

    case 256: {
      ctx->rounds = 14;

      K[0] = read32be(key +  0);
      K[1] = read32be(key +  4);
      K[2] = read32be(key +  8);
      K[3] = read32be(key + 12);
      K[4] = read32be(key + 16);
      K[5] = read32be(key + 20);
      K[6] = read32be(key + 24);
      K[7] = read32be(key + 28);

      for (;;) {
        word = K[7];

        K[8] = K[0]
          ^ (TE2[(word >> 16) & 0xff] & 0xff000000)
          ^ (TE3[(word >>  8) & 0xff] & 0x00ff0000)
          ^ (TE0[(word >>  0) & 0xff] & 0x0000ff00)
          ^ (TE1[(word >> 24) & 0xff] & 0x000000ff)
          ^ RCON[i];

        K[ 9] = K[1] ^ K[ 8];
        K[10] = K[2] ^ K[ 9];
        K[11] = K[3] ^ K[10];

        if (++i == 7)
          break;

        word = K[11];

        K[12] = K[4]
          ^ (TE2[(word >> 24) & 0xff] & 0xff000000)
          ^ (TE3[(word >> 16) & 0xff] & 0x00ff0000)
          ^ (TE0[(word >>  8) & 0xff] & 0x0000ff00)
          ^ (TE1[(word >>  0) & 0xff] & 0x000000ff);

        K[13] = K[5] ^ K[12];
        K[14] = K[6] ^ K[13];
        K[15] = K[7] ^ K[14];

        K += 8;
      }

      break;
    }

    default: {
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
    }
  }
}

void
aes_init_decrypt(aes_t *ctx) {
  uint32_t *K = ctx->deckey;
  uint32_t x, y;
  int i, j, k;

  memcpy(K, ctx->enckey, sizeof(ctx->enckey));

  for (i = 0, j = 4 * ctx->rounds; i < j; i += 4, j -= 4) {
    for (k = 0; k < 4; k++) {
      x = K[i + k];
      y = K[j + k];

      K[i + k] = y;
      K[j + k] = x;
    }
  }

  for (i = 1; i < ctx->rounds; i++) {
    K += 4;

    K[0] = TD0[TE1[(K[0] >> 24) & 0xff] & 0xff]
         ^ TD1[TE1[(K[0] >> 16) & 0xff] & 0xff]
         ^ TD2[TE1[(K[0] >>  8) & 0xff] & 0xff]
         ^ TD3[TE1[(K[0] >>  0) & 0xff] & 0xff];

    K[1] = TD0[TE1[(K[1] >> 24) & 0xff] & 0xff]
         ^ TD1[TE1[(K[1] >> 16) & 0xff] & 0xff]
         ^ TD2[TE1[(K[1] >>  8) & 0xff] & 0xff]
         ^ TD3[TE1[(K[1] >>  0) & 0xff] & 0xff];

    K[2] = TD0[TE1[(K[2] >> 24) & 0xff] & 0xff]
         ^ TD1[TE1[(K[2] >> 16) & 0xff] & 0xff]
         ^ TD2[TE1[(K[2] >>  8) & 0xff] & 0xff]
         ^ TD3[TE1[(K[2] >>  0) & 0xff] & 0xff];

    K[3] = TD0[TE1[(K[3] >> 24) & 0xff] & 0xff]
         ^ TD1[TE1[(K[3] >> 16) & 0xff] & 0xff]
         ^ TD2[TE1[(K[3] >>  8) & 0xff] & 0xff]
         ^ TD3[TE1[(K[3] >>  0) & 0xff] & 0xff];
  }
}

void
aes_encrypt(const aes_t *ctx, unsigned char *dst, const unsigned char *src) {
  const uint32_t *K = ctx->enckey;
  uint32_t s0 = read32be(src +  0) ^ K[0];
  uint32_t s1 = read32be(src +  4) ^ K[1];
  uint32_t s2 = read32be(src +  8) ^ K[2];
  uint32_t s3 = read32be(src + 12) ^ K[3];
  uint32_t t0, t1, t2, t3;
  int r = ctx->rounds >> 1;

  for (;;) {
    t0 = TE0[(s0 >> 24) & 0xff]
       ^ TE1[(s1 >> 16) & 0xff]
       ^ TE2[(s2 >>  8) & 0xff]
       ^ TE3[(s3 >>  0) & 0xff]
       ^ K[4];

    t1 = TE0[(s1 >> 24) & 0xff]
       ^ TE1[(s2 >> 16) & 0xff]
       ^ TE2[(s3 >>  8) & 0xff]
       ^ TE3[(s0 >>  0) & 0xff]
       ^ K[5];

    t2 = TE0[(s2 >> 24) & 0xff]
       ^ TE1[(s3 >> 16) & 0xff]
       ^ TE2[(s0 >>  8) & 0xff]
       ^ TE3[(s1 >>  0) & 0xff]
       ^ K[6];

    t3 = TE0[(s3 >> 24) & 0xff]
       ^ TE1[(s0 >> 16) & 0xff]
       ^ TE2[(s1 >>  8) & 0xff]
       ^ TE3[(s2 >>  0) & 0xff]
       ^ K[7];

    K += 8;

    if (--r == 0)
      break;

    s0 = TE0[(t0 >> 24) & 0xff]
       ^ TE1[(t1 >> 16) & 0xff]
       ^ TE2[(t2 >>  8) & 0xff]
       ^ TE3[(t3 >>  0) & 0xff]
       ^ K[0];

    s1 = TE0[(t1 >> 24) & 0xff]
       ^ TE1[(t2 >> 16) & 0xff]
       ^ TE2[(t3 >>  8) & 0xff]
       ^ TE3[(t0 >>  0) & 0xff]
       ^ K[1];

    s2 = TE0[(t2 >> 24) & 0xff]
       ^ TE1[(t3 >> 16) & 0xff]
       ^ TE2[(t0 >>  8) & 0xff]
       ^ TE3[(t1 >>  0) & 0xff]
       ^ K[2];

    s3 = TE0[(t3 >> 24) & 0xff]
       ^ TE1[(t0 >> 16) & 0xff]
       ^ TE2[(t1 >>  8) & 0xff]
       ^ TE3[(t2 >>  0) & 0xff]
       ^ K[3];
  }

  s0 = (TE2[(t0 >> 24) & 0xff] & 0xff000000)
     ^ (TE3[(t1 >> 16) & 0xff] & 0x00ff0000)
     ^ (TE0[(t2 >>  8) & 0xff] & 0x0000ff00)
     ^ (TE1[(t3 >>  0) & 0xff] & 0x000000ff)
     ^ K[0];

  s1 = (TE2[(t1 >> 24) & 0xff] & 0xff000000)
     ^ (TE3[(t2 >> 16) & 0xff] & 0x00ff0000)
     ^ (TE0[(t3 >>  8) & 0xff] & 0x0000ff00)
     ^ (TE1[(t0 >>  0) & 0xff] & 0x000000ff)
     ^ K[1];

  s2 = (TE2[(t2 >> 24) & 0xff] & 0xff000000)
     ^ (TE3[(t3 >> 16) & 0xff] & 0x00ff0000)
     ^ (TE0[(t0 >>  8) & 0xff] & 0x0000ff00)
     ^ (TE1[(t1 >>  0) & 0xff] & 0x000000ff)
     ^ K[2];

  s3 = (TE2[(t3 >> 24) & 0xff] & 0xff000000)
     ^ (TE3[(t0 >> 16) & 0xff] & 0x00ff0000)
     ^ (TE0[(t1 >>  8) & 0xff] & 0x0000ff00)
     ^ (TE1[(t2 >>  0) & 0xff] & 0x000000ff)
     ^ K[3];

  write32be(dst +  0, s0);
  write32be(dst +  4, s1);
  write32be(dst +  8, s2);
  write32be(dst + 12, s3);
}

void
aes_decrypt(const aes_t *ctx, unsigned char *dst, const unsigned char *src) {
  const uint32_t *K = ctx->deckey;
  uint32_t s0 = read32be(src +  0) ^ K[0];
  uint32_t s1 = read32be(src +  4) ^ K[1];
  uint32_t s2 = read32be(src +  8) ^ K[2];
  uint32_t s3 = read32be(src + 12) ^ K[3];
  uint32_t t0, t1, t2, t3;
  int r = ctx->rounds >> 1;

  for (;;) {
    t0 = TD0[(s0 >> 24) & 0xff]
       ^ TD1[(s3 >> 16) & 0xff]
       ^ TD2[(s2 >>  8) & 0xff]
       ^ TD3[(s1 >>  0) & 0xff]
       ^ K[4];

    t1 = TD0[(s1 >> 24) & 0xff]
       ^ TD1[(s0 >> 16) & 0xff]
       ^ TD2[(s3 >>  8) & 0xff]
       ^ TD3[(s2 >>  0) & 0xff]
       ^ K[5];

    t2 = TD0[(s2 >> 24) & 0xff]
       ^ TD1[(s1 >> 16) & 0xff]
       ^ TD2[(s0 >>  8) & 0xff]
       ^ TD3[(s3 >>  0) & 0xff]
       ^ K[6];

    t3 = TD0[(s3 >> 24) & 0xff]
       ^ TD1[(s2 >> 16) & 0xff]
       ^ TD2[(s1 >>  8) & 0xff]
       ^ TD3[(s0 >>  0) & 0xff]
       ^ K[7];

    K += 8;

    if (--r == 0)
      break;

    s0 = TD0[(t0 >> 24) & 0xff]
       ^ TD1[(t3 >> 16) & 0xff]
       ^ TD2[(t2 >>  8) & 0xff]
       ^ TD3[(t1 >>  0) & 0xff]
       ^ K[0];

    s1 = TD0[(t1 >> 24) & 0xff]
       ^ TD1[(t0 >> 16) & 0xff]
       ^ TD2[(t3 >>  8) & 0xff]
       ^ TD3[(t2 >>  0) & 0xff]
       ^ K[1];

    s2 = TD0[(t2 >> 24) & 0xff]
       ^ TD1[(t1 >> 16) & 0xff]
       ^ TD2[(t0 >>  8) & 0xff]
       ^ TD3[(t3 >>  0) & 0xff]
       ^ K[2];

    s3 = TD0[(t3 >> 24) & 0xff]
       ^ TD1[(t2 >> 16) & 0xff]
       ^ TD2[(t1 >>  8) & 0xff]
       ^ TD3[(t0 >>  0) & 0xff]
       ^ K[3];
  }

  s0 = (TD4[(t0 >> 24) & 0xff] << 24)
     ^ (TD4[(t3 >> 16) & 0xff] << 16)
     ^ (TD4[(t2 >>  8) & 0xff] <<  8)
     ^ (TD4[(t1 >>  0) & 0xff] <<  0)
     ^ K[0];

  s1 = (TD4[(t1 >> 24) & 0xff] << 24)
     ^ (TD4[(t0 >> 16) & 0xff] << 16)
     ^ (TD4[(t3 >>  8) & 0xff] <<  8)
     ^ (TD4[(t2 >>  0) & 0xff] <<  0)
     ^ K[1];

  s2 = (TD4[(t2 >> 24) & 0xff] << 24)
     ^ (TD4[(t1 >> 16) & 0xff] << 16)
     ^ (TD4[(t0 >>  8) & 0xff] <<  8)
     ^ (TD4[(t3 >>  0) & 0xff] <<  0)
     ^ K[2];

  s3 = (TD4[(t3 >> 24) & 0xff] << 24)
     ^ (TD4[(t2 >> 16) & 0xff] << 16)
     ^ (TD4[(t1 >>  8) & 0xff] <<  8)
     ^ (TD4[(t0 >>  0) & 0xff] <<  0)
     ^ K[3];

  write32be(dst +  0, s0);
  write32be(dst +  4, s1);
  write32be(dst +  8, s2);
  write32be(dst + 12, s3);
}

#undef TE0
#undef TE1
#undef TE2
#undef TE3
#undef TD0
#undef TD1
#undef TD2
#undef TD3
#undef TD4
#undef RCON

/*
 * ARC2
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RC2
 *   https://github.com/golang/crypto/blob/master/pkcs12/internal/rc2/rc2.go
 *   https://en.wikipedia.org/wiki/RC2
 *   https://www.ietf.org/rfc/rfc2268.txt
 *   http://people.csail.mit.edu/rivest/pubs/KRRR98.pdf
 */

#define PI arc2_PI
#define ROTL16(x, b) (((x) >> (16 - (b))) | ((x) << (b)))

static const uint8_t PI[256] = {
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};

void
arc2_init(arc2_t *ctx,
          const unsigned char *key,
          size_t key_len,
          unsigned int ekb) {
  /* Initialization logic borrowed from nettle. */
  uint8_t L[128];
  size_t i, len;
  uint8_t x;

  CHECK(key_len >= 1 && key_len <= 128);
  CHECK(ekb <= 1024);

  for (i = 0; i < key_len; i++)
    L[i] = key[i];

  for (i = key_len; i < 128; i++)
    L[i] = PI[(L[i - key_len] + L[i - 1]) & 0xff];

  L[0] = PI[L[0]];

  if (ekb > 0 && ekb < 1024) {
    len = (ekb + 7) >> 3;

    i = 128 - len;
    x = PI[L[i] & (255 >> (7 & -ekb))];

    L[i] = x;

    while (i--) {
      x = PI[x ^ L[i + len]];
      L[i] = x;
    }
  }

  for (i = 0; i < 64; i++)
    ctx->k[i] = read16le(L + i * 2);
}

void
arc2_encrypt(const arc2_t *ctx, unsigned char *dst, const unsigned char *src) {
  uint16_t r0 = read16le(src + 0);
  uint16_t r1 = read16le(src + 2);
  uint16_t r2 = read16le(src + 4);
  uint16_t r3 = read16le(src + 6);
  int j = 0;

  while (j <= 16) {
    /* mix r0 */
    r0 += ctx->k[j];
    r0 += r3 & r2;
    r0 += ~r3 & r1;
    r0 = ROTL16(r0, 1);
    j += 1;

    /* mix r1 */
    r1 += ctx->k[j];
    r1 += r0 & r3;
    r1 += ~r0 & r2;
    r1 = ROTL16(r1, 2);
    j += 1;

    /* mix r2 */
    r2 += ctx->k[j];
    r2 += r1 & r0;
    r2 += ~r1 & r3;
    r2 = ROTL16(r2, 3);
    j += 1;

    /* mix r3 */
    r3 += ctx->k[j];
    r3 += r2 & r1;
    r3 += ~r2 & r0;
    r3 = ROTL16(r3, 5);
    j += 1;
  };

  r0 += ctx->k[r3 & 63];
  r1 += ctx->k[r0 & 63];
  r2 += ctx->k[r1 & 63];
  r3 += ctx->k[r2 & 63];

  while (j <= 40) {
    /* mix r0 */
    r0 += ctx->k[j];
    r0 += r3 & r2;
    r0 += ~r3 & r1;
    r0 = ROTL16(r0, 1);
    j += 1;

    /* mix r1 */
    r1 += ctx->k[j];
    r1 += r0 & r3;
    r1 += ~r0 & r2;
    r1 = ROTL16(r1, 2);
    j += 1;

    /* mix r2 */
    r2 += ctx->k[j];
    r2 += r1 & r0;
    r2 += ~r1 & r3;
    r2 = ROTL16(r2, 3);
    j += 1;

    /* mix r3 */
    r3 += ctx->k[j];
    r3 += r2 & r1;
    r3 += ~r2 & r0;
    r3 = ROTL16(r3, 5);
    j += 1;
  }

  r0 += ctx->k[r3 & 63];
  r1 += ctx->k[r0 & 63];
  r2 += ctx->k[r1 & 63];
  r3 += ctx->k[r2 & 63];

  while (j <= 60) {
    /* mix r0 */
    r0 += ctx->k[j];
    r0 += r3 & r2;
    r0 += ~r3 & r1;
    r0 = ROTL16(r0, 1);
    j += 1;

    /* mix r1 */
    r1 += ctx->k[j];
    r1 += r0 & r3;
    r1 += ~r0 & r2;
    r1 = ROTL16(r1, 2);
    j += 1;

    /* mix r2 */
    r2 += ctx->k[j];
    r2 += r1 & r0;
    r2 += ~r1 & r3;
    r2 = ROTL16(r2, 3);
    j += 1;

    /* mix r3 */
    r3 += ctx->k[j];
    r3 += r2 & r1;
    r3 += ~r2 & r0;
    r3 = ROTL16(r3, 5);
    j += 1;
  }

  write16le(dst + 0, r0);
  write16le(dst + 2, r1);
  write16le(dst + 4, r2);
  write16le(dst + 6, r3);
}

void
arc2_decrypt(const arc2_t *ctx, unsigned char *dst, const unsigned char *src) {
  uint16_t r0 = read16le(src + 0);
  uint16_t r1 = read16le(src + 2);
  uint16_t r2 = read16le(src + 4);
  uint16_t r3 = read16le(src + 6);
  int j = 63;

  while (j >= 44) {
    /* unmix r3 */
    r3 = ROTL16(r3, 16 - 5);
    r3 -= ctx->k[j];
    r3 -= r2 & r1;
    r3 -= ~r2 & r0;
    j -= 1;

    /* unmix r2 */
    r2 = ROTL16(r2, 16 - 3);
    r2 -= ctx->k[j];
    r2 -= r1 & r0;
    r2 -= ~r1 & r3;
    j -= 1;

    /* unmix r1 */
    r1 = ROTL16(r1, 16 - 2);
    r1 -= ctx->k[j];
    r1 -= r0 & r3;
    r1 -= ~r0 & r2;
    j -= 1;

    /* unmix r0 */
    r0 = ROTL16(r0, 16 - 1);
    r0 -= ctx->k[j];
    r0 -= r3 & r2;
    r0 -= ~r3 & r1;
    j -= 1;
  }

  r3 -= ctx->k[r2 & 63];
  r2 -= ctx->k[r1 & 63];
  r1 -= ctx->k[r0 & 63];
  r0 -= ctx->k[r3 & 63];

  while (j >= 20) {
    /* unmix r3 */
    r3 = ROTL16(r3, 16 - 5);
    r3 -= ctx->k[j];
    r3 -= r2 & r1;
    r3 -= ~r2 & r0;
    j -= 1;

    /* unmix r2 */
    r2 = ROTL16(r2, 16 - 3);
    r2 -= ctx->k[j];
    r2 -= r1 & r0;
    r2 -= ~r1 & r3;
    j -= 1;

    /* unmix r1 */
    r1 = ROTL16(r1, 16 - 2);
    r1 -= ctx->k[j];
    r1 -= r0 & r3;
    r1 -= ~r0 & r2;
    j -= 1;

    /* unmix r0 */
    r0 = ROTL16(r0, 16 - 1);
    r0 -= ctx->k[j];
    r0 -= r3 & r2;
    r0 -= ~r3 & r1;
    j -= 1;
  }

  r3 -= ctx->k[r2 & 63];
  r2 -= ctx->k[r1 & 63];
  r1 -= ctx->k[r0 & 63];
  r0 -= ctx->k[r3 & 63];

  while (j >= 0) {
    /* unmix r3 */
    r3 = ROTL16(r3, 16 - 5);
    r3 -= ctx->k[j];
    r3 -= r2 & r1;
    r3 -= ~r2 & r0;
    j -= 1;

    /* unmix r2 */
    r2 = ROTL16(r2, 16 - 3);
    r2 -= ctx->k[j];
    r2 -= r1 & r0;
    r2 -= ~r1 & r3;
    j -= 1;

    /* unmix r1 */
    r1 = ROTL16(r1, 16 - 2);
    r1 -= ctx->k[j];
    r1 -= r0 & r3;
    r1 -= ~r0 & r2;
    j -= 1;

    /* unmix r0 */
    r0 = ROTL16(r0, 16 - 1);
    r0 -= ctx->k[j];
    r0 -= r3 & r2;
    r0 -= ~r3 & r1;
    j -= 1;
  }

  write16le(dst + 0, r0);
  write16le(dst + 2, r1);
  write16le(dst + 4, r2);
  write16le(dst + 6, r3);
}

#undef PI
#undef ROTL16

/**
 * Blowfish
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Blowfish_(cipher)
 *   https://www.schneier.com/blowfish.html
 *   https://github.com/joyent/node-bcrypt-pbkdf/blob/master/index.js
 */

static const blowfish_t blowfish_initial = {
  {
    {
      0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7,
      0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
      0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
      0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
      0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
      0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
      0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef,
      0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
      0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
      0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
      0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce,
      0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
      0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e,
      0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
      0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
      0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
      0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88,
      0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
      0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e,
      0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
      0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
      0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
      0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88,
      0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
      0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
      0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
      0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
      0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
      0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba,
      0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
      0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f,
      0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
      0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
      0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
      0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
      0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
      0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab,
      0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
      0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
      0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
      0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0,
      0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
      0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790,
      0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
      0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
      0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
      0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7,
      0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
      0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad,
      0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
      0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
      0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
      0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477,
      0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
      0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
      0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
      0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
      0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
      0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41,
      0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
      0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400,
      0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
      0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
      0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a
    },
    {
      0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
      0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
      0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1,
      0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
      0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
      0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
      0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e,
      0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
      0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737,
      0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
      0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
      0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
      0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701,
      0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
      0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41,
      0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
      0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
      0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
      0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e,
      0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
      0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
      0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
      0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
      0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
      0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b,
      0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
      0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e,
      0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
      0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
      0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
      0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
      0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
      0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66,
      0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
      0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
      0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
      0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510,
      0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
      0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14,
      0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
      0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
      0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
      0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8,
      0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
      0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99,
      0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
      0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
      0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
      0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0,
      0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
      0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
      0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
      0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
      0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
      0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00,
      0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
      0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb,
      0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
      0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
      0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
      0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
      0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
      0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20,
      0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7
    },
    {
      0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
      0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
      0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af,
      0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
      0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45,
      0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
      0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
      0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
      0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee,
      0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
      0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42,
      0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
      0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
      0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
      0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527,
      0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
      0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
      0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
      0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
      0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
      0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17,
      0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
      0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b,
      0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
      0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
      0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
      0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
      0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
      0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37,
      0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
      0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
      0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
      0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3,
      0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
      0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d,
      0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
      0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
      0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
      0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a,
      0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
      0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d,
      0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
      0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
      0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
      0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2,
      0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
      0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
      0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
      0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
      0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
      0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10,
      0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
      0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52,
      0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
      0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
      0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
      0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
      0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
      0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24,
      0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
      0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
      0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
      0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837,
      0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0
    },
    {
      0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b,
      0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
      0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
      0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
      0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8,
      0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
      0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304,
      0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
      0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
      0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
      0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9,
      0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
      0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
      0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
      0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
      0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
      0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b,
      0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
      0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c,
      0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
      0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
      0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
      0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
      0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
      0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991,
      0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
      0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
      0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
      0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae,
      0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
      0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5,
      0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
      0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
      0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
      0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84,
      0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
      0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8,
      0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
      0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
      0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
      0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38,
      0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
      0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
      0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
      0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
      0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
      0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964,
      0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
      0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8,
      0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
      0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
      0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
      0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
      0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
      0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614,
      0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
      0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
      0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
      0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0,
      0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
      0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e,
      0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
      0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
      0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
    }
  },
  {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
    0x9216d5d9, 0x8979fb1b
  }
};

void
blowfish_init(blowfish_t *ctx,
              const unsigned char *key, size_t key_len,
              const unsigned char *salt, size_t salt_len) {
  if (key_len > 72)
    key_len = 72;

  if (salt_len > 1096)
    salt_len = 1096;

  *ctx = blowfish_initial;

  if (salt_len > 0)
    blowfish_expandstate(ctx, key, key_len, salt, salt_len);
  else
    blowfish_expand0state(ctx, key, key_len);
}

#define substitute(x) (((ctx->S[0][((x) >> 24) & 0xff]  \
                       + ctx->S[1][((x) >> 16) & 0xff]) \
                       ^ ctx->S[2][((x) >>  8) & 0xff]) \
                       + ctx->S[3][((x) >>  0) & 0xff])

static void
blowfish_encipher(const blowfish_t *ctx, uint32_t *xl, uint32_t *xr) {
  uint32_t l = *xl ^ ctx->P[0];
  uint32_t r = *xr;

  r ^= substitute(l) ^ ctx->P[1];
  l ^= substitute(r) ^ ctx->P[2];
  r ^= substitute(l) ^ ctx->P[3];
  l ^= substitute(r) ^ ctx->P[4];
  r ^= substitute(l) ^ ctx->P[5];
  l ^= substitute(r) ^ ctx->P[6];
  r ^= substitute(l) ^ ctx->P[7];
  l ^= substitute(r) ^ ctx->P[8];
  r ^= substitute(l) ^ ctx->P[9];
  l ^= substitute(r) ^ ctx->P[10];
  r ^= substitute(l) ^ ctx->P[11];
  l ^= substitute(r) ^ ctx->P[12];
  r ^= substitute(l) ^ ctx->P[13];
  l ^= substitute(r) ^ ctx->P[14];
  r ^= substitute(l) ^ ctx->P[15];
  l ^= substitute(r) ^ ctx->P[16];

  *xl = r ^ ctx->P[17];
  *xr = l;
}

static void
blowfish_decipher(const blowfish_t *ctx, uint32_t *xl, uint32_t *xr) {
  uint32_t l = *xl ^ ctx->P[17];
  uint32_t r = *xr;

  r ^= substitute(l) ^ ctx->P[16];
  l ^= substitute(r) ^ ctx->P[15];
  r ^= substitute(l) ^ ctx->P[14];
  l ^= substitute(r) ^ ctx->P[13];
  r ^= substitute(l) ^ ctx->P[12];
  l ^= substitute(r) ^ ctx->P[11];
  r ^= substitute(l) ^ ctx->P[10];
  l ^= substitute(r) ^ ctx->P[9];
  r ^= substitute(l) ^ ctx->P[8];
  l ^= substitute(r) ^ ctx->P[7];
  r ^= substitute(l) ^ ctx->P[6];
  l ^= substitute(r) ^ ctx->P[5];
  r ^= substitute(l) ^ ctx->P[4];
  l ^= substitute(r) ^ ctx->P[3];
  r ^= substitute(l) ^ ctx->P[2];
  l ^= substitute(r) ^ ctx->P[1];

  *xl = r ^ ctx->P[0];
  *xr = l;
}

#undef substitute

uint32_t
blowfish_stream2word(const unsigned char *data, size_t len, size_t *off) {
  uint32_t word;

  if (len == 0) {
    *off = 0;
    return 0;
  }

  word = ((uint32_t)data[(*off + 0) % len] << 24)
       | ((uint32_t)data[(*off + 1) % len] << 16)
       | ((uint32_t)data[(*off + 2) % len] <<  8)
       | ((uint32_t)data[(*off + 3) % len] <<  0);

  *off = (*off + 4) % len;

  return word;
}

void
blowfish_expand0state(blowfish_t *ctx,
                      const unsigned char *key,
                      size_t key_len) {
  uint32_t xl = 0;
  uint32_t xr = 0;
  size_t off = 0;
  int i, k;

  for (i = 0; i < 18; i++)
    ctx->P[i] ^= blowfish_stream2word(key, key_len, &off);

  for (i = 0; i < 18; i += 2) {
    blowfish_encipher(ctx, &xl, &xr);

    ctx->P[i + 0] = xl;
    ctx->P[i + 1] = xr;
  }

  for (i = 0; i < 4; i++) {
    for (k = 0; k < 256; k += 2) {
      blowfish_encipher(ctx, &xl, &xr);

      ctx->S[i][k + 0] = xl;
      ctx->S[i][k + 1] = xr;
    }
  }
}

void
blowfish_expandstate(blowfish_t *ctx,
                     const unsigned char *key, size_t key_len,
                     const unsigned char *data, size_t data_len) {
  uint32_t xl = 0;
  uint32_t xr = 0;
  size_t off = 0;
  int i, k;

  for (i = 0; i < 18; i++)
    ctx->P[i] ^= blowfish_stream2word(key, key_len, &off);

  off = 0;

  for (i = 0; i < 18; i += 2) {
    xl ^= blowfish_stream2word(data, data_len, &off);
    xr ^= blowfish_stream2word(data, data_len, &off);

    blowfish_encipher(ctx, &xl, &xr);

    ctx->P[i + 0] = xl;
    ctx->P[i + 1] = xr;
  }

  for (i = 0; i < 4; i++) {
    for (k = 0; k < 256; k += 2) {
      xl ^= blowfish_stream2word(data, data_len, &off);
      xr ^= blowfish_stream2word(data, data_len, &off);

      blowfish_encipher(ctx, &xl, &xr);

      ctx->S[i][k + 0] = xl;
      ctx->S[i][k + 1] = xr;
    }
  }
}

void
blowfish_enc(const blowfish_t *ctx, uint32_t *data, size_t len) {
  size_t blocks = len / 2;

  while (blocks--) {
    blowfish_encipher(ctx, data + 0, data + 1);
    data += 2;
  }
}

void
blowfish_dec(const blowfish_t *ctx, uint32_t *data, size_t len) {
  size_t blocks = len / 2;

  while (blocks--) {
    blowfish_decipher(ctx, data + 0, data + 1);
    data += 2;
  }
}

void
blowfish_encrypt(const blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src) {
  uint32_t xl = read32be(src + 0);
  uint32_t xr = read32be(src + 4);

  blowfish_encipher(ctx, &xl, &xr);

  write32be(dst + 0, xl);
  write32be(dst + 4, xr);
}

void
blowfish_decrypt(const blowfish_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src) {
  uint32_t xl = read32be(src + 0);
  uint32_t xr = read32be(src + 4);

  blowfish_decipher(ctx, &xl, &xr);

  write32be(dst + 0, xl);
  write32be(dst + 4, xr);
}

/*
 * Camellia
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Camellia_(cipher)
 *   https://tools.ietf.org/html/rfc3713
 *   https://github.com/aead/camellia/blob/master/camellia.go
 */

#define sigma camellia_SIGMA
#define S1 camellia_S1
#define S2 camellia_S2
#define S3 camellia_S3
#define S4 camellia_S4

static const uint32_t sigma[12] = {
  0xa09e667f, 0x3bcc908b, 0xb67ae858, 0x4caa73b2,
  0xc6ef372f, 0xe94f82be, 0x54ff53a5, 0xf1d36f1c,
  0x10e527fa, 0xde682d1d, 0xb05688c2, 0xb3e6c1fd
};

static const uint32_t S1[256] = {
  0x70707000, 0x82828200, 0x2c2c2c00, 0xececec00,
  0xb3b3b300, 0x27272700, 0xc0c0c000, 0xe5e5e500,
  0xe4e4e400, 0x85858500, 0x57575700, 0x35353500,
  0xeaeaea00, 0x0c0c0c00, 0xaeaeae00, 0x41414100,
  0x23232300, 0xefefef00, 0x6b6b6b00, 0x93939300,
  0x45454500, 0x19191900, 0xa5a5a500, 0x21212100,
  0xededed00, 0x0e0e0e00, 0x4f4f4f00, 0x4e4e4e00,
  0x1d1d1d00, 0x65656500, 0x92929200, 0xbdbdbd00,
  0x86868600, 0xb8b8b800, 0xafafaf00, 0x8f8f8f00,
  0x7c7c7c00, 0xebebeb00, 0x1f1f1f00, 0xcecece00,
  0x3e3e3e00, 0x30303000, 0xdcdcdc00, 0x5f5f5f00,
  0x5e5e5e00, 0xc5c5c500, 0x0b0b0b00, 0x1a1a1a00,
  0xa6a6a600, 0xe1e1e100, 0x39393900, 0xcacaca00,
  0xd5d5d500, 0x47474700, 0x5d5d5d00, 0x3d3d3d00,
  0xd9d9d900, 0x01010100, 0x5a5a5a00, 0xd6d6d600,
  0x51515100, 0x56565600, 0x6c6c6c00, 0x4d4d4d00,
  0x8b8b8b00, 0x0d0d0d00, 0x9a9a9a00, 0x66666600,
  0xfbfbfb00, 0xcccccc00, 0xb0b0b000, 0x2d2d2d00,
  0x74747400, 0x12121200, 0x2b2b2b00, 0x20202000,
  0xf0f0f000, 0xb1b1b100, 0x84848400, 0x99999900,
  0xdfdfdf00, 0x4c4c4c00, 0xcbcbcb00, 0xc2c2c200,
  0x34343400, 0x7e7e7e00, 0x76767600, 0x05050500,
  0x6d6d6d00, 0xb7b7b700, 0xa9a9a900, 0x31313100,
  0xd1d1d100, 0x17171700, 0x04040400, 0xd7d7d700,
  0x14141400, 0x58585800, 0x3a3a3a00, 0x61616100,
  0xdedede00, 0x1b1b1b00, 0x11111100, 0x1c1c1c00,
  0x32323200, 0x0f0f0f00, 0x9c9c9c00, 0x16161600,
  0x53535300, 0x18181800, 0xf2f2f200, 0x22222200,
  0xfefefe00, 0x44444400, 0xcfcfcf00, 0xb2b2b200,
  0xc3c3c300, 0xb5b5b500, 0x7a7a7a00, 0x91919100,
  0x24242400, 0x08080800, 0xe8e8e800, 0xa8a8a800,
  0x60606000, 0xfcfcfc00, 0x69696900, 0x50505000,
  0xaaaaaa00, 0xd0d0d000, 0xa0a0a000, 0x7d7d7d00,
  0xa1a1a100, 0x89898900, 0x62626200, 0x97979700,
  0x54545400, 0x5b5b5b00, 0x1e1e1e00, 0x95959500,
  0xe0e0e000, 0xffffff00, 0x64646400, 0xd2d2d200,
  0x10101000, 0xc4c4c400, 0x00000000, 0x48484800,
  0xa3a3a300, 0xf7f7f700, 0x75757500, 0xdbdbdb00,
  0x8a8a8a00, 0x03030300, 0xe6e6e600, 0xdadada00,
  0x09090900, 0x3f3f3f00, 0xdddddd00, 0x94949400,
  0x87878700, 0x5c5c5c00, 0x83838300, 0x02020200,
  0xcdcdcd00, 0x4a4a4a00, 0x90909000, 0x33333300,
  0x73737300, 0x67676700, 0xf6f6f600, 0xf3f3f300,
  0x9d9d9d00, 0x7f7f7f00, 0xbfbfbf00, 0xe2e2e200,
  0x52525200, 0x9b9b9b00, 0xd8d8d800, 0x26262600,
  0xc8c8c800, 0x37373700, 0xc6c6c600, 0x3b3b3b00,
  0x81818100, 0x96969600, 0x6f6f6f00, 0x4b4b4b00,
  0x13131300, 0xbebebe00, 0x63636300, 0x2e2e2e00,
  0xe9e9e900, 0x79797900, 0xa7a7a700, 0x8c8c8c00,
  0x9f9f9f00, 0x6e6e6e00, 0xbcbcbc00, 0x8e8e8e00,
  0x29292900, 0xf5f5f500, 0xf9f9f900, 0xb6b6b600,
  0x2f2f2f00, 0xfdfdfd00, 0xb4b4b400, 0x59595900,
  0x78787800, 0x98989800, 0x06060600, 0x6a6a6a00,
  0xe7e7e700, 0x46464600, 0x71717100, 0xbababa00,
  0xd4d4d400, 0x25252500, 0xababab00, 0x42424200,
  0x88888800, 0xa2a2a200, 0x8d8d8d00, 0xfafafa00,
  0x72727200, 0x07070700, 0xb9b9b900, 0x55555500,
  0xf8f8f800, 0xeeeeee00, 0xacacac00, 0x0a0a0a00,
  0x36363600, 0x49494900, 0x2a2a2a00, 0x68686800,
  0x3c3c3c00, 0x38383800, 0xf1f1f100, 0xa4a4a400,
  0x40404000, 0x28282800, 0xd3d3d300, 0x7b7b7b00,
  0xbbbbbb00, 0xc9c9c900, 0x43434300, 0xc1c1c100,
  0x15151500, 0xe3e3e300, 0xadadad00, 0xf4f4f400,
  0x77777700, 0xc7c7c700, 0x80808000, 0x9e9e9e00
};

static const uint32_t S2[256] = {
  0x00e0e0e0, 0x00050505, 0x00585858, 0x00d9d9d9,
  0x00676767, 0x004e4e4e, 0x00818181, 0x00cbcbcb,
  0x00c9c9c9, 0x000b0b0b, 0x00aeaeae, 0x006a6a6a,
  0x00d5d5d5, 0x00181818, 0x005d5d5d, 0x00828282,
  0x00464646, 0x00dfdfdf, 0x00d6d6d6, 0x00272727,
  0x008a8a8a, 0x00323232, 0x004b4b4b, 0x00424242,
  0x00dbdbdb, 0x001c1c1c, 0x009e9e9e, 0x009c9c9c,
  0x003a3a3a, 0x00cacaca, 0x00252525, 0x007b7b7b,
  0x000d0d0d, 0x00717171, 0x005f5f5f, 0x001f1f1f,
  0x00f8f8f8, 0x00d7d7d7, 0x003e3e3e, 0x009d9d9d,
  0x007c7c7c, 0x00606060, 0x00b9b9b9, 0x00bebebe,
  0x00bcbcbc, 0x008b8b8b, 0x00161616, 0x00343434,
  0x004d4d4d, 0x00c3c3c3, 0x00727272, 0x00959595,
  0x00ababab, 0x008e8e8e, 0x00bababa, 0x007a7a7a,
  0x00b3b3b3, 0x00020202, 0x00b4b4b4, 0x00adadad,
  0x00a2a2a2, 0x00acacac, 0x00d8d8d8, 0x009a9a9a,
  0x00171717, 0x001a1a1a, 0x00353535, 0x00cccccc,
  0x00f7f7f7, 0x00999999, 0x00616161, 0x005a5a5a,
  0x00e8e8e8, 0x00242424, 0x00565656, 0x00404040,
  0x00e1e1e1, 0x00636363, 0x00090909, 0x00333333,
  0x00bfbfbf, 0x00989898, 0x00979797, 0x00858585,
  0x00686868, 0x00fcfcfc, 0x00ececec, 0x000a0a0a,
  0x00dadada, 0x006f6f6f, 0x00535353, 0x00626262,
  0x00a3a3a3, 0x002e2e2e, 0x00080808, 0x00afafaf,
  0x00282828, 0x00b0b0b0, 0x00747474, 0x00c2c2c2,
  0x00bdbdbd, 0x00363636, 0x00222222, 0x00383838,
  0x00646464, 0x001e1e1e, 0x00393939, 0x002c2c2c,
  0x00a6a6a6, 0x00303030, 0x00e5e5e5, 0x00444444,
  0x00fdfdfd, 0x00888888, 0x009f9f9f, 0x00656565,
  0x00878787, 0x006b6b6b, 0x00f4f4f4, 0x00232323,
  0x00484848, 0x00101010, 0x00d1d1d1, 0x00515151,
  0x00c0c0c0, 0x00f9f9f9, 0x00d2d2d2, 0x00a0a0a0,
  0x00555555, 0x00a1a1a1, 0x00414141, 0x00fafafa,
  0x00434343, 0x00131313, 0x00c4c4c4, 0x002f2f2f,
  0x00a8a8a8, 0x00b6b6b6, 0x003c3c3c, 0x002b2b2b,
  0x00c1c1c1, 0x00ffffff, 0x00c8c8c8, 0x00a5a5a5,
  0x00202020, 0x00898989, 0x00000000, 0x00909090,
  0x00474747, 0x00efefef, 0x00eaeaea, 0x00b7b7b7,
  0x00151515, 0x00060606, 0x00cdcdcd, 0x00b5b5b5,
  0x00121212, 0x007e7e7e, 0x00bbbbbb, 0x00292929,
  0x000f0f0f, 0x00b8b8b8, 0x00070707, 0x00040404,
  0x009b9b9b, 0x00949494, 0x00212121, 0x00666666,
  0x00e6e6e6, 0x00cecece, 0x00ededed, 0x00e7e7e7,
  0x003b3b3b, 0x00fefefe, 0x007f7f7f, 0x00c5c5c5,
  0x00a4a4a4, 0x00373737, 0x00b1b1b1, 0x004c4c4c,
  0x00919191, 0x006e6e6e, 0x008d8d8d, 0x00767676,
  0x00030303, 0x002d2d2d, 0x00dedede, 0x00969696,
  0x00262626, 0x007d7d7d, 0x00c6c6c6, 0x005c5c5c,
  0x00d3d3d3, 0x00f2f2f2, 0x004f4f4f, 0x00191919,
  0x003f3f3f, 0x00dcdcdc, 0x00797979, 0x001d1d1d,
  0x00525252, 0x00ebebeb, 0x00f3f3f3, 0x006d6d6d,
  0x005e5e5e, 0x00fbfbfb, 0x00696969, 0x00b2b2b2,
  0x00f0f0f0, 0x00313131, 0x000c0c0c, 0x00d4d4d4,
  0x00cfcfcf, 0x008c8c8c, 0x00e2e2e2, 0x00757575,
  0x00a9a9a9, 0x004a4a4a, 0x00575757, 0x00848484,
  0x00111111, 0x00454545, 0x001b1b1b, 0x00f5f5f5,
  0x00e4e4e4, 0x000e0e0e, 0x00737373, 0x00aaaaaa,
  0x00f1f1f1, 0x00dddddd, 0x00595959, 0x00141414,
  0x006c6c6c, 0x00929292, 0x00545454, 0x00d0d0d0,
  0x00787878, 0x00707070, 0x00e3e3e3, 0x00494949,
  0x00808080, 0x00505050, 0x00a7a7a7, 0x00f6f6f6,
  0x00777777, 0x00939393, 0x00868686, 0x00838383,
  0x002a2a2a, 0x00c7c7c7, 0x005b5b5b, 0x00e9e9e9,
  0x00eeeeee, 0x008f8f8f, 0x00010101, 0x003d3d3d
};

static const uint32_t S3[256] = {
  0x38003838, 0x41004141, 0x16001616, 0x76007676,
  0xd900d9d9, 0x93009393, 0x60006060, 0xf200f2f2,
  0x72007272, 0xc200c2c2, 0xab00abab, 0x9a009a9a,
  0x75007575, 0x06000606, 0x57005757, 0xa000a0a0,
  0x91009191, 0xf700f7f7, 0xb500b5b5, 0xc900c9c9,
  0xa200a2a2, 0x8c008c8c, 0xd200d2d2, 0x90009090,
  0xf600f6f6, 0x07000707, 0xa700a7a7, 0x27002727,
  0x8e008e8e, 0xb200b2b2, 0x49004949, 0xde00dede,
  0x43004343, 0x5c005c5c, 0xd700d7d7, 0xc700c7c7,
  0x3e003e3e, 0xf500f5f5, 0x8f008f8f, 0x67006767,
  0x1f001f1f, 0x18001818, 0x6e006e6e, 0xaf00afaf,
  0x2f002f2f, 0xe200e2e2, 0x85008585, 0x0d000d0d,
  0x53005353, 0xf000f0f0, 0x9c009c9c, 0x65006565,
  0xea00eaea, 0xa300a3a3, 0xae00aeae, 0x9e009e9e,
  0xec00ecec, 0x80008080, 0x2d002d2d, 0x6b006b6b,
  0xa800a8a8, 0x2b002b2b, 0x36003636, 0xa600a6a6,
  0xc500c5c5, 0x86008686, 0x4d004d4d, 0x33003333,
  0xfd00fdfd, 0x66006666, 0x58005858, 0x96009696,
  0x3a003a3a, 0x09000909, 0x95009595, 0x10001010,
  0x78007878, 0xd800d8d8, 0x42004242, 0xcc00cccc,
  0xef00efef, 0x26002626, 0xe500e5e5, 0x61006161,
  0x1a001a1a, 0x3f003f3f, 0x3b003b3b, 0x82008282,
  0xb600b6b6, 0xdb00dbdb, 0xd400d4d4, 0x98009898,
  0xe800e8e8, 0x8b008b8b, 0x02000202, 0xeb00ebeb,
  0x0a000a0a, 0x2c002c2c, 0x1d001d1d, 0xb000b0b0,
  0x6f006f6f, 0x8d008d8d, 0x88008888, 0x0e000e0e,
  0x19001919, 0x87008787, 0x4e004e4e, 0x0b000b0b,
  0xa900a9a9, 0x0c000c0c, 0x79007979, 0x11001111,
  0x7f007f7f, 0x22002222, 0xe700e7e7, 0x59005959,
  0xe100e1e1, 0xda00dada, 0x3d003d3d, 0xc800c8c8,
  0x12001212, 0x04000404, 0x74007474, 0x54005454,
  0x30003030, 0x7e007e7e, 0xb400b4b4, 0x28002828,
  0x55005555, 0x68006868, 0x50005050, 0xbe00bebe,
  0xd000d0d0, 0xc400c4c4, 0x31003131, 0xcb00cbcb,
  0x2a002a2a, 0xad00adad, 0x0f000f0f, 0xca00caca,
  0x70007070, 0xff00ffff, 0x32003232, 0x69006969,
  0x08000808, 0x62006262, 0x00000000, 0x24002424,
  0xd100d1d1, 0xfb00fbfb, 0xba00baba, 0xed00eded,
  0x45004545, 0x81008181, 0x73007373, 0x6d006d6d,
  0x84008484, 0x9f009f9f, 0xee00eeee, 0x4a004a4a,
  0xc300c3c3, 0x2e002e2e, 0xc100c1c1, 0x01000101,
  0xe600e6e6, 0x25002525, 0x48004848, 0x99009999,
  0xb900b9b9, 0xb300b3b3, 0x7b007b7b, 0xf900f9f9,
  0xce00cece, 0xbf00bfbf, 0xdf00dfdf, 0x71007171,
  0x29002929, 0xcd00cdcd, 0x6c006c6c, 0x13001313,
  0x64006464, 0x9b009b9b, 0x63006363, 0x9d009d9d,
  0xc000c0c0, 0x4b004b4b, 0xb700b7b7, 0xa500a5a5,
  0x89008989, 0x5f005f5f, 0xb100b1b1, 0x17001717,
  0xf400f4f4, 0xbc00bcbc, 0xd300d3d3, 0x46004646,
  0xcf00cfcf, 0x37003737, 0x5e005e5e, 0x47004747,
  0x94009494, 0xfa00fafa, 0xfc00fcfc, 0x5b005b5b,
  0x97009797, 0xfe00fefe, 0x5a005a5a, 0xac00acac,
  0x3c003c3c, 0x4c004c4c, 0x03000303, 0x35003535,
  0xf300f3f3, 0x23002323, 0xb800b8b8, 0x5d005d5d,
  0x6a006a6a, 0x92009292, 0xd500d5d5, 0x21002121,
  0x44004444, 0x51005151, 0xc600c6c6, 0x7d007d7d,
  0x39003939, 0x83008383, 0xdc00dcdc, 0xaa00aaaa,
  0x7c007c7c, 0x77007777, 0x56005656, 0x05000505,
  0x1b001b1b, 0xa400a4a4, 0x15001515, 0x34003434,
  0x1e001e1e, 0x1c001c1c, 0xf800f8f8, 0x52005252,
  0x20002020, 0x14001414, 0xe900e9e9, 0xbd00bdbd,
  0xdd00dddd, 0xe400e4e4, 0xa100a1a1, 0xe000e0e0,
  0x8a008a8a, 0xf100f1f1, 0xd600d6d6, 0x7a007a7a,
  0xbb00bbbb, 0xe300e3e3, 0x40004040, 0x4f004f4f
};

static const uint32_t S4[256] = {
  0x70700070, 0x2c2c002c, 0xb3b300b3, 0xc0c000c0,
  0xe4e400e4, 0x57570057, 0xeaea00ea, 0xaeae00ae,
  0x23230023, 0x6b6b006b, 0x45450045, 0xa5a500a5,
  0xeded00ed, 0x4f4f004f, 0x1d1d001d, 0x92920092,
  0x86860086, 0xafaf00af, 0x7c7c007c, 0x1f1f001f,
  0x3e3e003e, 0xdcdc00dc, 0x5e5e005e, 0x0b0b000b,
  0xa6a600a6, 0x39390039, 0xd5d500d5, 0x5d5d005d,
  0xd9d900d9, 0x5a5a005a, 0x51510051, 0x6c6c006c,
  0x8b8b008b, 0x9a9a009a, 0xfbfb00fb, 0xb0b000b0,
  0x74740074, 0x2b2b002b, 0xf0f000f0, 0x84840084,
  0xdfdf00df, 0xcbcb00cb, 0x34340034, 0x76760076,
  0x6d6d006d, 0xa9a900a9, 0xd1d100d1, 0x04040004,
  0x14140014, 0x3a3a003a, 0xdede00de, 0x11110011,
  0x32320032, 0x9c9c009c, 0x53530053, 0xf2f200f2,
  0xfefe00fe, 0xcfcf00cf, 0xc3c300c3, 0x7a7a007a,
  0x24240024, 0xe8e800e8, 0x60600060, 0x69690069,
  0xaaaa00aa, 0xa0a000a0, 0xa1a100a1, 0x62620062,
  0x54540054, 0x1e1e001e, 0xe0e000e0, 0x64640064,
  0x10100010, 0x00000000, 0xa3a300a3, 0x75750075,
  0x8a8a008a, 0xe6e600e6, 0x09090009, 0xdddd00dd,
  0x87870087, 0x83830083, 0xcdcd00cd, 0x90900090,
  0x73730073, 0xf6f600f6, 0x9d9d009d, 0xbfbf00bf,
  0x52520052, 0xd8d800d8, 0xc8c800c8, 0xc6c600c6,
  0x81810081, 0x6f6f006f, 0x13130013, 0x63630063,
  0xe9e900e9, 0xa7a700a7, 0x9f9f009f, 0xbcbc00bc,
  0x29290029, 0xf9f900f9, 0x2f2f002f, 0xb4b400b4,
  0x78780078, 0x06060006, 0xe7e700e7, 0x71710071,
  0xd4d400d4, 0xabab00ab, 0x88880088, 0x8d8d008d,
  0x72720072, 0xb9b900b9, 0xf8f800f8, 0xacac00ac,
  0x36360036, 0x2a2a002a, 0x3c3c003c, 0xf1f100f1,
  0x40400040, 0xd3d300d3, 0xbbbb00bb, 0x43430043,
  0x15150015, 0xadad00ad, 0x77770077, 0x80800080,
  0x82820082, 0xecec00ec, 0x27270027, 0xe5e500e5,
  0x85850085, 0x35350035, 0x0c0c000c, 0x41410041,
  0xefef00ef, 0x93930093, 0x19190019, 0x21210021,
  0x0e0e000e, 0x4e4e004e, 0x65650065, 0xbdbd00bd,
  0xb8b800b8, 0x8f8f008f, 0xebeb00eb, 0xcece00ce,
  0x30300030, 0x5f5f005f, 0xc5c500c5, 0x1a1a001a,
  0xe1e100e1, 0xcaca00ca, 0x47470047, 0x3d3d003d,
  0x01010001, 0xd6d600d6, 0x56560056, 0x4d4d004d,
  0x0d0d000d, 0x66660066, 0xcccc00cc, 0x2d2d002d,
  0x12120012, 0x20200020, 0xb1b100b1, 0x99990099,
  0x4c4c004c, 0xc2c200c2, 0x7e7e007e, 0x05050005,
  0xb7b700b7, 0x31310031, 0x17170017, 0xd7d700d7,
  0x58580058, 0x61610061, 0x1b1b001b, 0x1c1c001c,
  0x0f0f000f, 0x16160016, 0x18180018, 0x22220022,
  0x44440044, 0xb2b200b2, 0xb5b500b5, 0x91910091,
  0x08080008, 0xa8a800a8, 0xfcfc00fc, 0x50500050,
  0xd0d000d0, 0x7d7d007d, 0x89890089, 0x97970097,
  0x5b5b005b, 0x95950095, 0xffff00ff, 0xd2d200d2,
  0xc4c400c4, 0x48480048, 0xf7f700f7, 0xdbdb00db,
  0x03030003, 0xdada00da, 0x3f3f003f, 0x94940094,
  0x5c5c005c, 0x02020002, 0x4a4a004a, 0x33330033,
  0x67670067, 0xf3f300f3, 0x7f7f007f, 0xe2e200e2,
  0x9b9b009b, 0x26260026, 0x37370037, 0x3b3b003b,
  0x96960096, 0x4b4b004b, 0xbebe00be, 0x2e2e002e,
  0x79790079, 0x8c8c008c, 0x6e6e006e, 0x8e8e008e,
  0xf5f500f5, 0xb6b600b6, 0xfdfd00fd, 0x59590059,
  0x98980098, 0x6a6a006a, 0x46460046, 0xbaba00ba,
  0x25250025, 0x42420042, 0xa2a200a2, 0xfafa00fa,
  0x07070007, 0x55550055, 0xeeee00ee, 0x0a0a000a,
  0x49490049, 0x68680068, 0x38380038, 0xa4a400a4,
  0x28280028, 0x7b7b007b, 0xc9c900c9, 0xc1c100c1,
  0xe3e300e3, 0xf4f400f4, 0xc7c700c7, 0x9e9e009e
};

#define F(r0, r1, r2, r3, k0, k1) do { \
  uint32_t t0, t1, z;                  \
                                       \
  t0 = (k0) ^ (r0);                    \
  t1 = (k1) ^ (r1);                    \
                                       \
  z = S4[(t0 >>  0) & 0xff]            \
    ^ S3[(t0 >>  8) & 0xff]            \
    ^ S2[(t0 >> 16) & 0xff]            \
    ^ S1[(t0 >> 24) & 0xff];           \
                                       \
  (r3) ^= (z >> 8) | (z << (32 - 8));  \
                                       \
  z ^= S1[(t1 >>  0) & 0xff]           \
     ^ S4[(t1 >>  8) & 0xff]           \
     ^ S3[(t1 >> 16) & 0xff]           \
     ^ S2[(t1 >> 24) & 0xff];          \
                                       \
  (r2) ^= z;                           \
  (r3) ^= z;                           \
} while (0)

#define ROTL128(s0, s1, s2, s3, n) do {    \
  uint32_t t = (s0) >> (32 - n);           \
                                           \
  (s0) = ((s0) << n) | ((s1) >> (32 - n)); \
  (s1) = ((s1) << n) | ((s2) >> (32 - n)); \
  (s2) = ((s2) << n) | ((s3) >> (32 - n)); \
  (s3) = ((s3) << n) | t;                  \
} while (0)

static void
camellia128_init(camellia_t *ctx, const unsigned char *key) {
  uint32_t *k = ctx->key;
  uint32_t s0 = read32be(key +  0);
  uint32_t s1 = read32be(key +  4);
  uint32_t s2 = read32be(key +  8);
  uint32_t s3 = read32be(key + 12);

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  ctx->bits = 128;

  k[0] = s0;
  k[1] = s1;
  k[2] = s2;
  k[3] = s3;

  F(s0, s1, s2, s3, sigma[0], sigma[1]);
  F(s2, s3, s0, s1, sigma[2], sigma[3]);

  s0 ^= k[0];
  s1 ^= k[1];
  s2 ^= k[2];
  s3 ^= k[3];

  F(s0, s1, s2, s3, sigma[4], sigma[5]);
  F(s2, s3, s0, s1, sigma[6], sigma[7]);

  k[4] = s0;
  k[5] = s1;
  k[6] = s2;
  k[7] = s3;

  ROTL128(s0, s1, s2, s3, 15); /* KA << 15 */

  k[12] = s0;
  k[13] = s1;
  k[14] = s2;
  k[15] = s3;

  ROTL128(s0, s1, s2, s3, 15); /* KA << 30 */

  k[16] = s0;
  k[17] = s1;
  k[18] = s2;
  k[19] = s3;

  ROTL128(s0, s1, s2, s3, 15); /* KA << 45 */

  k[24] = s0;
  k[25] = s1;

  ROTL128(s0, s1, s2, s3, 15); /* KA << 60 */

  k[28] = s0;
  k[29] = s1;
  k[30] = s2;
  k[31] = s3;

  ROTL128(s1, s2, s3, s0, 2); /* KA << 94 */

  k[40] = s1;
  k[41] = s2;
  k[42] = s3;
  k[43] = s0;

  ROTL128(s1, s2, s3, s0, 17); /* KA << 111 */

  k[48] = s1;
  k[49] = s2;
  k[50] = s3;
  k[51] = s0;

  s0 = k[0];
  s1 = k[1];
  s2 = k[2];
  s3 = k[3];

  ROTL128(s0, s1, s2, s3, 15); /* KL << 15 */

  k[8] = s0;
  k[9] = s1;
  k[10] = s2;
  k[11] = s3;

  ROTL128(s0, s1, s2, s3, 30); /* KL << 45 */

  k[20] = s0;
  k[21] = s1;
  k[22] = s2;
  k[23] = s3;

  ROTL128(s0, s1, s2, s3, 15); /* KL << 60 */

  k[26] = s2;
  k[27] = s3;

  ROTL128(s0, s1, s2, s3, 17); /* KL << 77 */

  k[32] = s0;
  k[33] = s1;
  k[34] = s2;
  k[35] = s3;

  ROTL128(s0, s1, s2, s3, 17); /* KL << 94 */

  k[36] = s0;
  k[37] = s1;
  k[38] = s2;
  k[39] = s3;

  ROTL128(s0, s1, s2, s3, 17); /* KL << 111 */

  k[44] = s0;
  k[45] = s1;
  k[46] = s2;
  k[47] = s3;
}

static void
camellia128_encrypt(const camellia_t *ctx,
                    unsigned char *dst,
                    const unsigned char *src) {
  const uint32_t *k = ctx->key;
  uint32_t r0 = read32be(src +  0);
  uint32_t r1 = read32be(src +  4);
  uint32_t r2 = read32be(src +  8);
  uint32_t r3 = read32be(src + 12);
  uint32_t t;

  r0 ^= k[0];
  r1 ^= k[1];
  r2 ^= k[2];
  r3 ^= k[3];

  F(r0, r1, r2, r3, k[4], k[5]);
  F(r2, r3, r0, r1, k[6], k[7]);
  F(r0, r1, r2, r3, k[8], k[9]);
  F(r2, r3, r0, r1, k[10], k[11]);
  F(r0, r1, r2, r3, k[12], k[13]);
  F(r2, r3, r0, r1, k[14], k[15]);

  t = r0 & k[16];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[19];
  r0 ^= r1 | k[17];
  t = r2 & k[18];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[20], k[21]);
  F(r2, r3, r0, r1, k[22], k[23]);
  F(r0, r1, r2, r3, k[24], k[25]);
  F(r2, r3, r0, r1, k[26], k[27]);
  F(r0, r1, r2, r3, k[28], k[29]);
  F(r2, r3, r0, r1, k[30], k[31]);

  t = r0 & k[32];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[35];
  r0 ^= r1 | k[33];
  t = r2 & k[34];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[36], k[37]);
  F(r2, r3, r0, r1, k[38], k[39]);
  F(r0, r1, r2, r3, k[40], k[41]);
  F(r2, r3, r0, r1, k[42], k[43]);
  F(r0, r1, r2, r3, k[44], k[45]);
  F(r2, r3, r0, r1, k[46], k[47]);

  r2 ^= k[48];
  r3 ^= k[49];
  r0 ^= k[50];
  r1 ^= k[51];

  write32be(dst +  0, r2);
  write32be(dst +  4, r3);
  write32be(dst +  8, r0);
  write32be(dst + 12, r1);
}

static void
camellia128_decrypt(const camellia_t *ctx,
                    unsigned char *dst,
                    const unsigned char *src) {
  const uint32_t *k = ctx->key;
  uint32_t r0 = read32be(src +  0);
  uint32_t r1 = read32be(src +  4);
  uint32_t r2 = read32be(src +  8);
  uint32_t r3 = read32be(src + 12);
  uint32_t t;

  r3 ^= k[51];
  r2 ^= k[50];
  r1 ^= k[49];
  r0 ^= k[48];

  F(r0, r1, r2, r3, k[46], k[47]);
  F(r2, r3, r0, r1, k[44], k[45]);
  F(r0, r1, r2, r3, k[42], k[43]);
  F(r2, r3, r0, r1, k[40], k[41]);
  F(r0, r1, r2, r3, k[38], k[39]);
  F(r2, r3, r0, r1, k[36], k[37]);

  t = r0 & k[34];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[33];
  r0 ^= r1 | k[35];
  t = r2 & k[32];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[30], k[31]);
  F(r2, r3, r0, r1, k[28], k[29]);
  F(r0, r1, r2, r3, k[26], k[27]);
  F(r2, r3, r0, r1, k[24], k[25]);
  F(r0, r1, r2, r3, k[22], k[23]);
  F(r2, r3, r0, r1, k[20], k[21]);

  t = r0 & k[18];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[17];
  r0 ^= r1 | k[19];
  t = r2 & k[16];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[14], k[15]);
  F(r2, r3, r0, r1, k[12], k[13]);
  F(r0, r1, r2, r3, k[10], k[11]);
  F(r2, r3, r0, r1, k[8], k[9]);
  F(r0, r1, r2, r3, k[6], k[7]);
  F(r2, r3, r0, r1, k[4], k[5]);

  r1 ^= k[3];
  r0 ^= k[2];
  r3 ^= k[1];
  r2 ^= k[0];

  write32be(dst +  0, r2);
  write32be(dst +  4, r3);
  write32be(dst +  8, r0);
  write32be(dst + 12, r1);
}

static void
camellia256_init(camellia_t *ctx, const unsigned char *key, size_t key_len) {
  uint32_t *k = ctx->key;
  uint32_t s0, s1, s2, s3;

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  k[0] = read32be(key +  0);
  k[1] = read32be(key +  4);
  k[2] = read32be(key +  8);
  k[3] = read32be(key + 12);

  k[8] = read32be(key + 16);
  k[9] = read32be(key + 20);

  if (key_len == 24) {
    ctx->bits = 192;
    k[10] = ~k[8];
    k[11] = ~k[9];
  } else if (key_len == 32) {
    ctx->bits = 256;
    k[10] = read32be(key + 24);
    k[11] = read32be(key + 28);
  } else {
    torsion_abort(); /* LCOV_EXCL_LINE */
  }

  s0 = k[8] ^ k[0];
  s1 = k[9] ^ k[1];
  s2 = k[10] ^ k[2];
  s3 = k[11] ^ k[3];

  F(s0, s1, s2, s3, sigma[0], sigma[1]);
  F(s2, s3, s0, s1, sigma[2], sigma[3]);

  s0 ^= k[0];
  s1 ^= k[1];
  s2 ^= k[2];
  s3 ^= k[3];

  F(s0, s1, s2, s3, sigma[4], sigma[5]);
  F(s2, s3, s0, s1, sigma[6], sigma[7]);

  k[12] = s0;
  k[13] = s1;
  k[14] = s2;
  k[15] = s3;

  s0 ^= k[8];
  s1 ^= k[9];
  s2 ^= k[10];
  s3 ^= k[11];

  F(s0, s1, s2, s3, sigma[8], sigma[9]);
  F(s2, s3, s0, s1, sigma[10], sigma[11]);

  k[4] = s0;
  k[5] = s1;
  k[6] = s2;
  k[7] = s3;

  ROTL128(s0, s1, s2, s3, 30); /* KB << 30 */

  k[20] = s0;
  k[21] = s1;
  k[22] = s2;
  k[23] = s3;

  ROTL128(s0, s1, s2, s3, 30); /* KB << 60 */

  k[40] = s0;
  k[41] = s1;
  k[42] = s2;
  k[43] = s3;

  ROTL128(s1, s2, s3, s0, 19); /* KB << 111 */

  k[64] = s1;
  k[65] = s2;
  k[66] = s3;
  k[67] = s0;

  s0 = k[8];
  s1 = k[9];
  s2 = k[10];
  s3 = k[11];

  ROTL128(s0, s1, s2, s3, 15); /* KR << 15 */

  k[8] = s0;
  k[9] = s1;
  k[10] = s2;
  k[11] = s3;

  ROTL128(s0, s1, s2, s3, 15); /* KR << 30 */

  k[16] = s0;
  k[17] = s1;
  k[18] = s2;
  k[19] = s3;

  ROTL128(s0, s1, s2, s3, 30); /* KR << 60 */

  k[36] = s0;
  k[37] = s1;
  k[38] = s2;
  k[39] = s3;

  ROTL128(s1, s2, s3, s0, 2); /* KR << 94 */

  k[52] = s1;
  k[53] = s2;
  k[54] = s3;
  k[55] = s0;

  s0 = k[12];
  s1 = k[13];
  s2 = k[14];
  s3 = k[15];

  ROTL128(s0, s1, s2, s3, 15); /* KA << 15 */

  k[12] = s0;
  k[13] = s1;
  k[14] = s2;
  k[15] = s3;

  ROTL128(s0, s1, s2, s3, 30); /* KA << 45 */

  k[28] = s0;
  k[29] = s1;
  k[30] = s2;
  k[31] = s3;

  /* KA << 77 */
  k[48] = s1;
  k[49] = s2;
  k[50] = s3;
  k[51] = s0;

  ROTL128(s1, s2, s3, s0, 17); /* KA << 94 */

  k[56] = s1;
  k[57] = s2;
  k[58] = s3;
  k[59] = s0;

  s0 = k[0];
  s1 = k[1];
  s2 = k[2];
  s3 = k[3];

  ROTL128(s1, s2, s3, s0, 13); /* KL << 45 */

  k[24] = s1;
  k[25] = s2;
  k[26] = s3;
  k[27] = s0;

  ROTL128(s1, s2, s3, s0, 15); /* KL << 60 */

  k[32] = s1;
  k[33] = s2;
  k[34] = s3;
  k[35] = s0;

  ROTL128(s1, s2, s3, s0, 17); /* KL << 77 */

  k[44] = s1;
  k[45] = s2;
  k[46] = s3;
  k[47] = s0;

  ROTL128(s2, s3, s0, s1, 2); /* KL << 111 */

  k[60] = s2;
  k[61] = s3;
  k[62] = s0;
  k[63] = s1;
}

static void
camellia256_encrypt(const camellia_t *ctx,
                    unsigned char *dst,
                    const unsigned char *src) {
  const uint32_t *k = ctx->key;
  uint32_t r0 = read32be(src +  0);
  uint32_t r1 = read32be(src +  4);
  uint32_t r2 = read32be(src +  8);
  uint32_t r3 = read32be(src + 12);
  uint32_t t;

  r0 ^= k[0];
  r1 ^= k[1];
  r2 ^= k[2];
  r3 ^= k[3];

  F(r0, r1, r2, r3, k[4], k[5]);
  F(r2, r3, r0, r1, k[6], k[7]);
  F(r0, r1, r2, r3, k[8], k[9]);
  F(r2, r3, r0, r1, k[10], k[11]);
  F(r0, r1, r2, r3, k[12], k[13]);
  F(r2, r3, r0, r1, k[14], k[15]);

  t = r0 & k[16];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[19];
  r0 ^= r1 | k[17];
  t = r2 & k[18];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[20], k[21]);
  F(r2, r3, r0, r1, k[22], k[23]);
  F(r0, r1, r2, r3, k[24], k[25]);
  F(r2, r3, r0, r1, k[26], k[27]);
  F(r0, r1, r2, r3, k[28], k[29]);
  F(r2, r3, r0, r1, k[30], k[31]);

  t = r0 & k[32];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[35];
  r0 ^= r1 | k[33];
  t = r2 & k[34];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[36], k[37]);
  F(r2, r3, r0, r1, k[38], k[39]);
  F(r0, r1, r2, r3, k[40], k[41]);
  F(r2, r3, r0, r1, k[42], k[43]);
  F(r0, r1, r2, r3, k[44], k[45]);
  F(r2, r3, r0, r1, k[46], k[47]);

  t = r0 & k[48];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[51];
  r0 ^= r1 | k[49];
  t = r2 & k[50];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[52], k[53]);
  F(r2, r3, r0, r1, k[54], k[55]);
  F(r0, r1, r2, r3, k[56], k[57]);
  F(r2, r3, r0, r1, k[58], k[59]);
  F(r0, r1, r2, r3, k[60], k[61]);
  F(r2, r3, r0, r1, k[62], k[63]);

  r2 ^= k[64];
  r3 ^= k[65];
  r0 ^= k[66];
  r1 ^= k[67];

  write32be(dst +  0, r2);
  write32be(dst +  4, r3);
  write32be(dst +  8, r0);
  write32be(dst + 12, r1);
}

static void
camellia256_decrypt(const camellia_t *ctx,
                    unsigned char *dst,
                    const unsigned char *src) {
  const uint32_t *k = ctx->key;
  uint32_t r0 = read32be(src +  0);
  uint32_t r1 = read32be(src +  4);
  uint32_t r2 = read32be(src +  8);
  uint32_t r3 = read32be(src + 12);
  uint32_t t;

  r3 ^= k[67];
  r2 ^= k[66];
  r1 ^= k[65];
  r0 ^= k[64];

  F(r0, r1, r2, r3, k[62], k[63]);
  F(r2, r3, r0, r1, k[60], k[61]);
  F(r0, r1, r2, r3, k[58], k[59]);
  F(r2, r3, r0, r1, k[56], k[57]);
  F(r0, r1, r2, r3, k[54], k[55]);
  F(r2, r3, r0, r1, k[52], k[53]);

  t = r0 & k[50];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[49];
  r0 ^= r1 | k[51];
  t = r2 & k[48];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[46], k[47]);
  F(r2, r3, r0, r1, k[44], k[45]);
  F(r0, r1, r2, r3, k[42], k[43]);
  F(r2, r3, r0, r1, k[40], k[41]);
  F(r0, r1, r2, r3, k[38], k[39]);
  F(r2, r3, r0, r1, k[36], k[37]);

  t = r0 & k[34];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[33];
  r0 ^= r1 | k[35];
  t = r2 & k[32];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[30], k[31]);
  F(r2, r3, r0, r1, k[28], k[29]);
  F(r0, r1, r2, r3, k[26], k[27]);
  F(r2, r3, r0, r1, k[24], k[25]);
  F(r0, r1, r2, r3, k[22], k[23]);
  F(r2, r3, r0, r1, k[20], k[21]);

  t = r0 & k[18];
  r1 ^= (t << 1) | (t >> (32 - 1));
  r2 ^= r3 | k[17];
  r0 ^= r1 | k[19];
  t = r2 & k[16];
  r3 ^= (t << 1) | (t >> (32 - 1));

  F(r0, r1, r2, r3, k[14], k[15]);
  F(r2, r3, r0, r1, k[12], k[13]);
  F(r0, r1, r2, r3, k[10], k[11]);
  F(r2, r3, r0, r1, k[8], k[9]);
  F(r0, r1, r2, r3, k[6], k[7]);
  F(r2, r3, r0, r1, k[4], k[5]);

  r1 ^= k[3];
  r0 ^= k[2];
  r3 ^= k[1];
  r2 ^= k[0];

  write32be(dst +  0, r2);
  write32be(dst +  4, r3);
  write32be(dst +  8, r0);
  write32be(dst + 12, r1);
}

#undef F
#undef ROTL128

void
camellia_init(camellia_t *ctx, unsigned int bits, const unsigned char *key) {
  switch (bits) {
    case 128:
      camellia128_init(ctx, key);
      break;
    case 192:
      camellia256_init(ctx, key, 24);
      break;
    case 256:
      camellia256_init(ctx, key, 32);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

void
camellia_encrypt(const camellia_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src) {
  if (ctx->bits == 128)
    camellia128_encrypt(ctx, dst, src);
  else
    camellia256_encrypt(ctx, dst, src);
}

void
camellia_decrypt(const camellia_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src) {
  if (ctx->bits == 128)
    camellia128_decrypt(ctx, dst, src);
  else
    camellia256_decrypt(ctx, dst, src);
}

#undef sigma
#undef S1
#undef S2
#undef S3
#undef S4

/*
 * CAST5
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/CAST-128
 *   https://tools.ietf.org/html/rfc2144
 *   https://github.com/golang/crypto/blob/master/cast5/cast5.go
 */

#define S cast5_S
#define schedule cast5_schedule
#define X cast5_X
#define f1 cast5_f1
#define f2 cast5_f2
#define f3 cast5_f3

static const uint32_t S[8][256] = {
  {
    0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a,
    0x1e213f2f, 0x9c004dd3, 0x6003e540, 0xcf9fc949,
    0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675,
    0x6e63a0e0, 0x15c361d2, 0xc2e7661d, 0x22d4ff8e,
    0x28683b6f, 0xc07fd059, 0xff2379c8, 0x775f50e2,
    0x43c340d3, 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d,
    0xa1c9e0d6, 0x346c4819, 0x61b76d87, 0x22540f2f,
    0x2abe32e1, 0xaa54166b, 0x22568e3a, 0xa2d341d0,
    0x66db40c8, 0xa784392f, 0x004dff2f, 0x2db9d2de,
    0x97943fac, 0x4a97c1d8, 0x527644b7, 0xb5f437a7,
    0xb82cbaef, 0xd751d159, 0x6ff7f0ed, 0x5a097a1f,
    0x827b68d0, 0x90ecf52e, 0x22b0c054, 0xbc8e5935,
    0x4b6d2f7f, 0x50bb64a2, 0xd2664910, 0xbee5812d,
    0xb7332290, 0xe93b159f, 0xb48ee411, 0x4bff345d,
    0xfd45c240, 0xad31973f, 0xc4f6d02e, 0x55fc8165,
    0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d, 0xc19b0c50,
    0x882240f2, 0x0c6e4f38, 0xa4e4bfd7, 0x4f5ba272,
    0x564c1d2f, 0xc59c5319, 0xb949e354, 0xb04669fe,
    0xb1b6ab8a, 0xc71358dd, 0x6385c545, 0x110f935d,
    0x57538ad5, 0x6a390493, 0xe63d37e0, 0x2a54f6b3,
    0x3a787d5f, 0x6276a0b5, 0x19a6fcdf, 0x7a42206a,
    0x29f9d4d5, 0xf61b1891, 0xbb72275e, 0xaa508167,
    0x38901091, 0xc6b505eb, 0x84c7cb8c, 0x2ad75a0f,
    0x874a1427, 0xa2d1936b, 0x2ad286af, 0xaa56d291,
    0xd7894360, 0x425c750d, 0x93b39e26, 0x187184c9,
    0x6c00b32d, 0x73e2bb14, 0xa0bebc3c, 0x54623779,
    0x64459eab, 0x3f328b82, 0x7718cf82, 0x59a2cea6,
    0x04ee002e, 0x89fe78e6, 0x3fab0950, 0x325ff6c2,
    0x81383f05, 0x6963c5c8, 0x76cb5ad6, 0xd49974c9,
    0xca180dcf, 0x380782d5, 0xc7fa5cf6, 0x8ac31511,
    0x35e79e13, 0x47da91d0, 0xf40f9086, 0xa7e2419e,
    0x31366241, 0x051ef495, 0xaa573b04, 0x4a805d8d,
    0x548300d0, 0x00322a3c, 0xbf64cddf, 0xba57a68e,
    0x75c6372b, 0x50afd341, 0xa7c13275, 0x915a0bf5,
    0x6b54bfab, 0x2b0b1426, 0xab4cc9d7, 0x449ccd82,
    0xf7fbf265, 0xab85c5f3, 0x1b55db94, 0xaad4e324,
    0xcfa4bd3f, 0x2deaa3e2, 0x9e204d02, 0xc8bd25ac,
    0xeadf55b3, 0xd5bd9e98, 0xe31231b2, 0x2ad5ad6c,
    0x954329de, 0xadbe4528, 0xd8710f69, 0xaa51c90f,
    0xaa786bf6, 0x22513f1e, 0xaa51a79b, 0x2ad344cc,
    0x7b5a41f0, 0xd37cfbad, 0x1b069505, 0x41ece491,
    0xb4c332e6, 0x032268d4, 0xc9600acc, 0xce387e6d,
    0xbf6bb16c, 0x6a70fb78, 0x0d03d9c9, 0xd4df39de,
    0xe01063da, 0x4736f464, 0x5ad328d8, 0xb347cc96,
    0x75bb0fc3, 0x98511bfb, 0x4ffbcc35, 0xb58bcf6a,
    0xe11f0abc, 0xbfc5fe4a, 0xa70aec10, 0xac39570a,
    0x3f04442f, 0x6188b153, 0xe0397a2e, 0x5727cb79,
    0x9ceb418f, 0x1cacd68d, 0x2ad37c96, 0x0175cb9d,
    0xc69dff09, 0xc75b65f0, 0xd9db40d8, 0xec0e7779,
    0x4744ead4, 0xb11c3274, 0xdd24cb9e, 0x7e1c54bd,
    0xf01144f9, 0xd2240eb1, 0x9675b3fd, 0xa3ac3755,
    0xd47c27af, 0x51c85f4d, 0x56907596, 0xa5bb15e6,
    0x580304f0, 0xca042cf1, 0x011a37ea, 0x8dbfaadb,
    0x35ba3e4a, 0x3526ffa0, 0xc37b4d09, 0xbc306ed9,
    0x98a52666, 0x5648f725, 0xff5e569d, 0x0ced63d0,
    0x7c63b2cf, 0x700b45e1, 0xd5ea50f1, 0x85a92872,
    0xaf1fbda7, 0xd4234870, 0xa7870bf3, 0x2d3b4d79,
    0x42e04198, 0x0cd0ede7, 0x26470db8, 0xf881814c,
    0x474d6ad7, 0x7c0c5e5c, 0xd1231959, 0x381b7298,
    0xf5d2f4db, 0xab838653, 0x6e2f1e23, 0x83719c9e,
    0xbd91e046, 0x9a56456e, 0xdc39200c, 0x20c8c571,
    0x962bda1c, 0xe1e696ff, 0xb141ab08, 0x7cca89b9,
    0x1a69e783, 0x02cc4843, 0xa2f7c579, 0x429ef47d,
    0x427b169c, 0x5ac9f049, 0xdd8f0f00, 0x5c8165bf
  },
  {
    0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380,
    0xfe61cf7a, 0xeec5207a, 0x55889c94, 0x72fc0651,
    0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba,
    0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3,
    0xa0b52f7b, 0x59e83605, 0xee15b094, 0xe9ffd909,
    0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb,
    0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b,
    0x01420ddb, 0xe4e7ef5b, 0x25a1ff41, 0xe180f806,
    0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4,
    0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b,
    0xe113c85b, 0xacc40083, 0xd7503525, 0xf7ea615f,
    0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359,
    0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21,
    0x071f6181, 0x39f7627f, 0x361e3084, 0xe4eb573b,
    0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d,
    0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c,
    0x10843094, 0x2537a95e, 0xf46f6ffe, 0xa1ff3b1f,
    0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34,
    0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d,
    0x8a45388c, 0x1d804366, 0x721d9bfd, 0xa58684bb,
    0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4,
    0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd,
    0xc5d655dd, 0xeb667064, 0x77840b4d, 0xa1b6a801,
    0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860,
    0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755,
    0xb5625dbf, 0x68561be6, 0x83ca6b94, 0x2d6ed23b,
    0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709,
    0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304,
    0x81ed6f61, 0x20e74364, 0xb45e1378, 0xde18639b,
    0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b,
    0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c,
    0x488cb402, 0x1ba4fe5b, 0xa4b09f6b, 0x1ca815cf,
    0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9,
    0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c,
    0xee41e729, 0x6e1d2d7c, 0x50045286, 0x1e6685f3,
    0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13,
    0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9,
    0xcdff33a6, 0xa02b1741, 0x7cbad9a2, 0x2180036f,
    0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab,
    0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6,
    0xcdf0b680, 0x17844d3b, 0x31eef84d, 0x7e0824e4,
    0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6,
    0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43,
    0xb3faec54, 0x157fd7fa, 0xef8579cc, 0xd152de58,
    0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8,
    0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906,
    0xb8da230c, 0x80823028, 0xdcdef3c8, 0xd35fb171,
    0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d,
    0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89,
    0x8b1c34bc, 0x301e16e6, 0x273be979, 0xb0ffeaa6,
    0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b,
    0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4,
    0xdc8637a0, 0x16a7d3b1, 0x9fc393b7, 0xa7136eeb,
    0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6,
    0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e,
    0xdb92f2fb, 0x5eea29cb, 0x145892f5, 0x91584f7f,
    0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea,
    0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249,
    0xb284600c, 0xd835731d, 0xdcb1c647, 0xac4c56ea,
    0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa,
    0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd,
    0x649da589, 0xa345415e, 0x5c038323, 0x3e5d3bb9,
    0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef,
    0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1
  },
  {
    0x8defc240, 0x25fa5d9f, 0xeb903dbf, 0xe810c907,
    0x47607fff, 0x369fe44b, 0x8c1fc644, 0xaececa90,
    0xbeb1f9bf, 0xeefbcaea, 0xe8cf1950, 0x51df07ae,
    0x920e8806, 0xf0ad0548, 0xe13c8d83, 0x927010d5,
    0x11107d9f, 0x07647db9, 0xb2e3e4d4, 0x3d4f285e,
    0xb9afa820, 0xfade82e0, 0xa067268b, 0x8272792e,
    0x553fb2c0, 0x489ae22b, 0xd4ef9794, 0x125e3fbc,
    0x21fffcee, 0x825b1bfd, 0x9255c5ed, 0x1257a240,
    0x4e1a8302, 0xbae07fff, 0x528246e7, 0x8e57140e,
    0x3373f7bf, 0x8c9f8188, 0xa6fc4ee8, 0xc982b5a5,
    0xa8c01db7, 0x579fc264, 0x67094f31, 0xf2bd3f5f,
    0x40fff7c1, 0x1fb78dfc, 0x8e6bd2c1, 0x437be59b,
    0x99b03dbf, 0xb5dbc64b, 0x638dc0e6, 0x55819d99,
    0xa197c81c, 0x4a012d6e, 0xc5884a28, 0xccc36f71,
    0xb843c213, 0x6c0743f1, 0x8309893c, 0x0feddd5f,
    0x2f7fe850, 0xd7c07f7e, 0x02507fbf, 0x5afb9a04,
    0xa747d2d0, 0x1651192e, 0xaf70bf3e, 0x58c31380,
    0x5f98302e, 0x727cc3c4, 0x0a0fb402, 0x0f7fef82,
    0x8c96fdad, 0x5d2c2aae, 0x8ee99a49, 0x50da88b8,
    0x8427f4a0, 0x1eac5790, 0x796fb449, 0x8252dc15,
    0xefbd7d9b, 0xa672597d, 0xada840d8, 0x45f54504,
    0xfa5d7403, 0xe83ec305, 0x4f91751a, 0x925669c2,
    0x23efe941, 0xa903f12e, 0x60270df2, 0x0276e4b6,
    0x94fd6574, 0x927985b2, 0x8276dbcb, 0x02778176,
    0xf8af918d, 0x4e48f79e, 0x8f616ddf, 0xe29d840e,
    0x842f7d83, 0x340ce5c8, 0x96bbb682, 0x93b4b148,
    0xef303cab, 0x984faf28, 0x779faf9b, 0x92dc560d,
    0x224d1e20, 0x8437aa88, 0x7d29dc96, 0x2756d3dc,
    0x8b907cee, 0xb51fd240, 0xe7c07ce3, 0xe566b4a1,
    0xc3e9615e, 0x3cf8209d, 0x6094d1e3, 0xcd9ca341,
    0x5c76460e, 0x00ea983b, 0xd4d67881, 0xfd47572c,
    0xf76cedd9, 0xbda8229c, 0x127dadaa, 0x438a074e,
    0x1f97c090, 0x081bdb8a, 0x93a07ebe, 0xb938ca15,
    0x97b03cff, 0x3dc2c0f8, 0x8d1ab2ec, 0x64380e51,
    0x68cc7bfb, 0xd90f2788, 0x12490181, 0x5de5ffd4,
    0xdd7ef86a, 0x76a2e214, 0xb9a40368, 0x925d958f,
    0x4b39fffa, 0xba39aee9, 0xa4ffd30b, 0xfaf7933b,
    0x6d498623, 0x193cbcfa, 0x27627545, 0x825cf47a,
    0x61bd8ba0, 0xd11e42d1, 0xcead04f4, 0x127ea392,
    0x10428db7, 0x8272a972, 0x9270c4a8, 0x127de50b,
    0x285ba1c8, 0x3c62f44f, 0x35c0eaa5, 0xe805d231,
    0x428929fb, 0xb4fcdf82, 0x4fb66a53, 0x0e7dc15b,
    0x1f081fab, 0x108618ae, 0xfcfd086d, 0xf9ff2889,
    0x694bcc11, 0x236a5cae, 0x12deca4d, 0x2c3f8cc5,
    0xd2d02dfe, 0xf8ef5896, 0xe4cf52da, 0x95155b67,
    0x494a488c, 0xb9b6a80c, 0x5c8f82bc, 0x89d36b45,
    0x3a609437, 0xec00c9a9, 0x44715253, 0x0a874b49,
    0xd773bc40, 0x7c34671c, 0x02717ef6, 0x4feb5536,
    0xa2d02fff, 0xd2bf60c4, 0xd43f03c0, 0x50b4ef6d,
    0x07478cd1, 0x006e1888, 0xa2e53f55, 0xb9e6d4bc,
    0xa2048016, 0x97573833, 0xd7207d67, 0xde0f8f3d,
    0x72f87b33, 0xabcc4f33, 0x7688c55d, 0x7b00a6b0,
    0x947b0001, 0x570075d2, 0xf9bb88f8, 0x8942019e,
    0x4264a5ff, 0x856302e0, 0x72dbd92b, 0xee971b69,
    0x6ea22fde, 0x5f08ae2b, 0xaf7a616d, 0xe5c98767,
    0xcf1febd2, 0x61efc8c2, 0xf1ac2571, 0xcc8239c2,
    0x67214cb8, 0xb1e583d1, 0xb7dc3e62, 0x7f10bdce,
    0xf90a5c38, 0x0ff0443d, 0x606e6dc6, 0x60543a49,
    0x5727c148, 0x2be98a1d, 0x8ab41738, 0x20e1be24,
    0xaf96da0f, 0x68458425, 0x99833be5, 0x600d457d,
    0x282f9350, 0x8334b362, 0xd91d1120, 0x2b6d8da0,
    0x642b1e31, 0x9c305a00, 0x52bce688, 0x1b03588a,
    0xf7baefd5, 0x4142ed9c, 0xa4315c11, 0x83323ec5,
    0xdfef4636, 0xa133c501, 0xe9d3531c, 0xee353783
  },
  {
    0x9db30420, 0x1fb6e9de, 0xa7be7bef, 0xd273a298,
    0x4a4f7bdb, 0x64ad8c57, 0x85510443, 0xfa020ed1,
    0x7e287aff, 0xe60fb663, 0x095f35a1, 0x79ebf120,
    0xfd059d43, 0x6497b7b1, 0xf3641f63, 0x241e4adf,
    0x28147f5f, 0x4fa2b8cd, 0xc9430040, 0x0cc32220,
    0xfdd30b30, 0xc0a5374f, 0x1d2d00d9, 0x24147b15,
    0xee4d111a, 0x0fca5167, 0x71ff904c, 0x2d195ffe,
    0x1a05645f, 0x0c13fefe, 0x081b08ca, 0x05170121,
    0x80530100, 0xe83e5efe, 0xac9af4f8, 0x7fe72701,
    0xd2b8ee5f, 0x06df4261, 0xbb9e9b8a, 0x7293ea25,
    0xce84ffdf, 0xf5718801, 0x3dd64b04, 0xa26f263b,
    0x7ed48400, 0x547eebe6, 0x446d4ca0, 0x6cf3d6f5,
    0x2649abdf, 0xaea0c7f5, 0x36338cc1, 0x503f7e93,
    0xd3772061, 0x11b638e1, 0x72500e03, 0xf80eb2bb,
    0xabe0502e, 0xec8d77de, 0x57971e81, 0xe14f6746,
    0xc9335400, 0x6920318f, 0x081dbb99, 0xffc304a5,
    0x4d351805, 0x7f3d5ce3, 0xa6c866c6, 0x5d5bcca9,
    0xdaec6fea, 0x9f926f91, 0x9f46222f, 0x3991467d,
    0xa5bf6d8e, 0x1143c44f, 0x43958302, 0xd0214eeb,
    0x022083b8, 0x3fb6180c, 0x18f8931e, 0x281658e6,
    0x26486e3e, 0x8bd78a70, 0x7477e4c1, 0xb506e07c,
    0xf32d0a25, 0x79098b02, 0xe4eabb81, 0x28123b23,
    0x69dead38, 0x1574ca16, 0xdf871b62, 0x211c40b7,
    0xa51a9ef9, 0x0014377b, 0x041e8ac8, 0x09114003,
    0xbd59e4d2, 0xe3d156d5, 0x4fe876d5, 0x2f91a340,
    0x557be8de, 0x00eae4a7, 0x0ce5c2ec, 0x4db4bba6,
    0xe756bdff, 0xdd3369ac, 0xec17b035, 0x06572327,
    0x99afc8b0, 0x56c8c391, 0x6b65811c, 0x5e146119,
    0x6e85cb75, 0xbe07c002, 0xc2325577, 0x893ff4ec,
    0x5bbfc92d, 0xd0ec3b25, 0xb7801ab7, 0x8d6d3b24,
    0x20c763ef, 0xc366a5fc, 0x9c382880, 0x0ace3205,
    0xaac9548a, 0xeca1d7c7, 0x041afa32, 0x1d16625a,
    0x6701902c, 0x9b757a54, 0x31d477f7, 0x9126b031,
    0x36cc6fdb, 0xc70b8b46, 0xd9e66a48, 0x56e55a79,
    0x026a4ceb, 0x52437eff, 0x2f8f76b4, 0x0df980a5,
    0x8674cde3, 0xedda04eb, 0x17a9be04, 0x2c18f4df,
    0xb7747f9d, 0xab2af7b4, 0xefc34d20, 0x2e096b7c,
    0x1741a254, 0xe5b6a035, 0x213d42f6, 0x2c1c7c26,
    0x61c2f50f, 0x6552daf9, 0xd2c231f8, 0x25130f69,
    0xd8167fa2, 0x0418f2c8, 0x001a96a6, 0x0d1526ab,
    0x63315c21, 0x5e0a72ec, 0x49bafefd, 0x187908d9,
    0x8d0dbd86, 0x311170a7, 0x3e9b640c, 0xcc3e10d7,
    0xd5cad3b6, 0x0caec388, 0xf73001e1, 0x6c728aff,
    0x71eae2a1, 0x1f9af36e, 0xcfcbd12f, 0xc1de8417,
    0xac07be6b, 0xcb44a1d8, 0x8b9b0f56, 0x013988c3,
    0xb1c52fca, 0xb4be31cd, 0xd8782806, 0x12a3a4e2,
    0x6f7de532, 0x58fd7eb6, 0xd01ee900, 0x24adffc2,
    0xf4990fc5, 0x9711aac5, 0x001d7b95, 0x82e5e7d2,
    0x109873f6, 0x00613096, 0xc32d9521, 0xada121ff,
    0x29908415, 0x7fbb977f, 0xaf9eb3db, 0x29c9ed2a,
    0x5ce2a465, 0xa730f32c, 0xd0aa3fe8, 0x8a5cc091,
    0xd49e2ce7, 0x0ce454a9, 0xd60acd86, 0x015f1919,
    0x77079103, 0xdea03af6, 0x78a8565e, 0xdee356df,
    0x21f05cbe, 0x8b75e387, 0xb3c50651, 0xb8a5c3ef,
    0xd8eeb6d2, 0xe523be77, 0xc2154529, 0x2f69efdf,
    0xafe67afb, 0xf470c4b2, 0xf3e0eb5b, 0xd6cc9876,
    0x39e4460c, 0x1fda8538, 0x1987832f, 0xca007367,
    0xa99144f8, 0x296b299e, 0x492fc295, 0x9266beab,
    0xb5676e69, 0x9bd3ddda, 0xdf7e052f, 0xdb25701c,
    0x1b5e51ee, 0xf65324e6, 0x6afce36c, 0x0316cc04,
    0x8644213e, 0xb7dc59d0, 0x7965291f, 0xccd6fd43,
    0x41823979, 0x932bcdf6, 0xb657c34d, 0x4edfd282,
    0x7ae5290c, 0x3cb9536b, 0x851e20fe, 0x9833557e,
    0x13ecf0b0, 0xd3ffb372, 0x3f85c5c1, 0x0aef7ed2
  },
  {
    0x7ec90c04, 0x2c6e74b9, 0x9b0e66df, 0xa6337911,
    0xb86a7fff, 0x1dd358f5, 0x44dd9d44, 0x1731167f,
    0x08fbf1fa, 0xe7f511cc, 0xd2051b00, 0x735aba00,
    0x2ab722d8, 0x386381cb, 0xacf6243a, 0x69befd7a,
    0xe6a2e77f, 0xf0c720cd, 0xc4494816, 0xccf5c180,
    0x38851640, 0x15b0a848, 0xe68b18cb, 0x4caadeff,
    0x5f480a01, 0x0412b2aa, 0x259814fc, 0x41d0efe2,
    0x4e40b48d, 0x248eb6fb, 0x8dba1cfe, 0x41a99b02,
    0x1a550a04, 0xba8f65cb, 0x7251f4e7, 0x95a51725,
    0xc106ecd7, 0x97a5980a, 0xc539b9aa, 0x4d79fe6a,
    0xf2f3f763, 0x68af8040, 0xed0c9e56, 0x11b4958b,
    0xe1eb5a88, 0x8709e6b0, 0xd7e07156, 0x4e29fea7,
    0x6366e52d, 0x02d1c000, 0xc4ac8e05, 0x9377f571,
    0x0c05372a, 0x578535f2, 0x2261be02, 0xd642a0c9,
    0xdf13a280, 0x74b55bd2, 0x682199c0, 0xd421e5ec,
    0x53fb3ce8, 0xc8adedb3, 0x28a87fc9, 0x3d959981,
    0x5c1ff900, 0xfe38d399, 0x0c4eff0b, 0x062407ea,
    0xaa2f4fb1, 0x4fb96976, 0x90c79505, 0xb0a8a774,
    0xef55a1ff, 0xe59ca2c2, 0xa6b62d27, 0xe66a4263,
    0xdf65001f, 0x0ec50966, 0xdfdd55bc, 0x29de0655,
    0x911e739a, 0x17af8975, 0x32c7911c, 0x89f89468,
    0x0d01e980, 0x524755f4, 0x03b63cc9, 0x0cc844b2,
    0xbcf3f0aa, 0x87ac36e9, 0xe53a7426, 0x01b3d82b,
    0x1a9e7449, 0x64ee2d7e, 0xcddbb1da, 0x01c94910,
    0xb868bf80, 0x0d26f3fd, 0x9342ede7, 0x04a5c284,
    0x636737b6, 0x50f5b616, 0xf24766e3, 0x8eca36c1,
    0x136e05db, 0xfef18391, 0xfb887a37, 0xd6e7f7d4,
    0xc7fb7dc9, 0x3063fcdf, 0xb6f589de, 0xec2941da,
    0x26e46695, 0xb7566419, 0xf654efc5, 0xd08d58b7,
    0x48925401, 0xc1bacb7f, 0xe5ff550f, 0xb6083049,
    0x5bb5d0e8, 0x87d72e5a, 0xab6a6ee1, 0x223a66ce,
    0xc62bf3cd, 0x9e0885f9, 0x68cb3e47, 0x086c010f,
    0xa21de820, 0xd18b69de, 0xf3f65777, 0xfa02c3f6,
    0x407edac3, 0xcbb3d550, 0x1793084d, 0xb0d70eba,
    0x0ab378d5, 0xd951fb0c, 0xded7da56, 0x4124bbe4,
    0x94ca0b56, 0x0f5755d1, 0xe0e1e56e, 0x6184b5be,
    0x580a249f, 0x94f74bc0, 0xe327888e, 0x9f7b5561,
    0xc3dc0280, 0x05687715, 0x646c6bd7, 0x44904db3,
    0x66b4f0a3, 0xc0f1648a, 0x697ed5af, 0x49e92ff6,
    0x309e374f, 0x2cb6356a, 0x85808573, 0x4991f840,
    0x76f0ae02, 0x083be84d, 0x28421c9a, 0x44489406,
    0x736e4cb8, 0xc1092910, 0x8bc95fc6, 0x7d869cf4,
    0x134f616f, 0x2e77118d, 0xb31b2be1, 0xaa90b472,
    0x3ca5d717, 0x7d161bba, 0x9cad9010, 0xaf462ba2,
    0x9fe459d2, 0x45d34559, 0xd9f2da13, 0xdbc65487,
    0xf3e4f94e, 0x176d486f, 0x097c13ea, 0x631da5c7,
    0x445f7382, 0x175683f4, 0xcdc66a97, 0x70be0288,
    0xb3cdcf72, 0x6e5dd2f3, 0x20936079, 0x459b80a5,
    0xbe60e2db, 0xa9c23101, 0xeba5315c, 0x224e42f2,
    0x1c5c1572, 0xf6721b2c, 0x1ad2fff3, 0x8c25404e,
    0x324ed72f, 0x4067b7fd, 0x0523138e, 0x5ca3bc78,
    0xdc0fd66e, 0x75922283, 0x784d6b17, 0x58ebb16e,
    0x44094f85, 0x3f481d87, 0xfcfeae7b, 0x77b5ff76,
    0x8c2302bf, 0xaaf47556, 0x5f46b02a, 0x2b092801,
    0x3d38f5f7, 0x0ca81f36, 0x52af4a8a, 0x66d5e7c0,
    0xdf3b0874, 0x95055110, 0x1b5ad7a8, 0xf61ed5ad,
    0x6cf6e479, 0x20758184, 0xd0cefa65, 0x88f7be58,
    0x4a046826, 0x0ff6f8f3, 0xa09c7f70, 0x5346aba0,
    0x5ce96c28, 0xe176eda3, 0x6bac307f, 0x376829d2,
    0x85360fa9, 0x17e3fe2a, 0x24b79767, 0xf5a96b20,
    0xd6cd2595, 0x68ff1ebf, 0x7555442c, 0xf19f06be,
    0xf9e0659a, 0xeeb9491d, 0x34010718, 0xbb30cab8,
    0xe822fe15, 0x88570983, 0x750e6249, 0xda627e55,
    0x5e76ffa8, 0xb1534546, 0x6d47de08, 0xefe9e7d4
  },
  {
    0xf6fa8f9d, 0x2cac6ce1, 0x4ca34867, 0xe2337f7c,
    0x95db08e7, 0x016843b4, 0xeced5cbc, 0x325553ac,
    0xbf9f0960, 0xdfa1e2ed, 0x83f0579d, 0x63ed86b9,
    0x1ab6a6b8, 0xde5ebe39, 0xf38ff732, 0x8989b138,
    0x33f14961, 0xc01937bd, 0xf506c6da, 0xe4625e7e,
    0xa308ea99, 0x4e23e33c, 0x79cbd7cc, 0x48a14367,
    0xa3149619, 0xfec94bd5, 0xa114174a, 0xeaa01866,
    0xa084db2d, 0x09a8486f, 0xa888614a, 0x2900af98,
    0x01665991, 0xe1992863, 0xc8f30c60, 0x2e78ef3c,
    0xd0d51932, 0xcf0fec14, 0xf7ca07d2, 0xd0a82072,
    0xfd41197e, 0x9305a6b0, 0xe86be3da, 0x74bed3cd,
    0x372da53c, 0x4c7f4448, 0xdab5d440, 0x6dba0ec3,
    0x083919a7, 0x9fbaeed9, 0x49dbcfb0, 0x4e670c53,
    0x5c3d9c01, 0x64bdb941, 0x2c0e636a, 0xba7dd9cd,
    0xea6f7388, 0xe70bc762, 0x35f29adb, 0x5c4cdd8d,
    0xf0d48d8c, 0xb88153e2, 0x08a19866, 0x1ae2eac8,
    0x284caf89, 0xaa928223, 0x9334be53, 0x3b3a21bf,
    0x16434be3, 0x9aea3906, 0xefe8c36e, 0xf890cdd9,
    0x80226dae, 0xc340a4a3, 0xdf7e9c09, 0xa694a807,
    0x5b7c5ecc, 0x221db3a6, 0x9a69a02f, 0x68818a54,
    0xceb2296f, 0x53c0843a, 0xfe893655, 0x25bfe68a,
    0xb4628abc, 0xcf222ebf, 0x25ac6f48, 0xa9a99387,
    0x53bddb65, 0xe76ffbe7, 0xe967fd78, 0x0ba93563,
    0x8e342bc1, 0xe8a11be9, 0x4980740d, 0xc8087dfc,
    0x8de4bf99, 0xa11101a0, 0x7fd37975, 0xda5a26c0,
    0xe81f994f, 0x9528cd89, 0xfd339fed, 0xb87834bf,
    0x5f04456d, 0x22258698, 0xc9c4c83b, 0x2dc156be,
    0x4f628daa, 0x57f55ec5, 0xe2220abe, 0xd2916ebf,
    0x4ec75b95, 0x24f2c3c0, 0x42d15d99, 0xcd0d7fa0,
    0x7b6e27ff, 0xa8dc8af0, 0x7345c106, 0xf41e232f,
    0x35162386, 0xe6ea8926, 0x3333b094, 0x157ec6f2,
    0x372b74af, 0x692573e4, 0xe9a9d848, 0xf3160289,
    0x3a62ef1d, 0xa787e238, 0xf3a5f676, 0x74364853,
    0x20951063, 0x4576698d, 0xb6fad407, 0x592af950,
    0x36f73523, 0x4cfb6e87, 0x7da4cec0, 0x6c152daa,
    0xcb0396a8, 0xc50dfe5d, 0xfcd707ab, 0x0921c42f,
    0x89dff0bb, 0x5fe2be78, 0x448f4f33, 0x754613c9,
    0x2b05d08d, 0x48b9d585, 0xdc049441, 0xc8098f9b,
    0x7dede786, 0xc39a3373, 0x42410005, 0x6a091751,
    0x0ef3c8a6, 0x890072d6, 0x28207682, 0xa9a9f7be,
    0xbf32679d, 0xd45b5b75, 0xb353fd00, 0xcbb0e358,
    0x830f220a, 0x1f8fb214, 0xd372cf08, 0xcc3c4a13,
    0x8cf63166, 0x061c87be, 0x88c98f88, 0x6062e397,
    0x47cf8e7a, 0xb6c85283, 0x3cc2acfb, 0x3fc06976,
    0x4e8f0252, 0x64d8314d, 0xda3870e3, 0x1e665459,
    0xc10908f0, 0x513021a5, 0x6c5b68b7, 0x822f8aa0,
    0x3007cd3e, 0x74719eef, 0xdc872681, 0x073340d4,
    0x7e432fd9, 0x0c5ec241, 0x8809286c, 0xf592d891,
    0x08a930f6, 0x957ef305, 0xb7fbffbd, 0xc266e96f,
    0x6fe4ac98, 0xb173ecc0, 0xbc60b42a, 0x953498da,
    0xfba1ae12, 0x2d4bd736, 0x0f25faab, 0xa4f3fceb,
    0xe2969123, 0x257f0c3d, 0x9348af49, 0x361400bc,
    0xe8816f4a, 0x3814f200, 0xa3f94043, 0x9c7a54c2,
    0xbc704f57, 0xda41e7f9, 0xc25ad33a, 0x54f4a084,
    0xb17f5505, 0x59357cbe, 0xedbd15c8, 0x7f97c5ab,
    0xba5ac7b5, 0xb6f6deaf, 0x3a479c3a, 0x5302da25,
    0x653d7e6a, 0x54268d49, 0x51a477ea, 0x5017d55b,
    0xd7d25d88, 0x44136c76, 0x0404a8c8, 0xb8e5a121,
    0xb81a928a, 0x60ed5869, 0x97c55b96, 0xeaec991b,
    0x29935913, 0x01fdb7f1, 0x088e8dfa, 0x9ab6f6f5,
    0x3b4cbf9f, 0x4a5de3ab, 0xe6051d35, 0xa0e1d855,
    0xd36b4cf1, 0xf544edeb, 0xb0e93524, 0xbebb8fbd,
    0xa2d762cf, 0x49c92f54, 0x38b5f331, 0x7128a454,
    0x48392905, 0xa65b1db8, 0x851c97bd, 0xd675cf2f
  },
  {
    0x85e04019, 0x332bf567, 0x662dbfff, 0xcfc65693,
    0x2a8d7f6f, 0xab9bc912, 0xde6008a1, 0x2028da1f,
    0x0227bce7, 0x4d642916, 0x18fac300, 0x50f18b82,
    0x2cb2cb11, 0xb232e75c, 0x4b3695f2, 0xb28707de,
    0xa05fbcf6, 0xcd4181e9, 0xe150210c, 0xe24ef1bd,
    0xb168c381, 0xfde4e789, 0x5c79b0d8, 0x1e8bfd43,
    0x4d495001, 0x38be4341, 0x913cee1d, 0x92a79c3f,
    0x089766be, 0xbaeeadf4, 0x1286becf, 0xb6eacb19,
    0x2660c200, 0x7565bde4, 0x64241f7a, 0x8248dca9,
    0xc3b3ad66, 0x28136086, 0x0bd8dfa8, 0x356d1cf2,
    0x107789be, 0xb3b2e9ce, 0x0502aa8f, 0x0bc0351e,
    0x166bf52a, 0xeb12ff82, 0xe3486911, 0xd34d7516,
    0x4e7b3aff, 0x5f43671b, 0x9cf6e037, 0x4981ac83,
    0x334266ce, 0x8c9341b7, 0xd0d854c0, 0xcb3a6c88,
    0x47bc2829, 0x4725ba37, 0xa66ad22b, 0x7ad61f1e,
    0x0c5cbafa, 0x4437f107, 0xb6e79962, 0x42d2d816,
    0x0a961288, 0xe1a5c06e, 0x13749e67, 0x72fc081a,
    0xb1d139f7, 0xf9583745, 0xcf19df58, 0xbec3f756,
    0xc06eba30, 0x07211b24, 0x45c28829, 0xc95e317f,
    0xbc8ec511, 0x38bc46e9, 0xc6e6fa14, 0xbae8584a,
    0xad4ebc46, 0x468f508b, 0x7829435f, 0xf124183b,
    0x821dba9f, 0xaff60ff4, 0xea2c4e6d, 0x16e39264,
    0x92544a8b, 0x009b4fc3, 0xaba68ced, 0x9ac96f78,
    0x06a5b79a, 0xb2856e6e, 0x1aec3ca9, 0xbe838688,
    0x0e0804e9, 0x55f1be56, 0xe7e5363b, 0xb3a1f25d,
    0xf7debb85, 0x61fe033c, 0x16746233, 0x3c034c28,
    0xda6d0c74, 0x79aac56c, 0x3ce4e1ad, 0x51f0c802,
    0x98f8f35a, 0x1626a49f, 0xeed82b29, 0x1d382fe3,
    0x0c4fb99a, 0xbb325778, 0x3ec6d97b, 0x6e77a6a9,
    0xcb658b5c, 0xd45230c7, 0x2bd1408b, 0x60c03eb7,
    0xb9068d78, 0xa33754f4, 0xf430c87d, 0xc8a71302,
    0xb96d8c32, 0xebd4e7be, 0xbe8b9d2d, 0x7979fb06,
    0xe7225308, 0x8b75cf77, 0x11ef8da4, 0xe083c858,
    0x8d6b786f, 0x5a6317a6, 0xfa5cf7a0, 0x5dda0033,
    0xf28ebfb0, 0xf5b9c310, 0xa0eac280, 0x08b9767a,
    0xa3d9d2b0, 0x79d34217, 0x021a718d, 0x9ac6336a,
    0x2711fd60, 0x438050e3, 0x069908a8, 0x3d7fedc4,
    0x826d2bef, 0x4eeb8476, 0x488dcf25, 0x36c9d566,
    0x28e74e41, 0xc2610aca, 0x3d49a9cf, 0xbae3b9df,
    0xb65f8de6, 0x92aeaf64, 0x3ac7d5e6, 0x9ea80509,
    0xf22b017d, 0xa4173f70, 0xdd1e16c3, 0x15e0d7f9,
    0x50b1b887, 0x2b9f4fd5, 0x625aba82, 0x6a017962,
    0x2ec01b9c, 0x15488aa9, 0xd716e740, 0x40055a2c,
    0x93d29a22, 0xe32dbf9a, 0x058745b9, 0x3453dc1e,
    0xd699296e, 0x496cff6f, 0x1c9f4986, 0xdfe2ed07,
    0xb87242d1, 0x19de7eae, 0x053e561a, 0x15ad6f8c,
    0x66626c1c, 0x7154c24c, 0xea082b2a, 0x93eb2939,
    0x17dcb0f0, 0x58d4f2ae, 0x9ea294fb, 0x52cf564c,
    0x9883fe66, 0x2ec40581, 0x763953c3, 0x01d6692e,
    0xd3a0c108, 0xa1e7160e, 0xe4f2dfa6, 0x693ed285,
    0x74904698, 0x4c2b0edd, 0x4f757656, 0x5d393378,
    0xa132234f, 0x3d321c5d, 0xc3f5e194, 0x4b269301,
    0xc79f022f, 0x3c997e7e, 0x5e4f9504, 0x3ffafbbd,
    0x76f7ad0e, 0x296693f4, 0x3d1fce6f, 0xc61e45be,
    0xd3b5ab34, 0xf72bf9b7, 0x1b0434c0, 0x4e72b567,
    0x5592a33d, 0xb5229301, 0xcfd2a87f, 0x60aeb767,
    0x1814386b, 0x30bcc33d, 0x38a0c07d, 0xfd1606f2,
    0xc363519b, 0x589dd390, 0x5479f8e6, 0x1cb8d647,
    0x97fd61a9, 0xea7759f4, 0x2d57539d, 0x569a58cf,
    0xe84e63ad, 0x462e1b78, 0x6580f87e, 0xf3817914,
    0x91da55f4, 0x40a230f3, 0xd1988f35, 0xb6e318d2,
    0x3ffa50bc, 0x3d40f021, 0xc3c0bdae, 0x4958c24c,
    0x518f36b2, 0x84b1d370, 0x0fedce83, 0x878ddada,
    0xf2a279c7, 0x94e01be8, 0x90716f4b, 0x954b8aa3
  },
  {
    0xe216300d, 0xbbddfffc, 0xa7ebdabd, 0x35648095,
    0x7789f8b7, 0xe6c1121b, 0x0e241600, 0x052ce8b5,
    0x11a9cfb0, 0xe5952f11, 0xece7990a, 0x9386d174,
    0x2a42931c, 0x76e38111, 0xb12def3a, 0x37ddddfc,
    0xde9adeb1, 0x0a0cc32c, 0xbe197029, 0x84a00940,
    0xbb243a0f, 0xb4d137cf, 0xb44e79f0, 0x049eedfd,
    0x0b15a15d, 0x480d3168, 0x8bbbde5a, 0x669ded42,
    0xc7ece831, 0x3f8f95e7, 0x72df191b, 0x7580330d,
    0x94074251, 0x5c7dcdfa, 0xabbe6d63, 0xaa402164,
    0xb301d40a, 0x02e7d1ca, 0x53571dae, 0x7a3182a2,
    0x12a8ddec, 0xfdaa335d, 0x176f43e8, 0x71fb46d4,
    0x38129022, 0xce949ad4, 0xb84769ad, 0x965bd862,
    0x82f3d055, 0x66fb9767, 0x15b80b4e, 0x1d5b47a0,
    0x4cfde06f, 0xc28ec4b8, 0x57e8726e, 0x647a78fc,
    0x99865d44, 0x608bd593, 0x6c200e03, 0x39dc5ff6,
    0x5d0b00a3, 0xae63aff2, 0x7e8bd632, 0x70108c0c,
    0xbbd35049, 0x2998df04, 0x980cf42a, 0x9b6df491,
    0x9e7edd53, 0x06918548, 0x58cb7e07, 0x3b74ef2e,
    0x522fffb1, 0xd24708cc, 0x1c7e27cd, 0xa4eb215b,
    0x3cf1d2e2, 0x19b47a38, 0x424f7618, 0x35856039,
    0x9d17dee7, 0x27eb35e6, 0xc9aff67b, 0x36baf5b8,
    0x09c467cd, 0xc18910b1, 0xe11dbf7b, 0x06cd1af8,
    0x7170c608, 0x2d5e3354, 0xd4de495a, 0x64c6d006,
    0xbcc0c62c, 0x3dd00db3, 0x708f8f34, 0x77d51b42,
    0x264f620f, 0x24b8d2bf, 0x15c1b79e, 0x46a52564,
    0xf8d7e54e, 0x3e378160, 0x7895cda5, 0x859c15a5,
    0xe6459788, 0xc37bc75f, 0xdb07ba0c, 0x0676a3ab,
    0x7f229b1e, 0x31842e7b, 0x24259fd7, 0xf8bef472,
    0x835ffcb8, 0x6df4c1f2, 0x96f5b195, 0xfd0af0fc,
    0xb0fe134c, 0xe2506d3d, 0x4f9b12ea, 0xf215f225,
    0xa223736f, 0x9fb4c428, 0x25d04979, 0x34c713f8,
    0xc4618187, 0xea7a6e98, 0x7cd16efc, 0x1436876c,
    0xf1544107, 0xbedeee14, 0x56e9af27, 0xa04aa441,
    0x3cf7c899, 0x92ecbae6, 0xdd67016d, 0x151682eb,
    0xa842eedf, 0xfdba60b4, 0xf1907b75, 0x20e3030f,
    0x24d8c29e, 0xe139673b, 0xefa63fb8, 0x71873054,
    0xb6f2cf3b, 0x9f326442, 0xcb15a4cc, 0xb01a4504,
    0xf1e47d8d, 0x844a1be5, 0xbae7dfdc, 0x42cbda70,
    0xcd7dae0a, 0x57e85b7a, 0xd53f5af6, 0x20cf4d8c,
    0xcea4d428, 0x79d130a4, 0x3486ebfb, 0x33d3cddc,
    0x77853b53, 0x37effcb5, 0xc5068778, 0xe580b3e6,
    0x4e68b8f4, 0xc5c8b37e, 0x0d809ea2, 0x398feb7c,
    0x132a4f94, 0x43b7950e, 0x2fee7d1c, 0x223613bd,
    0xdd06caa2, 0x37df932b, 0xc4248289, 0xacf3ebc3,
    0x5715f6b7, 0xef3478dd, 0xf267616f, 0xc148cbe4,
    0x9052815e, 0x5e410fab, 0xb48a2465, 0x2eda7fa4,
    0xe87b40e4, 0xe98ea084, 0x5889e9e1, 0xefd390fc,
    0xdd07d35b, 0xdb485694, 0x38d7e5b2, 0x57720101,
    0x730edebc, 0x5b643113, 0x94917e4f, 0x503c2fba,
    0x646f1282, 0x7523d24a, 0xe0779695, 0xf9c17a8f,
    0x7a5b2121, 0xd187b896, 0x29263a4d, 0xba510cdf,
    0x81f47c9f, 0xad1163ed, 0xea7b5965, 0x1a00726e,
    0x11403092, 0x00da6d77, 0x4a0cdd61, 0xad1f4603,
    0x605bdfb0, 0x9eedc364, 0x22ebe6a8, 0xcee7d28a,
    0xa0e736a0, 0x5564a6b9, 0x10853209, 0xc7eb8f37,
    0x2de705ca, 0x8951570f, 0xdf09822b, 0xbd691a6c,
    0xaa12e4f2, 0x87451c0f, 0xe0f6a27a, 0x3ada4819,
    0x4cf1764f, 0x0d771c2b, 0x67cdb156, 0x350d8384,
    0x5938fa0f, 0x42399ef3, 0x36997b07, 0x0e84093d,
    0x4aa93e61, 0x8360d87b, 0x1fa98b0c, 0x1149382c,
    0xe97625a5, 0x0614d1b7, 0x0e25244b, 0x0c768347,
    0x589e8d82, 0x0d2059d1, 0xa466bb1e, 0xf8da0a82,
    0x04f19130, 0xba6e4ec0, 0x99265164, 0x1ee7230d,
    0x50b2ad80, 0xeaee6801, 0x8db2a283, 0xea8bf59e
  }
};

static const struct {
  uint8_t a[4][7];
  uint8_t b[4][5];
} schedule[4] = {
  {
    {
      { 0x04, 0x00, 0x0d, 0x0f, 0x0c, 0x0e, 0x08 },
      { 0x05, 0x02, 0x10, 0x12, 0x11, 0x13, 0x0a },
      { 0x06, 0x03, 0x17, 0x16, 0x15, 0x14, 0x09 },
      { 0x07, 0x01, 0x1a, 0x19, 0x1b, 0x18, 0x0b }
    },
    {
      { 0x18, 0x19, 0x17, 0x16, 0x12 },
      { 0x1a, 0x1b, 0x15, 0x14, 0x16 },
      { 0x1c, 0x1d, 0x13, 0x12, 0x19 },
      { 0x1e, 0x1f, 0x11, 0x10, 0x1c }
    }
  },
  {
    {
      { 0x00, 0x06, 0x15, 0x17, 0x14, 0x16, 0x10 },
      { 0x01, 0x04, 0x00, 0x02, 0x01, 0x03, 0x12 },
      { 0x02, 0x05, 0x07, 0x06, 0x05, 0x04, 0x11 },
      { 0x03, 0x07, 0x0a, 0x09, 0x0b, 0x08, 0x13 }
    },
    {
      { 0x03, 0x02, 0x0c, 0x0d, 0x08 },
      { 0x01, 0x00, 0x0e, 0x0f, 0x0d },
      { 0x07, 0x06, 0x08, 0x09, 0x03 },
      { 0x05, 0x04, 0x0a, 0x0b, 0x07 }
    }
  },
  {
    {
      { 0x04, 0x00, 0x0d, 0x0f, 0x0c, 0x0e, 0x08 },
      { 0x05, 0x02, 0x10, 0x12, 0x11, 0x13, 0x0a },
      { 0x06, 0x03, 0x17, 0x16, 0x15, 0x14, 0x09 },
      { 0x07, 0x01, 0x1a, 0x19, 0x1b, 0x18, 0x0b }
    },
    {
      { 0x13, 0x12, 0x1c, 0x1d, 0x19 },
      { 0x11, 0x10, 0x1e, 0x1f, 0x1c },
      { 0x17, 0x16, 0x18, 0x19, 0x12 },
      { 0x15, 0x14, 0x1a, 0x1b, 0x16 }
    }
  },
  {
    {
      { 0x00, 0x06, 0x15, 0x17, 0x14, 0x16, 0x10 },
      { 0x01, 0x04, 0x00, 0x02, 0x01, 0x03, 0x12 },
      { 0x02, 0x05, 0x07, 0x06, 0x05, 0x04, 0x11 },
      { 0x03, 0x07, 0x0a, 0x09, 0x0b, 0x08, 0x13 }
    },
    {
      { 0x08, 0x09, 0x07, 0x06, 0x03 },
      { 0x0a, 0x0b, 0x05, 0x04, 0x07 },
      { 0x0c, 0x0d, 0x03, 0x02, 0x08 },
      { 0x0e, 0x0f, 0x01, 0x00, 0x0d }
    }
  }
};

static const uint8_t X[4] = {6, 7, 4, 5};

static TORSION_INLINE uint32_t
f1(uint32_t d, uint32_t m, uint32_t r) {
  uint32_t c = -(uint32_t)(r != 0);
  uint32_t t = m + d;
  uint32_t I = (t << r) | (t >> ((32 - r) & c));

  return (((S[0][(I >> 24) & 0xff]
          ^ S[1][(I >> 16) & 0xff])
          - S[2][(I >>  8) & 0xff])
          + S[3][(I >>  0) & 0xff]);
}

static TORSION_INLINE uint32_t
f2(uint32_t d, uint32_t m, uint32_t r) {
  uint32_t c = -(uint32_t)(r != 0);
  uint32_t t = m ^ d;
  uint32_t I = (t << r) | (t >> ((32 - r) & c));

  return (((S[0][(I >> 24) & 0xff]
          - S[1][(I >> 16) & 0xff])
          + S[2][(I >>  8) & 0xff])
          ^ S[3][(I >>  0) & 0xff]);
}

static TORSION_INLINE uint32_t
f3(uint32_t d, uint32_t m, uint32_t r) {
  uint32_t c = -(uint32_t)(r != 0);
  uint32_t t = m - d;
  uint32_t I = (t << r) | (t >> ((32 - r) & c));

  return (((S[0][(I >> 24) & 0xff]
          + S[1][(I >> 16) & 0xff])
          ^ S[2][(I >>  8) & 0xff])
          - S[3][(I >>  0) & 0xff]);
}

void
cast5_init(cast5_t *ctx, const unsigned char *key) {
  int i, half, r, j;
  uint32_t k[32];
  uint32_t t[8];
  uint32_t w;
  int ki = 0;

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  for (i = 0; i < 4; i++)
    t[i] = read32be(key + i * 4);

  for (half = 0; half < 2; half++) {
    for (r = 0; r < 4; r++) {
      for (j = 0; j < 4; j++) {
        const uint8_t *a = schedule[r].a[j];

        w = t[a[1]]
          ^ S[4][(t[a[2] >> 2] >> (24 - 8 * (a[2] & 3))) & 0xff]
          ^ S[5][(t[a[3] >> 2] >> (24 - 8 * (a[3] & 3))) & 0xff]
          ^ S[6][(t[a[4] >> 2] >> (24 - 8 * (a[4] & 3))) & 0xff]
          ^ S[7][(t[a[5] >> 2] >> (24 - 8 * (a[5] & 3))) & 0xff];

        w ^= S[X[j]][(t[a[6] >> 2] >> (24 - 8 * (a[6] & 3))) & 0xff];

        t[a[0]] = w;
      }

      for (j = 0; j < 4; j++) {
        const uint8_t *b = schedule[r].b[j];

        w = S[4][(t[b[0] >> 2] >> (24 - 8 * (b[0] & 3))) & 0xff]
          ^ S[5][(t[b[1] >> 2] >> (24 - 8 * (b[1] & 3))) & 0xff]
          ^ S[6][(t[b[2] >> 2] >> (24 - 8 * (b[2] & 3))) & 0xff]
          ^ S[7][(t[b[3] >> 2] >> (24 - 8 * (b[3] & 3))) & 0xff];

        w ^= S[4 + j][(t[b[4] >> 2] >> (24 - 8 * (b[4] & 3))) & 0xff];

        k[ki++] = w;
      }
    }
  }

  for (i = 0; i < 16; i++) {
    ctx->masking[i] = k[i];
    ctx->rotate[i] = k[16 + i] & 0x1f;
  }
}

#define R(f, i) do {                             \
  t = l;                                         \
  l = r;                                         \
  r = t ^ f(r, ctx->masking[i], ctx->rotate[i]); \
} while (0)

void
cast5_encrypt(const cast5_t *ctx,
              unsigned char *dst,
              const unsigned char *src) {
  uint32_t l = read32be(src + 0);
  uint32_t r = read32be(src + 4);
  uint32_t t;

  R(f1,  0);
  R(f2,  1);
  R(f3,  2);
  R(f1,  3);
  R(f2,  4);
  R(f3,  5);
  R(f1,  6);
  R(f2,  7);
  R(f3,  8);
  R(f1,  9);
  R(f2, 10);
  R(f3, 11);
  R(f1, 12);
  R(f2, 13);
  R(f3, 14);
  R(f1, 15);

  write32be(dst + 0, r);
  write32be(dst + 4, l);
}

void
cast5_decrypt(const cast5_t *ctx,
              unsigned char *dst,
              const unsigned char *src) {
  uint32_t l = read32be(src + 0);
  uint32_t r = read32be(src + 4);
  uint32_t t;

  R(f1, 15);
  R(f3, 14);
  R(f2, 13);
  R(f1, 12);
  R(f3, 11);
  R(f2, 10);
  R(f1,  9);
  R(f3,  8);
  R(f2,  7);
  R(f1,  6);
  R(f3,  5);
  R(f2,  4);
  R(f1,  3);
  R(f3,  2);
  R(f2,  1);
  R(f1,  0);

  write32be(dst + 0, r);
  write32be(dst + 4, l);
}

#undef R

#undef S
#undef schedule
#undef X
#undef f1
#undef f2
#undef f3

/*
 * DES
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Data_Encryption_Standard
 *   https://github.com/indutny/des.js/tree/master/lib/des
 */

static const uint8_t des_pc2_table[48] = {
  0x0e, 0x0b, 0x11, 0x04, 0x1b, 0x17, 0x19, 0x00,
  0x0d, 0x16, 0x07, 0x12, 0x05, 0x09, 0x10, 0x18,
  0x02, 0x14, 0x0c, 0x15, 0x01, 0x08, 0x0f, 0x1a,

  0x0f, 0x04, 0x19, 0x13, 0x09, 0x01, 0x1a, 0x10,
  0x05, 0x0b, 0x17, 0x08, 0x0c, 0x07, 0x11, 0x00,
  0x16, 0x03, 0x0a, 0x0e, 0x06, 0x14, 0x1b, 0x18
};

static const uint8_t des_s_table[512] = {
  0x0e, 0x00, 0x04, 0x0f, 0x0d, 0x07, 0x01, 0x04,
  0x02, 0x0e, 0x0f, 0x02, 0x0b, 0x0d, 0x08, 0x01,
  0x03, 0x0a, 0x0a, 0x06, 0x06, 0x0c, 0x0c, 0x0b,
  0x05, 0x09, 0x09, 0x05, 0x00, 0x03, 0x07, 0x08,
  0x04, 0x0f, 0x01, 0x0c, 0x0e, 0x08, 0x08, 0x02,
  0x0d, 0x04, 0x06, 0x09, 0x02, 0x01, 0x0b, 0x07,
  0x0f, 0x05, 0x0c, 0x0b, 0x09, 0x03, 0x07, 0x0e,
  0x03, 0x0a, 0x0a, 0x00, 0x05, 0x06, 0x00, 0x0d,

  0x0f, 0x03, 0x01, 0x0d, 0x08, 0x04, 0x0e, 0x07,
  0x06, 0x0f, 0x0b, 0x02, 0x03, 0x08, 0x04, 0x0e,
  0x09, 0x0c, 0x07, 0x00, 0x02, 0x01, 0x0d, 0x0a,
  0x0c, 0x06, 0x00, 0x09, 0x05, 0x0b, 0x0a, 0x05,
  0x00, 0x0d, 0x0e, 0x08, 0x07, 0x0a, 0x0b, 0x01,
  0x0a, 0x03, 0x04, 0x0f, 0x0d, 0x04, 0x01, 0x02,
  0x05, 0x0b, 0x08, 0x06, 0x0c, 0x07, 0x06, 0x0c,
  0x09, 0x00, 0x03, 0x05, 0x02, 0x0e, 0x0f, 0x09,

  0x0a, 0x0d, 0x00, 0x07, 0x09, 0x00, 0x0e, 0x09,
  0x06, 0x03, 0x03, 0x04, 0x0f, 0x06, 0x05, 0x0a,
  0x01, 0x02, 0x0d, 0x08, 0x0c, 0x05, 0x07, 0x0e,
  0x0b, 0x0c, 0x04, 0x0b, 0x02, 0x0f, 0x08, 0x01,
  0x0d, 0x01, 0x06, 0x0a, 0x04, 0x0d, 0x09, 0x00,
  0x08, 0x06, 0x0f, 0x09, 0x03, 0x08, 0x00, 0x07,
  0x0b, 0x04, 0x01, 0x0f, 0x02, 0x0e, 0x0c, 0x03,
  0x05, 0x0b, 0x0a, 0x05, 0x0e, 0x02, 0x07, 0x0c,

  0x07, 0x0d, 0x0d, 0x08, 0x0e, 0x0b, 0x03, 0x05,
  0x00, 0x06, 0x06, 0x0f, 0x09, 0x00, 0x0a, 0x03,
  0x01, 0x04, 0x02, 0x07, 0x08, 0x02, 0x05, 0x0c,
  0x0b, 0x01, 0x0c, 0x0a, 0x04, 0x0e, 0x0f, 0x09,
  0x0a, 0x03, 0x06, 0x0f, 0x09, 0x00, 0x00, 0x06,
  0x0c, 0x0a, 0x0b, 0x01, 0x07, 0x0d, 0x0d, 0x08,
  0x0f, 0x09, 0x01, 0x04, 0x03, 0x05, 0x0e, 0x0b,
  0x05, 0x0c, 0x02, 0x07, 0x08, 0x02, 0x04, 0x0e,

  0x02, 0x0e, 0x0c, 0x0b, 0x04, 0x02, 0x01, 0x0c,
  0x07, 0x04, 0x0a, 0x07, 0x0b, 0x0d, 0x06, 0x01,
  0x08, 0x05, 0x05, 0x00, 0x03, 0x0f, 0x0f, 0x0a,
  0x0d, 0x03, 0x00, 0x09, 0x0e, 0x08, 0x09, 0x06,
  0x04, 0x0b, 0x02, 0x08, 0x01, 0x0c, 0x0b, 0x07,
  0x0a, 0x01, 0x0d, 0x0e, 0x07, 0x02, 0x08, 0x0d,
  0x0f, 0x06, 0x09, 0x0f, 0x0c, 0x00, 0x05, 0x09,
  0x06, 0x0a, 0x03, 0x04, 0x00, 0x05, 0x0e, 0x03,

  0x0c, 0x0a, 0x01, 0x0f, 0x0a, 0x04, 0x0f, 0x02,
  0x09, 0x07, 0x02, 0x0c, 0x06, 0x09, 0x08, 0x05,
  0x00, 0x06, 0x0d, 0x01, 0x03, 0x0d, 0x04, 0x0e,
  0x0e, 0x00, 0x07, 0x0b, 0x05, 0x03, 0x0b, 0x08,
  0x09, 0x04, 0x0e, 0x03, 0x0f, 0x02, 0x05, 0x0c,
  0x02, 0x09, 0x08, 0x05, 0x0c, 0x0f, 0x03, 0x0a,
  0x07, 0x0b, 0x00, 0x0e, 0x04, 0x01, 0x0a, 0x07,
  0x01, 0x06, 0x0d, 0x00, 0x0b, 0x08, 0x06, 0x0d,

  0x04, 0x0d, 0x0b, 0x00, 0x02, 0x0b, 0x0e, 0x07,
  0x0f, 0x04, 0x00, 0x09, 0x08, 0x01, 0x0d, 0x0a,
  0x03, 0x0e, 0x0c, 0x03, 0x09, 0x05, 0x07, 0x0c,
  0x05, 0x02, 0x0a, 0x0f, 0x06, 0x08, 0x01, 0x06,
  0x01, 0x06, 0x04, 0x0b, 0x0b, 0x0d, 0x0d, 0x08,
  0x0c, 0x01, 0x03, 0x04, 0x07, 0x0a, 0x0e, 0x07,
  0x0a, 0x09, 0x0f, 0x05, 0x06, 0x00, 0x08, 0x0f,
  0x00, 0x0e, 0x05, 0x02, 0x09, 0x03, 0x02, 0x0c,

  0x0d, 0x01, 0x02, 0x0f, 0x08, 0x0d, 0x04, 0x08,
  0x06, 0x0a, 0x0f, 0x03, 0x0b, 0x07, 0x01, 0x04,
  0x0a, 0x0c, 0x09, 0x05, 0x03, 0x06, 0x0e, 0x0b,
  0x05, 0x00, 0x00, 0x0e, 0x0c, 0x09, 0x07, 0x02,
  0x07, 0x02, 0x0b, 0x01, 0x04, 0x0e, 0x01, 0x07,
  0x09, 0x04, 0x0c, 0x0a, 0x0e, 0x08, 0x02, 0x0d,
  0x00, 0x0f, 0x06, 0x0c, 0x0a, 0x09, 0x0d, 0x00,
  0x0f, 0x03, 0x03, 0x05, 0x05, 0x06, 0x08, 0x0b
};

static const uint8_t des_permute_table[32] = {
  0x10, 0x19, 0x0c, 0x0b, 0x03, 0x14, 0x04, 0x0f,
  0x1f, 0x11, 0x09, 0x06, 0x1b, 0x0e, 0x01, 0x16,
  0x1e, 0x18, 0x08, 0x12, 0x00, 0x05, 0x1d, 0x17,
  0x0d, 0x13, 0x02, 0x1a, 0x0a, 0x15, 0x1c, 0x07
};

static const uint8_t des_shift_table[16] = {
  0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
  0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01
};

static TORSION_INLINE void
des_ip(uint32_t *xl, uint32_t *xr) {
  uint32_t l = *xl;
  uint32_t r = *xr;
  uint32_t u = 0;
  uint32_t v = 0;
  int i, j;

  for (i = 6; i >= 0; i -= 2) {
    for (j = 0; j <= 24; j += 8) {
      u <<= 1;
      u |= (r >> (j + i)) & 1;
    }

    for (j = 0; j <= 24; j += 8) {
      u <<= 1;
      u |= (l >> (j + i)) & 1;
    }
  }

  for (i = 6; i >= 0; i -= 2) {
    for (j = 1; j <= 25; j += 8) {
      v <<= 1;
      v |= (r >> (j + i)) & 1;
    }

    for (j = 1; j <= 25; j += 8) {
      v <<= 1;
      v |= (l >> (j + i)) & 1;
    }
  }

  *xl = u;
  *xr = v;
}

static TORSION_INLINE void
des_rip(uint32_t *xl, uint32_t *xr) {
  uint32_t l = *xl;
  uint32_t r = *xr;
  uint32_t u = 0;
  uint32_t v = 0;
  int i, j;

  for (i = 0; i < 4; i++) {
    for (j = 24; j >= 0; j -= 8) {
      u <<= 1;
      u |= (r >> (j + i)) & 1;
      u <<= 1;
      u |= (l >> (j + i)) & 1;
    }
  }

  for (i = 4; i < 8; i++) {
    for (j = 24; j >= 0; j -= 8) {
      v <<= 1;
      v |= (r >> (j + i)) & 1;
      v <<= 1;
      v |= (l >> (j + i)) & 1;
    }
  }

  *xl = u;
  *xr = v;
}

static TORSION_INLINE void
des_pc1(uint32_t *xl, uint32_t *xr) {
  uint32_t l = *xl;
  uint32_t r = *xr;
  uint32_t u = 0;
  uint32_t v = 0;
  int i, j;

  /* 7, 15, 23, 31, 39, 47, 55, 63
     6, 14, 22, 30, 39, 47, 55, 63
     5, 13, 21, 29, 39, 47, 55, 63
     4, 12, 20, 28 */
  for (i = 7; i >= 5; i--) {
    for (j = 0; j <= 24; j += 8) {
      u <<= 1;
      u |= (r >> (j + i)) & 1;
    }

    for (j = 0; j <= 24; j += 8) {
      u <<= 1;
      u |= (l >> (j + i)) & 1;
    }
  }

  for (j = 0; j <= 24; j += 8) {
    u <<= 1;
    u |= (r >> (j + 4)) & 1;
  }

  /* 1, 9, 17, 25, 33, 41, 49, 57
     2, 10, 18, 26, 34, 42, 50, 58
     3, 11, 19, 27, 35, 43, 51, 59
     36, 44, 52, 60 */
  for (i = 1; i <= 3; i++) {
    for (j = 0; j <= 24; j += 8) {
      v <<= 1;
      v |= (r >> (j + i)) & 1;
    }

    for (j = 0; j <= 24; j += 8) {
      v <<= 1;
      v |= (l >> (j + i)) & 1;
    }
  }

  for (j = 0; j <= 24; j += 8) {
    v <<= 1;
    v |= (l >> (j + 4)) & 1;
  }

  *xl = u;
  *xr = v;
}

static TORSION_INLINE uint32_t
des_r28shl(uint32_t x, unsigned int b) {
  return ((x << b) & 0xfffffff) | (x >> (28 - b));
}

static TORSION_INLINE void
des_pc2(uint32_t *xl, uint32_t *xr) {
  uint32_t l = *xl;
  uint32_t r = *xr;
  uint32_t u = 0;
  uint32_t v = 0;
  int i;

  for (i = 0; i < 24; i++) {
    u <<= 1;
    u |= (l >> des_pc2_table[i]) & 1;
  }

  for (i = 24; i < 48; i++) {
    v <<= 1;
    v |= (r >> des_pc2_table[i]) & 1;
  }

  *xl = u;
  *xr = v;
}

static TORSION_INLINE void
des_expand(uint32_t *xl, uint32_t *xr, uint32_t r) {
  uint32_t u = 0;
  uint32_t v = 0;
  int i;

  u = ((r & 1) << 5) | (r >> 27);

  for (i = 23; i >= 15; i -= 4) {
    u <<= 6;
    u |= (r >> i) & 0x3f;
  }

  for (i = 11; i >= 3; i -= 4) {
    v |= (r >> i) & 0x3f;
    v <<= 6;
  }

  v |= ((r & 0x1f) << 1) | (r >> 31);

  *xl = u;
  *xr = v;
}

static TORSION_INLINE uint32_t
des_substitute(uint32_t l, uint32_t r) {
  uint32_t s = 0;
  uint32_t b;
  int i;

  for (i = 0; i < 4; i++) {
    b = (l >> (18 - i * 6)) & 0x3f;
    s = (s << 4) | des_s_table[i * 0x40 + b];
  }

  for (i = 0; i < 4; i++) {
    b = (r >> (18 - i * 6)) & 0x3f;
    s = (s << 4) | des_s_table[4 * 0x40 + i * 0x40 + b];
  }

  return s;
}

static TORSION_INLINE uint32_t
des_permute(uint32_t s) {
  uint32_t f = 0;
  int i;

  for (i = 0; i < 32; i++) {
    f <<= 1;
    f |= (s >> des_permute_table[i]) & 1;
  }

  return f;
}

static void
des_encipher(const des_t *ctx, uint32_t *xl, uint32_t *xr) {
  uint32_t kl, kr, b1, b2, s, f, t;
  uint32_t l = *xl;
  uint32_t r = *xr;
  int i;

  /* Initial Permutation */
  des_ip(&l, &r);

  /* Apply f() x16 times */
  for (i = 0; i < 32; i += 2) {
    kl = ctx->keys[i + 0];
    kr = ctx->keys[i + 1];

    /* f(r, k) */
    des_expand(&b1, &b2, r);

    kl ^= b1;
    kr ^= b2;

    s = des_substitute(kl, kr);
    f = des_permute(s);
    t = r;

    r = l ^ f;
    l = t;
  }

  /* Reverse Initial Permutation */
  des_rip(&r, &l);

  *xl = r;
  *xr = l;
}

static void
des_decipher(const des_t *ctx, uint32_t *xl, uint32_t *xr) {
  uint32_t kl, kr, b1, b2, s, f, t;
  uint32_t l = *xr;
  uint32_t r = *xl;
  int i;

  /* Initial Permutation */
  des_ip(&r, &l);

  /* Apply f() x16 times */
  for (i = 32 - 2; i >= 0; i -= 2) {
    kl = ctx->keys[i + 0];
    kr = ctx->keys[i + 1];

    /* f(r, k) */
    des_expand(&b1, &b2, l);

    kl ^= b1;
    kr ^= b2;

    s = des_substitute(kl, kr);
    f = des_permute(s);
    t = l;

    l = r ^ f;
    r = t;
  }

  /* Reverse Initial Permutation */
  des_rip(&l, &r);

  *xl = l;
  *xr = r;
}

void
des_init(des_t *ctx, const unsigned char *key) {
  uint32_t kl = read32be(key + 0);
  uint32_t kr = read32be(key + 4);
  uint32_t k0, k1;
  int i, shift;

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  des_pc1(&kl, &kr);

  for (i = 0; i < 32; i += 2) {
    shift = des_shift_table[i >> 1];

    kl = des_r28shl(kl, shift);
    kr = des_r28shl(kr, shift);

    k0 = kl;
    k1 = kr;

    des_pc2(&k0, &k1);

    ctx->keys[i + 0] = k0;
    ctx->keys[i + 1] = k1;
  }
}

void
des_encrypt(const des_t *ctx, unsigned char *dst, const unsigned char *src) {
  uint32_t l = read32be(src + 0);
  uint32_t r = read32be(src + 4);

  des_encipher(ctx, &l, &r);

  write32be(dst + 0, l);
  write32be(dst + 4, r);
}

void
des_decrypt(const des_t *ctx, unsigned char *dst, const unsigned char *src) {
  uint32_t l = read32be(src + 0);
  uint32_t r = read32be(src + 4);

  des_decipher(ctx, &l, &r);

  write32be(dst + 0, l);
  write32be(dst + 4, r);
}

/*
 * DES-EDE
 */

void
des_ede_init(des_ede_t *ctx, const unsigned char *key) {
  des_init(&ctx->x, key + 0);
  des_init(&ctx->y, key + 8);
}

void
des_ede_encrypt(const des_ede_t *ctx,
                unsigned char *dst,
                const unsigned char *src) {
  des_encrypt(&ctx->x, dst, src);
  des_decrypt(&ctx->y, dst, dst);
  des_encrypt(&ctx->x, dst, dst);
}

void
des_ede_decrypt(const des_ede_t *ctx,
                unsigned char *dst,
                const unsigned char *src) {
  des_decrypt(&ctx->x, dst, src);
  des_encrypt(&ctx->y, dst, dst);
  des_decrypt(&ctx->x, dst, dst);
}

/*
 * DES-EDE3
 */

void
des_ede3_init(des_ede3_t *ctx, const unsigned char *key) {
  des_init(&ctx->x, key +  0);
  des_init(&ctx->y, key +  8);
  des_init(&ctx->z, key + 16);
}

void
des_ede3_encrypt(const des_ede3_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src) {
  des_encrypt(&ctx->x, dst, src);
  des_decrypt(&ctx->y, dst, dst);
  des_encrypt(&ctx->z, dst, dst);
}

void
des_ede3_decrypt(const des_ede3_t *ctx,
                 unsigned char *dst,
                 const unsigned char *src) {
  des_decrypt(&ctx->z, dst, src);
  des_encrypt(&ctx->y, dst, dst);
  des_decrypt(&ctx->x, dst, dst);
}

/*
 * IDEA
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
 *   https://github.com/dgryski/go-idea/blob/master/idea.go
 */

#undef HAVE_STRENGTH_REDUCTION

#if defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER)
#  if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ >= 8
#    define HAVE_STRENGTH_REDUCTION
#  endif
#endif

/* Constant-time IDEA.
 *
 * The code below assumes the compiler is strength
 * reducing our modulo by 65537. This is achieved
 * with something like:
 *
 *   x - (mulhi(x, c) >> 16)
 *
 * Where `mulhi` does a wide multiplication and
 * returns the high word, with following values
 * of `c`:
 *
 *   0xffff0001 (32 bit)
 *   0xffff0000ffff0001 (64 bit)
 *
 * Note: GCC & ICC strength-reduce the division
 * at every optimization level (except for -Os),
 * whereas clang requires -O1 or higher. Unsure
 * what MSVC does here.
 *
 * The inverse mod 65537 can then be computed in
 * constant-time by abusing a well-known property
 * of Fermat's little theorem:
 *
 *   x^65535 mod 65537 = x^-1 mod 65537
 *
 * An exponent of 65535 (0xffff) makes things
 * nice and simple. Normally left-to-right
 * exponentiation (z = x^y mod n) follows an
 * algorithm of:
 *
 *   z = 1
 *   for i = ceil(log2(y+1)) - 1 downto 0
 *     z = z * z mod n
 *     if floor(y / 2^i) mod 2 == 1
 *       z = z * x mod n
 *
 * This can be simplified in three ways:
 *
 *   1. The branch is not necessary as all bits
 *      in the exponent are set.
 *
 *   2. A 64-bit integer is wide enough to
 *      handle two multiplications of 17 bit
 *      integers, requiring only one modulo
 *      operation per iteration. i.e.
 *
 *        z = z * z * x mod n
 *
 *   3. The first round simply assigns `z`
 *      to `x`, allowing us to initialize `z`
 *      as `x` and skip the first iteration.
 *
 * The result is the very simple loop you see
 * below. Note that zero is handled properly as:
 *
 *   65536^-1 mod 65537 = 65536
 */

#if defined(HAVE_STRENGTH_REDUCTION)

static uint16_t
idea_mul(uint16_t x, uint16_t y) {
  uint64_t u = x;
  uint64_t v = y;

  u |= 0x10000 & -((u - 1) >> 63);
  v |= 0x10000 & -((v - 1) >> 63);

  return (u * v) % 0x10001;
}

static uint16_t
idea_inv(uint16_t x) {
  uint64_t z = x;
  int i;

  for (i = 0; i < 15; i++)
    z = (z * z * x) % 0x10001;

  return z;
}

#else /* !HAVE_STRENGTH_REDUCTION */

static uint16_t
idea_mul(uint16_t x, uint16_t y) {
  uint32_t u = x;
  uint32_t v = y;
  uint32_t w = u * v;
  uint32_t hi = w >> 16;
  uint32_t lo = w & 0xffff;
  uint32_t z = lo - hi + (lo < hi);

  z |= (1 - u) & -((v - 1) >> 31);
  z |= (1 - v) & -((u - 1) >> 31);

  return z;
}

static uint16_t
idea_inv(uint16_t x) {
  uint16_t z = x;
  int i;

  for (i = 0; i < 15; i++) {
    z = idea_mul(z, z);
    z = idea_mul(z, x);
  }

  return z;
}

#endif /* !HAVE_STRENGTH_REDUCTION */

void
idea_init(idea_t *ctx, const unsigned char *key) {
  idea_init_encrypt(ctx, key);
  idea_init_decrypt(ctx);
}

void
idea_init_encrypt(idea_t *ctx, const unsigned char *key) {
  uint16_t *K = ctx->enckey;
  int i = 0;
  int j = 0;

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  for (; j < 8; j++)
    K[j] = read16be(key + j * 2);

  for (; j < 52; j++) {
    i += 1;

    K[i + 7] = (K[(i + 0) & 7] << 9)
             | (K[(i + 1) & 7] >> 7);

    K += i & 8;
    i &= 7;
  }
}

void
idea_init_decrypt(idea_t *ctx) {
  uint16_t *K = ctx->enckey;
  uint16_t *D = ctx->deckey + 52;
  uint16_t t1, t2, t3;
  int i;

  t1 = idea_inv(*K++);
  t2 = -*K++;
  t3 = -*K++;

  *--D = idea_inv(*K++);
  *--D = t3;
  *--D = t2;
  *--D = t1;

  for (i = 0; i < 8 - 1; i++) {
    t1 = *K++;

    *--D = *K++;
    *--D = t1;

    t1 = idea_inv(*K++);
    t2 = -*K++;
    t3 = -*K++;

    *--D = idea_inv(*K++);
    *--D = t2;
    *--D = t3;
    *--D = t1;
  }

  t1 = *K++;

  *--D = *K++;
  *--D = t1;

  t1 = idea_inv(*K++);
  t2 = -*K++;
  t3 = -*K++;

  *--D = idea_inv(*K++);
  *--D = t3;
  *--D = t2;
  *--D = t1;
}

static void
idea_crypt(unsigned char *dst, const unsigned char *src, const uint16_t *K) {
  uint16_t x1 = read16be(src + 0);
  uint16_t x2 = read16be(src + 2);
  uint16_t x3 = read16be(src + 4);
  uint16_t x4 = read16be(src + 6);
  uint16_t s2 = 0;
  uint16_t s3 = 0;
  int i;

  for (i = 8 - 1; i >= 0; i--) {
    x1 = idea_mul(x1, *K++);
    x2 += *K++;
    x3 += *K++;
    x4 = idea_mul(x4, *K++);

    s3 = x3;
    x3 ^= x1;
    x3 = idea_mul(x3, *K++);
    s2 = x2;

    x2 ^= x4;
    x2 += x3;
    x2 = idea_mul(x2, *K++);
    x3 += x2;

    x1 ^= x2;
    x4 ^= x3;
    x2 ^= s3;
    x3 ^= s2;
  }

  x1 = idea_mul(x1, *K++);
  x3 += *K++;
  x2 += *K++;
  x4 = idea_mul(x4, *K++);

  write16be(dst + 0, x1);
  write16be(dst + 2, x3);
  write16be(dst + 4, x2);
  write16be(dst + 6, x4);
}

void
idea_encrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src) {
  idea_crypt(dst, src, ctx->enckey);
}

void
idea_decrypt(const idea_t *ctx, unsigned char *dst, const unsigned char *src) {
  idea_crypt(dst, src, ctx->deckey);
}

/*
 * Serpent
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Serpent_(cipher)
 *   https://www.cl.cam.ac.uk/~rja14/serpent.html
 *   https://github.com/aead/serpent
 */

#define linear serpent_linear
#define linearinv serpent_linearinv
#define sb0 serpent_sb0
#define sb0inv serpent_sb0inv
#define sb1 serpent_sb1
#define sb1inv serpent_sb1inv
#define sb2 serpent_sb2
#define sb2inv serpent_sb2inv
#define sb3 serpent_sb3
#define sb3inv serpent_sb3inv
#define sb4 serpent_sb4
#define sb4inv serpent_sb4inv
#define sb5 serpent_sb5
#define sb5inv serpent_sb5inv
#define sb6 serpent_sb6
#define sb6inv serpent_sb6inv
#define sb7 serpent_sb7
#define sb7inv serpent_sb7inv
#define xor4 serpent_xor4

static TORSION_INLINE void
linear(uint32_t *v0, uint32_t *v1, uint32_t *v2, uint32_t *v3) {
  uint32_t t0 = ((*v0 << 13) | (*v0 >> (32 - 13)));
  uint32_t t2 = ((*v2 << 3) | (*v2 >> (32 - 3)));
  uint32_t t1 = *v1 ^ t0 ^ t2;
  uint32_t t3 = *v3 ^ t2 ^ (t0 << 3);

  *v1 = (t1 << 1) | (t1 >> (32 - 1));
  *v3 = (t3 << 7) | (t3 >> (32 - 7));
  t0 ^= *v1 ^ *v3;
  t2 ^= *v3 ^ (*v1 << 7);
  *v0 = (t0 << 5) | (t0 >> (32 - 5));
  *v2 = (t2 << 22) | (t2 >> (32 - 22));
}

static TORSION_INLINE void
linearinv(uint32_t *v0, uint32_t *v1, uint32_t *v2, uint32_t *v3) {
  uint32_t t2 = (*v2 >> 22) | (*v2 << (32 - 22));
  uint32_t t0 = (*v0 >> 5) | (*v0 << (32 - 5));
  uint32_t t3, t1;

  t2 ^= *v3 ^ (*v1 << 7);
  t0 ^= *v1 ^ *v3;
  t3 = (*v3 >> 7) | (*v3 << (32 - 7));
  t1 = (*v1 >> 1) | (*v1 << (32 - 1));
  *v3 = t3 ^ t2 ^ (t0 << 3);
  *v1 = t1 ^ t0 ^ t2;
  *v2 = (t2 >> 3) | (t2 << (32 - 3));
  *v0 = (t0 >> 13) | (t0 << (32 - 13));
}

static TORSION_INLINE void
sb0(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t t0 = *r0 ^ *r3;
  uint32_t t1 = *r2 ^ t0;
  uint32_t t2 = *r1 ^ t1;
  uint32_t t3, t4;

  *r3 = (*r0 & *r3) ^ t2;
  t3 = *r0 ^ (*r1 & t0);
  *r2 = t2 ^ (*r2 | t3);
  t4 = *r3 & (t1 ^ t3);
  *r1 = (~t1) ^ t4;
  *r0 = t4 ^ (~t3);
}

static TORSION_INLINE void
sb0inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t t0 = ~(*r0);
  uint32_t t1 = *r0 ^ *r1;
  uint32_t t2 = *r3 ^ (t0 | t1);
  uint32_t t3 = *r2 ^ t2;
  uint32_t t4;

  *r2 = t1 ^ t3;
  t4 = t0 ^ (*r3 & t1);
  *r1 = t2 ^ (*r2 & t4);
  *r3 = (*r0 & t2) ^ (t3 | *r1);
  *r0 = *r3 ^ (t3 ^ t4);
}

static TORSION_INLINE void
sb1(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t t0 = *r1 ^ (~(*r0));
  uint32_t t1 = *r2 ^ (*r0 | t0);
  uint32_t t2, t3, t4;

  *r2 = *r3 ^ t1;
  t2 = *r1 ^ (*r3 | t0);
  t3 = t0 ^ *r2;
  *r3 = t3 ^ (t1 & t2);
  t4 = t1 ^ t2;
  *r1 = *r3 ^ t4;
  *r0 = t1 ^ (t3 & t4);
}

static TORSION_INLINE void
sb1inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t t0 = *r1 ^ *r3;
  uint32_t t1 = *r0 ^ (*r1 & t0);
  uint32_t t2 = t0 ^ t1;
  uint32_t t3, t4, t5, t6;

  *r3 = *r2 ^ t2;
  t3 = *r1 ^ (t0 & t1);
  t4 = *r3 | t3;
  *r1 = t1 ^ t4;
  t5 = ~(*r1);
  t6 = *r3 ^ t3;
  *r0 = t5 ^ t6;
  *r2 = t2 ^ (t5 | t6);
}

static TORSION_INLINE void
sb2(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v0 = *r0;
  uint32_t v3 = *r3;
  uint32_t t0 = ~v0;
  uint32_t t1 = *r1 ^ v3;
  uint32_t t2 = *r2 & t0;
  uint32_t t3, t4, t5;

  *r0 = t1 ^ t2;
  t3 = *r2 ^ t0;
  t4 = *r2 ^ *r0;
  t5 = *r1 & t4;
  *r3 = t3 ^ t5;
  *r2 = v0 ^ ((v3 | t5) & (*r0 | t3));
  *r1 = (t1 ^ *r3) ^ (*r2 ^ (v3 | t0));
}

static TORSION_INLINE void
sb2inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v0 = *r0;
  uint32_t v3 = *r3;
  uint32_t t0 = *r1 ^ v3;
  uint32_t t1 = ~t0;
  uint32_t t2 = v0 ^ *r2;
  uint32_t t3 = *r2 ^ t0;
  uint32_t t4 = *r1 & t3;
  uint32_t t5, t6, t7, t8, t9;

  *r0 = t2 ^ t4;
  t5 = v0 | t1;
  t6 = v3 ^ t5;
  t7 = t2 | t6;
  *r3 = t0 ^ t7;
  t8 = ~t3;
  t9 = *r0 | *r3;
  *r1 = t8 ^ t9;
  *r2 = (v3 & t8) ^ (t2 ^ t9);
}

static TORSION_INLINE void
sb3(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v1 = *r1;
  uint32_t v3 = *r3;
  uint32_t t0 = *r0 ^ *r1;
  uint32_t t1 = *r0 & *r2;
  uint32_t t2 = *r0 | *r3;
  uint32_t t3 = *r2 ^ *r3;
  uint32_t t4 = t0 & t2;
  uint32_t t5 = t1 | t4;
  uint32_t t6, t7, t8, t9;

  *r2 = t3 ^ t5;
  t6 = *r1 ^ t2;
  t7 = t5 ^ t6;
  t8 = t3 & t7;
  *r0 = t0 ^ t8;
  t9 = *r2 & *r0;
  *r1 = t7 ^ t9;
  *r3 = (v1 | v3) ^ (t3 ^ t9);
}

static TORSION_INLINE void
sb3inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t t0 = *r0 | *r1;
  uint32_t t1 = *r1 ^ *r2;
  uint32_t t2 = *r1 & t1;
  uint32_t t3 = *r0 ^ t2;
  uint32_t t4 = *r2 ^ t3;
  uint32_t t5 = *r3 | t3;
  uint32_t t6, t7, t8, t9;

  *r0 = t1 ^ t5;
  t6 = t1 | t5;
  t7 = *r3 ^ t6;
  *r2 = t4 ^ t7;
  t8 = t0 ^ t7;
  t9 = *r0 & t8;
  *r3 = t3 ^ t9;
  *r1 = *r3 ^ (*r0 ^ t8);
}

static TORSION_INLINE void
sb4(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v0 = *r0;
  uint32_t t0 = v0 ^ *r3;
  uint32_t t1 = *r3 & t0;
  uint32_t t2 = *r2 ^ t1;
  uint32_t t3 = *r1 | t2;
  uint32_t t4, t5, t6, t7, t8;

  *r3 = t0 ^ t3;
  t4 = ~(*r1);
  t5 = t0 | t4;
  *r0 = t2 ^ t5;
  t6 = v0 & *r0;
  t7 = t0 ^ t4;
  t8 = t3 & t7;
  *r2 = t6 ^ t8;
  *r1 = (v0 ^ t2) ^ (t7 & *r2);
}

static TORSION_INLINE void
sb4inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v3 = *r3;
  uint32_t t0 = *r2 | v3;
  uint32_t t1 = *r0 & t0;
  uint32_t t2 = *r1 ^ t1;
  uint32_t t3 = *r0 & t2;
  uint32_t t4 = *r2 ^ t3;
  uint32_t t5, t6, t7, t8;

  *r1 = v3 ^ t4;
  t5 = ~(*r0);
  t6 = t4 & *r1;
  *r3 = t2 ^ t6;
  t7 = *r1 | t5;
  t8 = v3 ^ t7;
  *r0 = *r3 ^ t8;
  *r2 = (t2 & t8) ^ (*r1 ^ t5);
}

static TORSION_INLINE void
sb5(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v1 = *r1;
  uint32_t t0 = ~(*r0);
  uint32_t t1 = *r0 ^ v1;
  uint32_t t2 = *r0 ^ *r3;
  uint32_t t3 = *r2 ^ t0;
  uint32_t t4 = t1 | t2;
  uint32_t t5, t6, t7, t8, t9;

  *r0 = t3 ^ t4;
  t5 = *r3 & *r0;
  t6 = t1 ^ *r0;
  *r1 = t5 ^ t6;
  t7 = t0 | *r0;
  t8 = t1 | t5;
  t9 = t2 ^ t7;
  *r2 = t8 ^ t9;
  *r3 = (v1 ^ t5) ^ (*r1 & t9);
}

static TORSION_INLINE void
sb5inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v0 = *r0;
  uint32_t v1 = *r1;
  uint32_t v3 = *r3;
  uint32_t t0 = ~(*r2);
  uint32_t t1 = v1 & t0;
  uint32_t t2 = v3 ^ t1;
  uint32_t t3 = v0 & t2;
  uint32_t t4 = v1 ^ t0;
  uint32_t t5, t6, t7, t8;

  *r3 = t3 ^ t4;
  t5 = v1 | *r3;
  t6 = v0 & t5;
  *r1 = t2 ^ t6;
  t7 = v0 | v3;
  t8 = t0 ^ t5;
  *r0 = t7 ^ t8;
  *r2 = (v1 & t7) ^ (t3 | (v0 ^ *r2));
}

static TORSION_INLINE void
sb6(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t t0 = ~(*r0);
  uint32_t t1 = *r0 ^ *r3;
  uint32_t t2 = *r1 ^ t1;
  uint32_t t3 = t0 | t1;
  uint32_t t4 = *r2 ^ t3;
  uint32_t t5, t6, t7, t8;

  *r1 = *r1 ^ t4;
  t5 = t1 | *r1;
  t6 = *r3 ^ t5;
  t7 = t4 & t6;
  *r2 = t2 ^ t7;
  t8 = t4 ^ t6;
  *r0 = *r2 ^ t8;
  *r3 = (~t4) ^ (t2 & t8);
}

static TORSION_INLINE void
sb6inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v1 = *r1;
  uint32_t v3 = *r3;
  uint32_t t0 = ~(*r0);
  uint32_t t1 = *r0 ^ v1;
  uint32_t t2 = *r2 ^ t1;
  uint32_t t3 = *r2 | t0;
  uint32_t t4 = v3 ^ t3;
  uint32_t t5, t6, t7, t8;

  *r1 = t2 ^ t4;
  t5 = t2 & t4;
  t6 = t1 ^ t5;
  t7 = v1 | t6;
  *r3 = t4 ^ t7;
  t8 = v1 | *r3;
  *r0 = t6 ^ t8;
  *r2 = (v3 & t0) ^ (t2 ^ t8);
}

static TORSION_INLINE void
sb7(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t t0 = *r1 ^ *r2;
  uint32_t t1 = *r2 & t0;
  uint32_t t2 = *r3 ^ t1;
  uint32_t t3 = *r0 ^ t2;
  uint32_t t4 = *r3 | t0;
  uint32_t t5 = t3 & t4;
  uint32_t t6, t7, t8, t9;

  *r1 = *r1 ^ t5;
  t6 = t2 | *r1;
  t7 = *r0 & t3;
  *r3 = t0 ^ t7;
  t8 = t3 ^ t6;
  t9 = *r3 & t8;
  *r2 = t2 ^ t9;
  *r0 = (~t8) ^ (*r3 & *r2);
}

static TORSION_INLINE void
sb7inv(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3) {
  uint32_t v0 = *r0;
  uint32_t v3 = *r3;
  uint32_t t0 = *r2 | (v0 & *r1);
  uint32_t t1 = v3 & (v0 | *r1);
  uint32_t t2, t3, t4;

  *r3 = t0 ^ t1;
  t2 = ~v3;
  t3 = *r1 ^ t1;
  t4 = t3 | (*r3 ^ t2);
  *r1 = v0 ^ t4;
  *r0 = (*r2 ^ t3) ^ (v3 | *r1);
  *r2 = (t0 ^ *r1) ^ (*r0 ^ (v0 & *r3));
}

static TORSION_INLINE void
xor4(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3,
     const uint32_t *sk, int i0, int i1, int i2, int i3) {
  *r0 ^= sk[i0];
  *r1 ^= sk[i1];
  *r2 ^= sk[i2];
  *r3 ^= sk[i3];
}

void
serpent_init(serpent_t *ctx, unsigned int bits, const unsigned char *key) {
  static const uint32_t phi = 0x9e3779b9;
  uint32_t *s = ctx->subkeys;
  size_t key_len = bits / 8;
  uint32_t k[16];
  size_t j = 0;
  uint32_t x;
  size_t i;

  CHECK(bits == 128 || bits == 192 || bits == 256);

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  for (i = 0; i < key_len; i += 4)
    k[j++] = read32le(key + i);

  if (j < 8)
    k[j++] = 1;

  while (j < 16)
    k[j++] = 0;

  for (i = 8; i < 16; i++) {
    x = k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ k[i - 1] ^ phi ^ (uint32_t)(i - 8);
    k[i] = (x << 11) | (x >> 21);
    s[i - 8] = k[i];
  }

  for (i = 8; i < 132; i++) {
    x = s[i - 8] ^ s[i - 5] ^ s[i - 3] ^ s[i - 1] ^ phi ^ (uint32_t)i;
    s[i] = (x << 11) | (x >> 21);
  }

  sb3(&s[0], &s[1], &s[2], &s[3]);
  sb2(&s[4], &s[5], &s[6], &s[7]);
  sb1(&s[8], &s[9], &s[10], &s[11]);
  sb0(&s[12], &s[13], &s[14], &s[15]);
  sb7(&s[16], &s[17], &s[18], &s[19]);
  sb6(&s[20], &s[21], &s[22], &s[23]);
  sb5(&s[24], &s[25], &s[26], &s[27]);
  sb4(&s[28], &s[29], &s[30], &s[31]);

  sb3(&s[32], &s[33], &s[34], &s[35]);
  sb2(&s[36], &s[37], &s[38], &s[39]);
  sb1(&s[40], &s[41], &s[42], &s[43]);
  sb0(&s[44], &s[45], &s[46], &s[47]);
  sb7(&s[48], &s[49], &s[50], &s[51]);
  sb6(&s[52], &s[53], &s[54], &s[55]);
  sb5(&s[56], &s[57], &s[58], &s[59]);
  sb4(&s[60], &s[61], &s[62], &s[63]);

  sb3(&s[64], &s[65], &s[66], &s[67]);
  sb2(&s[68], &s[69], &s[70], &s[71]);
  sb1(&s[72], &s[73], &s[74], &s[75]);
  sb0(&s[76], &s[77], &s[78], &s[79]);
  sb7(&s[80], &s[81], &s[82], &s[83]);
  sb6(&s[84], &s[85], &s[86], &s[87]);
  sb5(&s[88], &s[89], &s[90], &s[91]);
  sb4(&s[92], &s[93], &s[94], &s[95]);

  sb3(&s[96], &s[97], &s[98], &s[99]);
  sb2(&s[100], &s[101], &s[102], &s[103]);
  sb1(&s[104], &s[105], &s[106], &s[107]);
  sb0(&s[108], &s[109], &s[110], &s[111]);
  sb7(&s[112], &s[113], &s[114], &s[115]);
  sb6(&s[116], &s[117], &s[118], &s[119]);
  sb5(&s[120], &s[121], &s[122], &s[123]);
  sb4(&s[124], &s[125], &s[126], &s[127]);

  sb3(&s[128], &s[129], &s[130], &s[131]);
}

void
serpent_encrypt(const serpent_t *ctx,
                unsigned char *dst,
                const unsigned char *src) {
  const uint32_t *sk = ctx->subkeys;
  uint32_t r0 = read32le(src +  0);
  uint32_t r1 = read32le(src +  4);
  uint32_t r2 = read32le(src +  8);
  uint32_t r3 = read32le(src + 12);

  xor4(&r0, &r1, &r2, &r3, sk, 0, 1, 2, 3);

  sb0(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 4, 5, 6, 7);
  sb1(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 8, 9, 10, 11);
  sb2(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 12, 13, 14, 15);
  sb3(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 16, 17, 18, 19);
  sb4(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 20, 21, 22, 23);
  sb5(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 24, 25, 26, 27);
  sb6(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 28, 29, 30, 31);
  sb7(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);

  xor4(&r0, &r1, &r2, &r3, sk, 32, 33, 34, 35);
  sb0(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 36, 37, 38, 39);
  sb1(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 40, 41, 42, 43);
  sb2(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 44, 45, 46, 47);
  sb3(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 48, 49, 50, 51);
  sb4(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 52, 53, 54, 55);
  sb5(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 56, 57, 58, 59);
  sb6(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 60, 61, 62, 63);
  sb7(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);

  xor4(&r0, &r1, &r2, &r3, sk, 64, 65, 66, 67);
  sb0(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 68, 69, 70, 71);
  sb1(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 72, 73, 74, 75);
  sb2(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 76, 77, 78, 79);
  sb3(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 80, 81, 82, 83);
  sb4(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 84, 85, 86, 87);
  sb5(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 88, 89, 90, 91);
  sb6(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 92, 93, 94, 95);
  sb7(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);

  xor4(&r0, &r1, &r2, &r3, sk, 96, 97, 98, 99);
  sb0(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 100, 101, 102, 103);
  sb1(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 104, 105, 106, 107);
  sb2(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 108, 109, 110, 111);
  sb3(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 112, 113, 114, 115);
  sb4(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 116, 117, 118, 119);
  sb5(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 120, 121, 122, 123);
  sb6(&r0, &r1, &r2, &r3);
  linear(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 124, 125, 126, 127);
  sb7(&r0, &r1, &r2, &r3);

  xor4(&r0, &r1, &r2, &r3, sk, 128, 129, 130, 131);

  write32le(dst +  0, r0);
  write32le(dst +  4, r1);
  write32le(dst +  8, r2);
  write32le(dst + 12, r3);
}

void
serpent_decrypt(const serpent_t *ctx,
                unsigned char *dst,
                const unsigned char *src) {
  const uint32_t *sk = ctx->subkeys;
  uint32_t r0 = read32le(src +  0);
  uint32_t r1 = read32le(src +  4);
  uint32_t r2 = read32le(src +  8);
  uint32_t r3 = read32le(src + 12);

  xor4(&r0, &r1, &r2, &r3, sk, 128, 129, 130, 131);

  sb7inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 124, 125, 126, 127);
  linearinv(&r0, &r1, &r2, &r3);
  sb6inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 120, 121, 122, 123);
  linearinv(&r0, &r1, &r2, &r3);
  sb5inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 116, 117, 118, 119);
  linearinv(&r0, &r1, &r2, &r3);
  sb4inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 112, 113, 114, 115);
  linearinv(&r0, &r1, &r2, &r3);
  sb3inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 108, 109, 110, 111);
  linearinv(&r0, &r1, &r2, &r3);
  sb2inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 104, 105, 106, 107);
  linearinv(&r0, &r1, &r2, &r3);
  sb1inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 100, 101, 102, 103);
  linearinv(&r0, &r1, &r2, &r3);
  sb0inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 96, 97, 98, 99);
  linearinv(&r0, &r1, &r2, &r3);

  sb7inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 92, 93, 94, 95);
  linearinv(&r0, &r1, &r2, &r3);
  sb6inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 88, 89, 90, 91);
  linearinv(&r0, &r1, &r2, &r3);
  sb5inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 84, 85, 86, 87);
  linearinv(&r0, &r1, &r2, &r3);
  sb4inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 80, 81, 82, 83);
  linearinv(&r0, &r1, &r2, &r3);
  sb3inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 76, 77, 78, 79);
  linearinv(&r0, &r1, &r2, &r3);
  sb2inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 72, 73, 74, 75);
  linearinv(&r0, &r1, &r2, &r3);
  sb1inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 68, 69, 70, 71);
  linearinv(&r0, &r1, &r2, &r3);
  sb0inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 64, 65, 66, 67);
  linearinv(&r0, &r1, &r2, &r3);

  sb7inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 60, 61, 62, 63);
  linearinv(&r0, &r1, &r2, &r3);
  sb6inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 56, 57, 58, 59);
  linearinv(&r0, &r1, &r2, &r3);
  sb5inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 52, 53, 54, 55);
  linearinv(&r0, &r1, &r2, &r3);
  sb4inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 48, 49, 50, 51);
  linearinv(&r0, &r1, &r2, &r3);
  sb3inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 44, 45, 46, 47);
  linearinv(&r0, &r1, &r2, &r3);
  sb2inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 40, 41, 42, 43);
  linearinv(&r0, &r1, &r2, &r3);
  sb1inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 36, 37, 38, 39);
  linearinv(&r0, &r1, &r2, &r3);
  sb0inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 32, 33, 34, 35);
  linearinv(&r0, &r1, &r2, &r3);

  sb7inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 28, 29, 30, 31);
  linearinv(&r0, &r1, &r2, &r3);
  sb6inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 24, 25, 26, 27);
  linearinv(&r0, &r1, &r2, &r3);
  sb5inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 20, 21, 22, 23);
  linearinv(&r0, &r1, &r2, &r3);
  sb4inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 16, 17, 18, 19);
  linearinv(&r0, &r1, &r2, &r3);
  sb3inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 12, 13, 14, 15);
  linearinv(&r0, &r1, &r2, &r3);
  sb2inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 8, 9, 10, 11);
  linearinv(&r0, &r1, &r2, &r3);
  sb1inv(&r0, &r1, &r2, &r3);
  xor4(&r0, &r1, &r2, &r3, sk, 4, 5, 6, 7);
  linearinv(&r0, &r1, &r2, &r3);
  sb0inv(&r0, &r1, &r2, &r3);

  xor4(&r0, &r1, &r2, &r3, sk, 0, 1, 2, 3);

  write32le(dst +  0, r0);
  write32le(dst +  4, r1);
  write32le(dst +  8, r2);
  write32le(dst + 12, r3);
}

#undef linear
#undef linearinv
#undef sb0
#undef sb0inv
#undef sb1
#undef sb1inv
#undef sb2
#undef sb2inv
#undef sb3
#undef sb3inv
#undef sb4
#undef sb4inv
#undef sb5
#undef sb5inv
#undef sb6
#undef sb6inv
#undef sb7
#undef sb7inv
#undef xor4

/*
 * Twofish
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Twofish
 *   https://www.schneier.com/academic/twofish/
 *   https://github.com/golang/crypto/blob/master/twofish/twofish.go
 */

#define RS twofish_RS
#define S0 twofish_S0
#define S1 twofish_S1
#define gf_mul twofish_gf_mul
#define mds_mul twofish_mds_mul
#define h_gen twofish_h_gen
#define rol32 twofish_rol32
#define ror32 twofish_ror32

static const uint8_t RS[4][8] = {
  {0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e},
  {0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5},
  {0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19},
  {0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03}
};

static const uint8_t S0[256] = {
  0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76,
  0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
  0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c,
  0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
  0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23,
  0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
  0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c,
  0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
  0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b,
  0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
  0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66,
  0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
  0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba,
  0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
  0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8,
  0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
  0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2,
  0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
  0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab,
  0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
  0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b,
  0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
  0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a,
  0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
  0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02,
  0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
  0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72,
  0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
  0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8,
  0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
  0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00,
  0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0
};

static const uint8_t S1[256] = {
  0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8,
  0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
  0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1,
  0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
  0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d,
  0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
  0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3,
  0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
  0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96,
  0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
  0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70,
  0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
  0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc,
  0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
  0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9,
  0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
  0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3,
  0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
  0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49,
  0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
  0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01,
  0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
  0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19,
  0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
  0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5,
  0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
  0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e,
  0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
  0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab,
  0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
  0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2,
  0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91
};

static uint8_t
gf_mul(uint8_t a, uint8_t b, uint32_t p) {
  uint32_t B[2];
  uint32_t P[2];
  uint32_t res = 0;
  int i;

  B[0] = 0;
  B[1] = b;

  P[0] = 0;
  P[1] = p;

  for (i = 0; i < 7; i++) {
    res ^= B[a & 1];
    a >>= 1;
    B[1] = P[B[1] >> 7] ^ (B[1] << 1);
  }

  res ^= B[a & 1];

  return (uint8_t)res;
}

static uint32_t
mds_mul(uint8_t v, int col) {
  static const uint32_t MDS_POLY = 0x169; /* x^8 + x^6 + x^5 + x^3 + 1 */
  uint32_t x = v;
  uint32_t y = gf_mul(v, 0x5b, MDS_POLY);
  uint32_t z = gf_mul(v, 0xef, MDS_POLY);

  switch (col) {
    case 0:
      return x | (y << 8) | (z << 16) | (z << 24);
    case 1:
      return z | (z << 8) | (y << 16) | (x << 24);
    case 2:
      return y | (z << 8) | (x << 16) | (z << 24);
    case 3:
      return y | (x << 8) | (z << 16) | (y << 24);
  }

  torsion_abort(); /* LCOV_EXCL_LINE */

  return 0;
}

static uint32_t
h_gen(const uint8_t *v, const uint8_t *key, size_t off, int k) {
  uint32_t mult;
  uint8_t y[4];
  int i;

  for (i = 0; i < 4; i++)
    y[i] = v[i];

  switch (k) {
    case 4:
      y[0] = S1[y[0]] ^ key[4 * (6 + off) + 0];
      y[1] = S0[y[1]] ^ key[4 * (6 + off) + 1];
      y[2] = S0[y[2]] ^ key[4 * (6 + off) + 2];
      y[3] = S1[y[3]] ^ key[4 * (6 + off) + 3];
      /* fallthrough */
    case 3:
      y[0] = S1[y[0]] ^ key[4 * (4 + off) + 0];
      y[1] = S1[y[1]] ^ key[4 * (4 + off) + 1];
      y[2] = S0[y[2]] ^ key[4 * (4 + off) + 2];
      y[3] = S0[y[3]] ^ key[4 * (4 + off) + 3];
      /* fallthrough */
    case 2:
      y[0] = S1[S0[S0[y[0]]
           ^ key[4 * (2 + off) + 0]]
           ^ key[4 * (0 + off) + 0]];
      y[1] = S0[S0[S1[y[1]]
           ^ key[4 * (2 + off) + 1]]
           ^ key[4 * (0 + off) + 1]];
      y[2] = S1[S1[S0[y[2]]
           ^ key[4 * (2 + off) + 2]]
           ^ key[4 * (0 + off) + 2]];
      y[3] = S0[S1[S1[y[3]]
           ^ key[4 * (2 + off) + 3]]
           ^ key[4 * (0 + off) + 3]];
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }

  mult = 0;

  for (i = 0; i < 4; i++)
    mult ^= mds_mul(y[i], i);

  return mult;
}

static TORSION_INLINE uint32_t
rol32(uint32_t x, unsigned int y) {
  return (x << (y & 31)) | (x >> (32 - (y & 31)));
}

static TORSION_INLINE uint32_t
ror32(uint32_t x, unsigned int y) {
  return (x >> (y & 31)) | (x << (32 - (y & 31)));
}

void
twofish_init(twofish_t *ctx, unsigned int bits, const unsigned char *key) {
  static const uint32_t RS_POLY = 0x14d; /* x^8 + x^6 + x^3 + x^2 + 1 */
  int k = bits >> 6;
  uint8_t W[4 * 4];
  uint8_t tmp[4];
  uint32_t A, B;
  int i, j, v;

  CHECK(bits == 128 || bits == 192 || bits == 256);

  /* Defensive memset. */
  memset(ctx, 0, sizeof(*ctx));

  /* Create the S[..] words. */
  memset(W, 0, sizeof(W));

  for (i = 0; i < k; i++) {
    for (j = 0; j < 4; j++) {
      for (v = 0; v < 8; v++)
        W[4 * i + j] ^= gf_mul(key[8 * i + v], RS[j][v], RS_POLY);
    }
  }

  /* Calculate subkeys. */
  for (i = 0; i < 20; i++) {
    for (j = 0; j < 4; j++)
      tmp[j] = 2 * i;

    A = h_gen(tmp, key, 0, k);

    for (j = 0; j < 4; j++)
      tmp[j] = 2 * i + 1;

    B = rol32(h_gen(tmp, key, 1, k), 8);

    ctx->k[2 * i + 0] = A + B;
    ctx->k[2 * i + 1] = rol32(2 * B + A, 9);
  }

  /* Calculate sboxes. */
  switch (k) {
    case 2:
      for (i = 0; i < 256; i++) {
        ctx->S[0][i] = mds_mul(S1[S0[S0[i] ^ W[0]] ^ W[4]], 0);
        ctx->S[1][i] = mds_mul(S0[S0[S1[i] ^ W[1]] ^ W[5]], 1);
        ctx->S[2][i] = mds_mul(S1[S1[S0[i] ^ W[2]] ^ W[6]], 2);
        ctx->S[3][i] = mds_mul(S0[S1[S1[i] ^ W[3]] ^ W[7]], 3);
      }
      break;
    case 3:
      for (i = 0; i < 256; i++) {
        ctx->S[0][i] = mds_mul(S1[S0[S0[S1[i] ^ W[0]] ^ W[4]] ^ W[8]], 0);
        ctx->S[1][i] = mds_mul(S0[S0[S1[S1[i] ^ W[1]] ^ W[5]] ^ W[9]], 1);
        ctx->S[2][i] = mds_mul(S1[S1[S0[S0[i] ^ W[2]] ^ W[6]] ^ W[10]], 2);
        ctx->S[3][i] = mds_mul(S0[S1[S1[S0[i] ^ W[3]] ^ W[7]] ^ W[11]], 3);
      }
      break;
    case 4:
      for (i = 0; i < 256; i++) {
        ctx->S[0][i] =
          mds_mul(S1[S0[S0[S1[S1[i] ^ W[0]] ^ W[4]] ^ W[8]] ^ W[12]], 0);
        ctx->S[1][i] =
          mds_mul(S0[S0[S1[S1[S0[i] ^ W[1]] ^ W[5]] ^ W[9]] ^ W[13]], 1);
        ctx->S[2][i] =
          mds_mul(S1[S1[S0[S0[S0[i] ^ W[2]] ^ W[6]] ^ W[10]] ^ W[14]], 2);
        ctx->S[3][i] =
          mds_mul(S0[S1[S1[S0[S1[i] ^ W[3]] ^ W[7]] ^ W[11]] ^ W[15]], 3);
      }
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

void
twofish_encrypt(const twofish_t *ctx,
                unsigned char *dst,
                const unsigned char *src) {
  const uint32_t *Z0 = ctx->S[0];
  const uint32_t *Z1 = ctx->S[1];
  const uint32_t *Z2 = ctx->S[2];
  const uint32_t *Z3 = ctx->S[3];
  uint32_t ia = read32le(src +  0);
  uint32_t ib = read32le(src +  4);
  uint32_t ic = read32le(src +  8);
  uint32_t id = read32le(src + 12);
  uint32_t t1, t2, ta, tb, tc, td;
  const uint32_t *k;
  int i;

  /* Pre-whitening. */
  ia ^= ctx->k[0];
  ib ^= ctx->k[1];
  ic ^= ctx->k[2];
  id ^= ctx->k[3];

  for (i = 0; i < 8; i++) {
    k = &ctx->k[8 + i * 4];

    t2 = Z1[(ib >>  0) & 0xff]
       ^ Z2[(ib >>  8) & 0xff]
       ^ Z3[(ib >> 16) & 0xff]
       ^ Z0[(ib >> 24) & 0xff];

    t1 = Z0[(ia >>  0) & 0xff]
       ^ Z1[(ia >>  8) & 0xff]
       ^ Z2[(ia >> 16) & 0xff]
       ^ Z3[(ia >> 24) & 0xff];

    t1 += t2;

    ic = ror32(ic ^ (t1 + k[0]), 1);
    id = rol32(id, 1) ^ (t2 + t1 + k[1]);

    t2 = Z1[(id >>  0) & 0xff]
       ^ Z2[(id >>  8) & 0xff]
       ^ Z3[(id >> 16) & 0xff]
       ^ Z0[(id >> 24) & 0xff];

    t1 = Z0[(ic >>  0) & 0xff]
       ^ Z1[(ic >>  8) & 0xff]
       ^ Z2[(ic >> 16) & 0xff]
       ^ Z3[(ic >> 24) & 0xff];

    t1 += t2;

    ia = ror32(ia ^ (t1 + k[2]), 1);
    ib = rol32(ib, 1) ^ (t2 + t1 + k[3]);
  }

  /* Output with "undo last swap". */
  ta = ic ^ ctx->k[4];
  tb = id ^ ctx->k[5];
  tc = ia ^ ctx->k[6];
  td = ib ^ ctx->k[7];

  write32le(dst +  0, ta);
  write32le(dst +  4, tb);
  write32le(dst +  8, tc);
  write32le(dst + 12, td);
}

void
twofish_decrypt(const twofish_t *ctx,
                unsigned char *dst,
                const unsigned char *src) {
  const uint32_t *Z0 = ctx->S[0];
  const uint32_t *Z1 = ctx->S[1];
  const uint32_t *Z2 = ctx->S[2];
  const uint32_t *Z3 = ctx->S[3];
  uint32_t ta = read32le(src +  0);
  uint32_t tb = read32le(src +  4);
  uint32_t tc = read32le(src +  8);
  uint32_t td = read32le(src + 12);
  uint32_t t1, t2, ia, ib, ic, id;
  const uint32_t *k;
  int i;

  /* Undo undo final swap. */
  ia = tc ^ ctx->k[6];
  ib = td ^ ctx->k[7];
  ic = ta ^ ctx->k[4];
  id = tb ^ ctx->k[5];

  for (i = 8; i > 0; i--) {
    k = &ctx->k[4 + i * 4];

    t2 = Z1[(id >>  0) & 0xff]
       ^ Z2[(id >>  8) & 0xff]
       ^ Z3[(id >> 16) & 0xff]
       ^ Z0[(id >> 24) & 0xff];

    t1 = Z0[(ic >>  0) & 0xff]
       ^ Z1[(ic >>  8) & 0xff]
       ^ Z2[(ic >> 16) & 0xff]
       ^ Z3[(ic >> 24) & 0xff];

    t1 += t2;

    ia = rol32(ia, 1) ^ (t1 + k[2]);
    ib = ror32(ib ^ (t2 + t1 + k[3]), 1);

    t2 = Z1[(ib >>  0) & 0xff]
       ^ Z2[(ib >>  8) & 0xff]
       ^ Z3[(ib >> 16) & 0xff]
       ^ Z0[(ib >> 24) & 0xff];

    t1 = Z0[(ia >>  0) & 0xff]
       ^ Z1[(ia >>  8) & 0xff]
       ^ Z2[(ia >> 16) & 0xff]
       ^ Z3[(ia >> 24) & 0xff];

    t1 += t2;

    ic = rol32(ic, 1) ^ (t1 + k[0]);
    id = ror32(id ^ (t2 + t1 + k[1]), 1);
  }

  /* Undo pre-whitening. */
  ia ^= ctx->k[0];
  ib ^= ctx->k[1];
  ic ^= ctx->k[2];
  id ^= ctx->k[3];

  write32le(dst +  0, ia);
  write32le(dst +  4, ib);
  write32le(dst +  8, ic);
  write32le(dst + 12, id);
}

#undef RS
#undef S0
#undef S1
#undef gf_mul
#undef mds_mul
#undef h_gen
#undef rol32
#undef ror32

/*
 * PKCS7
 */

void
pkcs7_pad(unsigned char *dst,
          const unsigned char *src,
          size_t len,
          size_t size) {
  size_t left = size - len;
  size_t i;

  CHECK(len <= size);

  for (i = 0; i < len; i++)
    dst[i] = src[i];

  while (i < size)
    dst[i++] = left;
}

int
pkcs7_unpad(unsigned char *dst,
            size_t *len,
            const unsigned char *src,
            size_t size) {
  uint32_t bsize = size;
  uint32_t left = src[bsize - 1];
  uint32_t res = 1;
  uint32_t i, end, ch;

  /* left != 0 */
  res &= ((left - 1) >> 31) ^ 1;

  /* left <= bsize */
  res &= (left - bsize - 1) >> 31;

  /* left = 0 if left == 0 or left > bsize */
  left &= -res;

  /* Verify padding in constant time. */
  end = bsize - left;

  for (i = 0; i < bsize; i++) {
    ch = src[i];
    /* i < end or ch == left */
    res &= ((i - end) >> 31) | (((ch ^ left) - 1) >> 31);
  }

  for (i = 0; i < size; i++)
    dst[i] = src[i];

  *len = end & -res;

  return res;
}

/*
 * Cipher
 */

size_t
cipher_key_size(cipher_id_t type) {
  switch (type) {
    case CIPHER_AES128:
      return 16;
    case CIPHER_AES192:
      return 24;
    case CIPHER_AES256:
      return 32;
    case CIPHER_ARC2:
      return 8;
    case CIPHER_ARC2_GUTMANN:
      return 8;
    case CIPHER_ARC2_40:
      return 5;
    case CIPHER_ARC2_64:
      return 8;
    case CIPHER_ARC2_128:
      return 16;
    case CIPHER_ARC2_128_GUTMANN:
      return 16;
    case CIPHER_BLOWFISH:
      return 16;
    case CIPHER_CAMELLIA128:
      return 16;
    case CIPHER_CAMELLIA192:
      return 24;
    case CIPHER_CAMELLIA256:
      return 32;
    case CIPHER_CAST5:
      return 16;
    case CIPHER_DES:
      return 8;
    case CIPHER_DES_EDE:
      return 16;
    case CIPHER_DES_EDE3:
      return 24;
    case CIPHER_IDEA:
      return 16;
    case CIPHER_SERPENT128:
      return 16;
    case CIPHER_SERPENT192:
      return 24;
    case CIPHER_SERPENT256:
      return 32;
    case CIPHER_TWOFISH128:
      return 16;
    case CIPHER_TWOFISH192:
      return 24;
    case CIPHER_TWOFISH256:
      return 32;
    default:
      return 0;
  }
}

size_t
cipher_block_size(cipher_id_t type) {
  switch (type) {
    case CIPHER_AES128:
      return 16;
    case CIPHER_AES192:
      return 16;
    case CIPHER_AES256:
      return 16;
    case CIPHER_ARC2:
      return 8;
    case CIPHER_ARC2_GUTMANN:
      return 8;
    case CIPHER_ARC2_40:
      return 8;
    case CIPHER_ARC2_64:
      return 8;
    case CIPHER_ARC2_128:
      return 8;
    case CIPHER_ARC2_128_GUTMANN:
      return 8;
    case CIPHER_BLOWFISH:
      return 8;
    case CIPHER_CAMELLIA128:
      return 16;
    case CIPHER_CAMELLIA192:
      return 16;
    case CIPHER_CAMELLIA256:
      return 16;
    case CIPHER_CAST5:
      return 8;
    case CIPHER_DES:
      return 8;
    case CIPHER_DES_EDE:
      return 8;
    case CIPHER_DES_EDE3:
      return 8;
    case CIPHER_IDEA:
      return 8;
    case CIPHER_SERPENT128:
      return 16;
    case CIPHER_SERPENT192:
      return 16;
    case CIPHER_SERPENT256:
      return 16;
    case CIPHER_TWOFISH128:
      return 16;
    case CIPHER_TWOFISH192:
      return 16;
    case CIPHER_TWOFISH256:
      return 16;
    default:
      return 0;
  }
}

int
cipher_init(cipher_t *ctx,
            cipher_id_t type,
            const unsigned char *key,
            size_t key_len) {
  ctx->type = type;
  ctx->size = cipher_block_size(type);

  switch (type) {
    case CIPHER_AES128: {
      if (key_len != 16)
        goto fail;

      aes_init(&ctx->ctx.aes, 128, key);

      break;
    }

    case CIPHER_AES192: {
      if (key_len != 24)
        goto fail;

      aes_init(&ctx->ctx.aes, 192, key);

      break;
    }

    case CIPHER_AES256: {
      if (key_len != 32)
        goto fail;

      aes_init(&ctx->ctx.aes, 256, key);

      break;
    }

    case CIPHER_ARC2: {
      if (key_len < 1 || key_len > 128)
        goto fail;

      arc2_init(&ctx->ctx.arc2, key, key_len, key_len * 8);

      break;
    }

    case CIPHER_ARC2_GUTMANN: {
      if (key_len < 1 || key_len > 128)
        goto fail;

      arc2_init(&ctx->ctx.arc2, key, key_len, 0);

      break;
    }

    case CIPHER_ARC2_40: {
      if (key_len != 5)
        goto fail;

      arc2_init(&ctx->ctx.arc2, key, key_len, 40);

      break;
    }

    case CIPHER_ARC2_64: {
      if (key_len != 8)
        goto fail;

      arc2_init(&ctx->ctx.arc2, key, key_len, 64);

      break;
    }

    case CIPHER_ARC2_128: {
      if (key_len != 16)
        goto fail;

      arc2_init(&ctx->ctx.arc2, key, key_len, 128);

      break;
    }

    case CIPHER_ARC2_128_GUTMANN: {
      if (key_len != 16)
        goto fail;

      arc2_init(&ctx->ctx.arc2, key, key_len, 1024);

      break;
    }

    case CIPHER_BLOWFISH: {
      if (key_len < 1 || key_len > 72)
        goto fail;

      blowfish_init(&ctx->ctx.blowfish, key, key_len, NULL, 0);

      break;
    }

    case CIPHER_CAMELLIA128: {
      if (key_len != 16)
        goto fail;

      camellia_init(&ctx->ctx.camellia, 128, key);

      break;
    }

    case CIPHER_CAMELLIA192: {
      if (key_len != 24)
        goto fail;

      camellia_init(&ctx->ctx.camellia, 192, key);

      break;
    }

    case CIPHER_CAMELLIA256: {
      if (key_len != 32)
        goto fail;

      camellia_init(&ctx->ctx.camellia, 256, key);

      break;
    }

    case CIPHER_CAST5: {
      if (key_len != 16)
        goto fail;

      cast5_init(&ctx->ctx.cast5, key);

      break;
    }

    case CIPHER_DES: {
      if (key_len != 8)
        goto fail;

      des_init(&ctx->ctx.des, key);

      break;
    }

    case CIPHER_DES_EDE: {
      if (key_len != 16)
        goto fail;

      des_ede_init(&ctx->ctx.ede, key);

      break;
    }

    case CIPHER_DES_EDE3: {
      if (key_len != 24)
        goto fail;

      des_ede3_init(&ctx->ctx.ede3, key);

      break;
    }

    case CIPHER_IDEA: {
      if (key_len != 16)
        goto fail;

      idea_init(&ctx->ctx.idea, key);

      break;
    }

    case CIPHER_SERPENT128: {
      if (key_len != 16)
        goto fail;

      serpent_init(&ctx->ctx.serpent, 128, key);

      break;
    }

    case CIPHER_SERPENT192: {
      if (key_len != 24)
        goto fail;

      serpent_init(&ctx->ctx.serpent, 192, key);

      break;
    }

    case CIPHER_SERPENT256: {
      if (key_len != 32)
        goto fail;

      serpent_init(&ctx->ctx.serpent, 256, key);

      break;
    }

    case CIPHER_TWOFISH128: {
      if (key_len != 16)
        goto fail;

      twofish_init(&ctx->ctx.twofish, 128, key);

      break;
    }

    case CIPHER_TWOFISH192: {
      if (key_len != 24)
        goto fail;

      twofish_init(&ctx->ctx.twofish, 192, key);

      break;
    }

    case CIPHER_TWOFISH256: {
      if (key_len != 32)
        goto fail;

      twofish_init(&ctx->ctx.twofish, 256, key);

      break;
    }

    default: {
      goto fail;
    }
  }

  return 1;
fail:
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}

void
cipher_encrypt(const cipher_t *ctx,
               unsigned char *dst,
               const unsigned char *src) {
  switch (ctx->type) {
    case CIPHER_AES128:
    case CIPHER_AES192:
    case CIPHER_AES256:
      aes_encrypt(&ctx->ctx.aes, dst, src);
      break;
    case CIPHER_ARC2:
    case CIPHER_ARC2_GUTMANN:
    case CIPHER_ARC2_40:
    case CIPHER_ARC2_64:
    case CIPHER_ARC2_128:
    case CIPHER_ARC2_128_GUTMANN:
      arc2_encrypt(&ctx->ctx.arc2, dst, src);
      break;
    case CIPHER_BLOWFISH:
      blowfish_encrypt(&ctx->ctx.blowfish, dst, src);
      break;
    case CIPHER_CAMELLIA128:
    case CIPHER_CAMELLIA192:
    case CIPHER_CAMELLIA256:
      camellia_encrypt(&ctx->ctx.camellia, dst, src);
      break;
    case CIPHER_CAST5:
      cast5_encrypt(&ctx->ctx.cast5, dst, src);
      break;
    case CIPHER_DES:
      des_encrypt(&ctx->ctx.des, dst, src);
      break;
    case CIPHER_DES_EDE:
      des_ede_encrypt(&ctx->ctx.ede, dst, src);
      break;
    case CIPHER_DES_EDE3:
      des_ede3_encrypt(&ctx->ctx.ede3, dst, src);
      break;
    case CIPHER_IDEA:
      idea_encrypt(&ctx->ctx.idea, dst, src);
      break;
    case CIPHER_SERPENT128:
    case CIPHER_SERPENT192:
    case CIPHER_SERPENT256:
      serpent_encrypt(&ctx->ctx.serpent, dst, src);
      break;
    case CIPHER_TWOFISH128:
    case CIPHER_TWOFISH192:
    case CIPHER_TWOFISH256:
      twofish_encrypt(&ctx->ctx.twofish, dst, src);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

void
cipher_decrypt(const cipher_t *ctx,
               unsigned char *dst,
               const unsigned char *src) {
  switch (ctx->type) {
    case CIPHER_AES128:
    case CIPHER_AES192:
    case CIPHER_AES256:
      aes_decrypt(&ctx->ctx.aes, dst, src);
      break;
    case CIPHER_ARC2:
    case CIPHER_ARC2_GUTMANN:
    case CIPHER_ARC2_40:
    case CIPHER_ARC2_64:
    case CIPHER_ARC2_128:
    case CIPHER_ARC2_128_GUTMANN:
      arc2_decrypt(&ctx->ctx.arc2, dst, src);
      break;
    case CIPHER_BLOWFISH:
      blowfish_decrypt(&ctx->ctx.blowfish, dst, src);
      break;
    case CIPHER_CAMELLIA128:
    case CIPHER_CAMELLIA192:
    case CIPHER_CAMELLIA256:
      camellia_decrypt(&ctx->ctx.camellia, dst, src);
      break;
    case CIPHER_CAST5:
      cast5_decrypt(&ctx->ctx.cast5, dst, src);
      break;
    case CIPHER_DES:
      des_decrypt(&ctx->ctx.des, dst, src);
      break;
    case CIPHER_DES_EDE:
      des_ede_decrypt(&ctx->ctx.ede, dst, src);
      break;
    case CIPHER_DES_EDE3:
      des_ede3_decrypt(&ctx->ctx.ede3, dst, src);
      break;
    case CIPHER_IDEA:
      idea_decrypt(&ctx->ctx.idea, dst, src);
      break;
    case CIPHER_SERPENT128:
    case CIPHER_SERPENT192:
    case CIPHER_SERPENT256:
      serpent_decrypt(&ctx->ctx.serpent, dst, src);
      break;
    case CIPHER_TWOFISH128:
    case CIPHER_TWOFISH192:
    case CIPHER_TWOFISH256:
      twofish_decrypt(&ctx->ctx.twofish, dst, src);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

/*
 * ECB
 */

void
ecb_encrypt(const cipher_t *cipher, unsigned char *dst,
            const unsigned char *src, size_t len) {
  CHECK((len & (cipher->size - 1)) == 0);

  while (len > 0) {
    cipher_encrypt(cipher, dst, src);

    dst += cipher->size;
    src += cipher->size;
    len -= cipher->size;
  }
}

void
ecb_decrypt(const cipher_t *cipher, unsigned char *dst,
            const unsigned char *src, size_t len) {
  CHECK((len & (cipher->size - 1)) == 0);

  while (len > 0) {
    cipher_decrypt(cipher, dst, src);

    dst += cipher->size;
    src += cipher->size;
    len -= cipher->size;
  }
}

void
ecb_steal(const cipher_t *cipher,
          unsigned char *last, /* last ciphertext */
          unsigned char *block, /* partial block */
          size_t len) {
  unsigned char tmp;
  size_t i;

  CHECK(len < cipher->size);

  for (i = 0; i < len; i++) {
    tmp = block[i];
    block[i] = last[i];
    last[i] = tmp;
  }

  cipher_encrypt(cipher, last, last);
}

void
ecb_unsteal(const cipher_t *cipher,
            unsigned char *last, /* last plaintext */
            unsigned char *block, /* partial block */
            size_t len) {
  unsigned char tmp;
  size_t i;

  CHECK(len < cipher->size);

  for (i = 0; i < len; i++) {
    tmp = block[i];
    block[i] = last[i];
    last[i] = tmp;
  }

  cipher_decrypt(cipher, last, last);
}

/*
 * CBC
 */

void
cbc_init(cbc_t *mode, const cipher_t *cipher, const unsigned char *iv) {
  memcpy(mode->prev, iv, cipher->size);
}

void
cbc_encrypt(cbc_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  size_t i;

  CHECK((len & (cipher->size - 1)) == 0);

  while (len > 0) {
    for (i = 0; i < cipher->size; i++)
      mode->prev[i] ^= src[i];

    cipher_encrypt(cipher, dst, mode->prev);

    memcpy(mode->prev, dst, cipher->size);

    dst += cipher->size;
    src += cipher->size;
    len -= cipher->size;
  }
}

void
cbc_decrypt(cbc_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  size_t i;

  if (dst == src) {
    unsigned char tmp[CIPHER_MAX_BLOCK_SIZE];

    CHECK((len & (cipher->size - 1)) == 0);

    while (len > 0) {
      cipher_decrypt(cipher, tmp, src);

      for (i = 0; i < cipher->size; i++)
        tmp[i] ^= mode->prev[i];

      memcpy(mode->prev, src, cipher->size);
      memcpy(dst, tmp, cipher->size);

      dst += cipher->size;
      src += cipher->size;
      len -= cipher->size;
    }

    torsion_memzero(tmp, cipher->size);
  } else if (len > 0) {
    ecb_decrypt(cipher, dst, src, len);

    for (i = 0; i < cipher->size; i++)
      dst[i] ^= mode->prev[i];

    dst += cipher->size;
    len -= cipher->size;

    for (i = 0; i < len; i++)
      dst[i] ^= src[i];

    memcpy(mode->prev, src + len, cipher->size);
  }
}

void
cbc_steal(cbc_t *mode,
          const cipher_t *cipher,
          unsigned char *last, /* last ciphertext */
          unsigned char *block, /* partial block */
          size_t len) {
  size_t i;

  CHECK(len < cipher->size);

  for (i = 0; i < len; i++)
    mode->prev[i] ^= block[i];

  cipher_encrypt(cipher, mode->prev, mode->prev);

  memcpy(block, last, len);
  memcpy(last, mode->prev, cipher->size);
}

void
cbc_unsteal(cbc_t *mode,
            const cipher_t *cipher,
            unsigned char *last, /* last plaintext */
            unsigned char *block, /* partial block */
            size_t len) {
  unsigned char tmp[CIPHER_MAX_BLOCK_SIZE];
  size_t i;

  CHECK(len < cipher->size);

  cipher_decrypt(cipher, mode->prev, mode->prev);

  /* Recreate the previous (x2) ciphertext. */
  for (i = 0; i < cipher->size; i++)
    tmp[i] = last[i] ^ mode->prev[i];

  for (i = 0; i < len; i++) {
    last[i] = block[i];
    block[i] ^= mode->prev[i];
  }

  for (i = len; i < cipher->size; i++)
    last[i] = mode->prev[i];

  cipher_decrypt(cipher, last, last);

  for (i = 0; i < cipher->size; i++)
    last[i] ^= tmp[i];

  torsion_memzero(tmp, cipher->size);
}

/*
 * XTS
 */

void
xts_init(xts_t *mode, const cipher_t *cipher, const unsigned char *iv) {
  memcpy(mode->tweak, iv, cipher->size);
  memset(mode->prev, 0, cipher->size);
}

int
xts_setup(xts_t *mode, const cipher_t *cipher,
          const unsigned char *key, size_t key_len) {
  cipher_t c;

  if (!cipher_init(&c, cipher->type, key, key_len))
    return 0;

  cipher_encrypt(&c, mode->tweak, mode->tweak);

  torsion_memzero(&c, sizeof(c));

  return 1;
}

static void
xts_shift(uint8_t *dst, const uint8_t *src, size_t size) {
  /* Little-endian doubling. */
  uint32_t poly = poly_table[size >> 4];
  uint8_t c = src[size - 1] >> 7;
  size_t i;

  for (i = size - 1; i >= 1; i--)
    dst[i] = (src[i] << 1) | (src[i - 1] >> 7);

  dst[0] = src[0] << 1;

  dst[2] ^= (uint8_t)(poly >> 16) & -c;
  dst[1] ^= (uint8_t)(poly >>  8) & -c;
  dst[0] ^= (uint8_t)(poly >>  0) & -c;
}

void
xts_encrypt(xts_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  size_t i;

  CHECK((len & (cipher->size - 1)) == 0);

  while (len > 0) {
    for (i = 0; i < cipher->size; i++)
      dst[i] = src[i] ^ mode->tweak[i];

    cipher_encrypt(cipher, dst, dst);

    for (i = 0; i < cipher->size; i++)
      dst[i] ^= mode->tweak[i];

    xts_shift(mode->tweak, mode->tweak, cipher->size);

    dst += cipher->size;
    src += cipher->size;
    len -= cipher->size;
  }
}

void
xts_decrypt(xts_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  size_t i;

  CHECK((len & (cipher->size - 1)) == 0);

  while (len > 0) {
    if (len == cipher->size)
      memcpy(mode->prev, mode->tweak, cipher->size);

    for (i = 0; i < cipher->size; i++)
      dst[i] = src[i] ^ mode->tweak[i];

    cipher_decrypt(cipher, dst, dst);

    for (i = 0; i < cipher->size; i++)
      dst[i] ^= mode->tweak[i];

    xts_shift(mode->tweak, mode->tweak, cipher->size);

    dst += cipher->size;
    src += cipher->size;
    len -= cipher->size;
  }
}

void
xts_steal(xts_t *mode,
          const cipher_t *cipher,
          unsigned char *last, /* last ciphertext */
          unsigned char *block, /* partial block */
          size_t len) {
  unsigned char tmp;
  size_t i;

  if (len == 0)
    return;

  CHECK(len < cipher->size);

  for (i = 0; i < len; i++) {
    tmp = block[i];
    block[i] = last[i];
    last[i] = tmp;
  }

  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->tweak[i];

  cipher_encrypt(cipher, last, last);

  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->tweak[i];
}

void
xts_unsteal(xts_t *mode,
            const cipher_t *cipher,
            unsigned char *last, /* last plaintext */
            unsigned char *block, /* partial block */
            size_t len) {
  unsigned char tmp;
  size_t i;

  if (len == 0)
    return;

  CHECK(len < cipher->size);

  /* We could ask for the last ciphertext
     block, but it makes for a worse API.
     Instead, we simply re-encrypt. */
  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->prev[i];

  cipher_encrypt(cipher, last, last);

  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->prev[i];

  /* Recreate the last partial plaintext
     block (block) and the last ciphertext
     block (last). */
  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->tweak[i];

  cipher_decrypt(cipher, last, last);

  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->tweak[i];

  for (i = 0; i < len; i++) {
    tmp = block[i];
    block[i] = last[i];
    last[i] = tmp;
  }

  /* Now decrypt the last ciphertext block. */
  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->prev[i];

  cipher_decrypt(cipher, last, last);

  for (i = 0; i < cipher->size; i++)
    last[i] ^= mode->prev[i];
}

/*
 * Stream (Abstract)
 */

/* Avoid violating ISO C section 7.1.3. */
#define stream_f xstream_f
#define stream_update xstream_update

typedef void stream_f(stream_mode_t *mode, const cipher_t *cipher);
typedef void xor_f(stream_mode_t *mode, size_t pos, unsigned char *dst,
                   const unsigned char *src, size_t len);

static TORSION_INLINE void
stream_update(stream_mode_t *mode,
              const cipher_t *cipher,
              stream_f *stream,
              xor_f *permute,
              unsigned char *dst,
              const unsigned char *src,
              size_t len) {
  size_t size = cipher->size;
  size_t pos = mode->pos;
  size_t want = size - pos;

  if (len >= want) {
    if (pos > 0) {
      permute(mode, pos, dst, src, want);

      dst += want;
      src += want;
      len -= want;
      pos = 0;
    }

    while (len >= size) {
      stream(mode, cipher);

      permute(mode, 0, dst, src, size);

      dst += size;
      src += size;
      len -= size;
    }
  }

  if (len > 0) {
    if (pos == 0)
      stream(mode, cipher);

    permute(mode, pos, dst, src, len);

    pos += len;
  }

  mode->pos = pos;
}

/*
 * CTR
 */

void
ctr_init(ctr_t *mode, const cipher_t *cipher, const unsigned char *iv) {
  memcpy(mode->iv, iv, cipher->size);
  /* Defensive memset. */
  memset(mode->state, 0, cipher->size);
  mode->pos = 0;
}

static void
ctr_stream(ctr_t *mode, const cipher_t *cipher) {
  cipher_encrypt(cipher, mode->state, mode->iv);
  increment_be_var(mode->iv, cipher->size);
}

static void
ctr_xor(ctr_t *mode, size_t pos, unsigned char *dst,
        const unsigned char *src, size_t len) {
  torsion_memxor3(dst, src, mode->state + pos, len);
}

void
ctr_crypt(ctr_t *mode, const cipher_t *cipher,
          unsigned char *dst, const unsigned char *src, size_t len) {
  stream_update(mode, cipher, ctr_stream, ctr_xor, dst, src, len);
}

/*
 * CFB
 */

void
cfb_init(cfb_t *mode, const cipher_t *cipher, const unsigned char *iv) {
  memcpy(mode->iv, iv, cipher->size);
  /* Defensive memset. */
  memset(mode->state, 0, cipher->size);
  mode->pos = 0;
}

static void
cfb_stream(cfb_t *mode, const cipher_t *cipher) {
  cipher_encrypt(cipher, mode->state, mode->iv);
}

static void
cfb_xor_enc(cfb_t *mode, size_t pos, unsigned char *dst,
            const unsigned char *src, size_t len) {
  torsion_memxor3(dst, src, mode->state + pos, len);
  memcpy(mode->iv + pos, dst, len);
}

static void
cfb_xor_dec(cfb_t *mode, size_t pos, unsigned char *dst,
            const unsigned char *src, size_t len) {
  memcpy(mode->iv + pos, src, len);
  torsion_memxor3(dst, src, mode->state + pos, len);
}

void
cfb_encrypt(cfb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  stream_update(mode, cipher, cfb_stream, cfb_xor_enc, dst, src, len);
}

void
cfb_decrypt(cfb_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  stream_update(mode, cipher, cfb_stream, cfb_xor_dec, dst, src, len);
}

/*
 * OFB
 */

void
ofb_init(ofb_t *mode, const cipher_t *cipher, const unsigned char *iv) {
  memcpy(mode->state, iv, cipher->size);
  mode->pos = 0;
}

static void
ofb_stream(ofb_t *mode, const cipher_t *cipher) {
  cipher_encrypt(cipher, mode->state, mode->state);
}

void
ofb_crypt(ofb_t *mode, const cipher_t *cipher,
          unsigned char *dst, const unsigned char *src, size_t len) {
  stream_update(mode, cipher, ofb_stream, ctr_xor, dst, src, len);
}

/*
 * GHASH
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Galois/Counter_Mode
 *   https://dx.doi.org/10.6028/NIST.SP.800-38D
 *   https://github.com/golang/go/blob/master/src/crypto/cipher/gcm.go
 *   https://github.com/golang/go/blob/master/src/crypto/cipher/gcm_test.go
 *   https://github.com/DaGenix/rust-crypto/blob/master/src/ghash.rs
 */

typedef struct ghash_s ghash_t;
typedef struct ghash_fe_s gfe_t;

static const uint16_t ghash_reduction[16] = {
  0x0000, 0x1c20, 0x3840, 0x2460,
  0x7080, 0x6ca0, 0x48c0, 0x54e0,
  0xe100, 0xfd20, 0xd940, 0xc560,
  0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

static unsigned int
revbits(unsigned int x) {
  x = ((x << 2) & 0x0c) | ((x >> 2) & 0x03);
  x = ((x << 1) & 0x0a) | ((x >> 1) & 0x05);
  return x;
}

static void
gfe_add(gfe_t *z, const gfe_t *x, const gfe_t *y) {
  z->lo = x->lo ^ y->lo;
  z->hi = x->hi ^ y->hi;
}

static void
gfe_dbl(gfe_t *z, const gfe_t *x) {
  uint64_t msb = x->hi & 1;

  z->hi = x->hi >> 1;
  z->hi |= x->lo << 63;
  z->lo = x->lo >> 1;
  z->lo ^= UINT64_C(0xe100000000000000) & -msb;
}

static void
gfe_mul(gfe_t *z, const gfe_t *x, const gfe_t *table) {
  uint64_t word, msw;
  uint64_t lo = 0;
  uint64_t hi = 0;
  const gfe_t *t;
  int i, j;

  for (i = 0; i < 2; i++) {
    word = x->hi;

    if (i == 1)
      word = x->lo;

    for (j = 0; j < 64; j += 4) {
      msw = hi & 0x0f;

      hi >>= 4;
      hi |= lo << 60;
      lo >>= 4;
      lo ^= (uint64_t)ghash_reduction[msw] << 48;

      t = &table[word & 0x0f];

      lo ^= t->lo;
      hi ^= t->hi;

      word >>= 4;
    }
  }

  z->lo = lo;
  z->hi = hi;
}

static void
ghash_transform(ghash_t *ctx, const unsigned char *block) {
  ctx->state.lo ^= read64be(block + 0);
  ctx->state.hi ^= read64be(block + 8);

  gfe_mul(&ctx->state, &ctx->state, ctx->table);
}

static void
ghash_absorb(ghash_t *ctx, const unsigned char *data, size_t len) {
  const unsigned char *raw = data;
  size_t pos = ctx->pos;
  size_t want = 16 - pos;

  if (len >= want) {
    if (pos > 0) {
      memcpy(ctx->block + pos, raw, want);

      raw += want;
      len -= want;
      pos = 0;

      ghash_transform(ctx, ctx->block);
    }

    while (len >= 16) {
      ghash_transform(ctx, raw);
      raw += 16;
      len -= 16;
    }
  }

  if (len > 0) {
    memcpy(ctx->block + pos, raw, len);
    pos += len;
  }

  ctx->pos = pos;
}

static void
ghash_pad(ghash_t *ctx) {
  if (ctx->pos > 0) {
    while (ctx->pos < 16)
      ctx->block[ctx->pos++] = 0;

    ghash_transform(ctx, ctx->block);

    ctx->pos = 0;
  }
}

static void
ghash_init(ghash_t *ctx, const unsigned char *key) {
  gfe_t x;
  int i;

  /* Zero for struct assignment. */
  memset(&x, 0, sizeof(x));

  ctx->state = x;
  ctx->table[0] = x;

  x.lo = read64be(key + 0);
  x.hi = read64be(key + 8);

  ctx->table[revbits(1)] = x;

  for (i = 2; i < 16; i += 2) {
    gfe_dbl(&ctx->table[revbits(i + 0)], &ctx->table[revbits(i / 2)]);
    gfe_add(&ctx->table[revbits(i + 1)], &ctx->table[revbits(i)], &x);
  }

  /* Defensive memset. */
  memset(ctx->block, 0, 16);

  ctx->adlen = 0;
  ctx->ctlen = 0;
  ctx->pos = 0;
}

static void
ghash_aad(ghash_t *ctx, const unsigned char *data, size_t len) {
  ctx->adlen += len;
  ghash_absorb(ctx, data, len);
}

static void
ghash_update(ghash_t *ctx, const unsigned char *data, size_t len) {
  if (ctx->ctlen == 0)
    ghash_pad(ctx);

  ctx->ctlen += len;

  ghash_absorb(ctx, data, len);
}

static void
ghash_final(ghash_t *ctx, unsigned char *out) {
  ghash_pad(ctx);

  ctx->state.lo ^= ctx->adlen << 3;
  ctx->state.hi ^= ctx->ctlen << 3;

  gfe_mul(&ctx->state, &ctx->state, ctx->table);

  write64be(out + 0, ctx->state.lo);
  write64be(out + 8, ctx->state.hi);
}

/*
 * GCM
 */

static void
gcm_stream(ctr_t *ctr, const cipher_t *cipher) {
  cipher_encrypt(cipher, ctr->state, ctr->iv);
  increment_be(ctr->iv + 12, 4);
}

static void
gcm_crypt(gcm_t *mode,
          const cipher_t *cipher,
          unsigned char *dst,
          const unsigned char *src,
          size_t len) {
  stream_update(&mode->ctr, cipher, gcm_stream, ctr_xor, dst, src, len);
}

int
gcm_init(gcm_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len) {
  static const unsigned char initial[4] = {0, 0, 0, 1};
  static const unsigned char zero16[16] = {0};
  ctr_t *ctr = &mode->ctr;
  unsigned char key[16];

  if (cipher->size != 16) {
    memset(mode, 0, sizeof(*mode));
    return 0;
  }

  /* Defensive memset. */
  memset(ctr->state, 0, 16);
  memset(ctr->iv, 0, 16);

  ctr->pos = 0;

  gcm_crypt(mode, cipher, key, zero16, 16);

  if (iv_len == 12) {
    memcpy(ctr->iv, iv, 12);
    memcpy(ctr->iv + 12, initial, 4);
  } else {
    ghash_init(&mode->hash, key);
    ghash_update(&mode->hash, iv, iv_len);
    ghash_final(&mode->hash, ctr->iv);
  }

  ghash_init(&mode->hash, key);
  gcm_crypt(mode, cipher, mode->mask, zero16, 16);

  return 1;
}

void
gcm_aad(gcm_t *mode, const unsigned char *aad, size_t len) {
  ghash_aad(&mode->hash, aad, len);
}

void
gcm_encrypt(gcm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  gcm_crypt(mode, cipher, dst, src, len);
  ghash_update(&mode->hash, dst, len);
}

void
gcm_decrypt(gcm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  ghash_update(&mode->hash, src, len);
  gcm_crypt(mode, cipher, dst, src, len);
}

void
gcm_digest(gcm_t *mode, unsigned char *mac) {
  int i;

  ghash_final(&mode->hash, mac);

  for (i = 0; i < 16; i++)
    mac[i] ^= mode->mask[i];
}

/*
 * CBC-MAC
 */

typedef struct cmac_s cbcmac_t;

static void
cbcmac_init(cbcmac_t *ctx, const cipher_t *cipher) {
  memset(ctx->mac, 0, cipher->size);
  ctx->pos = 0;
}

static void
cbcmac_update(cbcmac_t *ctx, const cipher_t *cipher,
              const unsigned char *data, size_t len) {
  const unsigned char *raw = data;
  size_t pos = ctx->pos;
  size_t want = cipher->size - pos;

  if (len >= want) {
    if (pos > 0) {
      torsion_memxor(ctx->mac + pos, raw, want);

      cipher_encrypt(cipher, ctx->mac, ctx->mac);

      raw += want;
      len -= want;
      pos = 0;
    }

    while (len >= cipher->size) {
      torsion_memxor(ctx->mac, raw, cipher->size);

      cipher_encrypt(cipher, ctx->mac, ctx->mac);

      raw += cipher->size;
      len -= cipher->size;
    }
  }

  if (len > 0) {
    torsion_memxor(ctx->mac + pos, raw, len);
    pos += len;
  }

  ctx->pos = pos;
}

static void
cbcmac_pad(cbcmac_t *ctx, const cipher_t *cipher) {
  if (ctx->pos > 0) {
    cipher_encrypt(cipher, ctx->mac, ctx->mac);
    ctx->pos = 0;
  }
}

static void
cbcmac_final(cbcmac_t *ctx, const cipher_t *cipher, unsigned char *mac) {
  cbcmac_pad(ctx, cipher);
  memcpy(mac, ctx->mac, cipher->size);
}

/*
 * CCM
 * https://tools.ietf.org/html/rfc3610
 */

int
ccm_init(ccm_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len) {
  ctr_t *ctr = &mode->ctr;

  /* CCM is specified to have a block size of 16. */
  if (cipher->size != 16)
    goto fail;

  /* sjcl _does_ have a lower limit. */
  if (iv_len < 7)
    goto fail;

  /* sjcl compat: no upper limit on l(N). */
  if (iv_len > 13)
    iv_len = 13;

  cbcmac_init(&mode->hash, cipher);

  /* Defensive memsets. */
  memset(ctr->iv, 0, 16);
  memset(ctr->state, 0, 16);

  /* Store the IV here for now. Note that
     ccm_setup _must_ be called after this. */
  memcpy(ctr->state, iv, iv_len);

  ctr->pos = iv_len;

  return 1;
fail:
  memset(mode, 0, sizeof(*mode));
  return 0;
}

static size_t
ccm_log256(size_t x) {
  size_t z = 0;

  while (x > 0) {
    x >>= 1;
    z += 1;
  }

  z = (z + 7) / 8;

  if (z < 2)
    z = 2;

  return z;
}

int
ccm_setup(ccm_t *mode, const cipher_t *cipher,
          size_t msg_len, size_t tag_len,
          const unsigned char *aad, size_t aad_len) {
  ctr_t *ctr = &mode->ctr;
  const unsigned char *iv = ctr->state;
  size_t iv_len = ctr->pos;
  unsigned char block[16];
  size_t Adata = (aad_len > 0);
  size_t lm = msg_len;
  size_t L = ccm_log256(lm);
  size_t N = 15 - L;
  size_t M = tag_len;
  size_t i;

  /* Sanity checks (should already be initialized). */
  if (cipher->size != 16)
    return 0;

  if (iv_len < 7 || iv_len > 13)
    return 0;

  if (N < 7 || N > 13)
    return 0;

  /* Tag length restrictions. */
  if (M < 4 || M > 16 || (M & 1) != 0)
    return 0;

  /* sjcl compat: clamp nonces to 15-L. */
  if (iv_len > N)
    iv_len = N;

  /* Serialize flags. */
  block[0] = 64 * Adata + 8 * ((M - 2) / 2) + (L - 1);

  /* Serialize nonce. */
  memcpy(block + 1, iv, iv_len);

  /* Serialize message length. */
  for (i = 15; i >= 1 + iv_len; i--) {
    block[i] = lm & 0xff;
    lm >>= 8;
  }

  ASSERT(lm == 0);

  cbcmac_update(&mode->hash, cipher, block, 16);

  if (Adata) {
    unsigned char buf[10];

    if (aad_len < 0xff00) {
      /* 0 < l(a) < (2^16 - 2^8) */
      write16be(buf, aad_len);
      cbcmac_update(&mode->hash, cipher, buf, 2);
    } else if (aad_len - 1 < 0xffffffff) {
      /* (2^16 - 2^8) <= l(a) < 2^32 */
      write16be(buf + 0, 0xfffe);
      write32be(buf + 2, aad_len);
      cbcmac_update(&mode->hash, cipher, buf, 6);
    } else {
      /* 2^32 <= l(a) < 2^64 */
      write16be(buf + 0, 0xffff);
      write64be(buf + 2, aad_len);
      cbcmac_update(&mode->hash, cipher, buf, 10);
    }

    cbcmac_update(&mode->hash, cipher, aad, aad_len);
    cbcmac_pad(&mode->hash, cipher);
  }

  block[0] &= 7;
  block[15] = 1;

  for (i = 14; i >= 1 + N; i--)
    block[i] = 0;

  memcpy(ctr->iv, block, 16);

  ctr->pos = 0;

  return 1;
}

static void
ccm_crypt(ccm_t *mode, const cipher_t *cipher,
          unsigned char *dst, const unsigned char *src, size_t len) {
  ctr_crypt(&mode->ctr, cipher, dst, src, len);
}

void
ccm_encrypt(ccm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  cbcmac_update(&mode->hash, cipher, src, len);
  ccm_crypt(mode, cipher, dst, src, len);
}

void
ccm_decrypt(ccm_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  ccm_crypt(mode, cipher, dst, src, len);
  cbcmac_update(&mode->hash, cipher, dst, len);
}

void
ccm_digest(ccm_t *mode, const cipher_t *cipher, unsigned char *mac) {
  ctr_t *ctr = &mode->ctr;
  int i = 16 - ((ctr->iv[0] & 7) + 1);

  cbcmac_final(&mode->hash, cipher, mac);

  /* Recreate S_0. */
  while (i < 16)
    ctr->iv[i++] = 0;

  ctr->pos = 0;

  ccm_crypt(mode, cipher, mac, mac, 16);
}

/*
 * CMAC
 * https://tools.ietf.org/html/rfc4493
 */

typedef struct cmac_s cmac_t;

static void
cmac_init(cmac_t *ctx, const cipher_t *cipher, int flag) {
  memset(ctx->mac, 0, cipher->size);

  ctx->pos = 0;

  if (flag != -1) {
    ctx->mac[cipher->size - 1] ^= (flag & 0xff);
    ctx->pos = cipher->size;
  }
}

static void
cmac_shift(uint8_t *dst, const uint8_t *src, size_t size) {
  /* Big-endian doubling. */
  uint32_t poly = poly_table[size >> 4];
  uint8_t c = src[0] >> 7;
  size_t i;

  for (i = 0; i < size - 1; i++)
    dst[i] = (src[i] << 1) | (src[i + 1] >> 7);

  dst[size - 1] = src[size - 1] << 1;

  dst[size - 3] ^= (uint8_t)(poly >> 16) & -c;
  dst[size - 2] ^= (uint8_t)(poly >>  8) & -c;
  dst[size - 1] ^= (uint8_t)(poly >>  0) & -c;
}

static void
cmac_update(cmac_t *ctx, const cipher_t *cipher,
            const unsigned char *data, size_t len) {
  const unsigned char *raw = data;
  size_t pos = ctx->pos;
  size_t want = cipher->size - pos;

  if (len > want) {
    if (pos > 0) {
      torsion_memxor(ctx->mac + pos, raw, want);

      cipher_encrypt(cipher, ctx->mac, ctx->mac);

      raw += want;
      len -= want;
      pos = 0;
    }

    while (len > cipher->size) {
      torsion_memxor(ctx->mac, raw, cipher->size);

      cipher_encrypt(cipher, ctx->mac, ctx->mac);

      raw += cipher->size;
      len -= cipher->size;
    }
  }

  if (len > 0) {
    torsion_memxor(ctx->mac + pos, raw, len);
    pos += len;
  }

  ctx->pos = pos;
}

static void
cmac_final(cmac_t *ctx, const cipher_t *cipher, unsigned char *mac) {
  static const unsigned char zero[CIPHER_MAX_BLOCK_SIZE] = {0};
  unsigned char k[CIPHER_MAX_BLOCK_SIZE];
  size_t i;

  cipher_encrypt(cipher, k, zero);

  cmac_shift(k, k, cipher->size);

  if (ctx->pos < cipher->size) {
    ctx->mac[ctx->pos] ^= 0x80;
    cmac_shift(k, k, cipher->size);
  }

  for (i = 0; i < cipher->size; i++)
    ctx->mac[i] ^= k[i];

  cipher_encrypt(cipher, mac, ctx->mac);
}

/*
 * EAX
 */

int
eax_init(eax_t *mode, const cipher_t *cipher,
         const unsigned char *iv, size_t iv_len) {
  ctr_t *ctr = &mode->ctr;

  if (iv_len == 0) {
    memset(mode, 0, sizeof(*mode));
    return 0;
  }

  ctr->pos = 0;

  cmac_init(&mode->hash1, cipher, 0);
  cmac_update(&mode->hash1, cipher, iv, iv_len);
  cmac_final(&mode->hash1, cipher, mode->mask);

  memcpy(ctr->iv, mode->mask, cipher->size);

  /* Defensive memset. */
  memset(ctr->state, 0, cipher->size);

  cmac_init(&mode->hash1, cipher, 1);
  cmac_init(&mode->hash2, cipher, 2);

  return 1;
}

void
eax_aad(eax_t *mode, const cipher_t *cipher,
        const unsigned char *aad, size_t len) {
  cmac_update(&mode->hash1, cipher, aad, len);
}

static void
eax_stream(ctr_t *ctr, const cipher_t *cipher) {
  cipher_encrypt(cipher, ctr->state, ctr->iv);
  increment_be(ctr->iv, cipher->size);
}

static void
eax_crypt(eax_t *mode,
          const cipher_t *cipher,
          unsigned char *dst,
          const unsigned char *src,
          size_t len) {
  stream_update(&mode->ctr, cipher, eax_stream, ctr_xor, dst, src, len);
}

void
eax_encrypt(eax_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  eax_crypt(mode, cipher, dst, src, len);
  cmac_update(&mode->hash2, cipher, dst, len);
}

void
eax_decrypt(eax_t *mode, const cipher_t *cipher,
            unsigned char *dst, const unsigned char *src, size_t len) {
  cmac_update(&mode->hash2, cipher, src, len);
  eax_crypt(mode, cipher, dst, src, len);
}

void
eax_digest(eax_t *mode, const cipher_t *cipher, unsigned char *mac) {
  unsigned char mac1[CIPHER_MAX_BLOCK_SIZE];
  unsigned char mac2[CIPHER_MAX_BLOCK_SIZE];
  size_t i;

  cmac_final(&mode->hash1, cipher, mac1);
  cmac_final(&mode->hash2, cipher, mac2);

  for (i = 0; i < cipher->size; i++)
    mac[i] = mac1[i] ^ mac2[i] ^ mode->mask[i];
}

/*
 * Cipher Mode
 */

typedef struct cipher_mode_s cipher_mode_t;

static int
cipher_mode_init(cipher_mode_t *ctx, const cipher_t *cipher,
                 mode_id_t type, const unsigned char *iv, size_t iv_len) {
  ctx->type = type;

  switch (ctx->type) {
    case CIPHER_MODE_RAW:
    case CIPHER_MODE_ECB: {
      if (iv_len != 0)
        goto fail;

      return 1;
    }

    case CIPHER_MODE_CBC:
    case CIPHER_MODE_CTS: {
      if (iv_len != cipher->size)
        goto fail;

      cbc_init(&ctx->mode.block, cipher, iv);

      return 1;
    }

    case CIPHER_MODE_XTS: {
      if (iv_len != cipher->size)
        goto fail;

      xts_init(&ctx->mode.block, cipher, iv);

      return 1;
    }

    case CIPHER_MODE_CTR: {
      if (iv_len != cipher->size)
        goto fail;

      ctr_init(&ctx->mode.stream, cipher, iv);

      return 1;
    }

    case CIPHER_MODE_CFB: {
      if (iv_len != cipher->size)
        goto fail;

      cfb_init(&ctx->mode.stream, cipher, iv);

      return 1;
    }

    case CIPHER_MODE_OFB: {
      if (iv_len != cipher->size)
        goto fail;

      ofb_init(&ctx->mode.stream, cipher, iv);

      return 1;
    }

    case CIPHER_MODE_GCM: {
      return gcm_init(&ctx->mode.gcm, cipher, iv, iv_len);
    }

    case CIPHER_MODE_CCM: {
      return ccm_init(&ctx->mode.ccm, cipher, iv, iv_len);
    }

    case CIPHER_MODE_EAX: {
      return eax_init(&ctx->mode.eax, cipher, iv, iv_len);
    }
  }

fail:
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}

static int
cipher_mode_xts_setup(cipher_mode_t *ctx,
                      const cipher_t *cipher,
                      const unsigned char *key,
                      size_t key_len) {
  if (ctx->type != CIPHER_MODE_XTS)
    return 0;

  return xts_setup(&ctx->mode.block, cipher, key, key_len);
}

static int
cipher_mode_ccm_setup(cipher_mode_t *ctx,
                      const cipher_t *cipher,
                      size_t msg_len,
                      size_t tag_len,
                      const unsigned char *aad,
                      size_t aad_len) {
  if (ctx->type != CIPHER_MODE_CCM)
    return 0;

  return ccm_setup(&ctx->mode.ccm, cipher,
                   msg_len, tag_len, aad, aad_len);
}

static void
cipher_mode_aad(cipher_mode_t *ctx, const cipher_t *cipher,
                const unsigned char *aad, size_t len) {
  switch (ctx->type) {
    case CIPHER_MODE_GCM:
      gcm_aad(&ctx->mode.gcm, aad, len);
      break;
    case CIPHER_MODE_EAX:
      eax_aad(&ctx->mode.eax, cipher, aad, len);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

static void
cipher_mode_encrypt(cipher_mode_t *ctx,
                    const cipher_t *cipher,
                    unsigned char *dst,
                    const unsigned char *src,
                    size_t len) {
  switch (ctx->type) {
    case CIPHER_MODE_RAW:
    case CIPHER_MODE_ECB:
      ecb_encrypt(cipher, dst, src, len);
      break;
    case CIPHER_MODE_CBC:
    case CIPHER_MODE_CTS:
      cbc_encrypt(&ctx->mode.block, cipher, dst, src, len);
      break;
    case CIPHER_MODE_XTS:
      xts_encrypt(&ctx->mode.block, cipher, dst, src, len);
      break;
    case CIPHER_MODE_CTR:
      ctr_crypt(&ctx->mode.stream, cipher, dst, src, len);
      break;
    case CIPHER_MODE_CFB:
      cfb_encrypt(&ctx->mode.stream, cipher, dst, src, len);
      break;
    case CIPHER_MODE_OFB:
      ofb_crypt(&ctx->mode.stream, cipher, dst, src, len);
      break;
    case CIPHER_MODE_GCM:
      gcm_encrypt(&ctx->mode.gcm, cipher, dst, src, len);
      break;
    case CIPHER_MODE_CCM:
      ccm_encrypt(&ctx->mode.ccm, cipher, dst, src, len);
      break;
    case CIPHER_MODE_EAX:
      eax_encrypt(&ctx->mode.eax, cipher, dst, src, len);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

static void
cipher_mode_decrypt(cipher_mode_t *ctx,
                    const cipher_t *cipher,
                    unsigned char *dst,
                    const unsigned char *src,
                    size_t len) {
  switch (ctx->type) {
    case CIPHER_MODE_RAW:
    case CIPHER_MODE_ECB:
      ecb_decrypt(cipher, dst, src, len);
      break;
    case CIPHER_MODE_CBC:
    case CIPHER_MODE_CTS:
      cbc_decrypt(&ctx->mode.block, cipher, dst, src, len);
      break;
    case CIPHER_MODE_XTS:
      xts_decrypt(&ctx->mode.block, cipher, dst, src, len);
      break;
    case CIPHER_MODE_CTR:
      ctr_crypt(&ctx->mode.stream, cipher, dst, src, len);
      break;
    case CIPHER_MODE_CFB:
      cfb_decrypt(&ctx->mode.stream, cipher, dst, src, len);
      break;
    case CIPHER_MODE_OFB:
      ofb_crypt(&ctx->mode.stream, cipher, dst, src, len);
      break;
    case CIPHER_MODE_GCM:
      gcm_decrypt(&ctx->mode.gcm, cipher, dst, src, len);
      break;
    case CIPHER_MODE_CCM:
      ccm_decrypt(&ctx->mode.ccm, cipher, dst, src, len);
      break;
    case CIPHER_MODE_EAX:
      eax_decrypt(&ctx->mode.eax, cipher, dst, src, len);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

static void
cipher_mode_steal(cipher_mode_t *ctx,
                  const cipher_t *cipher,
                  unsigned char *last,
                  unsigned char *block,
                  size_t len) {
  switch (ctx->type) {
    case CIPHER_MODE_CTS:
      cbc_steal(&ctx->mode.block, cipher, last, block, len);
      break;
    case CIPHER_MODE_XTS:
      xts_steal(&ctx->mode.block, cipher, last, block, len);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

static void
cipher_mode_unsteal(cipher_mode_t *ctx,
                    const cipher_t *cipher,
                    unsigned char *last,
                    unsigned char *block,
                    size_t len) {
  switch (ctx->type) {
    case CIPHER_MODE_CTS:
      cbc_unsteal(&ctx->mode.block, cipher, last, block, len);
      break;
    case CIPHER_MODE_XTS:
      xts_unsteal(&ctx->mode.block, cipher, last, block, len);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

static void
cipher_mode_digest(cipher_mode_t *ctx,
                   const cipher_t *cipher,
                   unsigned char *mac) {
  switch (ctx->type) {
    case CIPHER_MODE_GCM:
      gcm_digest(&ctx->mode.gcm, mac);
      break;
    case CIPHER_MODE_CCM:
      ccm_digest(&ctx->mode.ccm, cipher, mac);
      break;
    case CIPHER_MODE_EAX:
      eax_digest(&ctx->mode.eax, cipher, mac);
      break;
    default:
      torsion_abort(); /* LCOV_EXCL_LINE */
      break;
  }
}

static int
cipher_mode_verify(cipher_mode_t *ctx,
                   const cipher_t *cipher,
                   const unsigned char *tag,
                   size_t tag_len) {
  unsigned char mac[CIPHER_MAX_TAG_SIZE];

  if (tag_len == 0 || tag_len > CIPHER_MAX_TAG_SIZE)
    return 0;

  /* Defensive memset. */
  memset(mac, 0, sizeof(mac));

  cipher_mode_digest(ctx, cipher, mac);

  return torsion_memequal(mac, tag, tag_len);
}

/*
 * Cipher Stream
 */

int
cipher_stream_init(cipher_stream_t *ctx,
                   cipher_id_t type, mode_id_t mode, int encrypt,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv, size_t iv_len) {
  int is_pad = mode == CIPHER_MODE_ECB || mode == CIPHER_MODE_CBC;
  int is_cts = mode == CIPHER_MODE_CTS || mode == CIPHER_MODE_XTS;

  ctx->encrypt = encrypt;
  ctx->padding = 1;
  ctx->unpad = (is_pad && !encrypt) || is_cts;
  ctx->block_size = cipher_block_size(type);
  ctx->block_pos = 0;
  ctx->last_size = 0;
  ctx->tag_len = 0;
  ctx->ccm_len = 0;

  /* Defensive memsets. */
  memset(ctx->block, 0, sizeof(ctx->block));
  memset(ctx->last, 0, sizeof(ctx->last));
  memset(ctx->tag, 0, sizeof(ctx->tag));

  if (mode == CIPHER_MODE_XTS) {
    if (key_len == 0 || (key_len & 1) != 0)
      goto fail;

    key_len /= 2;

    if (torsion_memequal(key, key + key_len, key_len))
      goto fail;
  }

  if (!cipher_init(&ctx->cipher, type, key, key_len))
    goto fail;

  if (!cipher_mode_init(&ctx->mode, &ctx->cipher, mode, iv, iv_len))
    goto fail;

  if (mode == CIPHER_MODE_XTS) {
    key += key_len;

    if (!cipher_mode_xts_setup(&ctx->mode, &ctx->cipher, key, key_len))
      goto fail;
  }

  return 1;
fail:
  memset(ctx, 0, sizeof(*ctx));
  return 0;
}

int
cipher_stream_set_padding(cipher_stream_t *ctx, int padding) {
  int is_pad = ctx->mode.type == CIPHER_MODE_ECB
            || ctx->mode.type == CIPHER_MODE_CBC;
  int is_cts = ctx->mode.type == CIPHER_MODE_CTS
            || ctx->mode.type == CIPHER_MODE_XTS;

  if (!is_pad && !is_cts)
    return 0;

  if (!ctx->encrypt || is_cts) {
    if (ctx->last_size != 0)
      return 0;

    if (ctx->block_pos != 0)
      return 0;
  }

  ctx->padding = !!padding;
  ctx->unpad = padding && (!ctx->encrypt || is_cts);

  return 1;
}

int
cipher_stream_set_aad(cipher_stream_t *ctx,
                      const unsigned char *aad, size_t len) {
  switch (ctx->mode.type) {
    case CIPHER_MODE_GCM:
    case CIPHER_MODE_EAX:
      cipher_mode_aad(&ctx->mode, &ctx->cipher, aad, len);
      return 1;
    default:
      return 0;
  }
}

int
cipher_stream_set_ccm(cipher_stream_t *ctx,
                      size_t msg_len,
                      size_t tag_len,
                      const unsigned char *aad,
                      size_t aad_len) {
  int r = cipher_mode_ccm_setup(&ctx->mode, &ctx->cipher,
                                msg_len, tag_len, aad, aad_len);

  if (r)
    ctx->ccm_len = tag_len;

  return r;
}

int
cipher_stream_set_tag(cipher_stream_t *ctx,
                      const unsigned char *tag, size_t len) {
  if (ctx->encrypt)
    return 0;

  switch (ctx->mode.type) {
    case CIPHER_MODE_GCM:
      if (len != 4 && len != 8 && !(len >= 12 && len <= 16))
        return 0;
      break;
    case CIPHER_MODE_CCM:
      if (ctx->ccm_len == 0 || len != ctx->ccm_len)
        return 0;
      break;
    case CIPHER_MODE_EAX:
      if (len == 0 || len > ctx->block_size)
        return 0;
      break;
    default:
      return 0;
  }

  ASSERT(len <= ctx->block_size);

  memcpy(ctx->tag, tag, len);

  ctx->tag_len = len;

  return 1;
}

int
cipher_stream_get_tag(cipher_stream_t *ctx, unsigned char *tag, size_t *len) {
  *len = 0;

  if (ctx->mode.type < CIPHER_MODE_GCM || !ctx->encrypt)
    return 0;

  if (ctx->tag_len == 0)
    return 0;

  memcpy(tag, ctx->tag, ctx->tag_len);

  *len = ctx->tag_len;

  return 1;
}

static void
cipher_stream_encipher(cipher_stream_t *ctx,
                       unsigned char *dst,
                       const unsigned char *src,
                       size_t len) {
  if (ctx->encrypt)
    cipher_mode_encrypt(&ctx->mode, &ctx->cipher, dst, src, len);
  else
    cipher_mode_decrypt(&ctx->mode, &ctx->cipher, dst, src, len);
}

void
cipher_stream_update(cipher_stream_t *ctx,
                     unsigned char *output, size_t *output_len,
                     const unsigned char *input, size_t input_len) {
  if (ctx->mode.type > CIPHER_MODE_XTS) {
    cipher_stream_encipher(ctx, output, input, input_len);
    *output_len = input_len;
    return;
  }

  *output_len = 0;

  if (ctx->block_pos + input_len < ctx->block_size) {
    if (input_len > 0)
      memcpy(ctx->block + ctx->block_pos, input, input_len);
    ctx->block_pos += input_len;
    return;
  }

  if (ctx->unpad) {
    memcpy(output, ctx->last, ctx->last_size);
    output += ctx->last_size;
    *output_len += ctx->last_size;
  }

  if (ctx->block_pos > 0) {
    size_t want = ctx->block_size - ctx->block_pos;

    memcpy(ctx->block + ctx->block_pos, input, want);

    input += want;
    input_len -= want;

    cipher_stream_encipher(ctx, output, ctx->block, ctx->block_size);

    output += ctx->block_size;
    *output_len += ctx->block_size;

    ctx->block_pos = 0;
  }

  if (input_len >= ctx->block_size) {
    size_t aligned = input_len & -ctx->block_size;

    cipher_stream_encipher(ctx, output, input, aligned);

    input += aligned;
    input_len -= aligned;

    output += aligned;
    *output_len += aligned;
  }

  if (input_len > 0) {
    memcpy(ctx->block, input, input_len);
    ctx->block_pos = input_len;
  }

  ASSERT(*output_len >= ctx->block_size);

  if (ctx->unpad) {
    memcpy(ctx->last, output - ctx->block_size, ctx->block_size);

    ctx->last_size = ctx->block_size;

    *output_len -= ctx->block_size;
  }
}

size_t
cipher_stream_update_size(const cipher_stream_t *ctx, size_t input_len) {
  size_t output_len;

  if (ctx->mode.type > CIPHER_MODE_XTS)
    return input_len;

  if (ctx->block_pos + input_len < ctx->block_size)
    return 0;

  output_len = 0;

  if (ctx->unpad)
    output_len += ctx->last_size;

  if (ctx->block_pos > 0) {
    input_len -= ctx->block_size - ctx->block_pos;
    output_len += ctx->block_size;
  }

  if (input_len >= ctx->block_size)
    output_len += input_len & -ctx->block_size;

  ASSERT(output_len >= ctx->block_size);

  return output_len;
}

int
cipher_stream_crypt(cipher_stream_t *ctx,
                    unsigned char *dst,
                    const unsigned char *src,
                    size_t len) {
  if (ctx->mode.type > CIPHER_MODE_XTS) {
    cipher_stream_encipher(ctx, dst, src, len);
    return 1;
  }

  if (ctx->unpad || ctx->block_pos != 0)
    return 0;

  if ((len & (ctx->block_size - 1)) != 0)
    return 0;

  cipher_stream_encipher(ctx, dst, src, len);

  return 1;
}

int
cipher_stream_final(cipher_stream_t *ctx,
                    unsigned char *output,
                    size_t *output_len) {
  *output_len = 0;

  switch (ctx->mode.type) {
    case CIPHER_MODE_RAW: {
      if (ctx->block_pos != 0)
        return 0;

      break;
    }

    case CIPHER_MODE_ECB:
    case CIPHER_MODE_CBC: {
      if (!ctx->padding) {
        if (ctx->block_pos != 0)
          return 0;

        return 1;
      }

      if (!ctx->encrypt) {
        if (ctx->block_pos != 0)
          return 0;

        if (ctx->last_size == 0)
          return 0;

        return pkcs7_unpad(output, output_len, ctx->last, ctx->block_size);
      }

      pkcs7_pad(output, ctx->block, ctx->block_pos, ctx->block_size);

      cipher_stream_encipher(ctx, output, output, ctx->block_size);

      *output_len = ctx->block_size;

      break;
    }

    case CIPHER_MODE_CTS:
    case CIPHER_MODE_XTS: {
      if (!ctx->padding) {
        if (ctx->block_pos != 0)
          return 0;

        return 1;
      }

      if (ctx->last_size == 0)
        return 0;

      if (ctx->encrypt) {
        cipher_mode_steal(&ctx->mode, &ctx->cipher, ctx->last,
                          ctx->block, ctx->block_pos);
      } else {
        cipher_mode_unsteal(&ctx->mode, &ctx->cipher, ctx->last,
                            ctx->block, ctx->block_pos);
      }

      memcpy(output, ctx->last, ctx->block_size);
      memcpy(output + ctx->block_size, ctx->block, ctx->block_pos);

      *output_len = ctx->block_size + ctx->block_pos;

      return 1;
    }

    case CIPHER_MODE_GCM:
    case CIPHER_MODE_EAX: {
      if (!ctx->encrypt) {
        return cipher_mode_verify(&ctx->mode, &ctx->cipher,
                                  ctx->tag, ctx->tag_len);
      }

      cipher_mode_digest(&ctx->mode, &ctx->cipher, ctx->tag);

      ctx->tag_len = ctx->block_size;

      break;
    }

    case CIPHER_MODE_CCM: {
      if (ctx->ccm_len == 0)
        return 0;

      if (!ctx->encrypt) {
        return cipher_mode_verify(&ctx->mode, &ctx->cipher,
                                  ctx->tag, ctx->tag_len);
      }

      cipher_mode_digest(&ctx->mode, &ctx->cipher, ctx->tag);

      ctx->tag_len = ctx->ccm_len;

      break;
    }

    default: {
      break;
    }
  }

  return 1;
}

size_t
cipher_stream_final_size(const cipher_stream_t *ctx) {
  switch (ctx->mode.type) {
    case CIPHER_MODE_ECB:
    case CIPHER_MODE_CBC: {
      if (!ctx->padding)
        return 0;

      return ctx->block_size;
    }

    case CIPHER_MODE_CTS:
    case CIPHER_MODE_XTS: {
      if (!ctx->padding)
        return 0;

      return ctx->block_size + ctx->block_pos;
    }

    default: {
      break;
    }
  }

  return 0;
}

/*
 * Static Encryption/Decryption
 */

static int
cipher_static_crypt(unsigned char *output,
                    size_t *output_len,
                    cipher_id_t type,
                    mode_id_t mode,
                    int encrypt,
                    const unsigned char *key,
                    size_t key_len,
                    const unsigned char *iv,
                    size_t iv_len,
                    const unsigned char *input,
                    size_t input_len) {
  cipher_stream_t ctx; /* ~5kb */
  size_t len1, len2;
  int r = 0;

  *output_len = 0;

  if (mode >= CIPHER_MODE_GCM)
    goto fail;

  if (!cipher_stream_init(&ctx, type, mode, encrypt, key, key_len, iv, iv_len))
    goto fail;

  cipher_stream_update(&ctx, output, &len1, input, input_len);

  if (!cipher_stream_final(&ctx, output + len1, &len2))
    goto fail;

  *output_len = len1 + len2;
  r = 1;
fail:
  torsion_memzero(&ctx, sizeof(ctx));
  return r;
}

int
cipher_static_encrypt(unsigned char *ct,
                      size_t *ct_len,
                      cipher_id_t type,
                      mode_id_t mode,
                      const unsigned char *key,
                      size_t key_len,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *pt,
                      size_t pt_len) {
  return cipher_static_crypt(ct, ct_len,
                             type, mode, 1,
                             key, key_len,
                             iv, iv_len,
                             pt, pt_len);
}

int
cipher_static_decrypt(unsigned char *pt,
                      size_t *pt_len,
                      cipher_id_t type,
                      mode_id_t mode,
                      const unsigned char *key,
                      size_t key_len,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *ct,
                      size_t ct_len) {
  return cipher_static_crypt(pt, pt_len,
                             type, mode, 0,
                             key, key_len,
                             iv, iv_len,
                             ct, ct_len);
}
