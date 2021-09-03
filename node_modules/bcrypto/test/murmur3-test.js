'use strict';

const assert = require('assert');
const murmur3 = require('../lib/murmur3');

const asciiVectors = [
  ['', 0, 0],
  ['', 0xfba4c795, 0x6a396f08],
  ['00', 0xfba4c795, 0x2a101837],
  ['hello world', 0, 0x5e928f0f],

  // From: https://github.com/spaolacci/murmur3/blob/master/murmur_test.go
  ['', 0x00, 0x00000000],
  ['hello', 0x00, 0x248bfa47],
  ['hello, world', 0x00, 0x149bbb7f],
  ['19 Jan 2038 at 3:14:07 AM', 0x00, 0xe31e8a70],
  ['The quick brown fox jumps over the lazy dog.', 0x00, 0xd5c48bfc],

  ['', 0x01, 0x514e28b7],
  ['hello', 0x01, 0xbb4abcad],
  ['hello, world', 0x01, 0x6f5cb2e9],
  ['19 Jan 2038 at 3:14:07 AM', 0x01, 0xf50e1f30],
  ['The quick brown fox jumps over the lazy dog.', 0x01, 0x846f6a36],

  ['', 0x2a, 0x087fcd5c],
  ['hello', 0x2a, 0xe2dbd2e1],
  ['hello, world', 0x2a, 0x7ec7c6c2],
  ['19 Jan 2038 at 3:14:07 AM', 0x2a, 0x58f745f6],
  ['The quick brown fox jumps over the lazy dog.', 0x2a, 0xc02d1434]
];

const hexVectors = [
  ['0011', 0x00000000, 0x16c6b7ab],
  ['001122', 0x00000000, 0x8eb51c3d],
  ['00112233', 0x00000000, 0xb4471bf8],
  ['0011223344', 0x00000000, 0xe2301fa8],
  ['001122334455', 0x00000000, 0xfc2e4a15],
  ['00112233445566', 0x00000000, 0xb074502c],
  ['0011223344556677', 0x00000000, 0x8034d2a0],
  ['001122334455667788', 0x00000000, 0xb4698def]
];

const tweakVectors = [
  ['', 0xf5afbb1c, 0x3bac103c, 0x75d142d3],
  ['5a', 0xcd8215c1, 0x6f381972, 0x723a6a82],
  ['1fd6', 0x3e1b1e33, 0xcdbb715d, 0x616e796a],
  ['b7b13c', 0xd3e83c4e, 0x894334d6, 0x9097817a],
  ['5fb6a79c', 0x1301f1c1, 0x8261fe1c, 0xb5b901f3],
  ['cbbe6fb48b', 0x7b98ed76, 0x19497f5b, 0xc0302c76],
  ['27529433dcfe', 0xb657be52, 0x7fc0568b, 0x4a48d5a4],
  ['430db045136914', 0x4fc10cb6, 0x045f5f16, 0x261a251b],
  ['fb0663b2ae9e3bc8', 0xee1c44a7, 0xac3e65dc, 0x95c15ad4],
  ['80bf2ed9f2b2cec461', 0x7c4cdae7, 0x7b10f7c8, 0xeb9760a2],
  ['1858f00059d60be401c7', 0x8353a45e, 0x90f37ac9, 0x6484d647],
  ['0ed1af06a147f64cf2fe4c', 0xf51033a9, 0xfe24fb84, 0x58f66baf],
  ['ab9158cc668e3ca79e2101fb', 0x451bc862, 0x65e8a012, 0x2f1c0261],
  ['27663dd49c75aa83de8983e119', 0x3cf21965, 0x79c09fa6, 0xb49f22c5],
  ['4544a5d5906aba5b54c6368ccd9a', 0x0c004937, 0x96bab024, 0x3465b78b],
  ['be5ab5d6914b29a45e554940d00981', 0xea02ecc2, 0x7d0c9bec, 0x04fb6666],
  ['a3f2dfc33688d5c2046a52e31c86fca1', 0x5511e6c1, 0x129e85fb, 0x4f9e0299],
  ['544fb7ab9232dca63effb3fa940b8fcc71', 0xfdca6830, 0x4f025dfc, 0x820dad45],
  ['da65587d60d8e23c9bf6ca1cfa791b7f257c', 0x6616f2af, 0xeee1c117, 0x0a549fee],
  ['c77a583649010e5cc7e9cbac67f1e1881ada2f', 0x2e6be78e, 0x61aa8503, 0x1bb28af7],
  ['46f91e17fa6b06e580082dbff358fa68c7967134', 0x6c9d231b, 0xc9e85da3, 0x807db650],
  ['82f89b90dd26efd5000d08480dc04dacf63bf175a0', 0x74640fe0, 0xc3b98bea, 0xa3fe488d],
  ['4397866d03221552eb1438ac51336d93cb8e64bb6229', 0xd4d8e354, 0x2076c1e5, 0xb2d54df4],
  ['a752f0f990dd8399610b7ab0781fa8d84a053d0e84b69f', 0x4bb9f36e, 0x9b6c983a, 0x1590a19d],
  ['52d0c01d25aa2f713d3f4bb05f133d1c93f3685daf720887', 0xe830113d, 0xb52d657a, 0x8125f4f0],
  ['51049f4995ed8553cfc0f86aba488966fdef07ecc649880053', 0x7925459f, 0xe44f85b0, 0xf1c94007],
  ['752d7825e09fbefabfd37268dae62a29c6c44f71712e7f78344b', 0x26f97af3, 0x53ce2e25, 0x6ff8d1fe],
  ['a1a3e023b352821cb4657fecdee9d7ae4e8f0430b8726567e688cf', 0xaab9b315, 0xcbd84415, 0x6208fe75],
  ['1930f30a6074fa7c4e81e0a3443330c1afa9a542ef868996ee43740f', 0xa36913a9, 0x6b0f5a92, 0xc4bbb716],
  ['a07e89de0e1f8d15237daf399b74dd0946c7682fb6ff56468898395d45', 0x7469035e, 0x926696dc, 0x7042d5ef],
  ['515b67cc98a646791062dd4acb30baddcd4b7c09f59e8b48f97a659dfd07', 0x47cfdac5, 0xb17593ba, 0x1940c06c],
  ['81ba13c4a402c31a986ab0729f3c0d608d6acc6faaa9f5cb4ef227d8c0f0fd', 0x6df2a4a7, 0x2acdf592, 0x78748881],
  ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 0xf5afbb1c, 0x5cd8c75e, 0x9e896781]
];

function toHex(num) {
  num = num.toString(16);

  while (num.length < 8)
    num = '0' + num;

  return num;
}

describe('Murmur3', function() {
  for (const [str, seed, sum] of asciiVectors) {
    const data = Buffer.from(str, 'binary');

    it(`should get murmur3 hash of 0x${toHex(sum)}`, () => {
      assert.strictEqual(murmur3.sum(data, seed), sum);
    });
  }

  for (const [str, seed, sum] of hexVectors) {
    const data = Buffer.from(str, 'hex');

    it(`should get murmur3 hash of 0x${toHex(sum)}`, () => {
      assert.strictEqual(murmur3.sum(data, seed), sum);
    });
  }

  for (const [str, seed, sum, tweak] of tweakVectors) {
    const data = Buffer.from(str, 'hex');

    it(`should get murmur3 hash of 0x${toHex(tweak)}`, () => {
      assert.strictEqual(murmur3.sum(data, seed), sum);
      assert.strictEqual(murmur3.tweak(data, sum, seed), tweak);
    });
  }
});
