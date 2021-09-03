'use strict';

const bench = require('./bench');
const secp256k1 = require('../lib/secp256k1');
const mul = secp256k1.native ? 10 : 1;

{
  const rounds = 1000 * mul;

  const key = Buffer.from('2576e04eda9e90aa0be40121a5b19612'
                        + '08ec8573c9bb02f75a5f69c9b63525b7', 'hex');

  const pub = secp256k1.publicKeyCreate(key, false);

  const tweak = Buffer.from('31260986ee940fa71d2c4cc7c00d4b1e'
                          + 'c2131b24f2b6243f48c2cbd3b7b82ea3', 'hex');

  const hash = Buffer.from('c9b2fd8ba02c138a9ca0ee2f481f8d0e'
                         + 'df54b6245999b67150b46c2da8ba7f36'
                         + 'fab8f7fae9e56aeecdac538a222c7810'
                         + '5df5e7c2861fd991a80b22dd81e1209a', 'hex');

  bench('secp256k1 tweak mul', rounds, () => {
    secp256k1.publicKeyTweakMul(pub, tweak);
  });

  bench('secp256k1 pubkey from hash', rounds, () => {
    secp256k1.publicKeyFromHash(hash);
  });

  bench('secp256k1 pubkey to hash', rounds, () => {
    secp256k1.publicKeyToHash(pub);
  });
}
