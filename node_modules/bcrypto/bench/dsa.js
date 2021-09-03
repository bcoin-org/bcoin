'use strict';

const assert = require('bsert');
const bench = require('./bench');
const dsa = require('../lib/dsa');
const mul = dsa.native ? 10 : 1;

// 1024
const raw = Buffer.from('308201ba02010002818100800a479388b0792c1f8515068d'
                      + 'd402fd7d297bd8979d246bb4cc5276cf3720ecc748916417'
                      + '72390454e6954ce5dbf0f051befe1f07f556cd9b15503d5e'
                      + 'cf5d58542b8417f8a9c2e639a090b7eabb55f2a246d42ff9'
                      + 'b0f03d13c8f84ec165bd0e6bf892ca0245a1b8f2ab8bc388'
                      + '9de5b600e70748d017108ccde6bc055d7bd9f3021500c02f'
                      + '8b03d02375351a84faa0d854d49e4727cda5028180651e00'
                      + '37ffb7597c273ee346fcbebe4f182cbbaa4ab55d52a97c3f'
                      + '3c10565ac3a8cad2098bfb6c25142e203e244ef3cc9d09b0'
                      + '664a764e01a962d7e32d75721b819e5685b9a41074026b1f'
                      + 'c2d4d44cb27ed02de3ff477ea79f9e6fa360716502ccfb6f'
                      + 'e52ff806b34151dae6249a723238a15006a7c01b78562ce7'
                      + '95327a89ce0281802333ab5f8db856e7c7ce433ac41d49e3'
                      + '7c8f36d74feb89e5e43af571b21c444adde5f0498904251a'
                      + '305f76974d23d89c579b967bc094df26311c7939ec473f73'
                      + '0cc59be7ccdc1ec203d59a3be3bc603ad3b4b63d11ce1619'
                      + '35fcf54c2d75b9cb744f06f6dfaa818d988cab2d7ea58c20'
                      + '7e5c1e5294f05151b0785f7ebf2d27de021460516a9ae55e'
                      + '9610b37a822669c318639d8448c0', 'hex');

// 2048
// eslint-disable-next-line
const big = Buffer.from('308203560201000282010100ebec69b74460e4e82f2bf927'
                      + 'f29a97d9ce739d9c66d7af40968ba13fca774eda2d6e890d'
                      + 'a47864623dee3c5c08ca41c78b3ee965eba0ccd1ef2509ea'
                      + '50a326de06f3e6f162d4e88103c5b3cba99f921e686b6f17'
                      + 'c5775f0a078613a7dd94182d2491e1e91e3c2d74ab82025a'
                      + '39ee6165dec08d5ca760f662c1c34302e11f7e77a6d98891'
                      + 'aead87bb2880a4da5ad5ea7e766f72bca2d002475172d9c6'
                      + '46a67c5219e4ad1c130f34c6a2f21df55819149f62af0839'
                      + '261b76302b6f7d6834c8971df2bf279c68e645d6aa7051b1'
                      + '34ec2c7fc42435ea1199217a868367e9aafd2afa2c806f9d'
                      + '6558ffec493158b52c48373064c6e3347136a6962584df89'
                      + 'd2b0ea6502210089696f4384d6dd941854dcf89ba02f3508'
                      + '86f7e60409f3fa660edbd79ce34c01028201002a014c9bfe'
                      + '67cc71839238905e70543bc1961bb6f5c888a1b14249f640'
                      + 'ca380a701ccb691e6859ecd39fbeb4680db0bd06b599fd5b'
                      + '25c9f3a10c663e3bb75535ad290aa31f65d36f3087ae3dcc'
                      + '0e8e7ae544fa65b1c1505a9cdf8648b1ad1701cf44e323ec'
                      + '08b2fd821cd231242f27a11e73e66253af950d074ffed768'
                      + 'c69b345be78fb304ea087c55bc7f20182df6618f99e94a1d'
                      + '592ac68371d035fd7deea066160aa4b2aa135e0015b4fbae'
                      + 'd467a8e63cc2175e1fe52c1689f329a941c326a4077ed9d9'
                      + '1dfaec107ef162e36efe6c225e11d075cbca656be2497c9c'
                      + '6378d172dbd9d804f4b294317b0e8e072daa5b1ce9ff0aa7'
                      + '1f2e7436a67b5a5c9f1d570282010100a68d684e602afb59'
                      + '37a8b0894ba97cd719176e1eb853437b813117626559a87f'
                      + '5a9e9c6040ddd79320602e5b561ee940c3e7b953bcbb6bdd'
                      + '0c87243f208bea504052ccd60d8edbd5f905e7e249843ed5'
                      + '83c4a49314b1f11884314dbde338b3c3da00afd64e25230d'
                      + 'e86500296d3c71380d0b1d879ab8381e20bd650005833f4b'
                      + 'fed04a46290825c836b5e1311e0ae1121da9ed04e14b80ce'
                      + '41c83c621fe2398167c1f7a2509dc6322560482dde2de74f'
                      + 'f6c01f15f71b1ba1d32402a5d04b3806e02b488b5e2ae3a7'
                      + '54fa9657ff582ecc30528fcf49f1b2879e9d3e8c883f37ec'
                      + '53efc8a29baf031202a39192d8e38949df38324a881eb101'
                      + 'ca1060537494c5e902202c6003fd996f0f72a7671d3afbf3'
                      + '4c8adcf951208eb22ad7f1de1a71fbf843b6', 'hex');

{
  const rounds = 1000 * mul;
  const key = raw;
  const pub = dsa.publicKeyCreate(key);
  const msg = Buffer.from('31260986ee940fa71d2c4cc7c00d4b1e'
                        + 'c2131b24f2b6243f48c2cbd3b7b82ea3', 'hex');
  const sig = dsa.sign(msg, key);

  assert(dsa.privateKeyVerify(key));
  assert(dsa.verify(msg, sig, pub));

  bench('dsa verify', rounds, () => {
    dsa.verify(msg, sig, pub);
  });
}
