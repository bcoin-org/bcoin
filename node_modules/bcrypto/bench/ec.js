'use strict';

const bench = require('./bench');
const secp256k1 = require('../lib/secp256k1');
const p256 = require('../lib/p256');
const p521 = require('../lib/p521');
const ed25519 = require('../lib/ed25519');
const ed448 = require('../lib/ed448');
const x25519 = require('../lib/x25519');
const x448 = require('../lib/x448');
const mul = secp256k1.native ? 10 : 1;

{
  const rounds = 1000 * mul;
  const key = Buffer.from('2576e04eda9e90aa0be40121a5b19612'
                        + '08ec8573c9bb02f75a5f69c9b63525b7', 'hex');
  const pub = secp256k1.publicKeyCreate(key);
  const msg = Buffer.from('31260986ee940fa71d2c4cc7c00d4b1e'
                        + 'c2131b24f2b6243f48c2cbd3b7b82ea3', 'hex');
  const sig = secp256k1.sign(msg, key);
  const ssig = secp256k1.schnorrSign(msg, key);

  bench('secp256k1 pubkey', rounds, () => {
    secp256k1.publicKeyCreate(key);
  });

  bench('secp256k1 verify (ecdsa)', rounds, () => {
    secp256k1.verify(msg, sig, pub);
  });

  bench('secp256k1 verify (schnorr)', rounds, () => {
    secp256k1.schnorrVerify(msg, ssig, pub);
  });

  bench('secp256k1 derive', rounds, () => {
    secp256k1.derive(pub, msg);
  });

  // Compare against elliptic.
  if (secp256k1.native === 0) {
    const secp256k1e = require('./deps/elliptic').ec('secp256k1');

    const sigO = {
      r: sig.slice(0, 32),
      s: sig.slice(32, 64)
    };

    bench('secp256k1 verify (elliptic)', rounds, () => {
      secp256k1e.verify(msg, sigO, pub);
    });
  }
}

{
  const rounds = 1000 * mul;
  const key = Buffer.from('ee3ce0978e7d702afa7747ba0cb3a7e8'
                        + '81dac0d9a7286ec34fc3dcdf12a96fc1', 'hex');
  const pub = p256.publicKeyCreate(key);
  const msg = Buffer.from('b84faf8f53996e23bb66af3d50e976e8'
                        + 'fdc793fbfa400ee3292b33fe32d114bf', 'hex');
  const sig = p256.sign(msg, key);

  bench('p256 pubkey', rounds, () => {
    p256.publicKeyCreate(key);
  });

  bench('p256 verify', rounds, () => {
    p256.verify(msg, sig, pub);
  });

  bench('p256 derive', rounds, () => {
    p256.derive(pub, msg);
  });

  // Compare against elliptic.
  if (p256.native === 0) {
    const p256e = require('./deps/elliptic').ec('p256');

    const sigO = {
      r: sig.slice(0, 32),
      s: sig.slice(32, 64)
    };

    bench('p256 verify (elliptic)', rounds, () => {
      p256e.verify(msg, sigO, pub);
    });
  }
}

{
  const rounds = 100 * mul;
  const key = Buffer.from('00835c006bcbf3bbcc731b037dbbd02a'
                        + '98dd2bc665086479629b63d19a8cbf22'
                        + 'af806b8932e5a09c0c5abb510ef9ba63'
                        + '16589e58349f086ca49473b1734cf173'
                        + '0544', 'hex');
  const pub = p521.publicKeyCreate(key);
  const msg = Buffer.from('8fa8a9d4ba8e7e592ad8fe02052b118d'
                        + '5039fe8d85765f5c6735a12b111125e3'
                        + '76474b31e00b7e23cb230738cacd6112'
                        + '60c1ee48502365a6b128e87342095e63', 'hex');
  const sig = p521.sign(msg, key);

  bench('p521 pubkey', rounds, () => {
    p521.publicKeyCreate(key);
  });

  bench('p521 verify', rounds, () => {
    p521.verify(msg, sig, pub);
  });

  // Compare against elliptic.
  if (p521.native === 0) {
    const p521e = require('./deps/elliptic').ec('p521');

    const sigO = {
      r: sig.slice(0, 66),
      s: sig.slice(66, 132)
    };

    bench('p521 verify (elliptic)', rounds, () => {
      p521e.verify(msg, sigO, pub);
    });
  }
}

{
  const rounds = 1000 * mul;
  const key = Buffer.from('cc22f711d6617e45d8fba2b18af6f147'
                        + '6ee977fa50f28998e2ac2d9322e224ba', 'hex');
  const pub = ed25519.publicKeyCreate(key);
  const msg = Buffer.from('ba1b14ca706a7a02f7ad7fbf15035cdf'
                        + '771e60698bdd9e321bc99e9c7f64e2a5', 'hex');
  const sig = ed25519.sign(msg, key);

  bench('ed25519 pubkey', rounds, () => {
    ed25519.publicKeyCreate(key);
  });

  bench('ed25519 verify', rounds, () => {
    ed25519.verify(msg, sig, pub);
  });

  bench('ed25519 derive', rounds, () => {
    ed25519.derive(pub, msg);
  });

  // Compare against elliptic.
  if (ed25519.native === 0) {
    const ed25519e = require('./deps/elliptic').eddsa('ed25519');

    const msgA = Array.from(msg);
    const sigA = Array.from(sig);
    const pubA = Array.from(pub);

    bench('ed25519 verify (elliptic)', rounds, () => {
      ed25519e.verify(msgA, sigA, pubA);
    });
  }
}

{
  const rounds = 100 * mul;
  const key = Buffer.from('38f24f5e0728fd720ccb9e201c2ba091'
                        + 'd9545be13b5639fdaf71744b67c019c5'
                        + 'e9a19182ebfeed0693df0044a273c5ff'
                        + 'ba169948d14ec6b5f9', 'hex');
  const pub = ed448.publicKeyCreate(key);
  const msg = Buffer.from('ee6daf8f30ede748d58feb1c392a5627'
                        + '318e594bdcb0b3d3f761226557381666', 'hex');
  const sig = ed448.sign(msg, key);

  bench('ed448 pubkey', rounds, () => {
    ed448.publicKeyCreate(key);
  });

  bench('ed448 verify', rounds, () => {
    ed448.verify(msg, sig, pub);
  });
}

{
  const rounds = 1000 * mul;
  const key = Buffer.from('50eaee9e4fa829f956e81dc083a03c22'
                        + '69a55b1fcf3bbeb3882b7b0c7dff3076', 'hex');
  const bob = Buffer.from('f84764dd9d4eedf235106a6fedaacf9e'
                        + '234e046afec65543de3036b0322c0f5f', 'hex');
  const pub = x25519.publicKeyCreate(bob);

  bench('x25519 pubkey', rounds, () => {
    x25519.publicKeyCreate(key);
  });

  bench('x25519 derive', rounds, () => {
    x25519.derive(pub, key);
  });
}

{
  const rounds = 100 * mul;
  const key = Buffer.from('9055eac0f6712d88fdb8b830b075b307'
                        + 'e75e2a303e8309497997cc1665cfa41e'
                        + '2f22a208c3c80d5238792000bfce969a'
                        + 'cd43eb2582f9ba82', 'hex');
  const bob = Buffer.from('30a5c0bfabf201998a0f91e47f0fe923'
                        + '7006cff0c4284a00db2bb1325781090a'
                        + 'cb779a070f7f302d13adff87afd07c46'
                        + '1afbef80bfd2349b', 'hex');
  const pub = x448.publicKeyCreate(bob);

  bench('x448 pubkey', rounds, () => {
    x448.publicKeyCreate(key);
  });

  bench('x448 derive', rounds, () => {
    x448.derive(pub, key);
  });
}
