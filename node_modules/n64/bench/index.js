'use strict';

const bench = require('./bench');
const Native = require('../lib/native').U64;
const N64 = require('../lib/n64').U64;
const BN = require('../vendor/bn.js');

function addn(N, name) {
  const end = bench('addn (' + name + ')');
  const A = new BN(0);

  for (let i = 0; i < 1000000; i++) {
    const a = A.clone();
    for (let j = 0; j < 5; j++)
      a.iaddn(0x3ffffff);
  }

  end(1000000 * 5);
}

function add(N, name) {
  const end = bench('add (' + name + ')');
  const A = new N(0);
  const B = new N(0x100000000);

  for (let i = 0; i < 1000000; i++) {
    const a = A.clone();
    const b = B.clone();
    for (let j = 0; j < 5; j++)
      a.iadd(b);
  }

  end(1000000 * 5);
}

function muln(N, name) {
  const end = bench('muln (' + name + ')');
  const A = new N(1);

  for (let i = 0; i < 1000000; i++) {
    const a = A.clone();
    for (let j = 0; j < 3; j++)
      a.imuln(0xffffff);
  }

  end(1000000 * 3);
}

function mul(N, name) {
  const end = bench('mul (' + name + ')');
  const A = new N(0);
  const B = new N(0xffffff);

  for (let i = 0; i < 1000000; i++) {
    const a = A.clone();
    const b = B.clone();
    for (let j = 0; j < 3; j++)
      a.imul(b);
  }

  end(1000000 * 3);
}

function divn(N, name) {
  const end = bench('divn (' + name + ')');
  const A = new N('ffffffffffffffff', 16);

  for (let i = 0; i < 1000000; i++) {
    const a = A.clone();
    for (let j = 0; j < 2; j++)
      a.idivn(0xffffff);
  }

  end(1000000 * 2);
}

function div(N, name) {
  const end = bench('div (' + name + ')');
  const A = new N('ffffffffffffffff', 16);
  const B = new N(0xffffff);

  for (let i = 0; i < 1000000; i++) {
    let a = A.clone();
    const b = B.clone();
    for (let j = 0; j < 2; j++)
      a = a.div(b);
  }

  end(1000000 * 2);
}

function modn(N, name) {
  if (!N.prototype.imodn)
    return;

  const end = bench('modn (' + name + ')');
  const A = new N('ffffffffffffffff', 16);

  for (let i = 0; i < 1000000; i++) {
    const a = A.clone();
    for (let j = 0; j < 2; j++)
      a.imodn(0xffffff);
  }

  end(1000000 * 2);
}

function mod(N, name) {
  const end = bench('mod (' + name + ')');
  const A = new N('ffffffffffffffff', 16);
  const B = new N(0xffffff);

  for (let i = 0; i < 1000000; i++) {
    const a = A.clone();
    const b = B.clone();
    for (let j = 0; j < 2; j++)
      a.mod(b);
  }

  end(1000000 * 2);
}

function muldiv(N, name) {
  const end = bench('muldiv (' + name + ')');
  const ten = new N(10);

  let n = new N(10);

  for (let i = 0; i < 1000000; i++) {
    n.imul(ten);
    n = n.div(ten);
  }

  end(1000000 * 2);
}

function muldivn(N, name) {
  const end = bench('muldivn (' + name + ')');
  const n = new N(10);

  for (let i = 0; i < 1000000; i++) {
    n.imuln(10);
    n.idivn(10);
  }

  end(1000000 * 2);
}

function run() {
  addn(N64, 'js');
  addn(Native, 'native');
  addn(BN, 'bn.js');

  console.log('--');

  add(N64, 'js');
  add(Native, 'native');
  add(BN, 'bn.js');

  console.log('--');

  muln(N64, 'js');
  muln(Native, 'native');
  muln(BN, 'bn.js');

  console.log('--');

  mul(N64, 'js');
  mul(Native, 'native');
  mul(BN, 'bn.js');

  console.log('--');

  divn(N64, 'js');
  divn(Native, 'native');
  divn(BN, 'bn.js');

  console.log('--');

  div(N64, 'js');
  div(Native, 'native');
  div(BN, 'bn.js');

  console.log('--');

  modn(N64, 'js');
  modn(Native, 'native');
  modn(BN, 'bn.js');

  console.log('--');

  mod(N64, 'js');
  mod(Native, 'native');
  mod(BN, 'bn.js');

  console.log('--');

  muldiv(N64, 'js');
  muldiv(Native, 'native');
  muldiv(BN, 'bn.js');

  console.log('--');

  muldivn(N64, 'js');
  muldivn(Native, 'native');
  muldivn(BN, 'bn.js');
}

run();
