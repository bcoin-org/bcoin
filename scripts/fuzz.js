'use strict';

const assert = require('assert');
const util = require('../lib/utils/util');
const Script = require('../lib/script/script');
const Stack = require('../lib/script/stack');
const Witness = require('../lib/script/witness');
const Input = require('../lib/primitives/input');
const Output = require('../lib/primitives/output');
const Outpoint = require('../lib/primitives/outpoint');
const TX = require('../lib/primitives/tx');
const random = require('../lib/crypto/random');

const MANDATORY = Script.flags.MANDATORY_VERIFY_FLAGS | Script.flags.VERIFY_WITNESS;
const STANDARD = Script.flags.STANDARD_VERIFY_FLAGS;

function randomOutpoint() {
  let hash = random.randomBytes(32).toString('hex');
  return new Outpoint(hash, util.random(0, 0xffffffff));
}

function randomInput() {
  let input = Input.fromOutpoint(randomOutpoint());

  if (util.random(0, 5) === 0)
    input.sequence = util.random(0, 0xffffffff);

  return input;
}

function randomOutput() {
  return Output.fromScript(randomScript(), util.random(0, 1e8));
}

function randomTX() {
  let tx = new TX();
  let inputs = util.random(1, 5);
  let outputs = util.random(0, 5);
  let i;

  tx.version = util.random(0, 0xffffffff);

  for (i = 0; i < inputs; i++)
    tx.inputs.push(randomInput());

  for (i = 0; i < outputs; i++)
    tx.inputs.push(randomOutput());

  if (util.random(0, 5) === 0)
    tx.locktime = util.random(0, 0xffffffff);

  tx.refresh();

  return tx;
}

function randomWitness(redeem) {
  let size = util.random(1, 100);
  let witness = new Witness();
  let i, len;

  for (i = 0; i < size; i++) {
    len = util.random(0, 100);
    witness.push(random.randomBytes(len));
  }

  if (redeem)
    witness.push(redeem);

  witness.compile();

  return witness;
}

function randomInputScript(redeem) {
  let size = util.random(1, 100);
  let script = new Script();
  let i, len;

  for (i = 0; i < size; i++) {
    len = util.random(0, 100);
    script.push(random.randomBytes(len));
  }

  if (redeem)
    script.push(redeem);

  script.compile();

  return script;
}

function randomOutputScript() {
  let size = util.random(1, 10000);
  return Script.fromRaw(random.randomBytes(size));
}

function isPushOnly(script) {
  let i, op;

  if (script.isPushOnly())
    return true;

  for (i = 0; i < script.code.length; i++) {
    op = script.code[i];

    if (op.value === Script.opcodes.NOP)
      continue;

    if (op.value === Script.opcodes.NOP_1)
      continue;

    if (op.value > Script.opcodes.NOP_3)
      continue;

    return false;
  }

  return true;
}

function randomPubkey() {
  let len = util.random(0, 2) === 0 ? 33 : 65;
  return Script.fromPubkey(random.randomBytes(len));
}

function randomPubkeyhash() {
  return Script.fromPubkeyhash(random.randomBytes(20));
}

function randomMultisig() {
  let n = util.random(1, 16);
  let m = util.random(1, n);
  let keys = [];
  let i, len;

  for (i = 0; i < n; i++) {
    len = util.random(0, 2) === 0 ? 33 : 65;
    keys.push(random.randomBytes(len));
  }

  return Script.fromMultisig(m, n, keys);
}

function randomScripthash() {
  return Script.fromScripthash(random.randomBytes(20));
}

function randomWitnessPubkeyhash() {
  return Script.fromProgram(0, random.randomBytes(20));
}

function randomWitnessScripthash() {
  return Script.fromProgram(0, random.randomBytes(32));
}

function randomProgram() {
  let version = util.random(0, 16);
  let size = util.random(2, 41);
  return Script.fromProgram(version, random.randomBytes(size));
}

function randomRedeem() {
  switch (util.random(0, 5)) {
    case 0:
      return randomPubkey();
    case 1:
      return randomPubkeyhash();
    case 2:
      return randomMultisig();
    case 3:
      return randomWitnessPubkeyhash();
    case 4:
      return randomProgram();
  }
  assert(false);
}

function randomScript() {
  switch (util.random(0, 7)) {
    case 0:
      return randomPubkey();
    case 1:
      return randomPubkeyhash();
    case 2:
      return randomMultisig();
    case 3:
      return randomScripthash();
    case 4:
      return randomWitnessPubkeyhash();
    case 5:
      return randomWitnessScripthash();
    case 6:
      return randomProgram();
  }
  assert(false);
}

function randomPubkeyContext() {
  return {
    input: randomInputScript(),
    witness: new Witness(),
    output: randomPubkey(),
    redeem: null
  };
}

function randomPubkeyhashContext() {
  return {
    input: randomInputScript(),
    witness: new Witness(),
    output: randomPubkeyhash(),
    redeem: null
  };
}

function randomScripthashContext() {
  let redeem = randomRedeem();
  return {
    input: randomInputScript(redeem.toRaw()),
    witness: new Witness(),
    output: Script.fromScripthash(redeem.hash160()),
    redeem: redeem
  };
}

function randomWitnessPubkeyhashContext() {
  return {
    input: new Script(),
    witness: randomWitness(),
    output: randomWitnessPubkeyhash(),
    redeem: null
  };
}

function randomWitnessScripthashContext() {
  let redeem = randomRedeem();
  return {
    input: new Script(),
    witness: randomWitness(redeem.toRaw()),
    output: Script.fromProgram(0, redeem.sha256()),
    redeem: redeem
  };
}

function randomWitnessNestedContext() {
  let redeem = randomRedeem();
  let program = Script.fromProgram(0, redeem.sha256());
  return {
    input: new Script([program.toRaw()]),
    witness: randomWitness(redeem.toRaw()),
    output: Script.fromScripthash(program.hash160()),
    redeem: redeem
  };
}

function randomContext() {
  switch (util.random(0, 6)) {
    case 0:
      return randomPubkeyContext();
    case 1:
      return randomPubkeyhashContext();
    case 2:
      return randomScripthashContext();
    case 3:
      return randomWitnessPubkeyhashContext();
    case 4:
      return randomWitnessScripthashContext();
    case 5:
      return randomWitnessNestedContext();
  }
  assert(false);
}

function fuzzSimple(flags) {
  let tx = randomTX();
  let total = -1;
  let stack, input, output;

  for (;;) {
    if (++total % 1000 === 0)
      util.log('Fuzzed %d scripts.', total);

    if (total % 500 === 0)
      tx = randomTX();

    stack = new Stack();
    input = randomInputScript();

    try {
      input.execute(stack, flags, tx, 0, 0, 0);
    } catch (e) {
      if (e.type === 'ScriptError')
        continue;
      throw e;
    }

    output = randomOutputScript();

    try {
      output.execute(stack, flags, tx, 0, 0, 0);
    } catch (e) {
      if (e.type === 'ScriptError')
        continue;
      throw e;
    }

    if (stack.length === 0)
      continue;

    if (!Script.bool(stack.top(-1)))
      continue;

    if (isPushOnly(output))
      continue;

    util.log('Produced valid scripts:');

    util.log('Input:');
    util.log(input);

    util.log('Output:');
    util.log(output);

    util.log('Stack:');
    util.log(stack);

    break;
  }
}

function fuzzVerify(flags) {
  let tx = randomTX();
  let total = -1;
  let input, output, witness;

  for (;;) {
    if (++total % 1000 === 0)
      util.log('Fuzzed %d scripts.', total);

    if (total % 500 === 0)
      tx = randomTX();

    input = randomInputScript();
    witness = randomWitness();
    output = randomOutputScript();

    try {
      Script.verify(
        input,
        witness,
        output,
        tx,
        0,
        0,
        flags
      );
    } catch (e) {
      if (e.type === 'ScriptError')
        continue;
      throw e;
    }

    if (isPushOnly(output))
      continue;

    util.log('Produced valid scripts:');

    util.log('Input:');
    util.log(input);

    util.log('Witness:');
    util.log(witness);

    util.log('Output:');
    util.log(output);

    break;
  }
}

function fuzzLess(flags) {
  let tx = randomTX();
  let total = -1;
  let ctx;

  for (;;) {
    if (++total % 1000 === 0)
      util.log('Fuzzed %d scripts.', total);

    if (total % 500 === 0)
      tx = randomTX();

    ctx = randomContext();

    try {
      Script.verify(
        ctx.input,
        ctx.witness,
        ctx.output,
        tx,
        0,
        0,
        flags
      );
    } catch (e) {
      if (e.type === 'ScriptError')
        continue;
      throw e;
    }

    util.log('Produced valid scripts:');

    util.log('Input:');
    util.log(ctx.input);

    util.log('Witness:');
    util.log(ctx.witness);

    util.log('Output:');
    util.log(ctx.output);

    if (ctx.redeem) {
      util.log('Redeem:');
      util.log(ctx.redeem);
    }

    break;
  }
}

function main() {
  let flags = process.argv.indexOf('--standard') !== -1 ? STANDARD : MANDATORY;

  switch (process.argv[2]) {
    case 'simple':
      return fuzzSimple(flags);
    case 'verify':
      return fuzzVerify(flags);
    case 'less':
      return fuzzLess(flags);
    default:
      util.log('Please select a mode:');
      util.log('simple, verify, less');
      util.log('Optional `--standard` flag.');
      break;
  }
}

main();
