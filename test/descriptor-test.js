/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

/**
 * Parts of these testcases are taken from Bitcoin core
 * @see https://github.com/bitcoin/bitcoin/blob/master/src/test/descriptor_tests.cpp
 * @see https://github.com/bitcoin/bitcoin/blob/master/test/functional/rpc_getdescriptorinfo.py
 */

'use strict';

const assert = require('bsert');
const parsable = require('./data/descriptors/desc-valid.json');
const unparsable = require('./data/descriptors/desc-invalid.json');
const privateKeyDescriptors = require('./data/descriptors/desc-privatekeys.json');
const common = require('../lib/descriptor/common');
const {parse} = require('../lib/descriptor/parser');
const PKDescriptor = require('../lib/descriptor/type/pk');
const PKHDescriptor = require('../lib/descriptor/type/pkh');
const WPKHDescriptor = require('../lib/descriptor/type/wpkh');
const SHDescriptor = require('../lib/descriptor/type/sh');
const WSHDescriptor = require('../lib/descriptor/type/wsh');
const ComboDescriptor = require('../lib/descriptor/type/combo');
const MultisigDescriptor = require('../lib/descriptor/type/multisig');
const RawDescriptor = require('../lib/descriptor/type/raw');
const AddressDescriptor = require('../lib/descriptor/type/addr');

function createDescriptorFromOptions(desc, type) {
  const options = {};
  options.keyProviders = desc.keyProviders;
  options.subdescriptors = desc.subdescriptors;
  options.threshold = desc.threshold;
  options.isSorted = desc.isSorted;
  options.address = desc.address;
  options.script = desc.script;
  options.network = desc.network;

  switch (type) {
    case 'pk':
      return new PKDescriptor(options);
    case 'pkh':
      return new PKHDescriptor(options);
    case 'wpkh':
      return new WPKHDescriptor(options);
    case 'combo':
      return new ComboDescriptor(options);
    case 'sh':
      return new SHDescriptor(options);
    case 'wsh':
      return new WSHDescriptor(options);
    case 'multisig':
      return new MultisigDescriptor(options);
    case 'addr':
      return new AddressDescriptor(options);
    case 'raw':
      return new RawDescriptor(options);
  }

  return null;
}

describe('Descriptor', () => {
  for (const type in parsable) {
    if (parsable.hasOwnProperty(type)) {
      for (const data of parsable[type]) {
        const {input, descriptor, checksum, isrange, issolvable, hasprivatekeys, requirechecksum, network} = data;

        const desc1 = parse(input, network, requirechecksum);

        it(`should create descriptor object from string for ${input}`, () => {
          assert.strictEqual(common.createChecksum(input.split('#')[0]), checksum);
          assert.strictEqual(desc1.isRange(), isrange);
          assert.strictEqual(desc1.isSolvable(), issolvable);
          assert.strictEqual(desc1.hasPrivateKeys(), hasprivatekeys);
          assert.strictEqual(desc1.toString(), descriptor);
        });

        const desc2 = createDescriptorFromOptions(desc1, type);

        it(`should create descriptor object from options object for ${input}`, () => {
          assert.strictEqual(common.createChecksum(input.split('#')[0]), checksum);
          assert.strictEqual(desc2.isRange(), isrange);
          assert.strictEqual(desc2.isSolvable(), issolvable);
          assert.strictEqual(desc2.hasPrivateKeys(), hasprivatekeys);
          assert.strictEqual(desc2.toString(), descriptor);
        });
      }
    }
  }

  for (const date of privateKeyDescriptors) {
    it('should output descriptor with private keys when all keys are private', () => {
      try {
        const desc = parse(date.input, date.network);
        assert.strictEqual(desc.toPrivateString(), date.expected);
      } catch (e) {
        assert.strictEqual(e.message, date.error);
      }
    });
  }

  for (const data of unparsable) {
    const {input, error, network, requirechecksum} = data;
    it(`should throw ('${error}') for ${input}`, () => {
      assert.throws(
        () => parse(input, network, requirechecksum),
        e => e.message === error
      );
    });
  }
});
