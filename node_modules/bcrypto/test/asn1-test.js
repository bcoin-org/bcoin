'use strict';

const assert = require('bsert');
const asn1 = require('../lib/encoding/asn1');

const oids = [
  ['MD5', '1.2.840.113549.2.5', '2a864886f70d0205'],
  ['SHA1', '1.3.14.3.2.26', '2b0e03021a'],
  ['RIPEMD160', '1.0.10118.3.0.49', '28cf06030031'],
  ['SHA224', '2.16.840.1.101.3.4.2.4', '608648016503040204'],
  ['SHA256', '2.16.840.1.101.3.4.2.1', '608648016503040201'],
  ['SHA384', '2.16.840.1.101.3.4.2.2', '608648016503040202'],
  ['SHA512', '2.16.840.1.101.3.4.2.3', '608648016503040203'],
  ['SHA3_224', '2.16.840.1.101.3.4.2.7', '608648016503040207'],
  ['SHA3_256', '2.16.840.1.101.3.4.2.8', '608648016503040208'],
  ['SHA3_384', '2.16.840.1.101.3.4.2.9', '608648016503040209'],
  ['SHA3_512', '2.16.840.1.101.3.4.2.10', '60864801650304020a'],
  ['BLAKE2B160', '1.3.6.1.4.1.1722.12.2.1.5', '2b060104018d3a0c020105'],
  ['BLAKE2B256', '1.3.6.1.4.1.1722.12.2.1.8', '2b060104018d3a0c020108'],
  ['BLAKE2B384', '1.3.6.1.4.1.1722.12.2.1.12', '2b060104018d3a0c02010c'],
  ['BLAKE2B512', '1.3.6.1.4.1.1722.12.2.1.16', '2b060104018d3a0c020110'],
  ['BLAKE2S128', '1.3.6.1.4.1.1722.12.2.2.4', '2b060104018d3a0c020204'],
  ['BLAKE2S160', '1.3.6.1.4.1.1722.12.2.2.5', '2b060104018d3a0c020205'],
  ['BLAKE2S224', '1.3.6.1.4.1.1722.12.2.2.7', '2b060104018d3a0c020207'],
  ['BLAKE2S256', '1.3.6.1.4.1.1722.12.2.2.8', '2b060104018d3a0c020208']
];

const numbers = [
  [-0x01, 'ff'],
  [0x00, '00'],
  [0x01, '01'],
  [0x02, '02'],
  [0x7f, '7f'],
  [-0x7f, '81'],
  [0x80, '0080'],
  [-0x80, '80'],
  [0x7fff, '7fff'],
  [-0x7fff, '8001'],
  [0x8000, '008000'],
  [-0x8000, '8000'],
  [0xffff, '00ffff'],
  [-0xffff, 'ff0001'],
  [0x7fff, '7fff'],
  [-0x7fff, '8001'],
  [0x8000, '008000'],
  [-0x8000, '8000'],
  [0x7fffff, '7fffff'],
  [-0x7fffff, '800001'],
  [0x800000, '00800000'],
  [-0x800000, '800000'],
  [0xffffff, '00ffffff'],
  [-0xffffff, 'ff000001'],
  [0x7fffff, '7fffff'],
  [-0x7fffff, '800001'],
  [0x800000, '00800000'],
  [-0x800000, '800000'],
  [0x7fffffff, '7fffffff'],
  [-0x7fffffff, '80000001'],
  [0x80000000, '0080000000'],
  [-0x80000000, '80000000'],
  [0xffffffff, '00ffffffff'],
  [-0xffffffff, 'ff00000001'],
  [0x7fffffff, '7fffffff'],
  [-0x7fffffff, '80000001'],
  [0x80000000, '0080000000'],
  [-0x80000000, '80000000'],
  [0x7fffffffff, '7fffffffff'],
  [-0x7fffffffff, '8000000001'],
  [0x8000000000, '008000000000'],
  [-0x8000000000, '8000000000'],
  [0xffffffffff, '00ffffffffff'],
  [-0xffffffffff, 'ff0000000001']
];

describe('ASN1', function() {
  for (const [name, id, hex] of oids) {
    it(`should serialize OID: ${name} (${id})`, () => {
      const raw = Buffer.from(hex, 'hex');

      const oid = asn1.OID.decodeBody(raw);
      assert.strictEqual(oid.toString(), id);

      const oid2 = asn1.OID.fromString(id);
      assert.strictEqual(oid2.toString(), id);
      assert.bufferEqual(oid2.encodeBody(), raw);
    });
  }

  for (const [num, hex] of numbers) {
    const raw = Buffer.from(hex, 'hex');

    it(`should serialize int: ${num}`, () => {
      {
        const n1 = new asn1.Integer(num);
        assert.strictEqual(n1.toNumber(), num);

        const data = n1.encodeBody();
        assert.bufferEqual(data, raw);

        const n2 = asn1.Integer.decodeBody(data);
        assert.strictEqual(n2.toNumber(), n1.toNumber());
        assert.strictEqual(n2.toNumber(), num);
      }

      {
        const n1 = new asn1.Integer(num);
        assert.strictEqual(n1.toNumber(), num);

        const n2 = asn1.Integer.decode(n1.encode());
        assert.strictEqual(n2.toNumber(), n1.toNumber());
        assert.strictEqual(n2.toNumber(), num);
      }
    });
  }

  it('should handle bit string', () => {
    const bs = new asn1.BitString(20); // 20 bits

    assert(!bs.getBit(1));
    bs.setBit(1, 1);
    assert(bs.getBit(1));

    assert(!bs.getBit(3));
    bs.setBit(3, 1);
    assert(bs.getBit(3));

    assert(!bs.getBit(18));
    bs.setBit(18, 1);
    assert(bs.getBit(18));
    bs.setBit(18, 0);
    assert(!bs.getBit(18));
    bs.setBit(18, 1);
    assert(bs.getBit(18));

    assert.strictEqual(bs.value.toString('hex'), '500020');
    assert.strictEqual(bs.rightAlign().toString('hex'), '050002');

    const r = asn1.BitString.decode(bs.encode());

    assert.strictEqual(r.value.toString('hex'), '500020');
    assert.strictEqual(r.rightAlign().toString('hex'), '050002');
  });

  it('should handle UTC time', () => {
    const time = new asn1.UTCTime('2018-09-21T11:09:39.907Z');
    assert.strictEqual(time.toString(), '2018-09-21T11:09:39Z');
    assert.strictEqual(time.unix(), 1537528179);

    const r = asn1.UTCTime.decode(time.encode());

    assert.strictEqual(r.toString(), '2018-09-21T11:09:39Z');
    assert.strictEqual(r.unix(), 1537528179);

    r.offset = -6 * 60 * 60;

    assert.strictEqual(r.toString(), '2018-09-21T11:09:39-0600');
    assert.strictEqual(r.unix(), 1537549779);

    const r2 = asn1.UTCTime.decode(r.encode());

    assert.strictEqual(r2.toString(), '2018-09-21T11:09:39-0600');
    assert.strictEqual(r2.unix(), 1537549779);
  });

  it('should handle GEN time', () => {
    const time = new asn1.GenTime('2018-09-21T11:09:39.907Z');
    assert.strictEqual(time.toString(), '2018-09-21T11:09:39Z');
    assert.strictEqual(time.unix(), 1537528179);

    const r = asn1.GenTime.decode(time.encode());

    assert.strictEqual(r.toString(), '2018-09-21T11:09:39Z');
    assert.strictEqual(r.unix(), 1537528179);

    r.offset = -6 * 60 * 60;

    assert.strictEqual(r.toString(), '2018-09-21T11:09:39-0600');
    assert.strictEqual(r.unix(), 1537549779);

    const r2 = asn1.GenTime.decode(r.encode());

    assert.strictEqual(r2.toString(), '2018-09-21T11:09:39-0600');
    assert.strictEqual(r2.unix(), 1537549779);
  });
});
