/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const ChaCha20 = require('../lib/crypto/chacha20');
const Poly1305 = require('../lib/crypto/poly1305');
const AEAD = require('../lib/crypto/aead');

function testChaCha(options) {
  const key = Buffer.from(options.key, 'hex');
  const nonce = Buffer.from(options.nonce, 'hex');
  const plain = Buffer.from(options.plain, 'hex');
  const ciphertext = Buffer.from(options.ciphertext, 'hex');
  const counter = options.counter;

  const ctx1 = new ChaCha20();
  ctx1.init(key, nonce, counter);
  const plainenc = Buffer.from(plain);
  ctx1.encrypt(plainenc);
  assert.bufferEqual(plainenc, ciphertext);

  const ctx2 = new ChaCha20();
  ctx2.init(key, nonce, counter);
  ctx2.encrypt(ciphertext);
  assert.bufferEqual(plain, ciphertext);
}

function testAEAD(options) {
  const plain = Buffer.from(options.plain, 'hex');
  const aad = Buffer.from(options.aad, 'hex');
  const key = Buffer.from(options.key, 'hex');
  const nonce = Buffer.from(options.nonce, 'hex');
  const pk = Buffer.from(options.pk, 'hex');
  const ciphertext = Buffer.from(options.ciphertext, 'hex');
  const tag = Buffer.from(options.tag, 'hex');

  const ctx1 = new AEAD();
  ctx1.init(key, nonce);
  assert.strictEqual(ctx1.chacha20.getCounter(), 1);
  assert.bufferEqual(ctx1.polyKey, pk);
  ctx1.aad(aad);
  const plainenc = Buffer.from(plain);
  ctx1.encrypt(plainenc);
  assert.bufferEqual(plainenc, ciphertext);
  assert.bufferEqual(ctx1.finish(), tag);

  const ctx2 = new AEAD();
  ctx2.init(key, nonce);
  assert.strictEqual(ctx2.chacha20.getCounter(), 1);
  assert.bufferEqual(ctx2.polyKey, pk);
  ctx2.aad(aad);
  ctx2.decrypt(ciphertext);
  assert.bufferEqual(ciphertext, plain);
  assert.bufferEqual(ctx2.finish(), tag);
}

describe('ChaCha20 / Poly1305 / AEAD', function() {
  it('should perform chacha20', () => {
    testChaCha({
      key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      nonce: '000000000000004a00000000',
      plain: ''
        + '4c616469657320616e642047656e746c656d656e206f6620746865206'
        + '36c617373206f66202739393a204966204920636f756c64206f6666657220796'
        + 'f75206f6e6c79206f6e652074697020666f7220746865206675747572652c207'
        + '3756e73637265656e20776f756c642062652069742e',
      ciphertext: ''
        + '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afcc'
        + 'fd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab'
        + '8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d'
        + '16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d',
      counter: 1
    });
  });

  it('should perform chacha20', () => {
    testChaCha({
      key: '0000000000000000000000000000000000000000000000000000000000000000',
      nonce: '000000000000000000000000',
      plain: ''
        + '0000000000000000000000000000000000000000000000000000000000000000'
        + '0000000000000000000000000000000000000000000000000000000000000000',
      ciphertext: ''
        + '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b77'
        + '0dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669'
        + 'b2ee6586',
      counter: 0
    });
  });

  it('should perform chacha20', () => {
    testChaCha({
      key: '0000000000000000000000000000000000000000000000000000000000000001',
      nonce: '000000000000000000000002',
      plain: ''
        + '416e79207375626d697373696f6e20746f20746865204945544620696e'
        + '74656e6465642062792074686520436f6e7472696275746f7220666f722'
        + '07075626c69636174696f6e20617320616c6c206f722070617274206f'
        + '6620616e204945544620496e7465726e65742d4472616674206f7220524'
        + '64320616e6420616e792073746174656d656e74206d6164652077697468696'
        + 'e2074686520636f6e74657874206f6620616e2049455446206163746976'
        + '69747920697320636f6e7369646572656420616e20224945544620436f6'
        + 'e747269627574696f6e222e20537563682073746174656d656e747320696e'
        + '636c756465206f72616c2073746174656d656e747320696e204945544620'
        + '73657373696f6e732c2061732077656c6c206173207772697474656e2061'
        + '6e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d'
        + '61646520617420616e792074696d65206f7220706c6163652c2077686963'
        + '68206172652061646472657373656420746f',
      ciphertext: ''
        + 'a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d'
        + '4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f'
        + '56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db'
        + '09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c'
        + '680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab05'
        + '2691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c91'
        + '39ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac'
        + '638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c'
        + 'cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e8'
        + '18b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80'
        + 'ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd'
        + '2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9'
        + 'cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b'
        + '862f3730e37cfdc4fd806c22f221',
      counter: 1
    });
  });

  it('should perform chacha20', () => {
    testChaCha({
      key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
      nonce: '000000000000000000000002',
      plain: ''
        + '2754776173206272696c6c69672c20616e642074686520736c6974687920746f76'
        + '65730a446964206779726520616e642067696d626c6520696e207468'
        + '6520776162653a0a416c6c206d696d73792077657265207468652062'
        + '6f726f676f7665732c0a416e6420746865206d6f6d65207261746873'
        + '206f757467726162652e',
      ciphertext: ''
        + '62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf16'
        + '6d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f6'
        + '0553ebf39c6402c42234e32a356b3e764312a61a5532055716ead696'
        + '2568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd72'
        + '8afa36757a797ac188d1',
      counter: 42
    });
  });

  it('should perform poly1305', () => {
    const expected = Buffer.from('ddb9da7ddd5e52792730ed5cda5f90a4', 'hex');
    const key = Buffer.allocUnsafe(32);
    const msg = Buffer.allocUnsafe(73);

    for (let i = 0; i < key.length; i++)
      key[i] = i + 221;

    for (let i = 0; i < msg.length; i++)
      msg[i] = i + 121;

    const mac = Poly1305.auth(msg, key);
    assert(Poly1305.verify(mac, expected));
    assert.bufferEqual(mac, expected);
  });

  it('should perform poly1305', () => {
    const key = Buffer.from(''
      + '85d6be7857556d337f4452fe42d506a'
      + '80103808afb0db2fd4abff6af4149f51b',
      'hex');

    const msg = Buffer.from('Cryptographic Forum Research Group', 'ascii');
    const tag = Buffer.from('a8061dc1305136c6c22b8baf0c0127a9', 'hex');

    const mac = Poly1305.auth(msg, key);

    assert(Poly1305.verify(mac, tag));

    mac[0] = 0;

    assert(!Poly1305.verify(mac, tag));
  });

  it('should create an AEAD and encrypt', () => {
    testAEAD({
      plain: ''
        + '4c616469657320616e642047656e746c656d656e206f662074686520636c6'
        + '17373206f66202739393a204966204920636f756c64206f666665722'
        + '0796f75206f6e6c79206f6e652074697020666f72207468652066757'
        + '47572652c2073756e73637265656e20776f756c642062652069742e',
      aad: '50515253c0c1c2c3c4c5c6c7',
      key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
      nonce: '07000000' + '4041424344454647',
      pk: '7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff',
      ciphertext: ''
        + 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee6'
        + '2d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a'
        + '5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad67'
        + '5945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116',
      tag: '1ae10b594f09e26a7e902ecbd0600691'
    });
  });

  it('should create an AEAD and encrypt', () => {
    testAEAD({
      key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
      ciphertext: ''
        + '64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8'
        + 'cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03'
        + 'b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d3'
        + '3bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b35063836069'
        + '07b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a'
        + '4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b004'
        + '7718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa7'
        + '6991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e61'
        + '7d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6'
        + 'f2c29a6ad5cb4022b02709b',
      nonce: '000000000102030405060708',
      aad: 'f33388860000000000004e91',
      tag: 'eead9d67890cbb22392336fea1851f38',
      pk: 'bdf04aa95ce4de8995b14bb6a18fecaf26478f50c054f563dbc0a21e261572aa',
      plain: ''
        + '496e7465726e65742d4472616674732061726520647261667420646f63756'
        + 'd656e74732076616c696420666f722061206d6178696d756d206f662'
        + '0736978206d6f6e74687320616e64206d61792062652075706461746'
        + '5642c207265706c616365642c206f72206f62736f6c6574656420627'
        + '9206f7468657220646f63756d656e747320617420616e792074696d6'
        + '52e20497420697320696e617070726f70726961746520746f2075736'
        + '520496e7465726e65742d447261667473206173207265666572656e6'
        + '365206d6174657269616c206f7220746f2063697465207468656d206'
        + 'f74686572207468616e206173202fe2809c776f726b20696e2070726'
        + 'f67726573732e2fe2809d'
    });
  });
});
