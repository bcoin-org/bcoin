'use strict';

const bcoin = require('../..');

(async () => {
  // use well known test mnemonic
  const phrase = [
    'abandon', 'abandon', 'abandon', 'abandon',
    'abandon', 'abandon', 'abandon', 'abandon',
    'abandon', 'abandon', 'abandon', 'about'
  ].join(' ');

  const network = bcoin.Network.get('regtest');

  const mnemonic = bcoin.Mnemonic.fromPhrase(phrase);

  // m'
  const priv = bcoin.HDPrivateKey.fromMnemonic(mnemonic);

  // m'/44'
  const bip44Key = priv.derive(44, true);

  // m'/44'/0'
  const bitcoinKey = bip44Key.derive(0, true);

  // m'/44'/0'/0'
  const accountKey = bitcoinKey.derive(0, true);

  // account extended public key
  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
  const xpub = accountKey.xpubkey(network.type);

  console.log('xpub to import:\n', xpub);

  // recommended to use hardware wallet to derive keys
  // see github.com/bcoin-org/bledger

  // create watch only wallet
  // the wallet will generate lookahead
  // addresses from the account extended public key
  // and can find spendable coins in the blockchain state
  const wdb = new bcoin.wallet.WalletDB({
    network: 'regtest',
    memory: true
  });

  await wdb.open();

  // new wallet still generates a master private key, but it will not be used
  const wallet = await wdb.create({
    name: 'my-watch-only-wallet',
    accountKey: xpub,
    watchOnly: true
  });

  // xpub account key placed at Account 0. Address 0 is already derived.
  const acct0 = await wallet.getAccount(0);

  // create new receive addresses through the deterministic chain
  const key1 = await wallet.createReceive(0);
  const addr1 = key1.getAddress('string', 'regtest');

  const key2 = await wallet.createReceive(0);
  const addr2 = key2.getAddress('string', 'regtest');

  console.log('Wallet:\n', wallet);
  console.log('Account:\n', acct0);
  console.log('Address 1:\n', addr1);
  console.log('Address 2:\n', addr2);
})();
