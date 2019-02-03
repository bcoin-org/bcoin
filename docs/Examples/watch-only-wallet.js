const {HDPrivateKey,Network} = require('bcoin');
const {Mnemonic} = require('bcoin/lib/hd');
const {WalletClient} = require('bclient');

(async () => {

  // use well know test passphrase
  const phrase = [
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'abandon',
    'about',
  ].join(' ');

  const network = Network.get('main');

  const mnemonic = Mnemonic.fromPhrase(phrase);

  // m'
  const priv = HDPrivateKey.fromMnemonic(mnemonic);

  // m'/44'
  const bip44Key = priv.derive(44, true);

  // m'/44'/0'
  const bitcoinKey = bip44Key.derive(0, true);

  // m'/44'/0'/0'
  const accountKey = bitcoinKey.derive(0, true);

  // account extended public key
  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
  const xpub = accountKey.xpubkey(network.type);

  // recommended to use hardware wallet to derive keys
  // see github.com/bcoin-org/bledger

  const client = new WalletClient({
    network: network.type,
    port: network.walletPort,
  });

  // create watch only wallet
  // the wallet will generate lookahead
  // addresses from the account extended public key
  // and can find spendable coins in the blockchain state
  const response = await client.createWallet('mywallet', {
    accountKey: xpub,
    watchOnly: true,
  });

})();


