'use strict';

const express = require('express');
const NodeClient = require('../../../lib/client/node');
const Network = require('../../../lib/protocol/network');
const config = require('../../../config')
const network = Network.get(config.network);
const WalletClient = require('../../../lib/client/wallet');
const KeyRing = require('../../../lib/primitives/keyring');
const WalletDB = require('../../../lib/wallet/walletdb');


const clientOptions = {
  network: network.type,
  port: config.clientPort,
  apiKey: config.client_apiKey
}
const client = new NodeClient(clientOptions);
const walletOptions = {
  network: network.type,
  port: config.walletPort,
  apiKey: config.wallet_apiKey
}
const walletClient = new WalletClient(walletOptions);




class Router {
  /**
   * Api Router
   * @param {object} options
   * @param {import('express').Express} options.app
   */
  constructor(options) {
    this.app = options.app;
    this.options = options;

  }

  init() {
    this.app.get('/', (req, res, next) => res.send('ο(=•ω＜=)ρ⌒☆'));


    this.app
      .get('/api/v2/tx/:tx', this.getTx)
      .get('/block', this.getBlockByHeight)
      .get('/balance', this.getBalance)
      .get('/api/v2/utxo/:xpubkey', this.getUTXO)
      .get('/tx/address/:address', this.getTxByAddress)
      .get('/api/v2/xpub/:xpubkey', this.getTxs)
      .get('/api/v1/estimatefee/:blocks', this.getEstimateFee)
      .get('/api/v2/sendtx/:txHex', this.sendTX)
  }



  async sendTX(req, res) {
    try {
      const tx = req.params.txHex;
      // const result = await client.broadcast(tx);
      const result = await client.execute('sendrawtransaction', [tx]);
      //console.log(result);
      res.status(200).json({
        result: result
      });

    } catch (error) {
      console.log('getEstimateFee failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }


  async getEstimateFee(req, res) {
    try {
      const blocks = Number(req.params.blocks);
      //console.log(blocks / 10);
      const data = await client.estimateFee(blocks / 10);
      console.log(data);
      res.status(200).json({
        result: String(data.rate)
      });

    } catch (error) {
      console.log('getEstimateFee failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }



  async getTxs(req, res) {
   
    try {
      
      const xpubkey = req.params.xpubkey;
      const offset = req.query.offset ? Number(req.query.offset) : 0;
      const limit = req.query.limit ? Number(req.query.limit) : 20;

      const wallet = walletClient.wallet(xpubkey.slice(0, 40));
   
      const txs = (await wallet.getHistory()).slice(offset, limit);
      const tokens = [];

      const txs_processed = [];
      for (let i = 0; i < txs.length; i++) {
        let valueIn = 0;
        const item = txs[i];
        const tx = await getTxByHash(item.hash);
        const vin = item.inputs.map((item, index) => {
          item.value = tx.vin[index].value;
          if (item.path && !tokens.includes(item.address)) {
            tokens.push(item.address)
          }
          valueIn += item.value;
          return {
            addresses: [item.address],
            value: item.value,
            coinbase: item.address ? false : true
          }
        });

        const vout = item.outputs.map((item) => {
          if (item.path && !tokens.includes(item.address)) {
            tokens.push(item.address)
          }
          return {
            addresses: [item.address],
            value: item.value
          }
        })

        txs_processed.push({
          txid: item.hash,
          blockTime: item.time,
          blockHeight: item.height,
          vin: vin,
          vout: vout,
          valueIn: valueIn

        })

      }





      res.status(200).json({
        tokens: tokens,
        transactions: txs_processed
      });

    } catch (error) {
      console.log('GetTxs failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }


  async getTxByAddress(req, res) {
    const address = req.params.address;
    const result = await client.getTXByAddress(address);
    console.log(result);
    res.status(200).json(result);
  }



  async getUTXO(req, res) {
    try {
      const xpubkey = req.params.xpubkey;
      const clientinfo = await client.getInfo();   
      await walletClient.rescan(clientinfo.chain.height);
      try {
        const createWallet = await walletClient.createWallet(xpubkey.slice(0, 40), {
          witness: false,
          watchOnly: true,
          accountKey: xpubkey
        });
        const wallet = walletClient.wallet(xpubkey.slice(0, 40));
        for (let i = 0; i < 22; i++) { //初始化钱包遍历22个深度
          await wallet.createAddress('default');
          await wallet.createChange('default');
        }
      } catch (err) {
        console.log(err); 
      }


      const wallet = walletClient.wallet(xpubkey.slice(0, 40));
      //console.log(await wallet.getAccount('default'));
      const coins = await wallet.getCoins();
      //console.log(coins);
      const items = [];
      for (let i of coins) {
        const tx = await wallet.getTX(i.hash);
        const path = tx.outputs[Number(i.index)].path.derivation.replace("m/", "m/44'/0'/");  //默认使用传统地址
        items.push({
          value: i.value,
          confirmations: i.height > 0 ? 1 : 0,
          address: i.address,
          height: i.height,
          path: path,
          txid: i.hash,
          vout: i.index
        })
      }

      res.status(200).json(items);

    } catch (error) {
      console.log('GetUTXO failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }


  }


  async getTx(req, res) {
    try {

      const txid = req.params.tx;
      const data = await client.getTX(txid);
      let valueIn = 0;
      const vin = data.inputs.map((item) => {
        valueIn += item.coin.value;
        return {
          addresses: [item.coin.address],
          value: item.coin.value,
          coinbase: item.coin.address ? false : true
        }
      });

      const vout = data.outputs.map((item) => {
        return {
          addresses: [item.address],
          value: item.value
        }
      })


      const result = {
        txid: data.hash,
        blockHeight: data.height,
        fees: data.fee,
        blockTime: data.time,
        confirmations: data.confirmations,
        value: 0,
        valueIn: valueIn,
        vin: vin,
        vout: vout


      }
      res.status(200).json(result);

    } catch (error) {
      console.log('GetTx failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }

  async getBlockByHeight(req, res) {
    try {
      const data = await client.execute('getblockbyheight', [Number(req.query.height), 1, 1]);
      res.status(200).json(data);

    } catch (error) {
      console.log('GetNames Block: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }


  async getBalance(req, res) {
    try {
      const wallet = walletClient.wallet(req.query.id);
      const data = await wallet.getInfo();
      res.status(200).json(data);

    } catch (error) {
      console.log('GetBalance failed: %o', error);
      res.status(500).json({ error: error.message || error });
    }
  }



}


async function getTxByHash(hash) {
  try {

    const data = await client.getTX(hash);
    let valueIn = 0;
    const vin = data.inputs.map((item) => {
      valueIn += item.coin.value;
      return {
        addresses: [item.coin.address],
        value: item.coin.value,
        coinbase: item.coin.address ? false : true
      }
    });

    const vout = data.outputs.map((item) => {
      return {
        addresses: [item.address],
        value: item.value
      }
    })


    return {
      txid: data.hash,
      blockHeight: data.height,
      fees: data.fee,
      blockTime: data.time,
      confirmations: data.confirmations,
      value: 0,
      valueIn: valueIn,
      vin: vin,
      vout: vout


    }
  } catch (err) {
    console.log(err);
    return {};
  }
}


async function getReceiveAddress(pub) {
  const wdb = new WalletDB({ network: 'regtest' });
  await wdb.open();
  const walletdb = await wdb.create({
    watchOnly: true,
    accountKey: pub,
    witness: false
  });
  const account = await walletdb.getAccount(0);
  const recAddr = account.toJSON().receiveAddress;
  await wdb.close();
  return recAddr;
}

module.exports = Router;
