'use strict';

const Logger = require('blgr');
const FullNode = require('../../lib/node/fullnode');
const Amount = require('../../lib/btc/amount');
const plugin = require('../../lib/wallet/plugin');
const ProxySocket = require('./proxysocket');

const body = document.getElementsByTagName('body')[0];
const log = document.getElementById('log');
const wdiv = document.getElementById('wallet');
const tdiv = document.getElementById('tx');
const floating = document.getElementById('floating');
const send = document.getElementById('send');
const newaddr = document.getElementById('newaddr');
const chainState = document.getElementById('state');
const rpc = document.getElementById('rpc');
const cmd = document.getElementById('cmd');
const items = [];

let scrollback = 0;

const logger = new Logger({
  level: 'debug',
  console: true
});

logger.writeConsole = function writeConsole(level, module, args) {
  const name = Logger.levelsByVal[level];
  const msg = this.fmt(args, false);

  if (++scrollback > 1000) {
    log.innerHTML = '';
    scrollback = 1;
  }

  const now = Math.floor(Date.now() / 1000);

  log.innerHTML += `<span style="color:blue;">${now}</span> `;

  if (name === 'error') {
    log.innerHTML += `<span style="color:red;">[${name}] `;
    if (module)
      log.innerHTML += `(${module}) `;
    log.innerHTML += '</span>';
  } else {
    log.innerHTML += `[${name}] `;
    if (module)
      log.innerHTML += `(${module}) `;
  }

  log.innerHTML += escape(msg) + '\n';
  log.scrollTop = log.scrollHeight;
};

const node = new FullNode({
  hash: true,
  query: true,
  prune: true,
  network: 'main',
  memory: false,
  coinCache: 30,
  logConsole: true,
  workers: true,
  workerFile: '/worker.js',
  createSocket: (port, host) => {
    const proto = global.location.protocol === 'https:' ? 'wss' : 'ws';
    const hostname = global.location.host;
    return ProxySocket.connect(`${proto}://${hostname}`, port, host);
  },
  logger: logger,
  plugins: [plugin]
});

const {wdb} = node.require('walletdb');
wdb.options.witness = true;

window.onunhandledrejection = function onunhandledrejection(event) {
  throw event.reason;
};

body.onmouseup = function onmouseup() {
  floating.style.display = 'none';
};

floating.onmouseup = function onmouseup(ev) {
  ev.stopPropagation();
  return false;
};

function show(obj) {
  if (obj instanceof Error) {
    floating.innerHTML = obj.stack;
    floating.style.display = 'block';
    return;
  }
  const json = obj && obj.toJSON ? obj.toJSON() : null;
  floating.innerHTML = escape(JSON.stringify(json, null, 2));
  floating.style.display = 'block';
}

rpc.onsubmit = function onsubmit(ev) {
  const text = cmd.value || '';
  const argv = text.trim().split(/\s+/);
  const method = argv.shift();
  const params = [];

  cmd.value = '';

  for (const arg of argv) {
    let param;
    try {
      param = JSON.parse(arg);
    } catch (e) {
      param = arg;
    }
    params.push(param);
  }

  (async () => {
    try {
      const result = await node.rpc.execute({ method, params });
      show(result);
    } catch (e) {
      show(e);
    }
  })();

  ev.preventDefault();
  ev.stopPropagation();

  return false;
};

send.onsubmit = function onsubmit(ev) {
  const value = document.getElementById('amount').value;
  const address = document.getElementById('address').value;

  const options = {
    outputs: [{
      address: address,
      value: Amount.value(value)
    }]
  };

  (async () => {
    try {
      const mtx = await wdb.primary.createTX(options);
      await wdb.primary.sign(mtx);
      await node.relay(mtx.toTX());
      show(mtx);
    } catch (e) {
      show(e);
    }
  })();

  ev.preventDefault();
  ev.stopPropagation();

  return false;
};

newaddr.onmouseup = function onmouseup() {
  (async () => {
    try {
      await wdb.primary.createReceive();
      formatWallet(wdb.primary);
    } catch (e) {
      show(e);
    }
  })();
};

function kb(size) {
  size /= 1000;
  return size.toFixed(2) + 'kb';
}

function create(html) {
  const el = document.createElement('div');
  el.innerHTML = html;
  return el.firstChild;
}

function escape(html, encode) {
  return html
    .replace(!encode ? /&(?!#?\w+;)/g : /&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function addItem(item, entry) {
  const height = entry ? entry.height : -1;

  if (items.length === 20) {
    const el = items.shift();
    tdiv.removeChild(el);
    el.onmouseup = null;
  }

  const el = create(''
    + `<a style="display:block;" href="#${item.rhash()}">`
    + `${item.rhash()} (${height} - ${kb(item.getSize())})`
    + '</a>'
  );

  tdiv.appendChild(el);

  setMouseup(el, item);

  items.push(el);

  chainState.innerHTML = ''
    + `tx=${node.chain.db.state.tx} `
    + `coin=${node.chain.db.state.coin} `
    + `value=${Amount.btc(node.chain.db.state.value)}`;
}

function setMouseup(el, obj) {
  el.onmouseup = function onmouseup(ev) {
    show(obj);
    ev.stopPropagation();
    return false;
  };
}

async function formatWallet(wallet) {
  try {
    await _formatWallet(wallet);
  } catch (e) {
    show(e);
  }
}

async function _formatWallet(wallet) {
  const {key, mnemonic} = wallet.master.toJSON(node.network, true);
  const account = await wallet.getAccount('default');
  const receive = account.receiveAddress();
  const nested = account.nestedAddress();
  const raddr = receive.toString(node.network);
  const naddr = nested ? nested.toString(node.network) : null;

  let html = '';

  html += '<b>Wallet</b><br>';

  if (naddr) {
    html += `Current Address (p2wpkh): <b>${raddr}</b><br>`;
    html += `Current Address (p2wpkh behind p2sh): <b>${naddr}</b><br>`;
  } else {
    html += `Current Address: <b>${raddr}</b><br>`;
  }

  html += `Extended Private Key: <b>${key.xprivkey}</b><br>`;
  html += `Mnemonic: <b>${mnemonic.phrase}</b><br>`;

  const balance = await wallet.getBalance();

  html += `Confirmed Balance: <b>${Amount.btc(balance.confirmed)}</b><br>`;
  html += `Unconfirmed Balance: <b>${Amount.btc(balance.unconfirmed)}</b><br>`;

  const txs = await wallet.getHistory();
  const det = await wallet.toDetails(txs);

  html += 'TXs:\n';
  wdiv.innerHTML = html;

  for (const tx of det) {
    const el = create(
      `<a style="display:block;" href="#${tx.hash}">${tx.hash}</a>`);
    wdiv.appendChild(el);
    setMouseup(el, tx.toJSON());
  }
}

node.chain.on('block', addItem);
node.mempool.on('tx', addItem);

(async () => {
  await node.open();
  await node.connect();
  node.startSync();
  wdb.primary.on('balance', () => {
    formatWallet(wdb.primary);
  });
  formatWallet(wdb.primary);
})().catch((err) => {
  throw err;
});
