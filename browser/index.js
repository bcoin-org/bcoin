;(function() {

'use strict';

var util = bcoin.util;
var body = document.getElementsByTagName('body')[0];
var log = document.getElementById('log');
var wdiv = document.getElementById('wallet');
var tdiv = document.getElementById('tx');
var floating = document.getElementById('floating');
var send = document.getElementById('send');
var newaddr = document.getElementById('newaddr');
var chainState = document.getElementById('state');
var rpc = document.getElementById('rpc');
var cmd = document.getElementById('cmd');
var items = [];
var scrollback = 0;
var logger, node, wdb;

window.onunhandledrejection = function(event) {
  throw event.reason;
};

body.onmouseup = function() {
  floating.style.display = 'none';
};

floating.onmouseup = function(ev) {
  ev.stopPropagation();
  return false;
};

function show(obj) {
  floating.innerHTML = escape(util.inspectify(obj, false));
  floating.style.display = 'block';
}

logger = new bcoin.logger({ level: 'debug', console: true });
logger.writeConsole = function(level, module, args) {
  var name = bcoin.logger.levelsByVal[level];
  var msg = util.format(args, false);
  if (++scrollback > 1000) {
    log.innerHTML = '';
    scrollback = 1;
  }
  log.innerHTML += '<span style="color:blue;">' + util.now() + '</span> ';
  if (name === 'error') {
    log.innerHTML += '<span style="color:red;">';
    log.innerHTML += '[';
    log.innerHTML += name
    log.innerHTML += '] ';
    if (module)
      log.innerHTML += '(' + module + ') ';
    log.innerHTML += '</span>';
  } else {
    log.innerHTML += '[';
    log.innerHTML += name
    log.innerHTML += '] ';
    if (module)
      log.innerHTML += '(' + module + ') ';
  }
  log.innerHTML += escape(msg) + '\n';
  log.scrollTop = log.scrollHeight;
};

rpc.onsubmit = function(ev) {
  var text = cmd.value || '';
  var argv = text.trim().split(/\s+/);
  var method = argv.shift();
  var params = [];
  var i, arg, param;

  cmd.value = '';

  for (i = 0; i < argv.length; i++) {
    arg = argv[i];
    try {
      param = JSON.parse(arg);
    } catch (e) {
      param = arg;
    }
    params.push(param);
  }

  node.rpc.execute({ method: method, params: params }).then(show, show);

  ev.preventDefault();
  ev.stopPropagation();

  return false;
};

send.onsubmit = function(ev) {
  var value = document.getElementById('amount').value;
  var address = document.getElementById('address').value;
  var tx, options;

  options = {
    outputs: [{
      address: address,
      value: bcoin.amount.value(value)
    }]
  };

  wdb.primary.createTX(options).then(function(mtx) {
    tx = mtx;
    return wdb.primary.sign(tx);
  }).then(function() {
    return node.sendTX(tx);
  }).then(function() {
    show(tx);
  });

  ev.preventDefault();
  ev.stopPropagation();

  return false;
};

newaddr.onmouseup = function() {
  wdb.primary.createReceive().then(function() {
    formatWallet(wdb.primary);
  });
};

function kb(size) {
  size /= 1000;
  return size.toFixed(2) + 'kb';
}

function create(html) {
  var el = document.createElement('div');
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
  var height = entry ? entry.height : -1;
  var el;

  if (items.length === 20) {
    el = items.shift();
    tdiv.removeChild(el);
    el.onmouseup = null;
  }

  el = create('<a style="display:block;" href="#'
    + item.rhash() + '">' + item.rhash() + ' (' + height
    + ' - ' + kb(item.getSize()) + ')</a>');
  tdiv.appendChild(el);

  setMouseup(el, item);

  items.push(el);

  chainState.innerHTML = ''
    + 'tx=' + node.chain.db.state.tx
    + ' coin=' + node.chain.db.state.coin
    + ' value=' + bcoin.amount.btc(node.chain.db.state.value);
}

function setMouseup(el, obj) {
  el.onmouseup = function(ev) {
    show(obj);
    ev.stopPropagation();
    return false;
  };
}

function formatWallet(wallet) {
  var html = '';
  var json = wallet.master.toJSON(true);
  var i, tx, el;

  html += '<b>Wallet</b><br>';

  if (wallet.account.witness) {
    html += 'Current Address (p2wpkh): <b>'
      + wallet.getAddress()
      + '</b><br>';
    html += 'Current Address (p2wpkh behind p2sh): <b>'
      + wallet.getNestedAddress()
      + '</b><br>';
  } else {
    html += 'Current Address: <b>' + wallet.getAddress() + '</b><br>';
  }

  html += 'Extended Private Key: <b>' + json.key.xprivkey + '</b><br>';
  html += 'Mnemonic: <b>' + json.mnemonic.phrase + '</b><br>';

  wallet.getBalance().then(function(balance) {
    html += 'Confirmed Balance: <b>'
      + bcoin.amount.btc(balance.confirmed)
      + '</b><br>';

    html += 'Unconfirmed Balance: <b>'
      + bcoin.amount.btc(balance.unconfirmed)
      + '</b><br>';

    return wallet.getHistory();
  }).then(function(txs) {
    return wallet.toDetails(txs);
  }).then(function(txs) {
    html += 'TXs:\n';
    wdiv.innerHTML = html;

    for (i = 0; i < txs.length; i++) {
      tx = txs[i];

      el = create(
        '<a style="display:block;" href="#' + tx.hash + '">'
        + tx.hash + '</a>');

      wdiv.appendChild(el);
      setMouseup(el, tx.toJSON());
    }
  });
}

node = new bcoin.fullnode({
  hash: true,
  query: true,
  prune: true,
  network: 'main',
  db: 'leveldb',
  coinCache: 30000000,
  logConsole: true,
  workers: true,
  workerFile: '/bcoin-worker.js',
  logger: logger
});

wdb = node.use(bcoin.wallet.plugin);

node.chain.on('block', addItem);
node.mempool.on('tx', addItem);

node.open().then(function() {
  return node.connect();
}).then(function() {
  node.startSync();

  wdb.primary.on('balance', function() {
    formatWallet(wdb.primary);
  });

  formatWallet(wdb.primary);
}).catch(function(err) {
  throw err;
});

})();
