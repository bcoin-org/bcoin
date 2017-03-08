/*!
 * upnp.js - upnp for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var dgram = require('dgram');
var url = require('url');
var request = require('../http/request');
var co = require('../utils/co');
var Lock = require('../utils/lock');
var IP = require('../utils/ip');

/**
 * UPNP
 * @alias module:net.UPNP
 * @constructor
 * @param {String?} host - Multicast IP.
 * @param {Number?} port - Multicast port.
 * @param {String?} gateway - Gateway name.
 */

function UPNP(host, port, gateway) {
  if (!(this instanceof UPNP))
    return new UPNP(host, port, gateway);

  this.host = host || '239.255.255.250';
  this.port = port || 1900;
  this.gateway = gateway || UPNP.INTERNET_GATEWAY;
  this.locker = new Lock();
  this.timeout = null;
  this.job = null;
}

/**
 * Default internet gateway string.
 * @const {String}
 * @default
 */

UPNP.INTERNET_GATEWAY = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1';

/**
 * Default service types.
 * @const {String[]}
 * @default
 */

UPNP.WAN_SERVICES = [
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANPPPConnection:1'
];

/**
 * Timeout before killing request.
 * @const {Number}
 * @default
 */

UPNP.RESPONSE_TIMEOUT = 1000;

/**
 * Clean up current job.
 * @private
 * @returns {Job}
 */

UPNP.prototype.cleanupJob = function cleanupJob() {
  var job = this.job;

  assert(this.socket);
  assert(this.job);

  this.job = null;

  this.socket.close();
  this.socket = null;

  this.stopTimeout();

  return job;
};

/**
 * Reject current job.
 * @private
 * @param {Error} err
 */

UPNP.prototype.rejectJob = function rejectJob(err) {
  var job = this.cleanupJob();
  job.reject(err);
};

/**
 * Resolve current job.
 * @private
 * @param {Object} result
 */

UPNP.prototype.resolveJob = function resolveJob(result) {
  var job = this.cleanupJob();
  job.resolve(result);
};

/**
 * Start gateway timeout.
 * @private
 */

UPNP.prototype.startTimeout = function startTimeout() {
  var self = this;
  this.stopTimeout();
  this.timeout = setTimeout(function() {
    self.timeout = null;
    self.rejectJob(new Error('Request timed out.'));
  }, UPNP.RESPONSE_TIMEOUT);
};

/**
 * Stop gateway timeout.
 * @private
 */

UPNP.prototype.stopTimeout = function stopTimeout() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

/**
 * Discover gateway.
 * @returns {Promise} Location string.
 */

UPNP.prototype.discover = co(function* discover() {
  var unlock = yield this.locker.lock();
  try {
    return yield this._discover();
  } finally {
    unlock();
  }
});

/**
 * Discover gateway (without a lock).
 * @private
 * @returns {Promise} Location string.
 */

UPNP.prototype._discover = co(function* discover() {
  var self = this;
  var socket, msg;

  socket = dgram.createSocket('udp4');

  socket.on('error', function(err) {
    self.rejectJob(err);
  });

  socket.on('message', function(data, rinfo) {
    var msg = data.toString('utf8');
    self.handleMsg(msg);
  });

  this.socket = socket;
  this.startTimeout();

  msg = ''
    + 'M-SEARCH * HTTP/1.1\r\n'
    + 'HOST: ' + this.host + ':' + this.port + '\r\n'
    + 'MAN: ssdp:discover\r\n'
    + 'MX: 10\r\n'
    + 'ST: ssdp:all\r\n';

  socket.send(msg, this.port, this.host);

  return yield new Promise(function(resolve, reject) {
    self.job = co.job(resolve, reject);
  });
});

/**
 * Handle incoming UDP message.
 * @private
 * @param {String} msg
 * @returns {Promise}
 */

UPNP.prototype.handleMsg = co(function* handleMsg(msg) {
  var headers;

  if (!this.socket)
    return;

  try {
    headers = UPNP.parseHeader(msg);
  } catch (e) {
    return;
  }

  if (!headers.location)
    return;

  if (headers.st !== this.gateway)
    return;

  this.resolveJob(headers.location);
});

/**
 * Resolve service parameters from location.
 * @param {String} location
 * @param {String[]} targets - Target services.
 * @returns {Promise}
 */

UPNP.prototype.resolve = co(function* resolve(location, targets) {
  var host = parseHost(location);
  var res, xml, services, service;

  if (!targets)
    targets = UPNP.WAN_SERVICES;

  res = yield request({
    method: 'GET',
    uri: location,
    timeout: UPNP.RESPONSE_TIMEOUT,
    expect: 'xml'
  });

  xml = XMLElement.fromRaw(res.body);

  services = parseServices(xml);
  assert(services.length > 0, 'No services found.');

  service = extractServices(services, targets);
  assert(service, 'No service found.');
  assert(service.serviceId, 'No service ID found.');
  assert(service.serviceId.length > 0, 'No service ID found.');
  assert(service.controlURL, 'No control URL found.');
  assert(service.controlURL.length > 0, 'No control URL found.');

  service.controlURL = prependHost(host, service.controlURL);

  if (service.eventSubURL)
    service.eventSubURL = prependHost(host, service.eventSubURL);

  if (service.SCPDURL)
    service.SCPDURL = prependHost(host, service.SCPDURL);

  return service;
});

/**
 * Parse UPNP datagram.
 * @private
 * @param {String} str
 * @returns {Object}
 */

UPNP.parseHeader = function parseHeader(str) {
  var lines = str.split(/\r?\n/);
  var headers = {};
  var i, line, index, left, right;

  for (i = 0; i < lines.length; i++) {
    line = lines[i];

    line = line.trim();

    if (line.length === 0)
      continue;

    index = line.indexOf(':');

    if (index === -1) {
      left = line.toLowerCase();
      headers[left] = '';
      continue;
    }

    left = line.substring(0, index);
    right = line.substring(index + 1);

    left = left.trim();
    right = right.trim();

    left = left.toLowerCase();

    headers[left] = right;
  }

  return headers;
};

/**
 * Discover gateway and resolve service.
 * @param {String?} host - Multicast IP.
 * @param {Number?} port - Multicast port.
 * @param {String?} gateway - Gateway type.
 * @param {String[]?} targets - Target service types.
 * @returns {Promise} Service.
 */

UPNP.discover = co(function* discover(host, port, gateway, targets) {
  var upnp = new UPNP(host, port, gateway);
  var location = yield upnp.discover();
  var service = yield upnp.resolve(location, targets);
  return new UPNPService(service);
});

/**
 * Gateway Service
 * @constructor
 * @ignore
 * @param {Object} options - Service parameters.
 */

function UPNPService(options) {
  if (!(this instanceof UPNPService))
    return new UPNPService(options);

  this.serviceType = options.serviceType;
  this.serviceId = options.serviceId;
  this.controlURL = options.controlURL;
  this.eventSubURL = options.eventSubURL;
  this.SCPDURL = options.SCPDURL;
}

/**
 * Compile SOAP request.
 * @private
 * @param {String} action
 * @param {String[]} args
 * @returns {String}
 */

UPNPService.prototype.createRequest = function createRequest(action, args) {
  var params = '';
  var i, arg;

  for (i = 0; i < args.length; i++) {
    arg = args[i];
    params += '<' + arg[0]+ '>';
    if (arg.length > 1)
      params += arg[1];
    params += '</' + arg[0] + '>';
  }

  return ''
    + '<?xml version="1.0"?>'
    + '<s:Envelope '
    + 'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    + 's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    + '<s:Body>'
    + '<u:' + action + ' xmlns:u='
    + JSON.stringify(this.serviceType) + '>'
    + params
    + '</u:' + action + '>'
    + '</s:Body>'
    + '</s:Envelope>';
};

/**
 * Send SOAP request and parse XML response.
 * @private
 * @param {String} action
 * @param {String[]} args
 * @returns {XMLElement}
 */

UPNPService.prototype.soapRequest = co(function* soapRequest(action, args) {
  var req = this.createRequest(action, args);
  var res, xml, err;

  res = yield request({
    method: 'POST',
    uri: this.controlURL,
    timeout: UPNP.RESPONSE_TIMEOUT,
    expect: 'xml',
    headers: {
      'Content-Type': 'text/xml; charset="utf-8"',
      'Content-Length': Buffer.byteLength(req, 'utf8') + '',
      'Connection': 'close',
      'SOAPAction': JSON.stringify(this.serviceType + '#' + action)
    },
    body: req
  });

  xml = XMLElement.fromRaw(res.body);
  err = findError(xml);

  if (err)
    throw err;

  return xml;
});

/**
 * Attempt to get external IP from service (wan).
 * @returns {Promise}
 */

UPNPService.prototype.getExternalIP = co(function* getExternalIP() {
  var action = 'GetExternalIPAddress';
  var xml = yield this.soapRequest(action, []);
  var ip = findIP(xml);

  if (!ip)
    throw new Error('Could not find external IP.');

  return ip;
});

/**
 * Attempt to add port mapping to local IP.
 * @param {String} remote - Remote IP.
 * @param {Number} src - Remote port.
 * @param {Number} dest - Local port.
 * @returns {Promise}
 */

UPNPService.prototype.addPortMapping = co(function* addPortMapping(remote, src, dest) {
  var action = 'AddPortMapping';
  var local = IP.getPrivate();
  var xml, child;

  if (local.length === 0)
    throw new Error('Cannot determine local IP.');

  xml = yield this.soapRequest(action, [
    ['NewRemoteHost', remote],
    ['NewExternalPort', src],
    ['NewProtocol', 'TCP'],
    ['NewInternalClient', local[0]],
    ['NewInternalPort', dest],
    ['NewEnabled', 'True'],
    ['NewPortMappingDescription', 'upnp:bcoin'],
    ['NewLeaseDuration', 0]
  ]);

  child = xml.find('AddPortMappingResponse');

  if (!child)
    throw new Error('Port mapping failed.');

  return child.text;
});

/**
 * Attempt to remove port mapping from local IP.
 * @param {String} remote - Remote IP.
 * @param {Number} port - Remote port.
 * @returns {Promise}
 */

UPNPService.prototype.removePortMapping = co(function* removePortMapping(remote, port) {
  var action = 'DeletePortMapping';
  var xml, child;

  xml = yield this.soapRequest(action, [
    ['NewRemoteHost', remote],
    ['NewExternalPort', port],
    ['NewProtocol', 'TCP']
  ]);

  child = xml.find('DeletePortMappingResponse');

  if (!child)
    throw new Error('Port unmapping failed.');

  return child.text;
});

/**
 * XML Element
 * @constructor
 * @ignore
 */

function XMLElement(name) {
  this.name = name;
  this.type = name.replace(/^[^:]:/, '');
  this.children = [];
  this.text = '';
}

/**
 * Insantiate element from raw XML.
 * @param {String} xml
 * @returns {XMLElement}
 */

XMLElement.fromRaw = function fromRaw(xml) {
  var sentinel = new XMLElement('');
  var current = sentinel;
  var stack = [];
  var decl = false;
  var m, element, name, text, trailing;

  stack.push(sentinel);

  while (xml.length) {
    if (m = /^<\?xml[^<>]*\?>/i.exec(xml)) {
      xml = xml.substring(m[0].length);
      assert(current === sentinel, 'XML declaration inside element.');
      assert(!decl, 'XML declaration seen twice.');
      decl = true;
      continue;
    }

    if (m = /^<([\w:]+)[^<>]*?(\/?)>/i.exec(xml)) {
      xml = xml.substring(m[0].length);
      name = m[1];
      trailing = m[2] === '/';
      element = new XMLElement(name);

      if (trailing) {
        current.add(element);
        continue;
      }

      stack.push(element);
      current.add(element);
      current = element;

      continue;
    }

    if (m = /^<\/([\w:]+)[^<>]*>/i.exec(xml)) {
      xml = xml.substring(m[0].length);
      name = m[1];
      assert(stack.length !== 1, 'No start tag.');
      element = stack.pop();
      assert(element.name === name, 'Tag mismatch.');
      current = stack[stack.length - 1];
      if (current === sentinel)
        break;
      continue;
    }

    if (m = /^([^<]+)/i.exec(xml)) {
      xml = xml.substring(m[0].length);
      text = m[1];
      current.text = text.trim();
      continue;
    }

    throw new Error('XML parse error.');
  }

  assert(sentinel.children.length > 0, 'No root element.');

  return sentinel.children[0];
};

/**
 * Push element onto children.
 * @param {XMLElement} child
 * @returns {Number}
 */

XMLElement.prototype.add = function add(child) {
  return this.children.push(child);
};

/**
 * Collect all descendants with matching name.
 * @param {String} name
 * @returns {XMLElement[]}
 */

XMLElement.prototype.collect = function collect(name) {
  return this._collect(name, []);
};

/**
 * Collect all descendants with matching name.
 * @private
 * @param {String} name
 * @param {XMLElement[]} result
 * @returns {XMLElement[]}
 */

XMLElement.prototype._collect = function _collect(name, result) {
  var i, child;

  for (i = 0; i < this.children.length; i++) {
    child = this.children[i];

    if (child.type === name) {
      result.push(child);
      continue;
    }

    child._collect(name, result);
  }

  return result;
};

/**
 * Find child element with matching name.
 * @param {String} name
 * @returns {XMLElement|null}
 */

XMLElement.prototype.find = function find(name) {
  var i, child;

  for (i = 0; i < this.children.length; i++) {
    child = this.children[i];

    if (child.type === name)
      return child;

    child = child.find(name);

    if (child)
      return child;
  }
};

/*
 * XML Helpers
 */

function parseServices(el) {
  var children = el.collect('service');
  var services = [];
  var i, child;

  for (i = 0; i < children.length; i++) {
    child = children[i];
    services.push(parseService(children[i]));
  }

  return services;
}

function parseService(el) {
  var service = {};
  var i, child;

  for (i = 0; i < el.children.length; i++) {
    child = el.children[i];

    if (child.children.length > 0)
      continue;

    service[child.type] = child.text;
  }

  return service;
}

function findService(services, name) {
  var i, service;

  for (i = 0; i < services.length; i++) {
    service = services[i];
    if (service.serviceType === name)
      return service;
  }
}

function extractServices(services, targets) {
  var i, name, service;

  for (i = 0; i < targets.length; i++) {
    name = targets[i];
    service = findService(services, name);
    if (service)
      return service;
  }
}

function findIP(el) {
  var child = el.find('NewExternalIPAddress');

  if (!child)
    return;

  return IP.normalize(child.text);
}

function findError(el) {
  var child = el.find('UPnPError');
  var code = -1;
  var desc = 'Unknown';
  var ccode, cdesc;

  if (!child)
    return;

  ccode = child.find('errorCode');
  cdesc = child.find('errorDescription');

  if (ccode && /^\d+$/.test(ccode.text))
    code = +ccode.text;

  if (cdesc)
    desc = cdesc.text;

  return new Error('UPnPError: ' + desc + ' (' + code + ')');
}

/*
 * Helpers
 */

function parseHost(uri) {
  var data = url.parse(uri);

  assert(data.protocol === 'http:' || data.protocol === 'https:',
    'Bad URL for location.');

  return data.protocol + '//' + data.host;
}

function prependHost(host, uri) {
  if (uri.indexOf('://') === -1) {
    if (uri[0] !== '/')
      uri = '/' + uri;
    uri = host + uri;
  }
  return uri;
}

/*
 * Expose
 */

module.exports = UPNP;
