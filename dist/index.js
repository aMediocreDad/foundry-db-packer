import { createRequire as yix6bKft } from 'module';const require = yix6bKft(import.meta.url);
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined")
    return require.apply(this, arguments);
  throw new Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS({
  "node_modules/@actions/core/lib/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toCommandProperties = exports.toCommandValue = void 0;
    function toCommandValue(input) {
      if (input === null || input === void 0) {
        return "";
      } else if (typeof input === "string" || input instanceof String) {
        return input;
      }
      return JSON.stringify(input);
    }
    exports.toCommandValue = toCommandValue;
    function toCommandProperties(annotationProperties) {
      if (!Object.keys(annotationProperties).length) {
        return {};
      }
      return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
      };
    }
    exports.toCommandProperties = toCommandProperties;
  }
});

// node_modules/@actions/core/lib/command.js
var require_command = __commonJS({
  "node_modules/@actions/core/lib/command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.issue = exports.issueCommand = void 0;
    var os2 = __importStar(__require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, properties, message) {
      const cmd = new Command(command, properties, message);
      process.stdout.write(cmd.toString() + os2.EOL);
    }
    exports.issueCommand = issueCommand;
    function issue(name, message = "") {
      issueCommand(name, {}, message);
    }
    exports.issue = issue;
    var CMD_STRING = "::";
    var Command = class {
      constructor(command, properties, message) {
        if (!command) {
          command = "missing.command";
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
      }
      toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
          cmdStr += " ";
          let first = true;
          for (const key in this.properties) {
            if (this.properties.hasOwnProperty(key)) {
              const val = this.properties[key];
              if (val) {
                if (first) {
                  first = false;
                } else {
                  cmdStr += ",";
                }
                cmdStr += `${key}=${escapeProperty(val)}`;
              }
            }
          }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
      }
    };
    function escapeData(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    }
    function escapeProperty(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
    }
  }
});

// node_modules/uuid/dist/esm-node/rng.js
import crypto from "crypto";
function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    crypto.randomFillSync(rnds8Pool);
    poolPtr = 0;
  }
  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}
var rnds8Pool, poolPtr;
var init_rng = __esm({
  "node_modules/uuid/dist/esm-node/rng.js"() {
    rnds8Pool = new Uint8Array(256);
    poolPtr = rnds8Pool.length;
  }
});

// node_modules/uuid/dist/esm-node/regex.js
var regex_default;
var init_regex = __esm({
  "node_modules/uuid/dist/esm-node/regex.js"() {
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// node_modules/uuid/dist/esm-node/validate.js
function validate(uuid) {
  return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default;
var init_validate = __esm({
  "node_modules/uuid/dist/esm-node/validate.js"() {
    init_regex();
    validate_default = validate;
  }
});

// node_modules/uuid/dist/esm-node/stringify.js
function stringify(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
var byteToHex, stringify_default;
var init_stringify = __esm({
  "node_modules/uuid/dist/esm-node/stringify.js"() {
    init_validate();
    byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// node_modules/uuid/dist/esm-node/v1.js
function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  let msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  let nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  const tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "node_modules/uuid/dist/esm-node/v1.js"() {
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// node_modules/uuid/dist/esm-node/parse.js
function parse(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  let v;
  const arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "node_modules/uuid/dist/esm-node/parse.js"() {
    init_validate();
    parse_default = parse;
  }
});

// node_modules/uuid/dist/esm-node/v35.js
function stringToBytes(str2) {
  str2 = unescape(encodeURIComponent(str2));
  const bytes = [];
  for (let i = 0; i < str2.length; ++i) {
    bytes.push(str2.charCodeAt(i));
  }
  return bytes;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 15 | version2;
    bytes[8] = bytes[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }
      return buf;
    }
    return stringify_default(bytes);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "node_modules/uuid/dist/esm-node/v35.js"() {
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// node_modules/uuid/dist/esm-node/md5.js
import crypto2 from "crypto";
function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return crypto2.createHash("md5").update(bytes).digest();
}
var md5_default;
var init_md5 = __esm({
  "node_modules/uuid/dist/esm-node/md5.js"() {
    md5_default = md5;
  }
});

// node_modules/uuid/dist/esm-node/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "node_modules/uuid/dist/esm-node/v3.js"() {
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// node_modules/uuid/dist/esm-node/v4.js
function v4(options, buf, offset) {
  options = options || {};
  const rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "node_modules/uuid/dist/esm-node/v4.js"() {
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// node_modules/uuid/dist/esm-node/sha1.js
import crypto3 from "crypto";
function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return crypto3.createHash("sha1").update(bytes).digest();
}
var sha1_default;
var init_sha1 = __esm({
  "node_modules/uuid/dist/esm-node/sha1.js"() {
    sha1_default = sha1;
  }
});

// node_modules/uuid/dist/esm-node/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "node_modules/uuid/dist/esm-node/v5.js"() {
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// node_modules/uuid/dist/esm-node/nil.js
var nil_default;
var init_nil = __esm({
  "node_modules/uuid/dist/esm-node/nil.js"() {
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// node_modules/uuid/dist/esm-node/version.js
function version(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "node_modules/uuid/dist/esm-node/version.js"() {
    init_validate();
    version_default = version;
  }
});

// node_modules/uuid/dist/esm-node/index.js
var esm_node_exports = {};
__export(esm_node_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_node = __esm({
  "node_modules/uuid/dist/esm-node/index.js"() {
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS({
  "node_modules/@actions/core/lib/file-command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.prepareKeyValueMessage = exports.issueFileCommand = void 0;
    var fs2 = __importStar(__require("fs"));
    var os2 = __importStar(__require("os"));
    var uuid_1 = (init_esm_node(), __toCommonJS(esm_node_exports));
    var utils_1 = require_utils();
    function issueFileCommand(command, message) {
      const filePath = process.env[`GITHUB_${command}`];
      if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
      }
      if (!fs2.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
      }
      fs2.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os2.EOL}`, {
        encoding: "utf8"
      });
    }
    exports.issueFileCommand = issueFileCommand;
    function prepareKeyValueMessage(key, value) {
      const delimiter = `ghadelimiter_${uuid_1.v4()}`;
      const convertedValue = utils_1.toCommandValue(value);
      if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
      }
      if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
      }
      return `${key}<<${delimiter}${os2.EOL}${convertedValue}${os2.EOL}${delimiter}`;
    }
    exports.prepareKeyValueMessage = prepareKeyValueMessage;
  }
});

// node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS({
  "node_modules/@actions/http-client/lib/proxy.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.checkBypass = exports.getProxyUrl = void 0;
    function getProxyUrl(reqUrl) {
      const usingSsl = reqUrl.protocol === "https:";
      if (checkBypass(reqUrl)) {
        return void 0;
      }
      const proxyVar = (() => {
        if (usingSsl) {
          return process.env["https_proxy"] || process.env["HTTPS_PROXY"];
        } else {
          return process.env["http_proxy"] || process.env["HTTP_PROXY"];
        }
      })();
      if (proxyVar) {
        return new URL(proxyVar);
      } else {
        return void 0;
      }
    }
    exports.getProxyUrl = getProxyUrl;
    function checkBypass(reqUrl) {
      if (!reqUrl.hostname) {
        return false;
      }
      const reqHost = reqUrl.hostname;
      if (isLoopbackAddress(reqHost)) {
        return true;
      }
      const noProxy = process.env["no_proxy"] || process.env["NO_PROXY"] || "";
      if (!noProxy) {
        return false;
      }
      let reqPort;
      if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
      } else if (reqUrl.protocol === "http:") {
        reqPort = 80;
      } else if (reqUrl.protocol === "https:") {
        reqPort = 443;
      }
      const upperReqHosts = [reqUrl.hostname.toUpperCase()];
      if (typeof reqPort === "number") {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
      }
      for (const upperNoProxyItem of noProxy.split(",").map((x) => x.trim().toUpperCase()).filter((x) => x)) {
        if (upperNoProxyItem === "*" || upperReqHosts.some((x) => x === upperNoProxyItem || x.endsWith(`.${upperNoProxyItem}`) || upperNoProxyItem.startsWith(".") && x.endsWith(`${upperNoProxyItem}`))) {
          return true;
        }
      }
      return false;
    }
    exports.checkBypass = checkBypass;
    function isLoopbackAddress(host) {
      const hostLower = host.toLowerCase();
      return hostLower === "localhost" || hostLower.startsWith("127.") || hostLower.startsWith("[::1]") || hostLower.startsWith("[0:0:0:0:0:0:0:1]");
    }
  }
});

// node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS({
  "node_modules/tunnel/lib/tunnel.js"(exports) {
    "use strict";
    var net = __require("net");
    var tls = __require("tls");
    var http = __require("http");
    var https = __require("https");
    var events = __require("events");
    var assert = __require("assert");
    var util = __require("util");
    exports.httpOverHttp = httpOverHttp;
    exports.httpsOverHttp = httpsOverHttp;
    exports.httpOverHttps = httpOverHttps;
    exports.httpsOverHttps = httpsOverHttps;
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      return agent;
    }
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      return agent;
    }
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function TunnelingAgent(options) {
      var self = this;
      self.options = options || {};
      self.proxyOptions = self.options.proxy || {};
      self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
      self.requests = [];
      self.sockets = [];
      self.on("free", function onFree(socket, host, port, localAddress) {
        var options2 = toOptions(host, port, localAddress);
        for (var i = 0, len = self.requests.length; i < len; ++i) {
          var pending = self.requests[i];
          if (pending.host === options2.host && pending.port === options2.port) {
            self.requests.splice(i, 1);
            pending.request.onSocket(socket);
            return;
          }
        }
        socket.destroy();
        self.removeSocket(socket);
      });
    }
    util.inherits(TunnelingAgent, events.EventEmitter);
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
      var self = this;
      var options = mergeOptions({ request: req }, self.options, toOptions(host, port, localAddress));
      if (self.sockets.length >= this.maxSockets) {
        self.requests.push(options);
        return;
      }
      self.createSocket(options, function(socket) {
        socket.on("free", onFree);
        socket.on("close", onCloseOrRemove);
        socket.on("agentRemove", onCloseOrRemove);
        req.onSocket(socket);
        function onFree() {
          self.emit("free", socket, options);
        }
        function onCloseOrRemove(err) {
          self.removeSocket(socket);
          socket.removeListener("free", onFree);
          socket.removeListener("close", onCloseOrRemove);
          socket.removeListener("agentRemove", onCloseOrRemove);
        }
      });
    };
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self = this;
      var placeholder = {};
      self.sockets.push(placeholder);
      var connectOptions = mergeOptions({}, self.proxyOptions, {
        method: "CONNECT",
        path: options.host + ":" + options.port,
        agent: false,
        headers: {
          host: options.host + ":" + options.port
        }
      });
      if (options.localAddress) {
        connectOptions.localAddress = options.localAddress;
      }
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {};
        connectOptions.headers["Proxy-Authorization"] = "Basic " + new Buffer(connectOptions.proxyAuth).toString("base64");
      }
      debug("making CONNECT request");
      var connectReq = self.request(connectOptions);
      connectReq.useChunkedEncodingByDefault = false;
      connectReq.once("response", onResponse);
      connectReq.once("upgrade", onUpgrade);
      connectReq.once("connect", onConnect);
      connectReq.once("error", onError);
      connectReq.end();
      function onResponse(res) {
        res.upgrade = true;
      }
      function onUpgrade(res, socket, head) {
        process.nextTick(function() {
          onConnect(res, socket, head);
        });
      }
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners();
        socket.removeAllListeners();
        if (res.statusCode !== 200) {
          debug(
            "tunneling socket could not be established, statusCode=%d",
            res.statusCode
          );
          socket.destroy();
          var error2 = new Error("tunneling socket could not be established, statusCode=" + res.statusCode);
          error2.code = "ECONNRESET";
          options.request.emit("error", error2);
          self.removeSocket(placeholder);
          return;
        }
        if (head.length > 0) {
          debug("got illegal response body from proxy");
          socket.destroy();
          var error2 = new Error("got illegal response body from proxy");
          error2.code = "ECONNRESET";
          options.request.emit("error", error2);
          self.removeSocket(placeholder);
          return;
        }
        debug("tunneling connection has established");
        self.sockets[self.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
      function onError(cause) {
        connectReq.removeAllListeners();
        debug(
          "tunneling socket could not be established, cause=%s\n",
          cause.message,
          cause.stack
        );
        var error2 = new Error("tunneling socket could not be established, cause=" + cause.message);
        error2.code = "ECONNRESET";
        options.request.emit("error", error2);
        self.removeSocket(placeholder);
      }
    };
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket);
      if (pos === -1) {
        return;
      }
      this.sockets.splice(pos, 1);
      var pending = this.requests.shift();
      if (pending) {
        this.createSocket(pending, function(socket2) {
          pending.request.onSocket(socket2);
        });
      }
    };
    function createSecureSocket(options, cb) {
      var self = this;
      TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
        var hostHeader = options.request.getHeader("host");
        var tlsOptions = mergeOptions({}, self.options, {
          socket,
          servername: hostHeader ? hostHeader.replace(/:.*$/, "") : options.host
        });
        var secureSocket = tls.connect(0, tlsOptions);
        self.sockets[self.sockets.indexOf(socket)] = secureSocket;
        cb(secureSocket);
      });
    }
    function toOptions(host, port, localAddress) {
      if (typeof host === "string") {
        return {
          host,
          port,
          localAddress
        };
      }
      return host;
    }
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i];
        if (typeof overrides === "object") {
          var keys = Object.keys(overrides);
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j];
            if (overrides[k] !== void 0) {
              target[k] = overrides[k];
            }
          }
        }
      }
      return target;
    }
    var debug;
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug = function() {
        var args = Array.prototype.slice.call(arguments);
        if (typeof args[0] === "string") {
          args[0] = "TUNNEL: " + args[0];
        } else {
          args.unshift("TUNNEL:");
        }
        console.error.apply(console, args);
      };
    } else {
      debug = function() {
      };
    }
    exports.debug = debug;
  }
});

// node_modules/tunnel/index.js
var require_tunnel2 = __commonJS({
  "node_modules/tunnel/index.js"(exports, module) {
    module.exports = require_tunnel();
  }
});

// node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS({
  "node_modules/@actions/http-client/lib/index.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.HttpClient = exports.isHttps = exports.HttpClientResponse = exports.HttpClientError = exports.getProxyUrl = exports.MediaTypes = exports.Headers = exports.HttpCodes = void 0;
    var http = __importStar(__require("http"));
    var https = __importStar(__require("https"));
    var pm = __importStar(require_proxy());
    var tunnel = __importStar(require_tunnel2());
    var HttpCodes;
    (function(HttpCodes2) {
      HttpCodes2[HttpCodes2["OK"] = 200] = "OK";
      HttpCodes2[HttpCodes2["MultipleChoices"] = 300] = "MultipleChoices";
      HttpCodes2[HttpCodes2["MovedPermanently"] = 301] = "MovedPermanently";
      HttpCodes2[HttpCodes2["ResourceMoved"] = 302] = "ResourceMoved";
      HttpCodes2[HttpCodes2["SeeOther"] = 303] = "SeeOther";
      HttpCodes2[HttpCodes2["NotModified"] = 304] = "NotModified";
      HttpCodes2[HttpCodes2["UseProxy"] = 305] = "UseProxy";
      HttpCodes2[HttpCodes2["SwitchProxy"] = 306] = "SwitchProxy";
      HttpCodes2[HttpCodes2["TemporaryRedirect"] = 307] = "TemporaryRedirect";
      HttpCodes2[HttpCodes2["PermanentRedirect"] = 308] = "PermanentRedirect";
      HttpCodes2[HttpCodes2["BadRequest"] = 400] = "BadRequest";
      HttpCodes2[HttpCodes2["Unauthorized"] = 401] = "Unauthorized";
      HttpCodes2[HttpCodes2["PaymentRequired"] = 402] = "PaymentRequired";
      HttpCodes2[HttpCodes2["Forbidden"] = 403] = "Forbidden";
      HttpCodes2[HttpCodes2["NotFound"] = 404] = "NotFound";
      HttpCodes2[HttpCodes2["MethodNotAllowed"] = 405] = "MethodNotAllowed";
      HttpCodes2[HttpCodes2["NotAcceptable"] = 406] = "NotAcceptable";
      HttpCodes2[HttpCodes2["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
      HttpCodes2[HttpCodes2["RequestTimeout"] = 408] = "RequestTimeout";
      HttpCodes2[HttpCodes2["Conflict"] = 409] = "Conflict";
      HttpCodes2[HttpCodes2["Gone"] = 410] = "Gone";
      HttpCodes2[HttpCodes2["TooManyRequests"] = 429] = "TooManyRequests";
      HttpCodes2[HttpCodes2["InternalServerError"] = 500] = "InternalServerError";
      HttpCodes2[HttpCodes2["NotImplemented"] = 501] = "NotImplemented";
      HttpCodes2[HttpCodes2["BadGateway"] = 502] = "BadGateway";
      HttpCodes2[HttpCodes2["ServiceUnavailable"] = 503] = "ServiceUnavailable";
      HttpCodes2[HttpCodes2["GatewayTimeout"] = 504] = "GatewayTimeout";
    })(HttpCodes = exports.HttpCodes || (exports.HttpCodes = {}));
    var Headers;
    (function(Headers2) {
      Headers2["Accept"] = "accept";
      Headers2["ContentType"] = "content-type";
    })(Headers = exports.Headers || (exports.Headers = {}));
    var MediaTypes;
    (function(MediaTypes2) {
      MediaTypes2["ApplicationJson"] = "application/json";
    })(MediaTypes = exports.MediaTypes || (exports.MediaTypes = {}));
    function getProxyUrl(serverUrl) {
      const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
      return proxyUrl ? proxyUrl.href : "";
    }
    exports.getProxyUrl = getProxyUrl;
    var HttpRedirectCodes = [
      HttpCodes.MovedPermanently,
      HttpCodes.ResourceMoved,
      HttpCodes.SeeOther,
      HttpCodes.TemporaryRedirect,
      HttpCodes.PermanentRedirect
    ];
    var HttpResponseRetryCodes = [
      HttpCodes.BadGateway,
      HttpCodes.ServiceUnavailable,
      HttpCodes.GatewayTimeout
    ];
    var RetryableHttpVerbs = ["OPTIONS", "GET", "DELETE", "HEAD"];
    var ExponentialBackoffCeiling = 10;
    var ExponentialBackoffTimeSlice = 5;
    var HttpClientError = class extends Error {
      constructor(message, statusCode) {
        super(message);
        this.name = "HttpClientError";
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, HttpClientError.prototype);
      }
    };
    exports.HttpClientError = HttpClientError;
    var HttpClientResponse = class {
      constructor(message) {
        this.message = message;
      }
      readBody() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2) => __awaiter(this, void 0, void 0, function* () {
            let output = Buffer.alloc(0);
            this.message.on("data", (chunk) => {
              output = Buffer.concat([output, chunk]);
            });
            this.message.on("end", () => {
              resolve2(output.toString());
            });
          }));
        });
      }
    };
    exports.HttpClientResponse = HttpClientResponse;
    function isHttps(requestUrl) {
      const parsedUrl = new URL(requestUrl);
      return parsedUrl.protocol === "https:";
    }
    exports.isHttps = isHttps;
    var HttpClient = class {
      constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
          if (requestOptions.ignoreSslError != null) {
            this._ignoreSslError = requestOptions.ignoreSslError;
          }
          this._socketTimeout = requestOptions.socketTimeout;
          if (requestOptions.allowRedirects != null) {
            this._allowRedirects = requestOptions.allowRedirects;
          }
          if (requestOptions.allowRedirectDowngrade != null) {
            this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
          }
          if (requestOptions.maxRedirects != null) {
            this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
          }
          if (requestOptions.keepAlive != null) {
            this._keepAlive = requestOptions.keepAlive;
          }
          if (requestOptions.allowRetries != null) {
            this._allowRetries = requestOptions.allowRetries;
          }
          if (requestOptions.maxRetries != null) {
            this._maxRetries = requestOptions.maxRetries;
          }
        }
      }
      options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("OPTIONS", requestUrl, null, additionalHeaders || {});
        });
      }
      get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("GET", requestUrl, null, additionalHeaders || {});
        });
      }
      del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("DELETE", requestUrl, null, additionalHeaders || {});
        });
      }
      post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("POST", requestUrl, data, additionalHeaders || {});
        });
      }
      patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PATCH", requestUrl, data, additionalHeaders || {});
        });
      }
      put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PUT", requestUrl, data, additionalHeaders || {});
        });
      }
      head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("HEAD", requestUrl, null, additionalHeaders || {});
        });
      }
      sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request(verb, requestUrl, stream, additionalHeaders);
        });
      }
      /**
       * Gets a typed object from an endpoint
       * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
       */
      getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          const res = yield this.get(requestUrl, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.post(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.put(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.patch(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      /**
       * Makes a raw http request.
       * All other methods such as get, post, patch, and request ultimately call this.
       * Prefer get, del, post and patch
       */
      request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._disposed) {
            throw new Error("Client has already been disposed.");
          }
          const parsedUrl = new URL(requestUrl);
          let info2 = this._prepareRequest(verb, parsedUrl, headers);
          const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb) ? this._maxRetries + 1 : 1;
          let numTries = 0;
          let response;
          do {
            response = yield this.requestRaw(info2, data);
            if (response && response.message && response.message.statusCode === HttpCodes.Unauthorized) {
              let authenticationHandler;
              for (const handler of this.handlers) {
                if (handler.canHandleAuthentication(response)) {
                  authenticationHandler = handler;
                  break;
                }
              }
              if (authenticationHandler) {
                return authenticationHandler.handleAuthentication(this, info2, data);
              } else {
                return response;
              }
            }
            let redirectsRemaining = this._maxRedirects;
            while (response.message.statusCode && HttpRedirectCodes.includes(response.message.statusCode) && this._allowRedirects && redirectsRemaining > 0) {
              const redirectUrl = response.message.headers["location"];
              if (!redirectUrl) {
                break;
              }
              const parsedRedirectUrl = new URL(redirectUrl);
              if (parsedUrl.protocol === "https:" && parsedUrl.protocol !== parsedRedirectUrl.protocol && !this._allowRedirectDowngrade) {
                throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
              }
              yield response.readBody();
              if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                for (const header in headers) {
                  if (header.toLowerCase() === "authorization") {
                    delete headers[header];
                  }
                }
              }
              info2 = this._prepareRequest(verb, parsedRedirectUrl, headers);
              response = yield this.requestRaw(info2, data);
              redirectsRemaining--;
            }
            if (!response.message.statusCode || !HttpResponseRetryCodes.includes(response.message.statusCode)) {
              return response;
            }
            numTries += 1;
            if (numTries < maxTries) {
              yield response.readBody();
              yield this._performExponentialBackoff(numTries);
            }
          } while (numTries < maxTries);
          return response;
        });
      }
      /**
       * Needs to be called if keepAlive is set to true in request options.
       */
      dispose() {
        if (this._agent) {
          this._agent.destroy();
        }
        this._disposed = true;
      }
      /**
       * Raw request.
       * @param info
       * @param data
       */
      requestRaw(info2, data) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2, reject) => {
            function callbackForResult(err, res) {
              if (err) {
                reject(err);
              } else if (!res) {
                reject(new Error("Unknown error"));
              } else {
                resolve2(res);
              }
            }
            this.requestRawWithCallback(info2, data, callbackForResult);
          });
        });
      }
      /**
       * Raw request with callback.
       * @param info
       * @param data
       * @param onResult
       */
      requestRawWithCallback(info2, data, onResult) {
        if (typeof data === "string") {
          if (!info2.options.headers) {
            info2.options.headers = {};
          }
          info2.options.headers["Content-Length"] = Buffer.byteLength(data, "utf8");
        }
        let callbackCalled = false;
        function handleResult(err, res) {
          if (!callbackCalled) {
            callbackCalled = true;
            onResult(err, res);
          }
        }
        const req = info2.httpModule.request(info2.options, (msg) => {
          const res = new HttpClientResponse(msg);
          handleResult(void 0, res);
        });
        let socket;
        req.on("socket", (sock) => {
          socket = sock;
        });
        req.setTimeout(this._socketTimeout || 3 * 6e4, () => {
          if (socket) {
            socket.end();
          }
          handleResult(new Error(`Request timeout: ${info2.options.path}`));
        });
        req.on("error", function(err) {
          handleResult(err);
        });
        if (data && typeof data === "string") {
          req.write(data, "utf8");
        }
        if (data && typeof data !== "string") {
          data.on("close", function() {
            req.end();
          });
          data.pipe(req);
        } else {
          req.end();
        }
      }
      /**
       * Gets an http agent. This function is useful when you need an http agent that handles
       * routing through a proxy server - depending upon the url and proxy environment variables.
       * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
       */
      getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
      }
      _prepareRequest(method, requestUrl, headers) {
        const info2 = {};
        info2.parsedUrl = requestUrl;
        const usingSsl = info2.parsedUrl.protocol === "https:";
        info2.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info2.options = {};
        info2.options.host = info2.parsedUrl.hostname;
        info2.options.port = info2.parsedUrl.port ? parseInt(info2.parsedUrl.port) : defaultPort;
        info2.options.path = (info2.parsedUrl.pathname || "") + (info2.parsedUrl.search || "");
        info2.options.method = method;
        info2.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
          info2.options.headers["user-agent"] = this.userAgent;
        }
        info2.options.agent = this._getAgent(info2.parsedUrl);
        if (this.handlers) {
          for (const handler of this.handlers) {
            handler.prepareRequest(info2.options);
          }
        }
        return info2;
      }
      _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
          return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
      }
      _getExistingOrDefaultHeader(additionalHeaders, header, _default2) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
          clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default2;
      }
      _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
          agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
          agent = this._agent;
        }
        if (agent) {
          return agent;
        }
        const usingSsl = parsedUrl.protocol === "https:";
        let maxSockets = 100;
        if (this.requestOptions) {
          maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        if (proxyUrl && proxyUrl.hostname) {
          const agentOptions = {
            maxSockets,
            keepAlive: this._keepAlive,
            proxy: Object.assign(Object.assign({}, (proxyUrl.username || proxyUrl.password) && {
              proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
            }), { host: proxyUrl.hostname, port: proxyUrl.port })
          };
          let tunnelAgent;
          const overHttps = proxyUrl.protocol === "https:";
          if (usingSsl) {
            tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
          } else {
            tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
          }
          agent = tunnelAgent(agentOptions);
          this._proxyAgent = agent;
        }
        if (this._keepAlive && !agent) {
          const options = { keepAlive: this._keepAlive, maxSockets };
          agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
          this._agent = agent;
        }
        if (!agent) {
          agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
          agent.options = Object.assign(agent.options || {}, {
            rejectUnauthorized: false
          });
        }
        return agent;
      }
      _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
          retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
          const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
          return new Promise((resolve2) => setTimeout(() => resolve2(), ms));
        });
      }
      _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2, reject) => __awaiter(this, void 0, void 0, function* () {
            const statusCode = res.message.statusCode || 0;
            const response = {
              statusCode,
              result: null,
              headers: {}
            };
            if (statusCode === HttpCodes.NotFound) {
              resolve2(response);
            }
            function dateTimeDeserializer(key, value) {
              if (typeof value === "string") {
                const a = new Date(value);
                if (!isNaN(a.valueOf())) {
                  return a;
                }
              }
              return value;
            }
            let obj;
            let contents;
            try {
              contents = yield res.readBody();
              if (contents && contents.length > 0) {
                if (options && options.deserializeDates) {
                  obj = JSON.parse(contents, dateTimeDeserializer);
                } else {
                  obj = JSON.parse(contents);
                }
                response.result = obj;
              }
              response.headers = res.message.headers;
            } catch (err) {
            }
            if (statusCode > 299) {
              let msg;
              if (obj && obj.message) {
                msg = obj.message;
              } else if (contents && contents.length > 0) {
                msg = contents;
              } else {
                msg = `Failed request: (${statusCode})`;
              }
              const err = new HttpClientError(msg, statusCode);
              err.result = response.result;
              reject(err);
            } else {
              resolve2(response);
            }
          }));
        });
      }
    };
    exports.HttpClient = HttpClient;
    var lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => (c[k.toLowerCase()] = obj[k], c), {});
  }
});

// node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS({
  "node_modules/@actions/http-client/lib/auth.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.PersonalAccessTokenCredentialHandler = exports.BearerCredentialHandler = exports.BasicCredentialHandler = void 0;
    var BasicCredentialHandler = class {
      constructor(username, password) {
        this.username = username;
        this.password = password;
      }
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BasicCredentialHandler = BasicCredentialHandler;
    var BearerCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Bearer ${this.token}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BearerCredentialHandler = BearerCredentialHandler;
    var PersonalAccessTokenCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
  }
});

// node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS({
  "node_modules/@actions/core/lib/oidc-utils.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.OidcClient = void 0;
    var http_client_1 = require_lib();
    var auth_1 = require_auth();
    var core_1 = require_core();
    var OidcClient = class {
      static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
          allowRetries: allowRetry,
          maxRetries: maxRetry
        };
        return new http_client_1.HttpClient("actions/oidc-client", [new auth_1.BearerCredentialHandler(OidcClient.getRequestToken())], requestOptions);
      }
      static getRequestToken() {
        const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
        if (!token) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
        }
        return token;
      }
      static getIDTokenUrl() {
        const runtimeUrl = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
        if (!runtimeUrl) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
        }
        return runtimeUrl;
      }
      static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
          const httpclient = OidcClient.createHttpClient();
          const res = yield httpclient.getJson(id_token_url).catch((error2) => {
            throw new Error(`Failed to get ID Token.

        Error Code : ${error2.statusCode}

        Error Message: ${error2.result.message}`);
          });
          const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
          if (!id_token) {
            throw new Error("Response json body do not have ID Token field");
          }
          return id_token;
        });
      }
      static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
          try {
            let id_token_url = OidcClient.getIDTokenUrl();
            if (audience) {
              const encodedAudience = encodeURIComponent(audience);
              id_token_url = `${id_token_url}&audience=${encodedAudience}`;
            }
            core_1.debug(`ID token url is ${id_token_url}`);
            const id_token = yield OidcClient.getCall(id_token_url);
            core_1.setSecret(id_token);
            return id_token;
          } catch (error2) {
            throw new Error(`Error message: ${error2.message}`);
          }
        });
      }
    };
    exports.OidcClient = OidcClient;
  }
});

// node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS({
  "node_modules/@actions/core/lib/summary.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.summary = exports.markdownSummary = exports.SUMMARY_DOCS_URL = exports.SUMMARY_ENV_VAR = void 0;
    var os_1 = __require("os");
    var fs_1 = __require("fs");
    var { access, appendFile, writeFile } = fs_1.promises;
    exports.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
    exports.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    var Summary = class {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._filePath) {
            return this._filePath;
          }
          const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR];
          if (!pathFromEnv) {
            throw new Error(`Unable to find environment variable for $${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          }
          try {
            yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
          } catch (_a) {
            throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
          }
          this._filePath = pathFromEnv;
          return this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
        if (!content) {
          return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(options) {
        return __awaiter(this, void 0, void 0, function* () {
          const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
          const filePath = yield this.filePath();
          const writeFunc = overwrite ? writeFile : appendFile;
          yield writeFunc(filePath, this._buffer, { encoding: "utf8" });
          return this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return __awaiter(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: true });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        this._buffer = "";
        return this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(os_1.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(code, lang) {
        const attrs = Object.assign({}, lang && { lang });
        const element = this.wrap("pre", this.wrap("code", code), attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(items, ordered = false) {
        const tag = ordered ? "ol" : "ul";
        const listItems = items.map((item) => this.wrap("li", item)).join("");
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(rows) {
        const tableBody = rows.map((row) => {
          const cells = row.map((cell) => {
            if (typeof cell === "string") {
              return this.wrap("td", cell);
            }
            const { header, data, colspan, rowspan } = cell;
            const tag = header ? "th" : "td";
            const attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
            return this.wrap(tag, data, attrs);
          }).join("");
          return this.wrap("tr", cells);
        }).join("");
        const element = this.wrap("table", tableBody);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(label, content) {
        const element = this.wrap("details", this.wrap("summary", label) + content);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, width && { width }), height && { height });
        const element = this.wrap("img", null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag) ? tag : "h1";
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const element = this.wrap("hr", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const element = this.wrap("br", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(text, cite) {
        const attrs = Object.assign({}, cite && { cite });
        const element = this.wrap("blockquote", text, attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(text, href) {
        const element = this.wrap("a", text, { href });
        return this.addRaw(element).addEOL();
      }
    };
    var _summary = new Summary();
    exports.markdownSummary = _summary;
    exports.summary = _summary;
  }
});

// node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS({
  "node_modules/@actions/core/lib/path-utils.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = void 0;
    var path2 = __importStar(__require("path"));
    function toPosixPath(pth) {
      return pth.replace(/[\\]/g, "/");
    }
    exports.toPosixPath = toPosixPath;
    function toWin32Path(pth) {
      return pth.replace(/[/]/g, "\\");
    }
    exports.toWin32Path = toWin32Path;
    function toPlatformPath(pth) {
      return pth.replace(/[/\\]/g, path2.sep);
    }
    exports.toPlatformPath = toPlatformPath;
  }
});

// node_modules/@actions/core/lib/core.js
var require_core = __commonJS({
  "node_modules/@actions/core/lib/core.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getIDToken = exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.notice = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getMultilineInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
    var command_1 = require_command();
    var file_command_1 = require_file_command();
    var utils_1 = require_utils();
    var os2 = __importStar(__require("os"));
    var path2 = __importStar(__require("path"));
    var oidc_utils_1 = require_oidc_utils();
    var ExitCode;
    (function(ExitCode2) {
      ExitCode2[ExitCode2["Success"] = 0] = "Success";
      ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
    })(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
    function exportVariable(name, val) {
      const convertedVal = utils_1.toCommandValue(val);
      process.env[name] = convertedVal;
      const filePath = process.env["GITHUB_ENV"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("ENV", file_command_1.prepareKeyValueMessage(name, val));
      }
      command_1.issueCommand("set-env", { name }, convertedVal);
    }
    exports.exportVariable = exportVariable;
    function setSecret(secret) {
      command_1.issueCommand("add-mask", {}, secret);
    }
    exports.setSecret = setSecret;
    function addPath(inputPath) {
      const filePath = process.env["GITHUB_PATH"] || "";
      if (filePath) {
        file_command_1.issueFileCommand("PATH", inputPath);
      } else {
        command_1.issueCommand("add-path", {}, inputPath);
      }
      process.env["PATH"] = `${inputPath}${path2.delimiter}${process.env["PATH"]}`;
    }
    exports.addPath = addPath;
    function getInput2(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      if (options && options.trimWhitespace === false) {
        return val;
      }
      return val.trim();
    }
    exports.getInput = getInput2;
    function getMultilineInput(name, options) {
      const inputs = getInput2(name, options).split("\n").filter((x) => x !== "");
      if (options && options.trimWhitespace === false) {
        return inputs;
      }
      return inputs.map((input) => input.trim());
    }
    exports.getMultilineInput = getMultilineInput;
    function getBooleanInput2(name, options) {
      const trueValue = ["true", "True", "TRUE"];
      const falseValue = ["false", "False", "FALSE"];
      const val = getInput2(name, options);
      if (trueValue.includes(val))
        return true;
      if (falseValue.includes(val))
        return false;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    exports.getBooleanInput = getBooleanInput2;
    function setOutput(name, value) {
      const filePath = process.env["GITHUB_OUTPUT"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("OUTPUT", file_command_1.prepareKeyValueMessage(name, value));
      }
      process.stdout.write(os2.EOL);
      command_1.issueCommand("set-output", { name }, utils_1.toCommandValue(value));
    }
    exports.setOutput = setOutput;
    function setCommandEcho(enabled) {
      command_1.issue("echo", enabled ? "on" : "off");
    }
    exports.setCommandEcho = setCommandEcho;
    function setFailed2(message) {
      process.exitCode = ExitCode.Failure;
      error2(message);
    }
    exports.setFailed = setFailed2;
    function isDebug() {
      return process.env["RUNNER_DEBUG"] === "1";
    }
    exports.isDebug = isDebug;
    function debug(message) {
      command_1.issueCommand("debug", {}, message);
    }
    exports.debug = debug;
    function error2(message, properties = {}) {
      command_1.issueCommand("error", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.error = error2;
    function warning(message, properties = {}) {
      command_1.issueCommand("warning", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.warning = warning;
    function notice(message, properties = {}) {
      command_1.issueCommand("notice", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.notice = notice;
    function info2(message) {
      process.stdout.write(message + os2.EOL);
    }
    exports.info = info2;
    function startGroup(name) {
      command_1.issue("group", name);
    }
    exports.startGroup = startGroup;
    function endGroup() {
      command_1.issue("endgroup");
    }
    exports.endGroup = endGroup;
    function group(name, fn) {
      return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
          result = yield fn();
        } finally {
          endGroup();
        }
        return result;
      });
    }
    exports.group = group;
    function saveState(name, value) {
      const filePath = process.env["GITHUB_STATE"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("STATE", file_command_1.prepareKeyValueMessage(name, value));
      }
      command_1.issueCommand("save-state", { name }, utils_1.toCommandValue(value));
    }
    exports.saveState = saveState;
    function getState(name) {
      return process.env[`STATE_${name}`] || "";
    }
    exports.getState = getState;
    function getIDToken(aud) {
      return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
      });
    }
    exports.getIDToken = getIDToken;
    var summary_1 = require_summary();
    Object.defineProperty(exports, "summary", { enumerable: true, get: function() {
      return summary_1.summary;
    } });
    var summary_2 = require_summary();
    Object.defineProperty(exports, "markdownSummary", { enumerable: true, get: function() {
      return summary_2.markdownSummary;
    } });
    var path_utils_1 = require_path_utils();
    Object.defineProperty(exports, "toPosixPath", { enumerable: true, get: function() {
      return path_utils_1.toPosixPath;
    } });
    Object.defineProperty(exports, "toWin32Path", { enumerable: true, get: function() {
      return path_utils_1.toWin32Path;
    } });
    Object.defineProperty(exports, "toPlatformPath", { enumerable: true, get: function() {
      return path_utils_1.toPlatformPath;
    } });
  }
});

// node_modules/@seald-io/nedb/lib/utils.js
var require_utils2 = __commonJS({
  "node_modules/@seald-io/nedb/lib/utils.js"(exports, module) {
    var uniq = (array, iteratee) => {
      if (iteratee)
        return [...new Map(array.map((x) => [iteratee(x), x])).values()];
      else
        return [...new Set(array)];
    };
    var isObject2 = (arg) => typeof arg === "object" && arg !== null;
    var isDate = (d) => isObject2(d) && Object.prototype.toString.call(d) === "[object Date]";
    var isRegExp = (re) => isObject2(re) && Object.prototype.toString.call(re) === "[object RegExp]";
    var pick = (object, keys) => {
      return keys.reduce((obj, key) => {
        if (object && Object.prototype.hasOwnProperty.call(object, key)) {
          obj[key] = object[key];
        }
        return obj;
      }, {});
    };
    var filterIndexNames = (indexNames) => ([k, v]) => !!(typeof v === "string" || typeof v === "number" || typeof v === "boolean" || isDate(v) || v === null) && indexNames.includes(k);
    module.exports.uniq = uniq;
    module.exports.isDate = isDate;
    module.exports.isRegExp = isRegExp;
    module.exports.pick = pick;
    module.exports.filterIndexNames = filterIndexNames;
  }
});

// node_modules/@seald-io/nedb/lib/model.js
var require_model = __commonJS({
  "node_modules/@seald-io/nedb/lib/model.js"(exports, module) {
    var { uniq, isDate, isRegExp } = require_utils2();
    var checkKey = (k, v) => {
      if (typeof k === "number")
        k = k.toString();
      if (k[0] === "$" && !(k === "$$date" && typeof v === "number") && !(k === "$$deleted" && v === true) && !(k === "$$indexCreated") && !(k === "$$indexRemoved"))
        throw new Error("Field names cannot begin with the $ character");
      if (k.indexOf(".") !== -1)
        throw new Error("Field names cannot contain a .");
    };
    var checkObject = (obj) => {
      if (Array.isArray(obj)) {
        obj.forEach((o) => {
          checkObject(o);
        });
      }
      if (typeof obj === "object" && obj !== null) {
        for (const k in obj) {
          if (Object.prototype.hasOwnProperty.call(obj, k)) {
            checkKey(k, obj[k]);
            checkObject(obj[k]);
          }
        }
      }
    };
    var serialize = (obj) => {
      return JSON.stringify(obj, function(k, v) {
        checkKey(k, v);
        if (v === void 0)
          return void 0;
        if (v === null)
          return null;
        if (typeof this[k].getTime === "function")
          return { $$date: this[k].getTime() };
        return v;
      });
    };
    var deserialize = (rawData) => JSON.parse(rawData, function(k, v) {
      if (k === "$$date")
        return new Date(v);
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean" || v === null)
        return v;
      if (v && v.$$date)
        return v.$$date;
      return v;
    });
    function deepCopy(obj, strictKeys) {
      if (typeof obj === "boolean" || typeof obj === "number" || typeof obj === "string" || obj === null || isDate(obj))
        return obj;
      if (Array.isArray(obj))
        return obj.map((o) => deepCopy(o, strictKeys));
      if (typeof obj === "object") {
        const res = {};
        for (const k in obj) {
          if (Object.prototype.hasOwnProperty.call(obj, k) && (!strictKeys || k[0] !== "$" && k.indexOf(".") === -1)) {
            res[k] = deepCopy(obj[k], strictKeys);
          }
        }
        return res;
      }
      return void 0;
    }
    var isPrimitiveType = (obj) => typeof obj === "boolean" || typeof obj === "number" || typeof obj === "string" || obj === null || isDate(obj) || Array.isArray(obj);
    var compareNSB = (a, b) => {
      if (a < b)
        return -1;
      if (a > b)
        return 1;
      return 0;
    };
    var compareArrays = (a, b) => {
      const minLength = Math.min(a.length, b.length);
      for (let i = 0; i < minLength; i += 1) {
        const comp = compareThings(a[i], b[i]);
        if (comp !== 0)
          return comp;
      }
      return compareNSB(a.length, b.length);
    };
    var compareThings = (a, b, _compareStrings) => {
      const compareStrings = _compareStrings || compareNSB;
      if (a === void 0)
        return b === void 0 ? 0 : -1;
      if (b === void 0)
        return 1;
      if (a === null)
        return b === null ? 0 : -1;
      if (b === null)
        return 1;
      if (typeof a === "number")
        return typeof b === "number" ? compareNSB(a, b) : -1;
      if (typeof b === "number")
        return typeof a === "number" ? compareNSB(a, b) : 1;
      if (typeof a === "string")
        return typeof b === "string" ? compareStrings(a, b) : -1;
      if (typeof b === "string")
        return typeof a === "string" ? compareStrings(a, b) : 1;
      if (typeof a === "boolean")
        return typeof b === "boolean" ? compareNSB(a, b) : -1;
      if (typeof b === "boolean")
        return typeof a === "boolean" ? compareNSB(a, b) : 1;
      if (isDate(a))
        return isDate(b) ? compareNSB(a.getTime(), b.getTime()) : -1;
      if (isDate(b))
        return isDate(a) ? compareNSB(a.getTime(), b.getTime()) : 1;
      if (Array.isArray(a))
        return Array.isArray(b) ? compareArrays(a, b) : -1;
      if (Array.isArray(b))
        return Array.isArray(a) ? compareArrays(a, b) : 1;
      const aKeys = Object.keys(a).sort();
      const bKeys = Object.keys(b).sort();
      for (let i = 0; i < Math.min(aKeys.length, bKeys.length); i += 1) {
        const comp = compareThings(a[aKeys[i]], b[bKeys[i]]);
        if (comp !== 0)
          return comp;
      }
      return compareNSB(aKeys.length, bKeys.length);
    };
    var createModifierFunction = (lastStepModifierFunction, unset = false) => (obj, field, value) => {
      const func = (obj2, field2, value2) => {
        const fieldParts = typeof field2 === "string" ? field2.split(".") : field2;
        if (fieldParts.length === 1)
          lastStepModifierFunction(obj2, field2, value2);
        else {
          if (obj2[fieldParts[0]] === void 0) {
            if (unset)
              return;
            obj2[fieldParts[0]] = {};
          }
          func(obj2[fieldParts[0]], fieldParts.slice(1), value2);
        }
      };
      return func(obj, field, value);
    };
    var $addToSetPartial = (obj, field, value) => {
      if (!Object.prototype.hasOwnProperty.call(obj, field)) {
        obj[field] = [];
      }
      if (!Array.isArray(obj[field]))
        throw new Error("Can't $addToSet an element on non-array values");
      if (value !== null && typeof value === "object" && value.$each) {
        if (Object.keys(value).length > 1)
          throw new Error("Can't use another field in conjunction with $each");
        if (!Array.isArray(value.$each))
          throw new Error("$each requires an array value");
        value.$each.forEach((v) => {
          $addToSetPartial(obj, field, v);
        });
      } else {
        let addToSet = true;
        obj[field].forEach((v) => {
          if (compareThings(v, value) === 0)
            addToSet = false;
        });
        if (addToSet)
          obj[field].push(value);
      }
    };
    var modifierFunctions = {
      /**
       * Set a field to a new value
       */
      $set: createModifierFunction((obj, field, value) => {
        obj[field] = value;
      }),
      /**
       * Unset a field
       */
      $unset: createModifierFunction((obj, field, value) => {
        delete obj[field];
      }, true),
      /**
       * Updates the value of the field, only if specified field is smaller than the current value of the field
       */
      $min: createModifierFunction((obj, field, value) => {
        if (typeof obj[field] === "undefined")
          obj[field] = value;
        else if (value < obj[field])
          obj[field] = value;
      }),
      /**
       * Updates the value of the field, only if specified field is greater than the current value of the field
       */
      $max: createModifierFunction((obj, field, value) => {
        if (typeof obj[field] === "undefined")
          obj[field] = value;
        else if (value > obj[field])
          obj[field] = value;
      }),
      /**
       * Increment a numeric field's value
       */
      $inc: createModifierFunction((obj, field, value) => {
        if (typeof value !== "number")
          throw new Error(`${value} must be a number`);
        if (typeof obj[field] !== "number") {
          if (!Object.prototype.hasOwnProperty.call(obj, field))
            obj[field] = value;
          else
            throw new Error("Don't use the $inc modifier on non-number fields");
        } else
          obj[field] += value;
      }),
      /**
       * Removes all instances of a value from an existing array
       */
      $pull: createModifierFunction((obj, field, value) => {
        if (!Array.isArray(obj[field]))
          throw new Error("Can't $pull an element from non-array values");
        const arr = obj[field];
        for (let i = arr.length - 1; i >= 0; i -= 1) {
          if (match(arr[i], value))
            arr.splice(i, 1);
        }
      }),
      /**
       * Remove the first or last element of an array
       */
      $pop: createModifierFunction((obj, field, value) => {
        if (!Array.isArray(obj[field]))
          throw new Error("Can't $pop an element from non-array values");
        if (typeof value !== "number")
          throw new Error(`${value} isn't an integer, can't use it with $pop`);
        if (value === 0)
          return;
        if (value > 0)
          obj[field] = obj[field].slice(0, obj[field].length - 1);
        else
          obj[field] = obj[field].slice(1);
      }),
      /**
       * Add an element to an array field only if it is not already in it
       * No modification if the element is already in the array
       * Note that it doesn't check whether the original array contains duplicates
       */
      $addToSet: createModifierFunction($addToSetPartial),
      /**
       * Push an element to the end of an array field
       * Optional modifier $each instead of value to push several values
       * Optional modifier $slice to slice the resulting array, see https://docs.mongodb.org/manual/reference/operator/update/slice/
       * Difference with MongoDB: if $slice is specified and not $each, we act as if value is an empty array
       */
      $push: createModifierFunction((obj, field, value) => {
        if (!Object.prototype.hasOwnProperty.call(obj, field))
          obj[field] = [];
        if (!Array.isArray(obj[field]))
          throw new Error("Can't $push an element on non-array values");
        if (value !== null && typeof value === "object" && value.$slice && value.$each === void 0)
          value.$each = [];
        if (value !== null && typeof value === "object" && value.$each) {
          if (Object.keys(value).length >= 3 || Object.keys(value).length === 2 && value.$slice === void 0)
            throw new Error("Can only use $slice in cunjunction with $each when $push to array");
          if (!Array.isArray(value.$each))
            throw new Error("$each requires an array value");
          value.$each.forEach((v) => {
            obj[field].push(v);
          });
          if (value.$slice === void 0 || typeof value.$slice !== "number")
            return;
          if (value.$slice === 0)
            obj[field] = [];
          else {
            let start;
            let end;
            const n = obj[field].length;
            if (value.$slice < 0) {
              start = Math.max(0, n + value.$slice);
              end = n;
            } else if (value.$slice > 0) {
              start = 0;
              end = Math.min(n, value.$slice);
            }
            obj[field] = obj[field].slice(start, end);
          }
        } else {
          obj[field].push(value);
        }
      })
    };
    var modify = (obj, updateQuery) => {
      const keys = Object.keys(updateQuery);
      const firstChars = keys.map((item) => item[0]);
      const dollarFirstChars = firstChars.filter((c) => c === "$");
      let newDoc;
      let modifiers;
      if (keys.indexOf("_id") !== -1 && updateQuery._id !== obj._id)
        throw new Error("You cannot change a document's _id");
      if (dollarFirstChars.length !== 0 && dollarFirstChars.length !== firstChars.length)
        throw new Error("You cannot mix modifiers and normal fields");
      if (dollarFirstChars.length === 0) {
        newDoc = deepCopy(updateQuery);
        newDoc._id = obj._id;
      } else {
        modifiers = uniq(keys);
        newDoc = deepCopy(obj);
        modifiers.forEach((m) => {
          if (!modifierFunctions[m])
            throw new Error(`Unknown modifier ${m}`);
          if (typeof updateQuery[m] !== "object")
            throw new Error(`Modifier ${m}'s argument must be an object`);
          const keys2 = Object.keys(updateQuery[m]);
          keys2.forEach((k) => {
            modifierFunctions[m](newDoc, k, updateQuery[m][k]);
          });
        });
      }
      checkObject(newDoc);
      if (obj._id !== newDoc._id)
        throw new Error("You can't change a document's _id");
      return newDoc;
    };
    var getDotValue = (obj, field) => {
      const fieldParts = typeof field === "string" ? field.split(".") : field;
      if (!obj)
        return void 0;
      if (fieldParts.length === 0)
        return obj;
      if (fieldParts.length === 1)
        return obj[fieldParts[0]];
      if (Array.isArray(obj[fieldParts[0]])) {
        const i = parseInt(fieldParts[1], 10);
        if (typeof i === "number" && !isNaN(i))
          return getDotValue(obj[fieldParts[0]][i], fieldParts.slice(2));
        return obj[fieldParts[0]].map((el) => getDotValue(el, fieldParts.slice(1)));
      } else
        return getDotValue(obj[fieldParts[0]], fieldParts.slice(1));
    };
    var getDotValues = (obj, fields) => {
      if (!Array.isArray(fields))
        throw new Error("fields must be an Array");
      if (fields.length > 1) {
        const key = {};
        for (const field of fields) {
          key[field] = getDotValue(obj, field);
        }
        return key;
      } else
        return getDotValue(obj, fields[0]);
    };
    var areThingsEqual = (a, b) => {
      if (a === null || typeof a === "string" || typeof a === "boolean" || typeof a === "number" || b === null || typeof b === "string" || typeof b === "boolean" || typeof b === "number")
        return a === b;
      if (isDate(a) || isDate(b))
        return isDate(a) && isDate(b) && a.getTime() === b.getTime();
      if (!(Array.isArray(a) && Array.isArray(b)) && (Array.isArray(a) || Array.isArray(b)) || a === void 0 || b === void 0)
        return false;
      let aKeys;
      let bKeys;
      try {
        aKeys = Object.keys(a);
        bKeys = Object.keys(b);
      } catch (e) {
        return false;
      }
      if (aKeys.length !== bKeys.length)
        return false;
      for (const el of aKeys) {
        if (bKeys.indexOf(el) === -1)
          return false;
        if (!areThingsEqual(a[el], b[el]))
          return false;
      }
      return true;
    };
    var areComparable = (a, b) => {
      if (typeof a !== "string" && typeof a !== "number" && !isDate(a) && typeof b !== "string" && typeof b !== "number" && !isDate(b))
        return false;
      if (typeof a !== typeof b)
        return false;
      return true;
    };
    var comparisonFunctions = {
      /** Lower than */
      $lt: (a, b) => areComparable(a, b) && a < b,
      /** Lower than or equals */
      $lte: (a, b) => areComparable(a, b) && a <= b,
      /** Greater than */
      $gt: (a, b) => areComparable(a, b) && a > b,
      /** Greater than or equals */
      $gte: (a, b) => areComparable(a, b) && a >= b,
      /** Does not equal */
      $ne: (a, b) => a === void 0 || !areThingsEqual(a, b),
      /** Is in Array */
      $in: (a, b) => {
        if (!Array.isArray(b))
          throw new Error("$in operator called with a non-array");
        for (const el of b) {
          if (areThingsEqual(a, el))
            return true;
        }
        return false;
      },
      /** Is not in Array */
      $nin: (a, b) => {
        if (!Array.isArray(b))
          throw new Error("$nin operator called with a non-array");
        return !comparisonFunctions.$in(a, b);
      },
      /** Matches Regexp */
      $regex: (a, b) => {
        if (!isRegExp(b))
          throw new Error("$regex operator called with non regular expression");
        if (typeof a !== "string")
          return false;
        else
          return b.test(a);
      },
      /** Returns true if field exists */
      $exists: (a, b) => {
        if (b || b === "")
          b = true;
        else
          b = false;
        if (a === void 0)
          return !b;
        else
          return b;
      },
      /** Specific to Arrays, returns true if a length equals b */
      $size: (a, b) => {
        if (!Array.isArray(a))
          return false;
        if (b % 1 !== 0)
          throw new Error("$size operator called without an integer");
        return a.length === b;
      },
      /** Specific to Arrays, returns true if some elements of a match the query b */
      $elemMatch: (a, b) => {
        if (!Array.isArray(a))
          return false;
        return a.some((el) => match(el, b));
      }
    };
    var arrayComparisonFunctions = { $size: true, $elemMatch: true };
    var logicalOperators = {
      /**
       * Match any of the subqueries
       * @param {document} obj
       * @param {query[]} query
       * @return {boolean}
       */
      $or: (obj, query) => {
        if (!Array.isArray(query))
          throw new Error("$or operator used without an array");
        for (let i = 0; i < query.length; i += 1) {
          if (match(obj, query[i]))
            return true;
        }
        return false;
      },
      /**
       * Match all of the subqueries
       * @param {document} obj
       * @param {query[]} query
       * @return {boolean}
       */
      $and: (obj, query) => {
        if (!Array.isArray(query))
          throw new Error("$and operator used without an array");
        for (let i = 0; i < query.length; i += 1) {
          if (!match(obj, query[i]))
            return false;
        }
        return true;
      },
      /**
       * Inverted match of the query
       * @param {document} obj
       * @param {query} query
       * @return {boolean}
       */
      $not: (obj, query) => !match(obj, query),
      /**
       * @callback whereCallback
       * @param {document} obj
       * @return {boolean}
       */
      /**
       * Use a function to match
       * @param {document} obj
       * @param {whereCallback} fn
       * @return {boolean}
       */
      $where: (obj, fn) => {
        if (typeof fn !== "function")
          throw new Error("$where operator used without a function");
        const result = fn.call(obj);
        if (typeof result !== "boolean")
          throw new Error("$where function must return boolean");
        return result;
      }
    };
    var match = (obj, query) => {
      if (isPrimitiveType(obj) || isPrimitiveType(query))
        return matchQueryPart({ needAKey: obj }, "needAKey", query);
      for (const queryKey in query) {
        if (Object.prototype.hasOwnProperty.call(query, queryKey)) {
          const queryValue = query[queryKey];
          if (queryKey[0] === "$") {
            if (!logicalOperators[queryKey])
              throw new Error(`Unknown logical operator ${queryKey}`);
            if (!logicalOperators[queryKey](obj, queryValue))
              return false;
          } else if (!matchQueryPart(obj, queryKey, queryValue))
            return false;
        }
      }
      return true;
    };
    function matchQueryPart(obj, queryKey, queryValue, treatObjAsValue) {
      const objValue = getDotValue(obj, queryKey);
      if (Array.isArray(objValue) && !treatObjAsValue) {
        if (Array.isArray(queryValue))
          return matchQueryPart(obj, queryKey, queryValue, true);
        if (queryValue !== null && typeof queryValue === "object" && !isRegExp(queryValue)) {
          for (const key in queryValue) {
            if (Object.prototype.hasOwnProperty.call(queryValue, key) && arrayComparisonFunctions[key]) {
              return matchQueryPart(obj, queryKey, queryValue, true);
            }
          }
        }
        for (const el of objValue) {
          if (matchQueryPart({ k: el }, "k", queryValue))
            return true;
        }
        return false;
      }
      if (queryValue !== null && typeof queryValue === "object" && !isRegExp(queryValue) && !Array.isArray(queryValue)) {
        const keys = Object.keys(queryValue);
        const firstChars = keys.map((item) => item[0]);
        const dollarFirstChars = firstChars.filter((c) => c === "$");
        if (dollarFirstChars.length !== 0 && dollarFirstChars.length !== firstChars.length)
          throw new Error("You cannot mix operators and normal fields");
        if (dollarFirstChars.length > 0) {
          for (const key of keys) {
            if (!comparisonFunctions[key])
              throw new Error(`Unknown comparison function ${key}`);
            if (!comparisonFunctions[key](objValue, queryValue[key]))
              return false;
          }
          return true;
        }
      }
      if (isRegExp(queryValue))
        return comparisonFunctions.$regex(objValue, queryValue);
      return areThingsEqual(objValue, queryValue);
    }
    module.exports.serialize = serialize;
    module.exports.deserialize = deserialize;
    module.exports.deepCopy = deepCopy;
    module.exports.checkObject = checkObject;
    module.exports.isPrimitiveType = isPrimitiveType;
    module.exports.modify = modify;
    module.exports.getDotValue = getDotValue;
    module.exports.getDotValues = getDotValues;
    module.exports.match = match;
    module.exports.areThingsEqual = areThingsEqual;
    module.exports.compareThings = compareThings;
  }
});

// node_modules/@seald-io/nedb/lib/cursor.js
var require_cursor = __commonJS({
  "node_modules/@seald-io/nedb/lib/cursor.js"(exports, module) {
    var model = require_model();
    var { callbackify } = __require("util");
    var Cursor = class {
      /**
       * Create a new cursor for this collection.
       * @param {Datastore} db - The datastore this cursor is bound to
       * @param {query} query - The query this cursor will operate on
       * @param {Cursor~mapFn} [mapFn] - Handler to be executed after cursor has found the results and before the callback passed to find/findOne/update/remove
       */
      constructor(db, query, mapFn) {
        this.db = db;
        this.query = query || {};
        if (mapFn)
          this.mapFn = mapFn;
        this._limit = void 0;
        this._skip = void 0;
        this._sort = void 0;
        this._projection = void 0;
      }
      /**
       * Set a limit to the number of results for the given Cursor.
       * @param {Number} limit
       * @return {Cursor} the same instance of Cursor, (useful for chaining).
       */
      limit(limit) {
        this._limit = limit;
        return this;
      }
      /**
       * Skip a number of results for the given Cursor.
       * @param {Number} skip
       * @return {Cursor} the same instance of Cursor, (useful for chaining).
       */
      skip(skip) {
        this._skip = skip;
        return this;
      }
      /**
       * Sort results of the query for the given Cursor.
       * @param {Object.<string, number>} sortQuery - sortQuery is { field: order }, field can use the dot-notation, order is 1 for ascending and -1 for descending
       * @return {Cursor} the same instance of Cursor, (useful for chaining).
       */
      sort(sortQuery) {
        this._sort = sortQuery;
        return this;
      }
      /**
       * Add the use of a projection to the given Cursor.
       * @param {Object.<string, number>} projection - MongoDB-style projection. {} means take all fields. Then it's { key1: 1, key2: 1 } to take only key1 and key2
       * { key1: 0, key2: 0 } to omit only key1 and key2. Except _id, you can't mix takes and omits.
       * @return {Cursor} the same instance of Cursor, (useful for chaining).
       */
      projection(projection) {
        this._projection = projection;
        return this;
      }
      /**
       * Apply the projection.
       *
       * This is an internal function. You should use {@link Cursor#execAsync} or {@link Cursor#exec}.
       * @param {document[]} candidates
       * @return {document[]}
       * @private
       */
      _project(candidates) {
        const res = [];
        let action;
        if (this._projection === void 0 || Object.keys(this._projection).length === 0) {
          return candidates;
        }
        const keepId = this._projection._id !== 0;
        const { _id, ...rest } = this._projection;
        this._projection = rest;
        const keys = Object.keys(this._projection);
        keys.forEach((k) => {
          if (action !== void 0 && this._projection[k] !== action)
            throw new Error("Can't both keep and omit fields except for _id");
          action = this._projection[k];
        });
        candidates.forEach((candidate) => {
          let toPush;
          if (action === 1) {
            toPush = { $set: {} };
            keys.forEach((k) => {
              toPush.$set[k] = model.getDotValue(candidate, k);
              if (toPush.$set[k] === void 0)
                delete toPush.$set[k];
            });
            toPush = model.modify({}, toPush);
          } else {
            toPush = { $unset: {} };
            keys.forEach((k) => {
              toPush.$unset[k] = true;
            });
            toPush = model.modify(candidate, toPush);
          }
          if (keepId)
            toPush._id = candidate._id;
          else
            delete toPush._id;
          res.push(toPush);
        });
        return res;
      }
      /**
       * Get all matching elements
       * Will return pointers to matched elements (shallow copies), returning full copies is the role of find or findOne
       * This is an internal function, use execAsync which uses the executor
       * @return {document[]|Promise<*>}
       * @private
       */
      async _execAsync() {
        let res = [];
        let added = 0;
        let skipped = 0;
        const candidates = await this.db._getCandidatesAsync(this.query);
        for (const candidate of candidates) {
          if (model.match(candidate, this.query)) {
            if (!this._sort) {
              if (this._skip && this._skip > skipped)
                skipped += 1;
              else {
                res.push(candidate);
                added += 1;
                if (this._limit && this._limit <= added)
                  break;
              }
            } else
              res.push(candidate);
          }
        }
        if (this._sort) {
          const criteria = Object.entries(this._sort).map(([key, direction]) => ({ key, direction }));
          res.sort((a, b) => {
            for (const criterion of criteria) {
              const compare = criterion.direction * model.compareThings(model.getDotValue(a, criterion.key), model.getDotValue(b, criterion.key), this.db.compareStrings);
              if (compare !== 0)
                return compare;
            }
            return 0;
          });
          const limit = this._limit || res.length;
          const skip = this._skip || 0;
          res = res.slice(skip, skip + limit);
        }
        res = this._project(res);
        if (this.mapFn)
          return this.mapFn(res);
        return res;
      }
      /**
       * @callback Cursor~execCallback
       * @param {Error} err
       * @param {document[]|*} res If a mapFn was given to the Cursor, then the type of this parameter is the one returned by the mapFn.
       */
      /**
       * Callback version of {@link Cursor#exec}.
       * @param {Cursor~execCallback} _callback
       * @see Cursor#execAsync
       */
      exec(_callback) {
        callbackify(() => this.execAsync())(_callback);
      }
      /**
       * Get all matching elements.
       * Will return pointers to matched elements (shallow copies), returning full copies is the role of {@link Datastore#findAsync} or {@link Datastore#findOneAsync}.
       * @return {Promise<document[]|*>}
       * @async
       */
      execAsync() {
        return this.db.executor.pushAsync(() => this._execAsync());
      }
      then(onFulfilled, onRejected) {
        return this.execAsync().then(onFulfilled, onRejected);
      }
      catch(onRejected) {
        return this.execAsync().catch(onRejected);
      }
      finally(onFinally) {
        return this.execAsync().finally(onFinally);
      }
    };
    module.exports = Cursor;
  }
});

// node_modules/@seald-io/nedb/lib/customUtils.js
var require_customUtils = __commonJS({
  "node_modules/@seald-io/nedb/lib/customUtils.js"(exports, module) {
    var crypto4 = __require("crypto");
    var uid = (len) => crypto4.randomBytes(Math.ceil(Math.max(8, len * 2))).toString("base64").replace(/[+/]/g, "").slice(0, len);
    module.exports.uid = uid;
  }
});

// node_modules/@seald-io/nedb/lib/waterfall.js
var require_waterfall = __commonJS({
  "node_modules/@seald-io/nedb/lib/waterfall.js"(exports, module) {
    var Waterfall = class {
      /**
       * Instantiate a new Waterfall.
       */
      constructor() {
        this.guardian = Promise.resolve();
      }
      /**
       *
       * @param {AsyncFunction} func
       * @return {AsyncFunction}
       */
      waterfall(func) {
        return (...args) => {
          this.guardian = this.guardian.then(() => {
            return func(...args).then((result) => ({ error: false, result }), (result) => ({ error: true, result }));
          });
          return this.guardian.then(({ error: error2, result }) => {
            if (error2)
              return Promise.reject(result);
            else
              return Promise.resolve(result);
          });
        };
      }
      /**
       * Shorthand for chaining a promise to the Waterfall
       * @param {Promise} promise
       * @return {Promise}
       */
      chain(promise) {
        return this.waterfall(() => promise)();
      }
    };
    module.exports = Waterfall;
  }
});

// node_modules/@seald-io/nedb/lib/executor.js
var require_executor = __commonJS({
  "node_modules/@seald-io/nedb/lib/executor.js"(exports, module) {
    var Waterfall = require_waterfall();
    var Executor = class {
      /**
       * Instantiates a new Executor.
       */
      constructor() {
        this.ready = false;
        this.queue = new Waterfall();
        this.buffer = null;
        this._triggerBuffer = null;
        this.resetBuffer();
      }
      /**
       * If executor is ready, queue task (and process it immediately if executor was idle)
       * If not, buffer task for later processing
       * @param {AsyncFunction} task Function to execute
       * @param {boolean} [forceQueuing = false] Optional (defaults to false) force executor to queue task even if it is not ready
       * @return {Promise<*>}
       * @async
       * @see Executor#push
       */
      pushAsync(task, forceQueuing = false) {
        if (this.ready || forceQueuing)
          return this.queue.waterfall(task)();
        else
          return this.buffer.waterfall(task)();
      }
      /**
       * Queue all tasks in buffer (in the same order they came in)
       * Automatically sets executor as ready
       */
      processBuffer() {
        this.ready = true;
        this._triggerBuffer();
        this.queue.waterfall(() => this.buffer.guardian);
      }
      /**
       * Removes all tasks queued up in the buffer
       */
      resetBuffer() {
        this.buffer = new Waterfall();
        this.buffer.chain(new Promise((resolve2) => {
          this._triggerBuffer = resolve2;
        }));
        if (this.ready)
          this._triggerBuffer();
      }
    };
    module.exports = Executor;
  }
});

// node_modules/@seald-io/binary-search-tree/lib/customUtils.js
var require_customUtils2 = __commonJS({
  "node_modules/@seald-io/binary-search-tree/lib/customUtils.js"(exports, module) {
    var getRandomArray = (n) => {
      if (n === 0)
        return [];
      if (n === 1)
        return [0];
      const res = getRandomArray(n - 1);
      const next = Math.floor(Math.random() * n);
      res.splice(next, 0, n - 1);
      return res;
    };
    module.exports.getRandomArray = getRandomArray;
    var defaultCompareKeysFunction = (a, b) => {
      if (a < b)
        return -1;
      if (a > b)
        return 1;
      if (a === b)
        return 0;
      const err = new Error("Couldn't compare elements");
      err.a = a;
      err.b = b;
      throw err;
    };
    module.exports.defaultCompareKeysFunction = defaultCompareKeysFunction;
    var defaultCheckValueEquality = (a, b) => a === b;
    module.exports.defaultCheckValueEquality = defaultCheckValueEquality;
  }
});

// node_modules/@seald-io/binary-search-tree/lib/bst.js
var require_bst = __commonJS({
  "node_modules/@seald-io/binary-search-tree/lib/bst.js"(exports, module) {
    var customUtils = require_customUtils2();
    var BinarySearchTree = class {
      /**
       * Constructor
       * @param {Object} options Optional
       * @param {Boolean}  options.unique Whether to enforce a 'unique' constraint on the key or not
       * @param {Key}      options.key Initialize this BST's key with key
       * @param {Value}    options.value Initialize this BST's data with [value]
       * @param {Function} options.compareKeys Initialize this BST's compareKeys
       */
      constructor(options) {
        options = options || {};
        this.left = null;
        this.right = null;
        this.parent = options.parent !== void 0 ? options.parent : null;
        if (Object.prototype.hasOwnProperty.call(options, "key")) {
          this.key = options.key;
        }
        this.data = Object.prototype.hasOwnProperty.call(options, "value") ? [options.value] : [];
        this.unique = options.unique || false;
        this.compareKeys = options.compareKeys || customUtils.defaultCompareKeysFunction;
        this.checkValueEquality = options.checkValueEquality || customUtils.defaultCheckValueEquality;
      }
      /**
       * Get the descendant with max key
       */
      getMaxKeyDescendant() {
        if (this.right)
          return this.right.getMaxKeyDescendant();
        else
          return this;
      }
      /**
       * Get the maximum key
       */
      getMaxKey() {
        return this.getMaxKeyDescendant().key;
      }
      /**
       * Get the descendant with min key
       */
      getMinKeyDescendant() {
        if (this.left)
          return this.left.getMinKeyDescendant();
        else
          return this;
      }
      /**
       * Get the minimum key
       */
      getMinKey() {
        return this.getMinKeyDescendant().key;
      }
      /**
       * Check that all nodes (incl. leaves) fullfil condition given by fn
       * test is a function passed every (key, data) and which throws if the condition is not met
       */
      checkAllNodesFullfillCondition(test) {
        if (!Object.prototype.hasOwnProperty.call(this, "key"))
          return;
        test(this.key, this.data);
        if (this.left)
          this.left.checkAllNodesFullfillCondition(test);
        if (this.right)
          this.right.checkAllNodesFullfillCondition(test);
      }
      /**
       * Check that the core BST properties on node ordering are verified
       * Throw if they aren't
       */
      checkNodeOrdering() {
        if (!Object.prototype.hasOwnProperty.call(this, "key"))
          return;
        if (this.left) {
          this.left.checkAllNodesFullfillCondition((k) => {
            if (this.compareKeys(k, this.key) >= 0)
              throw new Error(`Tree with root ${this.key} is not a binary search tree`);
          });
          this.left.checkNodeOrdering();
        }
        if (this.right) {
          this.right.checkAllNodesFullfillCondition((k) => {
            if (this.compareKeys(k, this.key) <= 0)
              throw new Error(`Tree with root ${this.key} is not a binary search tree`);
          });
          this.right.checkNodeOrdering();
        }
      }
      /**
       * Check that all pointers are coherent in this tree
       */
      checkInternalPointers() {
        if (this.left) {
          if (this.left.parent !== this)
            throw new Error(`Parent pointer broken for key ${this.key}`);
          this.left.checkInternalPointers();
        }
        if (this.right) {
          if (this.right.parent !== this)
            throw new Error(`Parent pointer broken for key ${this.key}`);
          this.right.checkInternalPointers();
        }
      }
      /**
       * Check that a tree is a BST as defined here (node ordering and pointer references)
       */
      checkIsBST() {
        this.checkNodeOrdering();
        this.checkInternalPointers();
        if (this.parent)
          throw new Error("The root shouldn't have a parent");
      }
      /**
       * Get number of keys inserted
       */
      getNumberOfKeys() {
        let res;
        if (!Object.prototype.hasOwnProperty.call(this, "key"))
          return 0;
        res = 1;
        if (this.left)
          res += this.left.getNumberOfKeys();
        if (this.right)
          res += this.right.getNumberOfKeys();
        return res;
      }
      /**
       * Create a BST similar (i.e. same options except for key and value) to the current one
       * Use the same constructor (i.e. BinarySearchTree, AVLTree etc)
       * @param {Object} options see constructor
       */
      createSimilar(options) {
        options = options || {};
        options.unique = this.unique;
        options.compareKeys = this.compareKeys;
        options.checkValueEquality = this.checkValueEquality;
        return new this.constructor(options);
      }
      /**
       * Create the left child of this BST and return it
       */
      createLeftChild(options) {
        const leftChild = this.createSimilar(options);
        leftChild.parent = this;
        this.left = leftChild;
        return leftChild;
      }
      /**
       * Create the right child of this BST and return it
       */
      createRightChild(options) {
        const rightChild = this.createSimilar(options);
        rightChild.parent = this;
        this.right = rightChild;
        return rightChild;
      }
      /**
       * Insert a new element
       */
      insert(key, value) {
        if (!Object.prototype.hasOwnProperty.call(this, "key")) {
          this.key = key;
          this.data.push(value);
          return;
        }
        if (this.compareKeys(this.key, key) === 0) {
          if (this.unique) {
            const err = new Error(`Can't insert key ${JSON.stringify(key)}, it violates the unique constraint`);
            err.key = key;
            err.errorType = "uniqueViolated";
            throw err;
          } else
            this.data.push(value);
          return;
        }
        if (this.compareKeys(key, this.key) < 0) {
          if (this.left)
            this.left.insert(key, value);
          else
            this.createLeftChild({ key, value });
        } else {
          if (this.right)
            this.right.insert(key, value);
          else
            this.createRightChild({ key, value });
        }
      }
      /**
       * Search for all data corresponding to a key
       */
      search(key) {
        if (!Object.prototype.hasOwnProperty.call(this, "key"))
          return [];
        if (this.compareKeys(this.key, key) === 0)
          return this.data;
        if (this.compareKeys(key, this.key) < 0) {
          if (this.left)
            return this.left.search(key);
          else
            return [];
        } else {
          if (this.right)
            return this.right.search(key);
          else
            return [];
        }
      }
      /**
       * Return a function that tells whether a given key matches a lower bound
       */
      getLowerBoundMatcher(query) {
        if (!Object.prototype.hasOwnProperty.call(query, "$gt") && !Object.prototype.hasOwnProperty.call(query, "$gte"))
          return () => true;
        if (Object.prototype.hasOwnProperty.call(query, "$gt") && Object.prototype.hasOwnProperty.call(query, "$gte")) {
          if (this.compareKeys(query.$gte, query.$gt) === 0)
            return (key) => this.compareKeys(key, query.$gt) > 0;
          if (this.compareKeys(query.$gte, query.$gt) > 0)
            return (key) => this.compareKeys(key, query.$gte) >= 0;
          else
            return (key) => this.compareKeys(key, query.$gt) > 0;
        }
        if (Object.prototype.hasOwnProperty.call(query, "$gt"))
          return (key) => this.compareKeys(key, query.$gt) > 0;
        else
          return (key) => this.compareKeys(key, query.$gte) >= 0;
      }
      /**
       * Return a function that tells whether a given key matches an upper bound
       */
      getUpperBoundMatcher(query) {
        if (!Object.prototype.hasOwnProperty.call(query, "$lt") && !Object.prototype.hasOwnProperty.call(query, "$lte"))
          return () => true;
        if (Object.prototype.hasOwnProperty.call(query, "$lt") && Object.prototype.hasOwnProperty.call(query, "$lte")) {
          if (this.compareKeys(query.$lte, query.$lt) === 0)
            return (key) => this.compareKeys(key, query.$lt) < 0;
          if (this.compareKeys(query.$lte, query.$lt) < 0)
            return (key) => this.compareKeys(key, query.$lte) <= 0;
          else
            return (key) => this.compareKeys(key, query.$lt) < 0;
        }
        if (Object.prototype.hasOwnProperty.call(query, "$lt"))
          return (key) => this.compareKeys(key, query.$lt) < 0;
        else
          return (key) => this.compareKeys(key, query.$lte) <= 0;
      }
      /**
       * Get all data for a key between bounds
       * Return it in key order
       * @param {Object} query Mongo-style query where keys are $lt, $lte, $gt or $gte (other keys are not considered)
       * @param {Functions} lbm/ubm matching functions calculated at the first recursive step
       */
      betweenBounds(query, lbm, ubm) {
        const res = [];
        if (!Object.prototype.hasOwnProperty.call(this, "key"))
          return [];
        lbm = lbm || this.getLowerBoundMatcher(query);
        ubm = ubm || this.getUpperBoundMatcher(query);
        if (lbm(this.key) && this.left)
          append(res, this.left.betweenBounds(query, lbm, ubm));
        if (lbm(this.key) && ubm(this.key))
          append(res, this.data);
        if (ubm(this.key) && this.right)
          append(res, this.right.betweenBounds(query, lbm, ubm));
        return res;
      }
      /**
       * Delete the current node if it is a leaf
       * Return true if it was deleted
       */
      deleteIfLeaf() {
        if (this.left || this.right)
          return false;
        if (!this.parent) {
          delete this.key;
          this.data = [];
          return true;
        }
        if (this.parent.left === this)
          this.parent.left = null;
        else
          this.parent.right = null;
        return true;
      }
      /**
       * Delete the current node if it has only one child
       * Return true if it was deleted
       */
      deleteIfOnlyOneChild() {
        let child;
        if (this.left && !this.right)
          child = this.left;
        if (!this.left && this.right)
          child = this.right;
        if (!child)
          return false;
        if (!this.parent) {
          this.key = child.key;
          this.data = child.data;
          this.left = null;
          if (child.left) {
            this.left = child.left;
            child.left.parent = this;
          }
          this.right = null;
          if (child.right) {
            this.right = child.right;
            child.right.parent = this;
          }
          return true;
        }
        if (this.parent.left === this) {
          this.parent.left = child;
          child.parent = this.parent;
        } else {
          this.parent.right = child;
          child.parent = this.parent;
        }
        return true;
      }
      /**
       * Delete a key or just a value
       * @param {Key} key
       * @param {Value} value Optional. If not set, the whole key is deleted. If set, only this value is deleted
       */
      delete(key, value) {
        const newData = [];
        let replaceWith;
        if (!Object.prototype.hasOwnProperty.call(this, "key"))
          return;
        if (this.compareKeys(key, this.key) < 0) {
          if (this.left)
            this.left.delete(key, value);
          return;
        }
        if (this.compareKeys(key, this.key) > 0) {
          if (this.right)
            this.right.delete(key, value);
          return;
        }
        if (!this.compareKeys(key, this.key) === 0)
          return;
        if (this.data.length > 1 && value !== void 0) {
          this.data.forEach((d) => {
            if (!this.checkValueEquality(d, value))
              newData.push(d);
          });
          this.data = newData;
          return;
        }
        if (this.deleteIfLeaf())
          return;
        if (this.deleteIfOnlyOneChild())
          return;
        if (Math.random() >= 0.5) {
          replaceWith = this.left.getMaxKeyDescendant();
          this.key = replaceWith.key;
          this.data = replaceWith.data;
          if (this === replaceWith.parent) {
            this.left = replaceWith.left;
            if (replaceWith.left)
              replaceWith.left.parent = replaceWith.parent;
          } else {
            replaceWith.parent.right = replaceWith.left;
            if (replaceWith.left)
              replaceWith.left.parent = replaceWith.parent;
          }
        } else {
          replaceWith = this.right.getMinKeyDescendant();
          this.key = replaceWith.key;
          this.data = replaceWith.data;
          if (this === replaceWith.parent) {
            this.right = replaceWith.right;
            if (replaceWith.right)
              replaceWith.right.parent = replaceWith.parent;
          } else {
            replaceWith.parent.left = replaceWith.right;
            if (replaceWith.right)
              replaceWith.right.parent = replaceWith.parent;
          }
        }
      }
      /**
       * Execute a function on every node of the tree, in key order
       * @param {Function} fn Signature: node. Most useful will probably be node.key and node.data
       */
      executeOnEveryNode(fn) {
        if (this.left)
          this.left.executeOnEveryNode(fn);
        fn(this);
        if (this.right)
          this.right.executeOnEveryNode(fn);
      }
      /**
       * Pretty print a tree
       * @param {Boolean} printData To print the nodes' data along with the key
       */
      prettyPrint(printData, spacing) {
        spacing = spacing || "";
        console.log(`${spacing}* ${this.key}`);
        if (printData)
          console.log(`${spacing}* ${this.data}`);
        if (!this.left && !this.right)
          return;
        if (this.left)
          this.left.prettyPrint(printData, `${spacing}  `);
        else
          console.log(`${spacing}  *`);
        if (this.right)
          this.right.prettyPrint(printData, `${spacing}  `);
        else
          console.log(`${spacing}  *`);
      }
    };
    function append(array, toAppend) {
      for (let i = 0; i < toAppend.length; i += 1) {
        array.push(toAppend[i]);
      }
    }
    module.exports = BinarySearchTree;
  }
});

// node_modules/@seald-io/binary-search-tree/lib/avltree.js
var require_avltree = __commonJS({
  "node_modules/@seald-io/binary-search-tree/lib/avltree.js"(exports, module) {
    var BinarySearchTree = require_bst();
    var customUtils = require_customUtils2();
    var AVLTree = class {
      /**
       * Constructor
       * We can't use a direct pointer to the root node (as in the simple binary search tree)
       * as the root will change during tree rotations
       * @param {Boolean}  options.unique Whether to enforce a 'unique' constraint on the key or not
       * @param {Function} options.compareKeys Initialize this BST's compareKeys
       */
      constructor(options) {
        this.tree = new _AVLTree(options);
      }
      checkIsAVLT() {
        this.tree.checkIsAVLT();
      }
      // Insert in the internal tree, update the pointer to the root if needed
      insert(key, value) {
        const newTree = this.tree.insert(key, value);
        if (newTree) {
          this.tree = newTree;
        }
      }
      // Delete a value
      delete(key, value) {
        const newTree = this.tree.delete(key, value);
        if (newTree) {
          this.tree = newTree;
        }
      }
    };
    var _AVLTree = class extends BinarySearchTree {
      /**
       * Constructor of the internal AVLTree
       * @param {Object} options Optional
       * @param {Boolean}  options.unique Whether to enforce a 'unique' constraint on the key or not
       * @param {Key}      options.key Initialize this BST's key with key
       * @param {Value}    options.value Initialize this BST's data with [value]
       * @param {Function} options.compareKeys Initialize this BST's compareKeys
       */
      constructor(options) {
        super();
        options = options || {};
        this.left = null;
        this.right = null;
        this.parent = options.parent !== void 0 ? options.parent : null;
        if (Object.prototype.hasOwnProperty.call(options, "key"))
          this.key = options.key;
        this.data = Object.prototype.hasOwnProperty.call(options, "value") ? [options.value] : [];
        this.unique = options.unique || false;
        this.compareKeys = options.compareKeys || customUtils.defaultCompareKeysFunction;
        this.checkValueEquality = options.checkValueEquality || customUtils.defaultCheckValueEquality;
      }
      /**
       * Check the recorded height is correct for every node
       * Throws if one height doesn't match
       */
      checkHeightCorrect() {
        if (!Object.prototype.hasOwnProperty.call(this, "key")) {
          return;
        }
        if (this.left && this.left.height === void 0) {
          throw new Error("Undefined height for node " + this.left.key);
        }
        if (this.right && this.right.height === void 0) {
          throw new Error("Undefined height for node " + this.right.key);
        }
        if (this.height === void 0) {
          throw new Error("Undefined height for node " + this.key);
        }
        const leftH = this.left ? this.left.height : 0;
        const rightH = this.right ? this.right.height : 0;
        if (this.height !== 1 + Math.max(leftH, rightH)) {
          throw new Error("Height constraint failed for node " + this.key);
        }
        if (this.left) {
          this.left.checkHeightCorrect();
        }
        if (this.right) {
          this.right.checkHeightCorrect();
        }
      }
      /**
       * Return the balance factor
       */
      balanceFactor() {
        const leftH = this.left ? this.left.height : 0;
        const rightH = this.right ? this.right.height : 0;
        return leftH - rightH;
      }
      /**
       * Check that the balance factors are all between -1 and 1
       */
      checkBalanceFactors() {
        if (Math.abs(this.balanceFactor()) > 1) {
          throw new Error("Tree is unbalanced at node " + this.key);
        }
        if (this.left) {
          this.left.checkBalanceFactors();
        }
        if (this.right) {
          this.right.checkBalanceFactors();
        }
      }
      /**
       * When checking if the BST conditions are met, also check that the heights are correct
       * and the tree is balanced
       */
      checkIsAVLT() {
        super.checkIsBST();
        this.checkHeightCorrect();
        this.checkBalanceFactors();
      }
      /**
       * Perform a right rotation of the tree if possible
       * and return the root of the resulting tree
       * The resulting tree's nodes' heights are also updated
       */
      rightRotation() {
        const q = this;
        const p = this.left;
        if (!p)
          return q;
        const b = p.right;
        if (q.parent) {
          p.parent = q.parent;
          if (q.parent.left === q)
            q.parent.left = p;
          else
            q.parent.right = p;
        } else {
          p.parent = null;
        }
        p.right = q;
        q.parent = p;
        q.left = b;
        if (b) {
          b.parent = q;
        }
        const ah = p.left ? p.left.height : 0;
        const bh = b ? b.height : 0;
        const ch = q.right ? q.right.height : 0;
        q.height = Math.max(bh, ch) + 1;
        p.height = Math.max(ah, q.height) + 1;
        return p;
      }
      /**
       * Perform a left rotation of the tree if possible
       * and return the root of the resulting tree
       * The resulting tree's nodes' heights are also updated
       */
      leftRotation() {
        const p = this;
        const q = this.right;
        if (!q) {
          return this;
        }
        const b = q.left;
        if (p.parent) {
          q.parent = p.parent;
          if (p.parent.left === p)
            p.parent.left = q;
          else
            p.parent.right = q;
        } else {
          q.parent = null;
        }
        q.left = p;
        p.parent = q;
        p.right = b;
        if (b) {
          b.parent = p;
        }
        const ah = p.left ? p.left.height : 0;
        const bh = b ? b.height : 0;
        const ch = q.right ? q.right.height : 0;
        p.height = Math.max(ah, bh) + 1;
        q.height = Math.max(ch, p.height) + 1;
        return q;
      }
      /**
       * Modify the tree if its right subtree is too small compared to the left
       * Return the new root if any
       */
      rightTooSmall() {
        if (this.balanceFactor() <= 1)
          return this;
        if (this.left.balanceFactor() < 0)
          this.left.leftRotation();
        return this.rightRotation();
      }
      /**
       * Modify the tree if its left subtree is too small compared to the right
       * Return the new root if any
       */
      leftTooSmall() {
        if (this.balanceFactor() >= -1) {
          return this;
        }
        if (this.right.balanceFactor() > 0)
          this.right.rightRotation();
        return this.leftRotation();
      }
      /**
       * Rebalance the tree along the given path. The path is given reversed (as he was calculated
       * in the insert and delete functions).
       * Returns the new root of the tree
       * Of course, the first element of the path must be the root of the tree
       */
      rebalanceAlongPath(path2) {
        let newRoot = this;
        let rotated;
        let i;
        if (!Object.prototype.hasOwnProperty.call(this, "key")) {
          delete this.height;
          return this;
        }
        for (i = path2.length - 1; i >= 0; i -= 1) {
          path2[i].height = 1 + Math.max(path2[i].left ? path2[i].left.height : 0, path2[i].right ? path2[i].right.height : 0);
          if (path2[i].balanceFactor() > 1) {
            rotated = path2[i].rightTooSmall();
            if (i === 0)
              newRoot = rotated;
          }
          if (path2[i].balanceFactor() < -1) {
            rotated = path2[i].leftTooSmall();
            if (i === 0)
              newRoot = rotated;
          }
        }
        return newRoot;
      }
      /**
       * Insert a key, value pair in the tree while maintaining the AVL tree height constraint
       * Return a pointer to the root node, which may have changed
       */
      insert(key, value) {
        const insertPath = [];
        let currentNode = this;
        if (!Object.prototype.hasOwnProperty.call(this, "key")) {
          this.key = key;
          this.data.push(value);
          this.height = 1;
          return this;
        }
        while (true) {
          if (currentNode.compareKeys(currentNode.key, key) === 0) {
            if (currentNode.unique) {
              const err = new Error(`Can't insert key ${JSON.stringify(key)}, it violates the unique constraint`);
              err.key = key;
              err.errorType = "uniqueViolated";
              throw err;
            } else
              currentNode.data.push(value);
            return this;
          }
          insertPath.push(currentNode);
          if (currentNode.compareKeys(key, currentNode.key) < 0) {
            if (!currentNode.left) {
              insertPath.push(currentNode.createLeftChild({ key, value }));
              break;
            } else
              currentNode = currentNode.left;
          } else {
            if (!currentNode.right) {
              insertPath.push(currentNode.createRightChild({ key, value }));
              break;
            } else
              currentNode = currentNode.right;
          }
        }
        return this.rebalanceAlongPath(insertPath);
      }
      /**
       * Delete a key or just a value and return the new root of the tree
       * @param {Key} key
       * @param {Value} value Optional. If not set, the whole key is deleted. If set, only this value is deleted
       */
      delete(key, value) {
        const newData = [];
        let replaceWith;
        let currentNode = this;
        const deletePath = [];
        if (!Object.prototype.hasOwnProperty.call(this, "key"))
          return this;
        while (true) {
          if (currentNode.compareKeys(key, currentNode.key) === 0) {
            break;
          }
          deletePath.push(currentNode);
          if (currentNode.compareKeys(key, currentNode.key) < 0) {
            if (currentNode.left) {
              currentNode = currentNode.left;
            } else
              return this;
          } else {
            if (currentNode.right) {
              currentNode = currentNode.right;
            } else
              return this;
          }
        }
        if (currentNode.data.length > 1 && value !== void 0) {
          currentNode.data.forEach(function(d) {
            if (!currentNode.checkValueEquality(d, value))
              newData.push(d);
          });
          currentNode.data = newData;
          return this;
        }
        if (!currentNode.left && !currentNode.right) {
          if (currentNode === this) {
            delete currentNode.key;
            currentNode.data = [];
            delete currentNode.height;
            return this;
          } else {
            if (currentNode.parent.left === currentNode)
              currentNode.parent.left = null;
            else
              currentNode.parent.right = null;
            return this.rebalanceAlongPath(deletePath);
          }
        }
        if (!currentNode.left || !currentNode.right) {
          replaceWith = currentNode.left ? currentNode.left : currentNode.right;
          if (currentNode === this) {
            replaceWith.parent = null;
            return replaceWith;
          } else {
            if (currentNode.parent.left === currentNode) {
              currentNode.parent.left = replaceWith;
              replaceWith.parent = currentNode.parent;
            } else {
              currentNode.parent.right = replaceWith;
              replaceWith.parent = currentNode.parent;
            }
            return this.rebalanceAlongPath(deletePath);
          }
        }
        deletePath.push(currentNode);
        replaceWith = currentNode.left;
        if (!replaceWith.right) {
          currentNode.key = replaceWith.key;
          currentNode.data = replaceWith.data;
          currentNode.left = replaceWith.left;
          if (replaceWith.left) {
            replaceWith.left.parent = currentNode;
          }
          return this.rebalanceAlongPath(deletePath);
        }
        while (true) {
          if (replaceWith.right) {
            deletePath.push(replaceWith);
            replaceWith = replaceWith.right;
          } else
            break;
        }
        currentNode.key = replaceWith.key;
        currentNode.data = replaceWith.data;
        replaceWith.parent.right = replaceWith.left;
        if (replaceWith.left)
          replaceWith.left.parent = replaceWith.parent;
        return this.rebalanceAlongPath(deletePath);
      }
    };
    AVLTree._AVLTree = _AVLTree;
    ["getNumberOfKeys", "search", "betweenBounds", "prettyPrint", "executeOnEveryNode"].forEach(function(fn) {
      AVLTree.prototype[fn] = function() {
        return this.tree[fn].apply(this.tree, arguments);
      };
    });
    module.exports = AVLTree;
  }
});

// node_modules/@seald-io/binary-search-tree/index.js
var require_binary_search_tree = __commonJS({
  "node_modules/@seald-io/binary-search-tree/index.js"(exports, module) {
    module.exports.BinarySearchTree = require_bst();
    module.exports.AVLTree = require_avltree();
  }
});

// node_modules/@seald-io/nedb/lib/indexes.js
var require_indexes = __commonJS({
  "node_modules/@seald-io/nedb/lib/indexes.js"(exports, module) {
    var BinarySearchTree = require_binary_search_tree().AVLTree;
    var model = require_model();
    var { uniq, isDate } = require_utils2();
    var checkValueEquality = (a, b) => a === b;
    var projectForUnique = (elt) => {
      if (elt === null)
        return "$null";
      if (typeof elt === "string")
        return "$string" + elt;
      if (typeof elt === "boolean")
        return "$boolean" + elt;
      if (typeof elt === "number")
        return "$number" + elt;
      if (isDate(elt))
        return "$date" + elt.getTime();
      return elt;
    };
    var Index = class {
      /**
       * Create a new index
       * All methods on an index guarantee that either the whole operation was successful and the index changed
       * or the operation was unsuccessful and an error is thrown while the index is unchanged
       * @param {object} options
       * @param {string} options.fieldName On which field should the index apply, can use dot notation to index on sub fields, can use comma-separated notation to use compound indexes
       * @param {boolean} [options.unique = false] Enforces a unique constraint
       * @param {boolean} [options.sparse = false] Allows a sparse index (we can have documents for which fieldName is `undefined`)
       */
      constructor(options) {
        this.fieldName = options.fieldName;
        if (typeof this.fieldName !== "string")
          throw new Error("fieldName must be a string");
        this._fields = this.fieldName.split(",");
        this.unique = options.unique || false;
        this.sparse = options.sparse || false;
        this.treeOptions = { unique: this.unique, compareKeys: model.compareThings, checkValueEquality };
        this.tree = new BinarySearchTree(this.treeOptions);
      }
      /**
       * Reset an index
       * @param {?document|?document[]} [newData] Data to initialize the index with. If an error is thrown during
       * insertion, the index is not modified.
       */
      reset(newData) {
        this.tree = new BinarySearchTree(this.treeOptions);
        if (newData)
          this.insert(newData);
      }
      /**
       * Insert a new document in the index
       * If an array is passed, we insert all its elements (if one insertion fails the index is not modified)
       * O(log(n))
       * @param {document|document[]} doc The document, or array of documents, to insert.
       */
      insert(doc) {
        let keys;
        let failingIndex;
        let error2;
        if (Array.isArray(doc)) {
          this.insertMultipleDocs(doc);
          return;
        }
        const key = model.getDotValues(doc, this._fields);
        if ((key === void 0 || typeof key === "object" && key !== null && Object.values(key).every((el) => el === void 0)) && this.sparse)
          return;
        if (!Array.isArray(key))
          this.tree.insert(key, doc);
        else {
          keys = uniq(key, projectForUnique);
          for (let i = 0; i < keys.length; i += 1) {
            try {
              this.tree.insert(keys[i], doc);
            } catch (e) {
              error2 = e;
              failingIndex = i;
              break;
            }
          }
          if (error2) {
            for (let i = 0; i < failingIndex; i += 1) {
              this.tree.delete(keys[i], doc);
            }
            throw error2;
          }
        }
      }
      /**
       * Insert an array of documents in the index
       * If a constraint is violated, the changes should be rolled back and an error thrown
       * @param {document[]} docs Array of documents to insert.
       * @private
       */
      insertMultipleDocs(docs) {
        let error2;
        let failingIndex;
        for (let i = 0; i < docs.length; i += 1) {
          try {
            this.insert(docs[i]);
          } catch (e) {
            error2 = e;
            failingIndex = i;
            break;
          }
        }
        if (error2) {
          for (let i = 0; i < failingIndex; i += 1) {
            this.remove(docs[i]);
          }
          throw error2;
        }
      }
      /**
       * Removes a document from the index.
       * If an array is passed, we remove all its elements
       * The remove operation is safe with regards to the 'unique' constraint
       * O(log(n))
       * @param {document[]|document} doc The document, or Array of documents, to remove.
       */
      remove(doc) {
        if (Array.isArray(doc)) {
          doc.forEach((d) => {
            this.remove(d);
          });
          return;
        }
        const key = model.getDotValues(doc, this._fields);
        if (key === void 0 && this.sparse)
          return;
        if (!Array.isArray(key)) {
          this.tree.delete(key, doc);
        } else {
          uniq(key, projectForUnique).forEach((_key) => {
            this.tree.delete(_key, doc);
          });
        }
      }
      /**
       * Update a document in the index
       * If a constraint is violated, changes are rolled back and an error thrown
       * Naive implementation, still in O(log(n))
       * @param {document|Array.<{oldDoc: document, newDoc: document}>} oldDoc Document to update, or an `Array` of
       * `{oldDoc, newDoc}` pairs.
       * @param {document} [newDoc] Document to replace the oldDoc with. If the first argument is an `Array` of
       * `{oldDoc, newDoc}` pairs, this second argument is ignored.
       */
      update(oldDoc, newDoc) {
        if (Array.isArray(oldDoc)) {
          this.updateMultipleDocs(oldDoc);
          return;
        }
        this.remove(oldDoc);
        try {
          this.insert(newDoc);
        } catch (e) {
          this.insert(oldDoc);
          throw e;
        }
      }
      /**
       * Update multiple documents in the index
       * If a constraint is violated, the changes need to be rolled back
       * and an error thrown
       * @param {Array.<{oldDoc: document, newDoc: document}>} pairs
       *
       * @private
       */
      updateMultipleDocs(pairs2) {
        let failingIndex;
        let error2;
        for (let i = 0; i < pairs2.length; i += 1) {
          this.remove(pairs2[i].oldDoc);
        }
        for (let i = 0; i < pairs2.length; i += 1) {
          try {
            this.insert(pairs2[i].newDoc);
          } catch (e) {
            error2 = e;
            failingIndex = i;
            break;
          }
        }
        if (error2) {
          for (let i = 0; i < failingIndex; i += 1) {
            this.remove(pairs2[i].newDoc);
          }
          for (let i = 0; i < pairs2.length; i += 1) {
            this.insert(pairs2[i].oldDoc);
          }
          throw error2;
        }
      }
      /**
       * Revert an update
       * @param {document|Array.<{oldDoc: document, newDoc: document}>} oldDoc Document to revert to, or an `Array` of `{oldDoc, newDoc}` pairs.
       * @param {document} [newDoc] Document to revert from. If the first argument is an Array of {oldDoc, newDoc}, this second argument is ignored.
       */
      revertUpdate(oldDoc, newDoc) {
        const revert = [];
        if (!Array.isArray(oldDoc))
          this.update(newDoc, oldDoc);
        else {
          oldDoc.forEach((pair) => {
            revert.push({ oldDoc: pair.newDoc, newDoc: pair.oldDoc });
          });
          this.update(revert);
        }
      }
      /**
       * Get all documents in index whose key match value (if it is a Thing) or one of the elements of value (if it is an array of Things)
       * @param {Array.<*>|*} value Value to match the key against
       * @return {document[]}
       */
      getMatching(value) {
        if (!Array.isArray(value))
          return this.tree.search(value);
        else {
          const _res = {};
          const res = [];
          value.forEach((v) => {
            this.getMatching(v).forEach((doc) => {
              _res[doc._id] = doc;
            });
          });
          Object.keys(_res).forEach((_id) => {
            res.push(_res[_id]);
          });
          return res;
        }
      }
      /**
       * Get all documents in index whose key is between bounds are they are defined by query
       * Documents are sorted by key
       * @param {object} query An object with at least one matcher among $gt, $gte, $lt, $lte.
       * @param {*} [query.$gt] Greater than matcher.
       * @param {*} [query.$gte] Greater than or equal matcher.
       * @param {*} [query.$lt] Lower than matcher.
       * @param {*} [query.$lte] Lower than or equal matcher.
       * @return {document[]}
       */
      getBetweenBounds(query) {
        return this.tree.betweenBounds(query);
      }
      /**
       * Get all elements in the index
       * @return {document[]}
       */
      getAll() {
        const res = [];
        this.tree.executeOnEveryNode((node) => {
          res.push(...node.data);
        });
        return res;
      }
    };
    module.exports = Index;
  }
});

// node_modules/@seald-io/nedb/lib/byline.js
var require_byline = __commonJS({
  "node_modules/@seald-io/nedb/lib/byline.js"(exports, module) {
    var stream = __require("stream");
    var timers = __require("timers");
    var createLineStream = (readStream, options) => {
      if (!readStream)
        throw new Error("expected readStream");
      if (!readStream.readable)
        throw new Error("readStream must be readable");
      const ls = new LineStream(options);
      readStream.pipe(ls);
      return ls;
    };
    var LineStream = class extends stream.Transform {
      constructor(options) {
        super(options);
        options = options || {};
        this._readableState.objectMode = true;
        this._lineBuffer = [];
        this._keepEmptyLines = options.keepEmptyLines || false;
        this._lastChunkEndedWithCR = false;
        this.once("pipe", (src) => {
          if (!this.encoding && src instanceof stream.Readable)
            this.encoding = src._readableState.encoding;
        });
      }
      _transform(chunk, encoding, done) {
        encoding = encoding || "utf8";
        if (Buffer.isBuffer(chunk)) {
          if (encoding === "buffer") {
            chunk = chunk.toString();
            encoding = "utf8";
          } else
            chunk = chunk.toString(encoding);
        }
        this._chunkEncoding = encoding;
        const lines = chunk.split(/\r\n|[\n\v\f\r\x85\u2028\u2029]/g);
        if (this._lastChunkEndedWithCR && chunk[0] === "\n")
          lines.shift();
        if (this._lineBuffer.length > 0) {
          this._lineBuffer[this._lineBuffer.length - 1] += lines[0];
          lines.shift();
        }
        this._lastChunkEndedWithCR = chunk[chunk.length - 1] === "\r";
        this._lineBuffer = this._lineBuffer.concat(lines);
        this._pushBuffer(encoding, 1, done);
      }
      _pushBuffer(encoding, keep, done) {
        while (this._lineBuffer.length > keep) {
          const line = this._lineBuffer.shift();
          if (this._keepEmptyLines || line.length > 0) {
            if (!this.push(this._reencode(line, encoding))) {
              timers.setImmediate(() => {
                this._pushBuffer(encoding, keep, done);
              });
              return;
            }
          }
        }
        done();
      }
      _flush(done) {
        this._pushBuffer(this._chunkEncoding, 0, done);
      }
      // see Readable::push
      _reencode(line, chunkEncoding) {
        if (this.encoding && this.encoding !== chunkEncoding)
          return Buffer.from(line, chunkEncoding).toString(this.encoding);
        else if (this.encoding)
          return line;
        else
          return Buffer.from(line, chunkEncoding);
      }
    };
    module.exports = createLineStream;
  }
});

// node_modules/@seald-io/nedb/lib/storage.js
var require_storage = __commonJS({
  "node_modules/@seald-io/nedb/lib/storage.js"(exports, module) {
    var fs2 = __require("fs");
    var fsPromises = fs2.promises;
    var path2 = __require("path");
    var { Readable } = __require("stream");
    var DEFAULT_DIR_MODE = 493;
    var DEFAULT_FILE_MODE = 420;
    var existsAsync = (file) => fsPromises.access(file, fs2.constants.F_OK).then(() => true, () => false);
    var renameAsync = fsPromises.rename;
    var writeFileAsync = fsPromises.writeFile;
    var writeFileStream = fs2.createWriteStream;
    var unlinkAsync = fsPromises.unlink;
    var appendFileAsync = fsPromises.appendFile;
    var readFileAsync = fsPromises.readFile;
    var readFileStream = fs2.createReadStream;
    var mkdirAsync = fsPromises.mkdir;
    var ensureFileDoesntExistAsync = async (file) => {
      if (await existsAsync(file))
        await unlinkAsync(file);
    };
    var flushToStorageAsync = async (options) => {
      let filename;
      let flags;
      let mode;
      if (typeof options === "string") {
        filename = options;
        flags = "r+";
        mode = DEFAULT_FILE_MODE;
      } else {
        filename = options.filename;
        flags = options.isDir ? "r" : "r+";
        mode = options.mode !== void 0 ? options.mode : DEFAULT_FILE_MODE;
      }
      let filehandle, errorOnFsync, errorOnClose;
      try {
        filehandle = await fsPromises.open(filename, flags, mode);
        try {
          await filehandle.sync();
        } catch (errFS) {
          errorOnFsync = errFS;
        }
      } catch (error2) {
        if (error2.code !== "EISDIR" || !options.isDir)
          throw error2;
      } finally {
        try {
          await filehandle.close();
        } catch (errC) {
          errorOnClose = errC;
        }
      }
      if ((errorOnFsync || errorOnClose) && !((errorOnFsync.code === "EPERM" || errorOnClose.code === "EISDIR") && options.isDir)) {
        const e = new Error("Failed to flush to storage");
        e.errorOnFsync = errorOnFsync;
        e.errorOnClose = errorOnClose;
        throw e;
      }
    };
    var writeFileLinesAsync = (filename, lines, mode = DEFAULT_FILE_MODE) => new Promise((resolve2, reject) => {
      try {
        const stream = writeFileStream(filename, { mode });
        const readable = Readable.from(lines);
        readable.on("data", (line) => {
          try {
            stream.write(line + "\n");
          } catch (err) {
            reject(err);
          }
        });
        readable.on("end", () => {
          stream.close((err) => {
            if (err)
              reject(err);
            else
              resolve2();
          });
        });
        readable.on("error", (err) => {
          reject(err);
        });
        stream.on("error", (err) => {
          reject(err);
        });
      } catch (err) {
        reject(err);
      }
    });
    var crashSafeWriteFileLinesAsync = async (filename, lines, modes = { fileMode: DEFAULT_FILE_MODE, dirMode: DEFAULT_DIR_MODE }) => {
      const tempFilename = filename + "~";
      await flushToStorageAsync({ filename: path2.dirname(filename), isDir: true, mode: modes.dirMode });
      const exists = await existsAsync(filename);
      if (exists)
        await flushToStorageAsync({ filename, mode: modes.fileMode });
      await writeFileLinesAsync(tempFilename, lines, modes.fileMode);
      await flushToStorageAsync({ filename: tempFilename, mode: modes.fileMode });
      await renameAsync(tempFilename, filename);
      await flushToStorageAsync({ filename: path2.dirname(filename), isDir: true, mode: modes.dirMode });
    };
    var ensureDatafileIntegrityAsync = async (filename, mode = DEFAULT_FILE_MODE) => {
      const tempFilename = filename + "~";
      const filenameExists = await existsAsync(filename);
      if (filenameExists)
        return;
      const oldFilenameExists = await existsAsync(tempFilename);
      if (!oldFilenameExists)
        await writeFileAsync(filename, "", { encoding: "utf8", mode });
      else
        await renameAsync(tempFilename, filename);
    };
    module.exports.existsAsync = existsAsync;
    module.exports.renameAsync = renameAsync;
    module.exports.writeFileAsync = writeFileAsync;
    module.exports.writeFileLinesAsync = writeFileLinesAsync;
    module.exports.crashSafeWriteFileLinesAsync = crashSafeWriteFileLinesAsync;
    module.exports.appendFileAsync = appendFileAsync;
    module.exports.readFileAsync = readFileAsync;
    module.exports.unlinkAsync = unlinkAsync;
    module.exports.mkdirAsync = mkdirAsync;
    module.exports.readFileStream = readFileStream;
    module.exports.flushToStorageAsync = flushToStorageAsync;
    module.exports.ensureDatafileIntegrityAsync = ensureDatafileIntegrityAsync;
    module.exports.ensureFileDoesntExistAsync = ensureFileDoesntExistAsync;
  }
});

// node_modules/@seald-io/nedb/lib/persistence.js
var require_persistence = __commonJS({
  "node_modules/@seald-io/nedb/lib/persistence.js"(exports, module) {
    var path2 = __require("path");
    var { deprecate } = __require("util");
    var byline = require_byline();
    var customUtils = require_customUtils();
    var Index = require_indexes();
    var model = require_model();
    var storage = require_storage();
    var DEFAULT_DIR_MODE = 493;
    var DEFAULT_FILE_MODE = 420;
    var Persistence = class {
      /**
       * Create a new Persistence object for database options.db
       * @param {Datastore} options.db
       * @param {Number} [options.corruptAlertThreshold] Optional, threshold after which an alert is thrown if too much data is corrupt
       * @param {serializationHook} [options.beforeDeserialization] Hook you can use to transform data after it was serialized and before it is written to disk.
       * @param {serializationHook} [options.afterSerialization] Inverse of `afterSerialization`.
       * @param {object} [options.modes] Modes to use for FS permissions. Will not work on Windows.
       * @param {number} [options.modes.fileMode=0o644] Mode to use for files.
       * @param {number} [options.modes.dirMode=0o755] Mode to use for directories.
       * @param {boolean} [options.testSerializationHooks=true] Whether to test the serialization hooks or not, might be CPU-intensive
       */
      constructor(options) {
        this.db = options.db;
        this.inMemoryOnly = this.db.inMemoryOnly;
        this.filename = this.db.filename;
        this.corruptAlertThreshold = options.corruptAlertThreshold !== void 0 ? options.corruptAlertThreshold : 0.1;
        this.modes = options.modes !== void 0 ? options.modes : { fileMode: DEFAULT_FILE_MODE, dirMode: DEFAULT_DIR_MODE };
        if (this.modes.fileMode === void 0)
          this.modes.fileMode = DEFAULT_FILE_MODE;
        if (this.modes.dirMode === void 0)
          this.modes.dirMode = DEFAULT_DIR_MODE;
        if (!this.inMemoryOnly && this.filename && this.filename.charAt(this.filename.length - 1) === "~")
          throw new Error("The datafile name can't end with a ~, which is reserved for crash safe backup files");
        if (options.afterSerialization && !options.beforeDeserialization)
          throw new Error("Serialization hook defined but deserialization hook undefined, cautiously refusing to start NeDB to prevent dataloss");
        if (!options.afterSerialization && options.beforeDeserialization)
          throw new Error("Serialization hook undefined but deserialization hook defined, cautiously refusing to start NeDB to prevent dataloss");
        this.afterSerialization = options.afterSerialization || ((s) => s);
        this.beforeDeserialization = options.beforeDeserialization || ((s) => s);
        if (options.testSerializationHooks === void 0 || options.testSerializationHooks) {
          for (let i = 1; i < 30; i += 1) {
            for (let j = 0; j < 10; j += 1) {
              const randomString = customUtils.uid(i);
              if (this.beforeDeserialization(this.afterSerialization(randomString)) !== randomString) {
                throw new Error("beforeDeserialization is not the reverse of afterSerialization, cautiously refusing to start NeDB to prevent dataloss");
              }
            }
          }
        }
      }
      /**
       * Internal version without using the {@link Datastore#executor} of {@link Datastore#compactDatafileAsync}, use it instead.
       * @return {Promise<void>}
       * @private
       */
      async persistCachedDatabaseAsync() {
        const lines = [];
        if (this.inMemoryOnly)
          return;
        this.db.getAllData().forEach((doc) => {
          lines.push(this.afterSerialization(model.serialize(doc)));
        });
        Object.keys(this.db.indexes).forEach((fieldName) => {
          if (fieldName !== "_id") {
            lines.push(this.afterSerialization(model.serialize({
              $$indexCreated: {
                fieldName: this.db.indexes[fieldName].fieldName,
                unique: this.db.indexes[fieldName].unique,
                sparse: this.db.indexes[fieldName].sparse
              }
            })));
          }
        });
        await storage.crashSafeWriteFileLinesAsync(this.filename, lines, this.modes);
        this.db.emit("compaction.done");
      }
      /**
       * @see Datastore#compactDatafile
       * @deprecated
       * @param {NoParamCallback} [callback = () => {}]
       * @see Persistence#compactDatafileAsync
       */
      compactDatafile(callback) {
        deprecate((_callback) => this.db.compactDatafile(_callback), "@seald-io/nedb: calling Datastore#persistence#compactDatafile is deprecated, please use Datastore#compactDatafile, it will be removed in the next major version.")(callback);
      }
      /**
       * @see Datastore#setAutocompactionInterval
       * @deprecated
       */
      setAutocompactionInterval(interval) {
        deprecate((_interval) => this.db.setAutocompactionInterval(_interval), "@seald-io/nedb: calling Datastore#persistence#setAutocompactionInterval is deprecated, please use Datastore#setAutocompactionInterval, it will be removed in the next major version.")(interval);
      }
      /**
       * @see Datastore#stopAutocompaction
       * @deprecated
       */
      stopAutocompaction() {
        deprecate(() => this.db.stopAutocompaction(), "@seald-io/nedb: calling Datastore#persistence#stopAutocompaction is deprecated, please use Datastore#stopAutocompaction, it will be removed in the next major version.")();
      }
      /**
       * Persist new state for the given newDocs (can be insertion, update or removal)
       * Use an append-only format
       *
       * Do not use directly, it should only used by a {@link Datastore} instance.
       * @param {document[]} newDocs Can be empty if no doc was updated/removed
       * @return {Promise}
       * @private
       */
      async persistNewStateAsync(newDocs) {
        let toPersist = "";
        if (this.inMemoryOnly)
          return;
        newDocs.forEach((doc) => {
          toPersist += this.afterSerialization(model.serialize(doc)) + "\n";
        });
        if (toPersist.length === 0)
          return;
        await storage.appendFileAsync(this.filename, toPersist, { encoding: "utf8", mode: this.modes.fileMode });
      }
      /**
       * @typedef rawIndex
       * @property {string} fieldName
       * @property {boolean} [unique]
       * @property {boolean} [sparse]
       */
      /**
       * From a database's raw data, return the corresponding machine understandable collection.
       *
       * Do not use directly, it should only used by a {@link Datastore} instance.
       * @param {string} rawData database file
       * @return {{data: document[], indexes: Object.<string, rawIndex>}}
       * @private
       */
      treatRawData(rawData) {
        const data = rawData.split("\n");
        const dataById = {};
        const indexes = {};
        let dataLength = data.length;
        let corruptItems = 0;
        for (const datum of data) {
          if (datum === "") {
            dataLength--;
            continue;
          }
          try {
            const doc = model.deserialize(this.beforeDeserialization(datum));
            if (doc._id) {
              if (doc.$$deleted === true)
                delete dataById[doc._id];
              else
                dataById[doc._id] = doc;
            } else if (doc.$$indexCreated && doc.$$indexCreated.fieldName != null)
              indexes[doc.$$indexCreated.fieldName] = doc.$$indexCreated;
            else if (typeof doc.$$indexRemoved === "string")
              delete indexes[doc.$$indexRemoved];
          } catch (e) {
            corruptItems += 1;
          }
        }
        if (dataLength > 0) {
          const corruptionRate = corruptItems / dataLength;
          if (corruptionRate > this.corruptAlertThreshold) {
            const error2 = new Error(`${Math.floor(100 * corruptionRate)}% of the data file is corrupt, more than given corruptAlertThreshold (${Math.floor(100 * this.corruptAlertThreshold)}%). Cautiously refusing to start NeDB to prevent dataloss.`);
            error2.corruptionRate = corruptionRate;
            error2.corruptItems = corruptItems;
            error2.dataLength = dataLength;
            throw error2;
          }
        }
        const tdata = Object.values(dataById);
        return { data: tdata, indexes };
      }
      /**
       * From a database's raw data stream, return the corresponding machine understandable collection
       * Is only used by a {@link Datastore} instance.
       *
       * Is only used in the Node.js version, since [React-Native]{@link module:storageReactNative} &
       * [browser]{@link module:storageBrowser} storage modules don't provide an equivalent of
       * {@link module:storage.readFileStream}.
       *
       * Do not use directly, it should only used by a {@link Datastore} instance.
       * @param {Readable} rawStream
       * @return {Promise<{data: document[], indexes: Object.<string, rawIndex>}>}
       * @async
       * @private
       */
      treatRawStreamAsync(rawStream) {
        return new Promise((resolve2, reject) => {
          const dataById = {};
          const indexes = {};
          let corruptItems = 0;
          const lineStream = byline(rawStream);
          let dataLength = 0;
          lineStream.on("data", (line) => {
            if (line === "")
              return;
            try {
              const doc = model.deserialize(this.beforeDeserialization(line));
              if (doc._id) {
                if (doc.$$deleted === true)
                  delete dataById[doc._id];
                else
                  dataById[doc._id] = doc;
              } else if (doc.$$indexCreated && doc.$$indexCreated.fieldName != null)
                indexes[doc.$$indexCreated.fieldName] = doc.$$indexCreated;
              else if (typeof doc.$$indexRemoved === "string")
                delete indexes[doc.$$indexRemoved];
            } catch (e) {
              corruptItems += 1;
            }
            dataLength++;
          });
          lineStream.on("end", () => {
            if (dataLength > 0) {
              const corruptionRate = corruptItems / dataLength;
              if (corruptionRate > this.corruptAlertThreshold) {
                const error2 = new Error(`${Math.floor(100 * corruptionRate)}% of the data file is corrupt, more than given corruptAlertThreshold (${Math.floor(100 * this.corruptAlertThreshold)}%). Cautiously refusing to start NeDB to prevent dataloss.`);
                error2.corruptionRate = corruptionRate;
                error2.corruptItems = corruptItems;
                error2.dataLength = dataLength;
                reject(error2, null);
                return;
              }
            }
            const data = Object.values(dataById);
            resolve2({ data, indexes });
          });
          lineStream.on("error", function(err) {
            reject(err, null);
          });
        });
      }
      /**
       * Load the database
       * 1) Create all indexes
       * 2) Insert all data
       * 3) Compact the database
       *
       * This means pulling data out of the data file or creating it if it doesn't exist
       * Also, all data is persisted right away, which has the effect of compacting the database file
       * This operation is very quick at startup for a big collection (60ms for ~10k docs)
       *
       * Do not use directly as it does not use the [Executor]{@link Datastore.executor}, use {@link Datastore#loadDatabaseAsync} instead.
       * @return {Promise<void>}
       * @private
       */
      async loadDatabaseAsync() {
        this.db._resetIndexes();
        if (this.inMemoryOnly)
          return;
        await Persistence.ensureDirectoryExistsAsync(path2.dirname(this.filename), this.modes.dirMode);
        await storage.ensureDatafileIntegrityAsync(this.filename, this.modes.fileMode);
        let treatedData;
        if (storage.readFileStream) {
          const fileStream = storage.readFileStream(this.filename, { encoding: "utf8", mode: this.modes.fileMode });
          treatedData = await this.treatRawStreamAsync(fileStream);
        } else {
          const rawData = await storage.readFileAsync(this.filename, { encoding: "utf8", mode: this.modes.fileMode });
          treatedData = this.treatRawData(rawData);
        }
        Object.keys(treatedData.indexes).forEach((key) => {
          this.db.indexes[key] = new Index(treatedData.indexes[key]);
        });
        try {
          this.db._resetIndexes(treatedData.data);
        } catch (e) {
          this.db._resetIndexes();
          throw e;
        }
        await this.db.persistence.persistCachedDatabaseAsync();
        this.db.executor.processBuffer();
      }
      /**
       * See {@link Datastore#dropDatabaseAsync}. This function uses {@link Datastore#executor} internally. Decorating this
       * function with an {@link Executor#pushAsync} will result in a deadlock.
       * @return {Promise<void>}
       * @private
       * @see Datastore#dropDatabaseAsync
       */
      async dropDatabaseAsync() {
        this.db.stopAutocompaction();
        this.db.executor.ready = false;
        this.db.executor.resetBuffer();
        await this.db.executor.queue.guardian;
        this.db.indexes = {};
        this.db.indexes._id = new Index({ fieldName: "_id", unique: true });
        this.db.ttlIndexes = {};
        if (!this.db.inMemoryOnly) {
          await this.db.executor.pushAsync(async () => {
            if (await storage.existsAsync(this.filename))
              await storage.unlinkAsync(this.filename);
          }, true);
        }
      }
      /**
       * Check if a directory stat and create it on the fly if it is not the case.
       * @param {string} dir
       * @param {number} [mode=0o777]
       * @return {Promise<void>}
       * @private
       */
      static async ensureDirectoryExistsAsync(dir, mode = DEFAULT_DIR_MODE) {
        await storage.mkdirAsync(dir, { recursive: true, mode });
      }
    };
    module.exports = Persistence;
  }
});

// node_modules/@seald-io/nedb/lib/datastore.js
var require_datastore = __commonJS({
  "node_modules/@seald-io/nedb/lib/datastore.js"(exports, module) {
    var { EventEmitter } = __require("events");
    var { callbackify, deprecate } = __require("util");
    var Cursor = require_cursor();
    var customUtils = require_customUtils();
    var Executor = require_executor();
    var Index = require_indexes();
    var model = require_model();
    var Persistence = require_persistence();
    var { isDate, pick, filterIndexNames } = require_utils2();
    var Datastore2 = class extends EventEmitter {
      /**
       * Create a new collection, either persistent or in-memory.
       *
       * If you use a persistent datastore without the `autoload` option, you need to call {@link Datastore#loadDatabase} or
       * {@link Datastore#loadDatabaseAsync} manually. This function fetches the data from datafile and prepares the database.
       * **Don't forget it!** If you use a persistent datastore, no command (insert, find, update, remove) will be executed
       * before it is called, so make sure to call it yourself or use the `autoload` option.
       *
       * Also, if loading fails, all commands registered to the {@link Datastore#executor} afterwards will not be executed.
       * They will be registered and executed, in sequence, only after a successful loading.
       *
       * @param {object|string} options Can be an object or a string. If options is a string, the behavior is the same as in
       * v0.6: it will be interpreted as `options.filename`. **Giving a string is deprecated, and will be removed in the
       * next major version.**
       * @param {string} [options.filename = null] Path to the file where the data is persisted. If left blank, the datastore is
       * automatically considered in-memory only. It cannot end with a `~` which is used in the temporary files NeDB uses to
       * perform crash-safe writes. Not used if `options.inMemoryOnly` is `true`.
       * @param {boolean} [options.inMemoryOnly = false] If set to true, no data will be written in storage. This option has
       * priority over `options.filename`.
       * @param {object} [options.modes] Permissions to use for FS. Only used for Node.js storage module. Will not work on Windows.
       * @param {number} [options.modes.fileMode = 0o644] Permissions to use for database files
       * @param {number} [options.modes.dirMode = 0o755] Permissions to use for database directories
       * @param {boolean} [options.timestampData = false] If set to true, createdAt and updatedAt will be created and
       * populated automatically (if not specified by user)
       * @param {boolean} [options.autoload = false] If used, the database will automatically be loaded from the datafile
       * upon creation (you don't need to call `loadDatabase`). Any command issued before load is finished is buffered and
       * will be executed when load is done. When autoloading is done, you can either use the `onload` callback, or you can
       * use `this.autoloadPromise` which resolves (or rejects) when autloading is done.
       * @param {NoParamCallback} [options.onload] If you use autoloading, this is the handler called after the `loadDatabase`. It
       * takes one `error` argument. If you use autoloading without specifying this handler, and an error happens during
       * load, an error will be thrown.
       * @param {serializationHook} [options.beforeDeserialization] Hook you can use to transform data after it was serialized and
       * before it is written to disk. Can be used for example to encrypt data before writing database to disk. This
       * function takes a string as parameter (one line of an NeDB data file) and outputs the transformed string, **which
       * must absolutely not contain a `\n` character** (or data will be lost).
       * @param {serializationHook} [options.afterSerialization] Inverse of `afterSerialization`. Make sure to include both and not
       * just one, or you risk data loss. For the same reason, make sure both functions are inverses of one another. Some
       * failsafe mechanisms are in place to prevent data loss if you misuse the serialization hooks: NeDB checks that never
       * one is declared without the other, and checks that they are reverse of one another by testing on random strings of
       * various lengths. In addition, if too much data is detected as corrupt, NeDB will refuse to start as it could mean
       * you're not using the deserialization hook corresponding to the serialization hook used before.
       * @param {number} [options.corruptAlertThreshold = 0.1] Between 0 and 1, defaults to 10%. NeDB will refuse to start
       * if more than this percentage of the datafile is corrupt. 0 means you don't tolerate any corruption, 1 means you
       * don't care.
       * @param {compareStrings} [options.compareStrings] If specified, it overrides default string comparison which is not
       * well adapted to non-US characters in particular accented letters. Native `localCompare` will most of the time be
       * the right choice.
       * @param {boolean} [options.testSerializationHooks=true] Whether to test the serialization hooks or not,
       * might be CPU-intensive
       */
      constructor(options) {
        super();
        let filename;
        if (typeof options === "string") {
          deprecate(() => {
            filename = options;
            this.inMemoryOnly = false;
          }, "@seald-io/nedb: Giving a string to the Datastore constructor is deprecated and will be removed in the next major version. Please use an options object with an argument 'filename'.")();
        } else {
          options = options || {};
          filename = options.filename;
          this.inMemoryOnly = options.inMemoryOnly || false;
          this.autoload = options.autoload || false;
          this.timestampData = options.timestampData || false;
        }
        if (!filename || typeof filename !== "string" || filename.length === 0) {
          this.filename = null;
          this.inMemoryOnly = true;
        } else {
          this.filename = filename;
        }
        this.compareStrings = options.compareStrings;
        this.persistence = new Persistence({
          db: this,
          afterSerialization: options.afterSerialization,
          beforeDeserialization: options.beforeDeserialization,
          corruptAlertThreshold: options.corruptAlertThreshold,
          modes: options.modes,
          testSerializationHooks: options.testSerializationHooks
        });
        this.executor = new Executor();
        if (this.inMemoryOnly)
          this.executor.ready = true;
        this.indexes = {};
        this.indexes._id = new Index({ fieldName: "_id", unique: true });
        this.ttlIndexes = {};
        if (this.autoload) {
          this.autoloadPromise = this.loadDatabaseAsync();
          this.autoloadPromise.then(() => {
            if (options.onload)
              options.onload();
          }, (err) => {
            if (options.onload)
              options.onload(err);
            else
              throw err;
          });
        } else
          this.autoloadPromise = null;
        this._autocompactionIntervalId = null;
      }
      /**
       * Queue a compaction/rewrite of the datafile.
       * It works by rewriting the database file, and compacts it since the cache always contains only the number of
       * documents in the collection while the data file is append-only so it may grow larger.
       *
       * @async
       */
      compactDatafileAsync() {
        return this.executor.pushAsync(() => this.persistence.persistCachedDatabaseAsync());
      }
      /**
       * Callback version of {@link Datastore#compactDatafileAsync}.
       * @param {NoParamCallback} [callback = () => {}]
       * @see Datastore#compactDatafileAsync
       */
      compactDatafile(callback) {
        const promise = this.compactDatafileAsync();
        if (typeof callback === "function")
          callbackify(() => promise)(callback);
      }
      /**
       * Set automatic compaction every `interval` ms
       * @param {Number} interval in milliseconds, with an enforced minimum of 5000 milliseconds
       */
      setAutocompactionInterval(interval) {
        const minInterval = 5e3;
        if (Number.isNaN(Number(interval)))
          throw new Error("Interval must be a non-NaN number");
        const realInterval = Math.max(Number(interval), minInterval);
        this.stopAutocompaction();
        this._autocompactionIntervalId = setInterval(() => {
          this.compactDatafile();
        }, realInterval);
      }
      /**
       * Stop autocompaction (do nothing if automatic compaction was not running)
       */
      stopAutocompaction() {
        if (this._autocompactionIntervalId) {
          clearInterval(this._autocompactionIntervalId);
          this._autocompactionIntervalId = null;
        }
      }
      /**
       * Callback version of {@link Datastore#loadDatabaseAsync}.
       * @param {NoParamCallback} [callback]
       * @see Datastore#loadDatabaseAsync
       */
      loadDatabase(callback) {
        const promise = this.loadDatabaseAsync();
        if (typeof callback === "function")
          callbackify(() => promise)(callback);
      }
      /**
       * Stops auto-compaction, finishes all queued operations, drops the database both in memory and in storage.
       * **WARNING**: it is not recommended re-using an instance of NeDB if its database has been dropped, it is
       * preferable to instantiate a new one.
       * @async
       * @return {Promise}
       */
      dropDatabaseAsync() {
        return this.persistence.dropDatabaseAsync();
      }
      /**
       * Callback version of {@link Datastore#dropDatabaseAsync}.
       * @param {NoParamCallback} [callback]
       * @see Datastore#dropDatabaseAsync
       */
      dropDatabase(callback) {
        const promise = this.dropDatabaseAsync();
        if (typeof callback === "function")
          callbackify(() => promise)(callback);
      }
      /**
       * Load the database from the datafile, and trigger the execution of buffered commands if any.
       * @async
       * @return {Promise}
       */
      loadDatabaseAsync() {
        return this.executor.pushAsync(() => this.persistence.loadDatabaseAsync(), true);
      }
      /**
       * Get an array of all the data in the database.
       * @return {document[]}
       */
      getAllData() {
        return this.indexes._id.getAll();
      }
      /**
       * Reset all currently defined indexes.
       * @param {?document|?document[]} [newData]
       * @private
       */
      _resetIndexes(newData) {
        for (const index of Object.values(this.indexes)) {
          index.reset(newData);
        }
      }
      /**
       * Callback version of {@link Datastore#ensureIndex}.
       * @param {object} options
       * @param {string|string[]} options.fieldName
       * @param {boolean} [options.unique = false]
       * @param {boolean} [options.sparse = false]
       * @param {number} [options.expireAfterSeconds]
       * @param {NoParamCallback} [callback]
       * @see Datastore#ensureIndex
       */
      ensureIndex(options = {}, callback) {
        const promise = this.ensureIndexAsync(options);
        if (typeof callback === "function")
          callbackify(() => promise)(callback);
      }
      /**
       * Ensure an index is kept for this field. Same parameters as lib/indexes
       * This function acts synchronously on the indexes, however the persistence of the indexes is deferred with the
       * executor.
       * @param {object} options
       * @param {string|string[]} options.fieldName Name of the field to index. Use the dot notation to index a field in a nested
       * document. For a compound index, use an array of field names. Using a comma in a field name is not permitted.
       * @param {boolean} [options.unique = false] Enforce field uniqueness. Note that a unique index will raise an error
       * if you try to index two documents for which the field is not defined.
       * @param {boolean} [options.sparse = false] Don't index documents for which the field is not defined. Use this option
       * along with "unique" if you want to accept multiple documents for which it is not defined.
       * @param {number} [options.expireAfterSeconds] - If set, the created index is a TTL (time to live) index, that will
       * automatically remove documents when the system date becomes larger than the date on the indexed field plus
       * `expireAfterSeconds`. Documents where the indexed field is not specified or not a `Date` object are ignored.
       * @return {Promise<void>}
       */
      async ensureIndexAsync(options = {}) {
        if (!options.fieldName) {
          const err = new Error("Cannot create an index without a fieldName");
          err.missingFieldName = true;
          throw err;
        }
        const _fields = [].concat(options.fieldName).sort();
        if (_fields.some((field) => field.includes(","))) {
          throw new Error("Cannot use comma in index fieldName");
        }
        const _options = {
          ...options,
          fieldName: _fields.join(",")
        };
        if (this.indexes[_options.fieldName])
          return;
        this.indexes[_options.fieldName] = new Index(_options);
        if (options.expireAfterSeconds !== void 0)
          this.ttlIndexes[_options.fieldName] = _options.expireAfterSeconds;
        try {
          this.indexes[_options.fieldName].insert(this.getAllData());
        } catch (e) {
          delete this.indexes[_options.fieldName];
          throw e;
        }
        await this.executor.pushAsync(() => this.persistence.persistNewStateAsync([{ $$indexCreated: _options }]), true);
      }
      /**
       * Callback version of {@link Datastore#removeIndexAsync}.
       * @param {string} fieldName
       * @param {NoParamCallback} [callback]
       * @see Datastore#removeIndexAsync
       */
      removeIndex(fieldName, callback = () => {
      }) {
        const promise = this.removeIndexAsync(fieldName);
        callbackify(() => promise)(callback);
      }
      /**
       * Remove an index.
       * @param {string} fieldName Field name of the index to remove. Use the dot notation to remove an index referring to a
       * field in a nested document.
       * @return {Promise<void>}
       * @see Datastore#removeIndex
       */
      async removeIndexAsync(fieldName) {
        delete this.indexes[fieldName];
        await this.executor.pushAsync(() => this.persistence.persistNewStateAsync([{ $$indexRemoved: fieldName }]), true);
      }
      /**
       * Add one or several document(s) to all indexes.
       *
       * This is an internal function.
       * @param {document} doc
       * @private
       */
      _addToIndexes(doc) {
        let failingIndex;
        let error2;
        const keys = Object.keys(this.indexes);
        for (let i = 0; i < keys.length; i += 1) {
          try {
            this.indexes[keys[i]].insert(doc);
          } catch (e) {
            failingIndex = i;
            error2 = e;
            break;
          }
        }
        if (error2) {
          for (let i = 0; i < failingIndex; i += 1) {
            this.indexes[keys[i]].remove(doc);
          }
          throw error2;
        }
      }
      /**
       * Remove one or several document(s) from all indexes.
       *
       * This is an internal function.
       * @param {document} doc
       * @private
       */
      _removeFromIndexes(doc) {
        for (const index of Object.values(this.indexes)) {
          index.remove(doc);
        }
      }
      /**
       * Update one or several documents in all indexes.
       *
       * To update multiple documents, oldDoc must be an array of { oldDoc, newDoc } pairs.
       *
       * If one update violates a constraint, all changes are rolled back.
       *
       * This is an internal function.
       * @param {document|Array.<{oldDoc: document, newDoc: document}>} oldDoc Document to update, or an `Array` of
       * `{oldDoc, newDoc}` pairs.
       * @param {document} [newDoc] Document to replace the oldDoc with. If the first argument is an `Array` of
       * `{oldDoc, newDoc}` pairs, this second argument is ignored.
       * @private
       */
      _updateIndexes(oldDoc, newDoc) {
        let failingIndex;
        let error2;
        const keys = Object.keys(this.indexes);
        for (let i = 0; i < keys.length; i += 1) {
          try {
            this.indexes[keys[i]].update(oldDoc, newDoc);
          } catch (e) {
            failingIndex = i;
            error2 = e;
            break;
          }
        }
        if (error2) {
          for (let i = 0; i < failingIndex; i += 1) {
            this.indexes[keys[i]].revertUpdate(oldDoc, newDoc);
          }
          throw error2;
        }
      }
      /**
       * Get all candidate documents matching the query, regardless of their expiry status.
       * @param {query} query
       * @return {document[]}
       *
       * @private
       */
      _getRawCandidates(query) {
        const indexNames = Object.keys(this.indexes);
        let usableQuery;
        usableQuery = Object.entries(query).filter(filterIndexNames(indexNames)).pop();
        if (usableQuery)
          return this.indexes[usableQuery[0]].getMatching(usableQuery[1]);
        const compoundQueryKeys = indexNames.filter((indexName) => indexName.indexOf(",") !== -1).map((indexName) => indexName.split(",")).filter(
          (subIndexNames) => Object.entries(query).filter(filterIndexNames(subIndexNames)).length === subIndexNames.length
        );
        if (compoundQueryKeys.length > 0)
          return this.indexes[compoundQueryKeys[0]].getMatching(pick(query, compoundQueryKeys[0]));
        usableQuery = Object.entries(query).filter(
          ([k, v]) => !!(query[k] && Object.prototype.hasOwnProperty.call(query[k], "$in")) && indexNames.includes(k)
        ).pop();
        if (usableQuery)
          return this.indexes[usableQuery[0]].getMatching(usableQuery[1].$in);
        usableQuery = Object.entries(query).filter(
          ([k, v]) => !!(query[k] && (Object.prototype.hasOwnProperty.call(query[k], "$lt") || Object.prototype.hasOwnProperty.call(query[k], "$lte") || Object.prototype.hasOwnProperty.call(query[k], "$gt") || Object.prototype.hasOwnProperty.call(query[k], "$gte"))) && indexNames.includes(k)
        ).pop();
        if (usableQuery)
          return this.indexes[usableQuery[0]].getBetweenBounds(usableQuery[1]);
        return this.getAllData();
      }
      /**
       * Return the list of candidates for a given query
       * Crude implementation for now, we return the candidates given by the first usable index if any
       * We try the following query types, in this order: basic match, $in match, comparison match
       * One way to make it better would be to enable the use of multiple indexes if the first usable index
       * returns too much data. I may do it in the future.
       *
       * Returned candidates will be scanned to find and remove all expired documents
       *
       * This is an internal function.
       * @param {query} query
       * @param {boolean} [dontExpireStaleDocs = false] If true don't remove stale docs. Useful for the remove function
       * which shouldn't be impacted by expirations.
       * @return {Promise<document[]>} candidates
       * @private
       */
      async _getCandidatesAsync(query, dontExpireStaleDocs = false) {
        const validDocs = [];
        const docs = this._getRawCandidates(query);
        if (!dontExpireStaleDocs) {
          const expiredDocsIds = [];
          const ttlIndexesFieldNames = Object.keys(this.ttlIndexes);
          docs.forEach((doc) => {
            if (ttlIndexesFieldNames.every((i) => !(doc[i] !== void 0 && isDate(doc[i]) && Date.now() > doc[i].getTime() + this.ttlIndexes[i] * 1e3)))
              validDocs.push(doc);
            else
              expiredDocsIds.push(doc._id);
          });
          for (const _id of expiredDocsIds) {
            await this._removeAsync({ _id }, {});
          }
        } else
          validDocs.push(...docs);
        return validDocs;
      }
      /**
       * Insert a new document
       * This is an internal function, use {@link Datastore#insertAsync} which has the same signature.
       * @param {document|document[]} newDoc
       * @return {Promise<document|document[]>}
       * @private
       */
      async _insertAsync(newDoc) {
        const preparedDoc = this._prepareDocumentForInsertion(newDoc);
        this._insertInCache(preparedDoc);
        await this.persistence.persistNewStateAsync(Array.isArray(preparedDoc) ? preparedDoc : [preparedDoc]);
        return model.deepCopy(preparedDoc);
      }
      /**
       * Create a new _id that's not already in use
       * @return {string} id
       * @private
       */
      _createNewId() {
        let attemptId = customUtils.uid(16);
        if (this.indexes._id.getMatching(attemptId).length > 0)
          attemptId = this._createNewId();
        return attemptId;
      }
      /**
       * Prepare a document (or array of documents) to be inserted in a database
       * Meaning adds _id and timestamps if necessary on a copy of newDoc to avoid any side effect on user input
       * @param {document|document[]} newDoc document, or Array of documents, to prepare
       * @return {document|document[]} prepared document, or Array of prepared documents
       * @private
       */
      _prepareDocumentForInsertion(newDoc) {
        let preparedDoc;
        if (Array.isArray(newDoc)) {
          preparedDoc = [];
          newDoc.forEach((doc) => {
            preparedDoc.push(this._prepareDocumentForInsertion(doc));
          });
        } else {
          preparedDoc = model.deepCopy(newDoc);
          if (preparedDoc._id === void 0)
            preparedDoc._id = this._createNewId();
          const now = /* @__PURE__ */ new Date();
          if (this.timestampData && preparedDoc.createdAt === void 0)
            preparedDoc.createdAt = now;
          if (this.timestampData && preparedDoc.updatedAt === void 0)
            preparedDoc.updatedAt = now;
          model.checkObject(preparedDoc);
        }
        return preparedDoc;
      }
      /**
       * If newDoc is an array of documents, this will insert all documents in the cache
       * @param {document|document[]} preparedDoc
       * @private
       */
      _insertInCache(preparedDoc) {
        if (Array.isArray(preparedDoc))
          this._insertMultipleDocsInCache(preparedDoc);
        else
          this._addToIndexes(preparedDoc);
      }
      /**
       * If one insertion fails (e.g. because of a unique constraint), roll back all previous
       * inserts and throws the error
       * @param {document[]} preparedDocs
       * @private
       */
      _insertMultipleDocsInCache(preparedDocs) {
        let failingIndex;
        let error2;
        for (let i = 0; i < preparedDocs.length; i += 1) {
          try {
            this._addToIndexes(preparedDocs[i]);
          } catch (e) {
            error2 = e;
            failingIndex = i;
            break;
          }
        }
        if (error2) {
          for (let i = 0; i < failingIndex; i += 1) {
            this._removeFromIndexes(preparedDocs[i]);
          }
          throw error2;
        }
      }
      /**
       * Callback version of {@link Datastore#insertAsync}.
       * @param {document|document[]} newDoc
       * @param {SingleDocumentCallback|MultipleDocumentsCallback} [callback]
       * @see Datastore#insertAsync
       */
      insert(newDoc, callback) {
        const promise = this.insertAsync(newDoc);
        if (typeof callback === "function")
          callbackify(() => promise)(callback);
      }
      /**
       * Insert a new document, or new documents.
       * @param {document|document[]} newDoc Document or array of documents to insert.
       * @return {Promise<document|document[]>} The document(s) inserted.
       * @async
       */
      insertAsync(newDoc) {
        return this.executor.pushAsync(() => this._insertAsync(newDoc));
      }
      /**
       * Callback for {@link Datastore#countCallback}.
       * @callback Datastore~countCallback
       * @param {?Error} err
       * @param {?number} count
       */
      /**
       * Callback-version of {@link Datastore#countAsync}.
       * @param {query} query
       * @param {Datastore~countCallback} [callback]
       * @return {Cursor<number>|undefined}
       * @see Datastore#countAsync
       */
      count(query, callback) {
        const cursor = this.countAsync(query);
        if (typeof callback === "function")
          callbackify(cursor.execAsync.bind(cursor))(callback);
        else
          return cursor;
      }
      /**
       * Count all documents matching the query.
       * @param {query} query MongoDB-style query
       * @return {Cursor<number>} count
       * @async
       */
      countAsync(query) {
        return new Cursor(this, query, (docs) => docs.length);
      }
      /**
       * Callback version of {@link Datastore#findAsync}.
       * @param {query} query
       * @param {projection|MultipleDocumentsCallback} [projection = {}]
       * @param {MultipleDocumentsCallback} [callback]
       * @return {Cursor<document[]>|undefined}
       * @see Datastore#findAsync
       */
      find(query, projection, callback) {
        if (arguments.length === 1) {
          projection = {};
        } else if (arguments.length === 2) {
          if (typeof projection === "function") {
            callback = projection;
            projection = {};
          }
        }
        const cursor = this.findAsync(query, projection);
        if (typeof callback === "function")
          callbackify(cursor.execAsync.bind(cursor))(callback);
        else
          return cursor;
      }
      /**
       * Find all documents matching the query.
       * We return the {@link Cursor} that the user can either `await` directly or use to can {@link Cursor#limit} or
       * {@link Cursor#skip} before.
       * @param {query} query MongoDB-style query
       * @param {projection} [projection = {}] MongoDB-style projection
       * @return {Cursor<document[]>}
       * @async
       */
      findAsync(query, projection = {}) {
        const cursor = new Cursor(this, query, (docs) => docs.map((doc) => model.deepCopy(doc)));
        cursor.projection(projection);
        return cursor;
      }
      /**
       * @callback Datastore~findOneCallback
       * @param {?Error} err
       * @param {document} doc
       */
      /**
       * Callback version of {@link Datastore#findOneAsync}.
       * @param {query} query
       * @param {projection|SingleDocumentCallback} [projection = {}]
       * @param {SingleDocumentCallback} [callback]
       * @return {Cursor<document>|undefined}
       * @see Datastore#findOneAsync
       */
      findOne(query, projection, callback) {
        if (arguments.length === 1) {
          projection = {};
        } else if (arguments.length === 2) {
          if (typeof projection === "function") {
            callback = projection;
            projection = {};
          }
        }
        const cursor = this.findOneAsync(query, projection);
        if (typeof callback === "function")
          callbackify(cursor.execAsync.bind(cursor))(callback);
        else
          return cursor;
      }
      /**
       * Find one document matching the query.
       * We return the {@link Cursor} that the user can either `await` directly or use to can {@link Cursor#skip} before.
       * @param {query} query MongoDB-style query
       * @param {projection} projection MongoDB-style projection
       * @return {Cursor<document>}
       */
      findOneAsync(query, projection = {}) {
        const cursor = new Cursor(this, query, (docs) => docs.length === 1 ? model.deepCopy(docs[0]) : null);
        cursor.projection(projection).limit(1);
        return cursor;
      }
      /**
       * See {@link Datastore#updateAsync} return type for the definition of the callback parameters.
       *
       * **WARNING:** Prior to 3.0.0, `upsert` was either `true` of falsy (but not `false`), it is now always a boolean.
       * `affectedDocuments` could be `undefined` when `returnUpdatedDocs` was `false`, it is now `null` in these cases.
       *
       * **WARNING:** Prior to 1.8.0, the `upsert` argument was not given, it was impossible for the developer to determine
       * during a `{ multi: false, returnUpdatedDocs: true, upsert: true }` update if it inserted a document or just updated
       * it.
       *
       * @callback Datastore~updateCallback
       * @param {?Error} err
       * @param {number} numAffected
       * @param {?document[]|?document} affectedDocuments
       * @param {boolean} upsert
       * @see {Datastore#updateAsync}
       */
      /**
       * Version without the using {@link Datastore~executor} of {@link Datastore#updateAsync}, use it instead.
       *
       * @param {query} query
       * @param {document|update} update
       * @param {Object} options
       * @param {boolean} [options.multi = false]
       * @param {boolean} [options.upsert = false]
       * @param {boolean} [options.returnUpdatedDocs = false]
       * @return {Promise<{numAffected: number, affectedDocuments: document[]|document|null, upsert: boolean}>}
       * @private
       * @see Datastore#updateAsync
       */
      async _updateAsync(query, update, options) {
        const multi = options.multi !== void 0 ? options.multi : false;
        const upsert = options.upsert !== void 0 ? options.upsert : false;
        if (upsert) {
          const cursor = new Cursor(this, query);
          const docs = await cursor.limit(1)._execAsync();
          if (docs.length !== 1) {
            let toBeInserted;
            try {
              model.checkObject(update);
              toBeInserted = update;
            } catch (e) {
              toBeInserted = model.modify(model.deepCopy(query, true), update);
            }
            const newDoc = await this._insertAsync(toBeInserted);
            return { numAffected: 1, affectedDocuments: newDoc, upsert: true };
          }
        }
        let numReplaced = 0;
        let modifiedDoc;
        const modifications = [];
        let createdAt;
        const candidates = await this._getCandidatesAsync(query);
        for (const candidate of candidates) {
          if (model.match(candidate, query) && (multi || numReplaced === 0)) {
            numReplaced += 1;
            if (this.timestampData) {
              createdAt = candidate.createdAt;
            }
            modifiedDoc = model.modify(candidate, update);
            if (this.timestampData) {
              modifiedDoc.createdAt = createdAt;
              modifiedDoc.updatedAt = /* @__PURE__ */ new Date();
            }
            modifications.push({ oldDoc: candidate, newDoc: modifiedDoc });
          }
        }
        this._updateIndexes(modifications);
        const updatedDocs = modifications.map((x) => x.newDoc);
        await this.persistence.persistNewStateAsync(updatedDocs);
        if (!options.returnUpdatedDocs)
          return { numAffected: numReplaced, upsert: false, affectedDocuments: null };
        else {
          let updatedDocsDC = [];
          updatedDocs.forEach((doc) => {
            updatedDocsDC.push(model.deepCopy(doc));
          });
          if (!multi)
            updatedDocsDC = updatedDocsDC[0];
          return { numAffected: numReplaced, affectedDocuments: updatedDocsDC, upsert: false };
        }
      }
      /**
       * Callback version of {@link Datastore#updateAsync}.
       * @param {query} query
       * @param {document|*} update
       * @param {Object|Datastore~updateCallback} [options|]
       * @param {boolean} [options.multi = false]
       * @param {boolean} [options.upsert = false]
       * @param {boolean} [options.returnUpdatedDocs = false]
       * @param {Datastore~updateCallback} [callback]
       * @see Datastore#updateAsync
       *
       */
      update(query, update, options, callback) {
        if (typeof options === "function") {
          callback = options;
          options = {};
        }
        const _callback = (err, res = {}) => {
          if (callback)
            callback(err, res.numAffected, res.affectedDocuments, res.upsert);
        };
        callbackify((query2, update2, options2) => this.updateAsync(query2, update2, options2))(query, update, options, _callback);
      }
      /**
       * Update all docs matching query.
       * @param {query} query is the same kind of finding query you use with `find` and `findOne`.
       * @param {document|*} update specifies how the documents should be modified. It is either a new document or a
       * set of modifiers (you cannot use both together, it doesn't make sense!). Using a new document will replace the
       * matched docs. Using a set of modifiers will create the fields they need to modify if they don't exist, and you can
       * apply them to subdocs. Available field modifiers are `$set` to change a field's value, `$unset` to delete a field,
       * `$inc` to increment a field's value and `$min`/`$max` to change field's value, only if provided value is
       * less/greater than current value. To work on arrays, you have `$push`, `$pop`, `$addToSet`, `$pull`, and the special
       * `$each` and `$slice`.
       * @param {Object} [options = {}] Optional options
       * @param {boolean} [options.multi = false] If true, can update multiple documents
       * @param {boolean} [options.upsert = false] If true, can insert a new document corresponding to the `update` rules if
       * your `query` doesn't match anything. If your `update` is a simple object with no modifiers, it is the inserted
       * document. In the other case, the `query` is stripped from all operator recursively, and the `update` is applied to
       * it.
       * @param {boolean} [options.returnUpdatedDocs = false] (not Mongo-DB compatible) If true and update is not an upsert,
       * will return the array of documents matched by the find query and updated. Updated documents will be returned even
       * if the update did not actually modify them.
       * @return {Promise<{numAffected: number, affectedDocuments: document[]|document|null, upsert: boolean}>}
       * - `upsert` is `true` if and only if the update did insert a document, **cannot be true if `options.upsert !== true`**.
       * - `numAffected` is the number of documents affected by the update or insertion (if `options.multi` is `false` or `options.upsert` is `true`, cannot exceed `1`);
       * - `affectedDocuments` can be one of the following:
       *    - If `upsert` is `true`, the inserted document;
       *    - If `options.returnUpdatedDocs` is `false`, `null`;
       *    - If `options.returnUpdatedDocs` is `true`:
       *      - If `options.multi` is `false`, the updated document;
       *      - If `options.multi` is `true`, the array of updated documents.
       * @async
       */
      updateAsync(query, update, options = {}) {
        return this.executor.pushAsync(() => this._updateAsync(query, update, options));
      }
      /**
       * @callback Datastore~removeCallback
       * @param {?Error} err
       * @param {?number} numRemoved
       */
      /**
       * Internal version without using the {@link Datastore#executor} of {@link Datastore#removeAsync}, use it instead.
       *
       * @param {query} query
       * @param {object} [options]
       * @param {boolean} [options.multi = false]
       * @return {Promise<number>}
       * @private
       * @see Datastore#removeAsync
       */
      async _removeAsync(query, options = {}) {
        const multi = options.multi !== void 0 ? options.multi : false;
        const candidates = await this._getCandidatesAsync(query, true);
        const removedDocs = [];
        let numRemoved = 0;
        candidates.forEach((d) => {
          if (model.match(d, query) && (multi || numRemoved === 0)) {
            numRemoved += 1;
            removedDocs.push({ $$deleted: true, _id: d._id });
            this._removeFromIndexes(d);
          }
        });
        await this.persistence.persistNewStateAsync(removedDocs);
        return numRemoved;
      }
      /**
       * Callback version of {@link Datastore#removeAsync}.
       * @param {query} query
       * @param {object|Datastore~removeCallback} [options={}]
       * @param {boolean} [options.multi = false]
       * @param {Datastore~removeCallback} [cb = () => {}]
       * @see Datastore#removeAsync
       */
      remove(query, options, cb) {
        if (typeof options === "function") {
          cb = options;
          options = {};
        }
        const callback = cb || (() => {
        });
        callbackify((query2, options2) => this.removeAsync(query2, options2))(query, options, callback);
      }
      /**
       * Remove all docs matching the query.
       * @param {query} query MongoDB-style query
       * @param {object} [options={}] Optional options
       * @param {boolean} [options.multi = false] If true, can update multiple documents
       * @return {Promise<number>} How many documents were removed
       * @async
       */
      removeAsync(query, options = {}) {
        return this.executor.pushAsync(() => this._removeAsync(query, options));
      }
    };
    module.exports = Datastore2;
  }
});

// node_modules/@seald-io/nedb/index.js
var require_nedb = __commonJS({
  "node_modules/@seald-io/nedb/index.js"(exports, module) {
    var Datastore2 = require_datastore();
    module.exports = Datastore2;
  }
});

// node_modules/nedb-promises/src/Cursor.js
var require_Cursor = __commonJS({
  "node_modules/nedb-promises/src/Cursor.js"(exports, module) {
    var OriginalCursor = require_cursor();
    var Cursor = class {
      constructor(datastore, op, ...args) {
        const cursor = datastore.__original[op](...args);
        if (!(cursor instanceof OriginalCursor)) {
          throw new TypeError(`Unexpected ${typeof original}, expected: Cursor (nedb/lib/cursor)`);
        }
        Object.defineProperties(this, {
          __original: {
            configurable: false,
            enumerable: false,
            writable: false,
            value: cursor
          },
          __datastore: {
            configurable: false,
            enumerable: false,
            writable: false,
            value: datastore
          },
          __op: {
            configurable: false,
            enumerable: false,
            writable: false,
            value: op
          },
          __args: {
            configurable: false,
            enumerable: false,
            writable: false,
            value: args
          }
        });
      }
      /**
       * Sort the queried documents.
       *
       * See: https://github.com/louischatriot/nedb#sorting-and-paginating
       *
       * @return {Cursor}
       */
      sort(...args) {
        this.__original.sort(...args);
        return this;
      }
      /**
       * Skip some of the queried documents.
       *
       * See: https://github.com/louischatriot/nedb#sorting-and-paginating
       *
       * @return {Cursor}
       */
      skip(...args) {
        this.__original.skip(...args);
        return this;
      }
      /**
       * Limit the queried documents.
       *
       * See: https://github.com/louischatriot/nedb#sorting-and-paginating
       *
       * @return {Cursor}
       */
      limit(...args) {
        this.__original.limit(...args);
        return this;
      }
      /**
       * Set the document projection.
       *
       * See: https://github.com/louischatriot/nedb#projections
       *
       * @return {Cursor}
       */
      project(...args) {
        this.__original.projection(...args);
        return this;
      }
      /**
       * Execute the cursor.
       *
       * Since the Cursor has a `then` and a `catch` method
       * JavaScript identifies it as a thenable object
       * thus you can await it in async functions.
       *
       * @example
       * // in an async function
       * await datastore.find(...)
       *  .sort(...)
       *  .limit(...)
       *
       * @example
       * // the previous is the same as:
       * await datastore.find(...)
       *  .sort(...)
       *  .limit(...)
       *  .exec()
       *
       * @return {Promise<Object[]>}
       */
      async exec() {
        await this.__datastore.load();
        try {
          const result = await this.__original.execAsync();
          this.__datastore.broadcastSuccess(this.__op, result, ...this.__args);
          return result;
        } catch (error2) {
          this.__datastore.broadcastError(this.__op, error2, ...this.__args);
          throw error2;
        }
      }
      /**
       * Execute the cursor and set promise callbacks.
       *
       * For more information visit:
       * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/then
       *
       * @param  {Function} fulfilled
       * @param  {Function} [rejected]
       * @return {Promise}
       */
      then(fulfilled, rejected) {
        return this.exec().then(fulfilled, rejected);
      }
      /**
       * Execute the cursor and set promise error callback.
       *
       * For more information visit:
       * https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/catch
       *
       * @param  {Function} rejected
       * @return {Promise}
       */
      catch(rejected) {
        return this.exec().catch(rejected);
      }
    };
    module.exports = Cursor;
  }
});

// node_modules/nedb-promises/src/Datastore.js
var require_Datastore = __commonJS({
  "node_modules/nedb-promises/src/Datastore.js"(exports, module) {
    var EventEmitter = __require("events");
    var OriginalDatastore = require_nedb();
    var Cursor = require_Cursor();
    var Datastore2 = class extends EventEmitter {
      /**
       * Create a database instance.
       *
       * Use this over `new Datastore(...)` to access
       * original nedb datastore properties, such as
       * `datastore.persistence`.
       *
       * Note that this method only creates the `Datastore`
       * class instance, not the datastore file itself.
       * The file will only be created once an operation
       * is issued against the datastore or if you call
       * the `load` instance method explicitly.
       *
       * The path (if specified) will be relative to `process.cwd()`
       * (unless an absolute path was passed).
       *
       * For more information visit:
       * https://github.com/louischatriot/nedb#creatingloading-a-database
       *
       * @param  {string|Object} [pathOrOptions]
       * @return {Proxy<static>}
       */
      static create(pathOrOptions) {
        return new Proxy(new this(pathOrOptions), {
          get(target, key) {
            return target[key] ? target[key] : target.__original[key];
          },
          set(target, key, value) {
            return Object.prototype.hasOwnProperty.call(target.__original, key) ? target.__original[key] = value : target[key] = value;
          }
        });
      }
      /**
       * Datastore constructor...
       *
       * You should use `Datastore.create(...)` instead
       * of `new Datastore(...)`. With that you can access
       * the original datastore's properties such as `datastore.persistence`.
       *
       * Create a Datastore instance.
       *
       * Note that the datastore will be created
       * relative to `process.cwd()`
       * (unless an absolute path was passed).
       *
       * It's basically the same as the original:
       * https://github.com/louischatriot/nedb#creatingloading-a-database
       *
       * @param  {string|Object} [pathOrOptions]
       * @return {static}
       */
      constructor(pathOrOptions) {
        super();
        const datastore = new OriginalDatastore(
          typeof pathOrOptions === "string" ? { filename: pathOrOptions } : pathOrOptions
        );
        Object.defineProperties(this, {
          __loaded: {
            enumerable: false,
            writable: true,
            value: null
          },
          __original: {
            configurable: true,
            enumerable: false,
            writable: false,
            value: datastore
          }
        });
        this.__original.on("compaction.done", () => {
          this.emit("compactionDone", this);
        });
      }
      /**
       * Load the datastore.
       *
       * Note that you don't necessarily have to call
       * this method to load the datastore as it will
       * automatically be called and awaited on any
       * operation issued against the datastore
       * (i.e.: `find`, `findOne`, etc.).
       *
       * @return {Promise<undefined>}
       */
      load() {
        if (!(this.__loaded instanceof Promise)) {
          this.__loaded = this.__original.loadDatabaseAsync().then(() => this.broadcastSuccess("load")).catch((error2) => {
            this.broadcastError("load", error2);
            throw error2;
          });
        }
        return this.__loaded;
      }
      /**
       * Find documents that match the specified `query`.
       *
       * It's basically the same as the original:
       * https://github.com/louischatriot/nedb#finding-documents
       *
       * There are differences minor in how the cursor works though.
       *
       * @example
       * datastore.find({ ... }).sort({ ... }).exec().then(...)
       *
       * @example
       * datastore.find({ ... }).sort({ ... }).then(...)
       *
       * @example
       * // in an async function
       * await datastore.find({ ... }).sort({ ... })
       *
       * @param  {Object} [query]
       * @param  {Object} [projection]
       * @return {Cursor}
       */
      find(query = {}, projection) {
        if (typeof projection === "function") {
          projection = {};
        }
        return new Cursor(this, "find", query, projection);
      }
      /**
       * Find a document that matches the specified `query`.
       *
       * It's basically the same as the original:
       * https://github.com/louischatriot/nedb#finding-documents
       *
       * @example
       * datastore.findOne({ ... }).then(...)
       *
       * @example
       * // in an async function
       * await datastore.findOne({ ... }).sort({ ... })
       *
       * @param  {Object} [query]
       * @param  {Object} [projection]
       * @return {Cursor}
       */
      findOne(query = {}, projection) {
        if (typeof projection === "function") {
          projection = {};
        }
        return new Cursor(this, "findOne", query, projection);
      }
      /**
       * Insert a document or documents.
       *
       * It's basically the same as the original:
       * https://github.com/louischatriot/nedb#inserting-documents
       *
       * @param  {Object|Object[]} docs
       * @return {Promise<Object|Object[]>}
       */
      async insert(docs) {
        await this.load();
        try {
          const result = await this.__original.insertAsync(docs);
          this.broadcastSuccess("insert", docs);
          return result;
        } catch (error2) {
          this.broadcastError("insert", error2, docs);
          throw error2;
        }
      }
      /**
       * Insert a single document.
       *
       * This is just an alias for `insert` with object destructuring
       * to ensure a single document.
       *
       * @param  {Object} doc
       * @return {Promise<Object>}
       */
      insertOne({ ...doc }) {
        return this.insert(doc);
      }
      /**
       * Insert multiple documents.
       *
       * This is just an alias for `insert` with array destructuring
       * to ensure multiple documents.
       *
       * @param  {Object[]} docs
       * @return {Promise<Object[]>}
       */
      insertMany([...docs]) {
        return this.insert(docs);
      }
      /**
       * Update documents that match the specified `query`.
       *
       * It's basically the same as the original:
       * https://github.com/louischatriot/nedb#updating-documents
       *
       * If you set `options.returnUpdatedDocs`,
       * the returned promise will resolve with
       * an object (if `options.multi` is `false`) or
       * with an array of objects.
       *
       * @param  {Object} query
       * @param  {Object} update
       * @param  {Object} [options]
       * @return {Promise<number|Object|Object[]>}
       */
      async update(query, update, options = {}) {
        await this.load();
        try {
          const { numAffected, affectedDocuments } = await this.__original.updateAsync(query, update, options);
          const result = options.returnUpdatedDocs ? affectedDocuments : numAffected;
          this.broadcastSuccess("update", result, query, update, options);
          return result;
        } catch (error2) {
          this.broadcastError("update", error2, query, update, options);
          throw error2;
        }
      }
      /**
       * Update a single document that matches the specified `query`.
       *
       * This is just an alias for `update` with `options.multi` set to `false`.
       *
       * @param  {Object} query
       * @param  {Object} update
       * @param  {Object} [options]
       *
       * @return {Promise<number|Object>}
       */
      updateOne(query, update, options = {}) {
        return this.update(query, update, { ...options, multi: false });
      }
      /**
       * Update multiple documents that match the specified `query`.
       *
       * This is just an alias for `update` with `options.multi` set to `true`.
       *
       * @param  {Object} query
       * @param  {Object} update
       * @param  {Object} [options]
       *
       * @return {Promise<number|Object[]>}
       */
      updateMany(query, update, options = {}) {
        return this.update(query, update, { ...options, multi: true });
      }
      /**
       * Remove documents that match the specified `query`.
       *
       * It's basically the same as the original:
       * https://github.com/louischatriot/nedb#removing-documents
       *
       * @param  {Object} [query]
       * @param  {Object} [options]
       * @return {Promise<number>}
       */
      async remove(query = {}, options = {}) {
        await this.load();
        try {
          const result = await this.__original.removeAsync(query, options);
          this.broadcastSuccess("remove", result, query, options);
          return result;
        } catch (error2) {
          this.broadcastError("remove", error2, query, options);
          throw error2;
        }
      }
      /**
       * Remove the first document that matches the specified `query`.
       *
       * This is just an alias for `remove` with `options.multi` set to `false`.
       *
       * @param  {Object} [query]
       * @param  {Object} [options]
       *
       * @return {Promise<number>}
       */
      removeOne(query, options = {}) {
        return this.remove(query, { ...options, multi: false });
      }
      /**
       * Remove all documents that match the specified `query`.
       *
       * This is just an alias for `remove` with `options.multi` set to `true`.
       *
       * @param  {Object} [query]
       * @param  {Object} [options]
       *
       * @return {Promise<number>}
       */
      removeMany(query, options = {}) {
        return this.remove(query, { ...options, multi: true });
      }
      /**
       * Remove the first document that matches the specified `query`.
       *
       * This is just an alias for `removeOne`.
       *
       * @param  {Object} [query]
       * @param  {Object} [options]
       *
       * @return {Promise<number>}
       */
      deleteOne(query, options) {
        return this.removeOne(query, options);
      }
      /**
       * Remove all documents that match the specified `query`.
       *
       * This is just an alias for `removeMany`.
       *
       * @param  {Object} [query]
       * @param  {Object} [options]
       *
       * @return {Promise<number>}
       */
      deleteMany(query, options) {
        return this.removeMany(query, options);
      }
      /**
       * Count documents matching the specified `query`.
       *
       * It's basically the same as the original:
       * https://github.com/louischatriot/nedb#counting-documents
       *
       * @example
       * datastore.count({ ... }).limit(...).then(...)
       *
       * @example
       * // in an async function
       * await datastore.count({ ... })
       * // or
       * await datastore.count({ ... }).sort(...).limit(...)
       *
       * @param  {Object} [query]
       * @return {Cursor}
       */
      count(query = {}) {
        return new Cursor(this, "count", query);
      }
      /**
       * https://github.com/louischatriot/nedb#indexing
       *
       * @param  {Object} options
       * @return {Promise<undefined>}
       */
      async ensureIndex(options) {
        try {
          const result = await this.__original.ensureIndexAsync(options);
          this.broadcastSuccess("ensureIndex", result, options);
          return result;
        } catch (error2) {
          this.broadcastError("ensureIndex", error2, options);
          throw error2;
        }
      }
      /**
       * https://github.com/louischatriot/nedb#indexing
       *
       * @param  {string} field
       * @return {Promise<undefined>}
       */
      async removeIndex(field) {
        try {
          const result = await this.__original.removeIndexAsync(field);
          this.broadcastSuccess("removeIndex", result, field);
          return result;
        } catch (error2) {
          this.broadcastError("removeIndex", error2, field);
          throw error2;
        }
      }
      /**
       * Broadcasts operation success messages.
       *
       * @param  {string} op
       * @param  {*}      result
       * @param  {...*}   args
       *
       * @return {undefined}
       * @private
       */
      broadcastSuccess(op, result, ...args) {
        this.emit(op, this, result, ...args);
        return this;
      }
      /**
       * Broadcasts operation error messages.
       *
       * @param  {string} op
       * @param  {Error}  error
       * @param  {...*}   args
       *
       * @return {undefined}
       * @private
       */
      broadcastError(op, error2, ...args) {
        this.emit(`${op}Error`, this, error2, ...args);
        this.emit("__error__", this, op, error2, ...args);
        return this;
      }
    };
    module.exports = Datastore2;
  }
});

// node_modules/nedb-promises/index.js
var require_nedb_promises = __commonJS({
  "node_modules/nedb-promises/index.js"(exports, module) {
    module.exports = require_Datastore();
  }
});

// node_modules/chalk/source/vendor/ansi-styles/index.js
function assembleStyles() {
  const codes = /* @__PURE__ */ new Map();
  for (const [groupName, group] of Object.entries(styles)) {
    for (const [styleName, style] of Object.entries(group)) {
      styles[styleName] = {
        open: `\x1B[${style[0]}m`,
        close: `\x1B[${style[1]}m`
      };
      group[styleName] = styles[styleName];
      codes.set(style[0], style[1]);
    }
    Object.defineProperty(styles, groupName, {
      value: group,
      enumerable: false
    });
  }
  Object.defineProperty(styles, "codes", {
    value: codes,
    enumerable: false
  });
  styles.color.close = "\x1B[39m";
  styles.bgColor.close = "\x1B[49m";
  styles.color.ansi = wrapAnsi16();
  styles.color.ansi256 = wrapAnsi256();
  styles.color.ansi16m = wrapAnsi16m();
  styles.bgColor.ansi = wrapAnsi16(ANSI_BACKGROUND_OFFSET);
  styles.bgColor.ansi256 = wrapAnsi256(ANSI_BACKGROUND_OFFSET);
  styles.bgColor.ansi16m = wrapAnsi16m(ANSI_BACKGROUND_OFFSET);
  Object.defineProperties(styles, {
    rgbToAnsi256: {
      value(red, green, blue) {
        if (red === green && green === blue) {
          if (red < 8) {
            return 16;
          }
          if (red > 248) {
            return 231;
          }
          return Math.round((red - 8) / 247 * 24) + 232;
        }
        return 16 + 36 * Math.round(red / 255 * 5) + 6 * Math.round(green / 255 * 5) + Math.round(blue / 255 * 5);
      },
      enumerable: false
    },
    hexToRgb: {
      value(hex) {
        const matches = /[a-f\d]{6}|[a-f\d]{3}/i.exec(hex.toString(16));
        if (!matches) {
          return [0, 0, 0];
        }
        let [colorString] = matches;
        if (colorString.length === 3) {
          colorString = [...colorString].map((character) => character + character).join("");
        }
        const integer = Number.parseInt(colorString, 16);
        return [
          /* eslint-disable no-bitwise */
          integer >> 16 & 255,
          integer >> 8 & 255,
          integer & 255
          /* eslint-enable no-bitwise */
        ];
      },
      enumerable: false
    },
    hexToAnsi256: {
      value: (hex) => styles.rgbToAnsi256(...styles.hexToRgb(hex)),
      enumerable: false
    },
    ansi256ToAnsi: {
      value(code) {
        if (code < 8) {
          return 30 + code;
        }
        if (code < 16) {
          return 90 + (code - 8);
        }
        let red;
        let green;
        let blue;
        if (code >= 232) {
          red = ((code - 232) * 10 + 8) / 255;
          green = red;
          blue = red;
        } else {
          code -= 16;
          const remainder = code % 36;
          red = Math.floor(code / 36) / 5;
          green = Math.floor(remainder / 6) / 5;
          blue = remainder % 6 / 5;
        }
        const value = Math.max(red, green, blue) * 2;
        if (value === 0) {
          return 30;
        }
        let result = 30 + (Math.round(blue) << 2 | Math.round(green) << 1 | Math.round(red));
        if (value === 2) {
          result += 60;
        }
        return result;
      },
      enumerable: false
    },
    rgbToAnsi: {
      value: (red, green, blue) => styles.ansi256ToAnsi(styles.rgbToAnsi256(red, green, blue)),
      enumerable: false
    },
    hexToAnsi: {
      value: (hex) => styles.ansi256ToAnsi(styles.hexToAnsi256(hex)),
      enumerable: false
    }
  });
  return styles;
}
var ANSI_BACKGROUND_OFFSET, wrapAnsi16, wrapAnsi256, wrapAnsi16m, styles, modifierNames, foregroundColorNames, backgroundColorNames, colorNames, ansiStyles, ansi_styles_default;
var init_ansi_styles = __esm({
  "node_modules/chalk/source/vendor/ansi-styles/index.js"() {
    ANSI_BACKGROUND_OFFSET = 10;
    wrapAnsi16 = (offset = 0) => (code) => `\x1B[${code + offset}m`;
    wrapAnsi256 = (offset = 0) => (code) => `\x1B[${38 + offset};5;${code}m`;
    wrapAnsi16m = (offset = 0) => (red, green, blue) => `\x1B[${38 + offset};2;${red};${green};${blue}m`;
    styles = {
      modifier: {
        reset: [0, 0],
        // 21 isn't widely supported and 22 does the same thing
        bold: [1, 22],
        dim: [2, 22],
        italic: [3, 23],
        underline: [4, 24],
        overline: [53, 55],
        inverse: [7, 27],
        hidden: [8, 28],
        strikethrough: [9, 29]
      },
      color: {
        black: [30, 39],
        red: [31, 39],
        green: [32, 39],
        yellow: [33, 39],
        blue: [34, 39],
        magenta: [35, 39],
        cyan: [36, 39],
        white: [37, 39],
        // Bright color
        blackBright: [90, 39],
        gray: [90, 39],
        // Alias of `blackBright`
        grey: [90, 39],
        // Alias of `blackBright`
        redBright: [91, 39],
        greenBright: [92, 39],
        yellowBright: [93, 39],
        blueBright: [94, 39],
        magentaBright: [95, 39],
        cyanBright: [96, 39],
        whiteBright: [97, 39]
      },
      bgColor: {
        bgBlack: [40, 49],
        bgRed: [41, 49],
        bgGreen: [42, 49],
        bgYellow: [43, 49],
        bgBlue: [44, 49],
        bgMagenta: [45, 49],
        bgCyan: [46, 49],
        bgWhite: [47, 49],
        // Bright color
        bgBlackBright: [100, 49],
        bgGray: [100, 49],
        // Alias of `bgBlackBright`
        bgGrey: [100, 49],
        // Alias of `bgBlackBright`
        bgRedBright: [101, 49],
        bgGreenBright: [102, 49],
        bgYellowBright: [103, 49],
        bgBlueBright: [104, 49],
        bgMagentaBright: [105, 49],
        bgCyanBright: [106, 49],
        bgWhiteBright: [107, 49]
      }
    };
    modifierNames = Object.keys(styles.modifier);
    foregroundColorNames = Object.keys(styles.color);
    backgroundColorNames = Object.keys(styles.bgColor);
    colorNames = [...foregroundColorNames, ...backgroundColorNames];
    ansiStyles = assembleStyles();
    ansi_styles_default = ansiStyles;
  }
});

// node_modules/chalk/source/vendor/supports-color/index.js
import process2 from "node:process";
import os from "node:os";
import tty from "node:tty";
function hasFlag(flag, argv = globalThis.Deno ? globalThis.Deno.args : process2.argv) {
  const prefix = flag.startsWith("-") ? "" : flag.length === 1 ? "-" : "--";
  const position = argv.indexOf(prefix + flag);
  const terminatorPosition = argv.indexOf("--");
  return position !== -1 && (terminatorPosition === -1 || position < terminatorPosition);
}
function envForceColor() {
  if ("FORCE_COLOR" in env) {
    if (env.FORCE_COLOR === "true") {
      return 1;
    }
    if (env.FORCE_COLOR === "false") {
      return 0;
    }
    return env.FORCE_COLOR.length === 0 ? 1 : Math.min(Number.parseInt(env.FORCE_COLOR, 10), 3);
  }
}
function translateLevel(level) {
  if (level === 0) {
    return false;
  }
  return {
    level,
    hasBasic: true,
    has256: level >= 2,
    has16m: level >= 3
  };
}
function _supportsColor(haveStream, { streamIsTTY, sniffFlags = true } = {}) {
  const noFlagForceColor = envForceColor();
  if (noFlagForceColor !== void 0) {
    flagForceColor = noFlagForceColor;
  }
  const forceColor = sniffFlags ? flagForceColor : noFlagForceColor;
  if (forceColor === 0) {
    return 0;
  }
  if (sniffFlags) {
    if (hasFlag("color=16m") || hasFlag("color=full") || hasFlag("color=truecolor")) {
      return 3;
    }
    if (hasFlag("color=256")) {
      return 2;
    }
  }
  if ("TF_BUILD" in env && "AGENT_NAME" in env) {
    return 1;
  }
  if (haveStream && !streamIsTTY && forceColor === void 0) {
    return 0;
  }
  const min = forceColor || 0;
  if (env.TERM === "dumb") {
    return min;
  }
  if (process2.platform === "win32") {
    const osRelease = os.release().split(".");
    if (Number(osRelease[0]) >= 10 && Number(osRelease[2]) >= 10586) {
      return Number(osRelease[2]) >= 14931 ? 3 : 2;
    }
    return 1;
  }
  if ("CI" in env) {
    if ("GITHUB_ACTIONS" in env) {
      return 3;
    }
    if (["TRAVIS", "CIRCLECI", "APPVEYOR", "GITLAB_CI", "BUILDKITE", "DRONE"].some((sign) => sign in env) || env.CI_NAME === "codeship") {
      return 1;
    }
    return min;
  }
  if ("TEAMCITY_VERSION" in env) {
    return /^(9\.(0*[1-9]\d*)\.|\d{2,}\.)/.test(env.TEAMCITY_VERSION) ? 1 : 0;
  }
  if (env.COLORTERM === "truecolor") {
    return 3;
  }
  if (env.TERM === "xterm-kitty") {
    return 3;
  }
  if ("TERM_PROGRAM" in env) {
    const version2 = Number.parseInt((env.TERM_PROGRAM_VERSION || "").split(".")[0], 10);
    switch (env.TERM_PROGRAM) {
      case "iTerm.app": {
        return version2 >= 3 ? 3 : 2;
      }
      case "Apple_Terminal": {
        return 2;
      }
    }
  }
  if (/-256(color)?$/i.test(env.TERM)) {
    return 2;
  }
  if (/^screen|^xterm|^vt100|^vt220|^rxvt|color|ansi|cygwin|linux/i.test(env.TERM)) {
    return 1;
  }
  if ("COLORTERM" in env) {
    return 1;
  }
  return min;
}
function createSupportsColor(stream, options = {}) {
  const level = _supportsColor(stream, {
    streamIsTTY: stream && stream.isTTY,
    ...options
  });
  return translateLevel(level);
}
var env, flagForceColor, supportsColor, supports_color_default;
var init_supports_color = __esm({
  "node_modules/chalk/source/vendor/supports-color/index.js"() {
    ({ env } = process2);
    if (hasFlag("no-color") || hasFlag("no-colors") || hasFlag("color=false") || hasFlag("color=never")) {
      flagForceColor = 0;
    } else if (hasFlag("color") || hasFlag("colors") || hasFlag("color=true") || hasFlag("color=always")) {
      flagForceColor = 1;
    }
    supportsColor = {
      stdout: createSupportsColor({ isTTY: tty.isatty(1) }),
      stderr: createSupportsColor({ isTTY: tty.isatty(2) })
    };
    supports_color_default = supportsColor;
  }
});

// node_modules/chalk/source/utilities.js
function stringReplaceAll(string, substring, replacer) {
  let index = string.indexOf(substring);
  if (index === -1) {
    return string;
  }
  const substringLength = substring.length;
  let endIndex = 0;
  let returnValue = "";
  do {
    returnValue += string.slice(endIndex, index) + substring + replacer;
    endIndex = index + substringLength;
    index = string.indexOf(substring, endIndex);
  } while (index !== -1);
  returnValue += string.slice(endIndex);
  return returnValue;
}
function stringEncaseCRLFWithFirstIndex(string, prefix, postfix, index) {
  let endIndex = 0;
  let returnValue = "";
  do {
    const gotCR = string[index - 1] === "\r";
    returnValue += string.slice(endIndex, gotCR ? index - 1 : index) + prefix + (gotCR ? "\r\n" : "\n") + postfix;
    endIndex = index + 1;
    index = string.indexOf("\n", endIndex);
  } while (index !== -1);
  returnValue += string.slice(endIndex);
  return returnValue;
}
var init_utilities = __esm({
  "node_modules/chalk/source/utilities.js"() {
  }
});

// node_modules/chalk/source/index.js
function createChalk(options) {
  return chalkFactory(options);
}
var stdoutColor, stderrColor, GENERATOR, STYLER, IS_EMPTY, levelMapping, styles2, applyOptions, chalkFactory, getModelAnsi, usedModels, proto, createStyler, createBuilder, applyStyle, chalk, chalkStderr, source_default;
var init_source = __esm({
  "node_modules/chalk/source/index.js"() {
    init_ansi_styles();
    init_supports_color();
    init_utilities();
    init_ansi_styles();
    ({ stdout: stdoutColor, stderr: stderrColor } = supports_color_default);
    GENERATOR = Symbol("GENERATOR");
    STYLER = Symbol("STYLER");
    IS_EMPTY = Symbol("IS_EMPTY");
    levelMapping = [
      "ansi",
      "ansi",
      "ansi256",
      "ansi16m"
    ];
    styles2 = /* @__PURE__ */ Object.create(null);
    applyOptions = (object, options = {}) => {
      if (options.level && !(Number.isInteger(options.level) && options.level >= 0 && options.level <= 3)) {
        throw new Error("The `level` option should be an integer from 0 to 3");
      }
      const colorLevel = stdoutColor ? stdoutColor.level : 0;
      object.level = options.level === void 0 ? colorLevel : options.level;
    };
    chalkFactory = (options) => {
      const chalk2 = (...strings) => strings.join(" ");
      applyOptions(chalk2, options);
      Object.setPrototypeOf(chalk2, createChalk.prototype);
      return chalk2;
    };
    Object.setPrototypeOf(createChalk.prototype, Function.prototype);
    for (const [styleName, style] of Object.entries(ansi_styles_default)) {
      styles2[styleName] = {
        get() {
          const builder = createBuilder(this, createStyler(style.open, style.close, this[STYLER]), this[IS_EMPTY]);
          Object.defineProperty(this, styleName, { value: builder });
          return builder;
        }
      };
    }
    styles2.visible = {
      get() {
        const builder = createBuilder(this, this[STYLER], true);
        Object.defineProperty(this, "visible", { value: builder });
        return builder;
      }
    };
    getModelAnsi = (model, level, type2, ...arguments_) => {
      if (model === "rgb") {
        if (level === "ansi16m") {
          return ansi_styles_default[type2].ansi16m(...arguments_);
        }
        if (level === "ansi256") {
          return ansi_styles_default[type2].ansi256(ansi_styles_default.rgbToAnsi256(...arguments_));
        }
        return ansi_styles_default[type2].ansi(ansi_styles_default.rgbToAnsi(...arguments_));
      }
      if (model === "hex") {
        return getModelAnsi("rgb", level, type2, ...ansi_styles_default.hexToRgb(...arguments_));
      }
      return ansi_styles_default[type2][model](...arguments_);
    };
    usedModels = ["rgb", "hex", "ansi256"];
    for (const model of usedModels) {
      styles2[model] = {
        get() {
          const { level } = this;
          return function(...arguments_) {
            const styler = createStyler(getModelAnsi(model, levelMapping[level], "color", ...arguments_), ansi_styles_default.color.close, this[STYLER]);
            return createBuilder(this, styler, this[IS_EMPTY]);
          };
        }
      };
      const bgModel = "bg" + model[0].toUpperCase() + model.slice(1);
      styles2[bgModel] = {
        get() {
          const { level } = this;
          return function(...arguments_) {
            const styler = createStyler(getModelAnsi(model, levelMapping[level], "bgColor", ...arguments_), ansi_styles_default.bgColor.close, this[STYLER]);
            return createBuilder(this, styler, this[IS_EMPTY]);
          };
        }
      };
    }
    proto = Object.defineProperties(() => {
    }, {
      ...styles2,
      level: {
        enumerable: true,
        get() {
          return this[GENERATOR].level;
        },
        set(level) {
          this[GENERATOR].level = level;
        }
      }
    });
    createStyler = (open, close, parent) => {
      let openAll;
      let closeAll;
      if (parent === void 0) {
        openAll = open;
        closeAll = close;
      } else {
        openAll = parent.openAll + open;
        closeAll = close + parent.closeAll;
      }
      return {
        open,
        close,
        openAll,
        closeAll,
        parent
      };
    };
    createBuilder = (self, _styler, _isEmpty) => {
      const builder = (...arguments_) => applyStyle(builder, arguments_.length === 1 ? "" + arguments_[0] : arguments_.join(" "));
      Object.setPrototypeOf(builder, proto);
      builder[GENERATOR] = self;
      builder[STYLER] = _styler;
      builder[IS_EMPTY] = _isEmpty;
      return builder;
    };
    applyStyle = (self, string) => {
      if (self.level <= 0 || !string) {
        return self[IS_EMPTY] ? "" : string;
      }
      let styler = self[STYLER];
      if (styler === void 0) {
        return string;
      }
      const { openAll, closeAll } = styler;
      if (string.includes("\x1B")) {
        while (styler !== void 0) {
          string = stringReplaceAll(string, styler.close, styler.open);
          styler = styler.parent;
        }
      }
      const lfIndex = string.indexOf("\n");
      if (lfIndex !== -1) {
        string = stringEncaseCRLFWithFirstIndex(string, closeAll, openAll, lfIndex);
      }
      return openAll + string + closeAll;
    };
    Object.defineProperties(createChalk.prototype, styles2);
    chalk = createChalk();
    chalkStderr = createChalk({ level: stderrColor ? stderrColor.level : 0 });
    source_default = chalk;
  }
});

// node_modules/js-yaml/dist/js-yaml.mjs
function isNothing(subject) {
  return typeof subject === "undefined" || subject === null;
}
function isObject(subject) {
  return typeof subject === "object" && subject !== null;
}
function toArray(sequence) {
  if (Array.isArray(sequence))
    return sequence;
  else if (isNothing(sequence))
    return [];
  return [sequence];
}
function extend(target, source) {
  var index, length, key, sourceKeys;
  if (source) {
    sourceKeys = Object.keys(source);
    for (index = 0, length = sourceKeys.length; index < length; index += 1) {
      key = sourceKeys[index];
      target[key] = source[key];
    }
  }
  return target;
}
function repeat(string, count) {
  var result = "", cycle;
  for (cycle = 0; cycle < count; cycle += 1) {
    result += string;
  }
  return result;
}
function isNegativeZero(number) {
  return number === 0 && Number.NEGATIVE_INFINITY === 1 / number;
}
function formatError(exception2, compact) {
  var where = "", message = exception2.reason || "(unknown reason)";
  if (!exception2.mark)
    return message;
  if (exception2.mark.name) {
    where += 'in "' + exception2.mark.name + '" ';
  }
  where += "(" + (exception2.mark.line + 1) + ":" + (exception2.mark.column + 1) + ")";
  if (!compact && exception2.mark.snippet) {
    where += "\n\n" + exception2.mark.snippet;
  }
  return message + " " + where;
}
function YAMLException$1(reason, mark) {
  Error.call(this);
  this.name = "YAMLException";
  this.reason = reason;
  this.mark = mark;
  this.message = formatError(this, false);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  } else {
    this.stack = new Error().stack || "";
  }
}
function getLine(buffer, lineStart, lineEnd, position, maxLineLength) {
  var head = "";
  var tail = "";
  var maxHalfLength = Math.floor(maxLineLength / 2) - 1;
  if (position - lineStart > maxHalfLength) {
    head = " ... ";
    lineStart = position - maxHalfLength + head.length;
  }
  if (lineEnd - position > maxHalfLength) {
    tail = " ...";
    lineEnd = position + maxHalfLength - tail.length;
  }
  return {
    str: head + buffer.slice(lineStart, lineEnd).replace(/\t/g, "\u2192") + tail,
    pos: position - lineStart + head.length
    // relative position
  };
}
function padStart(string, max) {
  return common.repeat(" ", max - string.length) + string;
}
function makeSnippet(mark, options) {
  options = Object.create(options || null);
  if (!mark.buffer)
    return null;
  if (!options.maxLength)
    options.maxLength = 79;
  if (typeof options.indent !== "number")
    options.indent = 1;
  if (typeof options.linesBefore !== "number")
    options.linesBefore = 3;
  if (typeof options.linesAfter !== "number")
    options.linesAfter = 2;
  var re = /\r?\n|\r|\0/g;
  var lineStarts = [0];
  var lineEnds = [];
  var match;
  var foundLineNo = -1;
  while (match = re.exec(mark.buffer)) {
    lineEnds.push(match.index);
    lineStarts.push(match.index + match[0].length);
    if (mark.position <= match.index && foundLineNo < 0) {
      foundLineNo = lineStarts.length - 2;
    }
  }
  if (foundLineNo < 0)
    foundLineNo = lineStarts.length - 1;
  var result = "", i, line;
  var lineNoLength = Math.min(mark.line + options.linesAfter, lineEnds.length).toString().length;
  var maxLineLength = options.maxLength - (options.indent + lineNoLength + 3);
  for (i = 1; i <= options.linesBefore; i++) {
    if (foundLineNo - i < 0)
      break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo - i],
      lineEnds[foundLineNo - i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo - i]),
      maxLineLength
    );
    result = common.repeat(" ", options.indent) + padStart((mark.line - i + 1).toString(), lineNoLength) + " | " + line.str + "\n" + result;
  }
  line = getLine(mark.buffer, lineStarts[foundLineNo], lineEnds[foundLineNo], mark.position, maxLineLength);
  result += common.repeat(" ", options.indent) + padStart((mark.line + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  result += common.repeat("-", options.indent + lineNoLength + 3 + line.pos) + "^\n";
  for (i = 1; i <= options.linesAfter; i++) {
    if (foundLineNo + i >= lineEnds.length)
      break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo + i],
      lineEnds[foundLineNo + i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo + i]),
      maxLineLength
    );
    result += common.repeat(" ", options.indent) + padStart((mark.line + i + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  }
  return result.replace(/\n$/, "");
}
function compileStyleAliases(map2) {
  var result = {};
  if (map2 !== null) {
    Object.keys(map2).forEach(function(style) {
      map2[style].forEach(function(alias) {
        result[String(alias)] = style;
      });
    });
  }
  return result;
}
function Type$1(tag, options) {
  options = options || {};
  Object.keys(options).forEach(function(name) {
    if (TYPE_CONSTRUCTOR_OPTIONS.indexOf(name) === -1) {
      throw new exception('Unknown option "' + name + '" is met in definition of "' + tag + '" YAML type.');
    }
  });
  this.options = options;
  this.tag = tag;
  this.kind = options["kind"] || null;
  this.resolve = options["resolve"] || function() {
    return true;
  };
  this.construct = options["construct"] || function(data) {
    return data;
  };
  this.instanceOf = options["instanceOf"] || null;
  this.predicate = options["predicate"] || null;
  this.represent = options["represent"] || null;
  this.representName = options["representName"] || null;
  this.defaultStyle = options["defaultStyle"] || null;
  this.multi = options["multi"] || false;
  this.styleAliases = compileStyleAliases(options["styleAliases"] || null);
  if (YAML_NODE_KINDS.indexOf(this.kind) === -1) {
    throw new exception('Unknown kind "' + this.kind + '" is specified for "' + tag + '" YAML type.');
  }
}
function compileList(schema2, name) {
  var result = [];
  schema2[name].forEach(function(currentType) {
    var newIndex = result.length;
    result.forEach(function(previousType, previousIndex) {
      if (previousType.tag === currentType.tag && previousType.kind === currentType.kind && previousType.multi === currentType.multi) {
        newIndex = previousIndex;
      }
    });
    result[newIndex] = currentType;
  });
  return result;
}
function compileMap() {
  var result = {
    scalar: {},
    sequence: {},
    mapping: {},
    fallback: {},
    multi: {
      scalar: [],
      sequence: [],
      mapping: [],
      fallback: []
    }
  }, index, length;
  function collectType(type2) {
    if (type2.multi) {
      result.multi[type2.kind].push(type2);
      result.multi["fallback"].push(type2);
    } else {
      result[type2.kind][type2.tag] = result["fallback"][type2.tag] = type2;
    }
  }
  for (index = 0, length = arguments.length; index < length; index += 1) {
    arguments[index].forEach(collectType);
  }
  return result;
}
function Schema$1(definition) {
  return this.extend(definition);
}
function resolveYamlNull(data) {
  if (data === null)
    return true;
  var max = data.length;
  return max === 1 && data === "~" || max === 4 && (data === "null" || data === "Null" || data === "NULL");
}
function constructYamlNull() {
  return null;
}
function isNull(object) {
  return object === null;
}
function resolveYamlBoolean(data) {
  if (data === null)
    return false;
  var max = data.length;
  return max === 4 && (data === "true" || data === "True" || data === "TRUE") || max === 5 && (data === "false" || data === "False" || data === "FALSE");
}
function constructYamlBoolean(data) {
  return data === "true" || data === "True" || data === "TRUE";
}
function isBoolean(object) {
  return Object.prototype.toString.call(object) === "[object Boolean]";
}
function isHexCode(c) {
  return 48 <= c && c <= 57 || 65 <= c && c <= 70 || 97 <= c && c <= 102;
}
function isOctCode(c) {
  return 48 <= c && c <= 55;
}
function isDecCode(c) {
  return 48 <= c && c <= 57;
}
function resolveYamlInteger(data) {
  if (data === null)
    return false;
  var max = data.length, index = 0, hasDigits = false, ch;
  if (!max)
    return false;
  ch = data[index];
  if (ch === "-" || ch === "+") {
    ch = data[++index];
  }
  if (ch === "0") {
    if (index + 1 === max)
      return true;
    ch = data[++index];
    if (ch === "b") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_")
          continue;
        if (ch !== "0" && ch !== "1")
          return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "x") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_")
          continue;
        if (!isHexCode(data.charCodeAt(index)))
          return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "o") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_")
          continue;
        if (!isOctCode(data.charCodeAt(index)))
          return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
  }
  if (ch === "_")
    return false;
  for (; index < max; index++) {
    ch = data[index];
    if (ch === "_")
      continue;
    if (!isDecCode(data.charCodeAt(index))) {
      return false;
    }
    hasDigits = true;
  }
  if (!hasDigits || ch === "_")
    return false;
  return true;
}
function constructYamlInteger(data) {
  var value = data, sign = 1, ch;
  if (value.indexOf("_") !== -1) {
    value = value.replace(/_/g, "");
  }
  ch = value[0];
  if (ch === "-" || ch === "+") {
    if (ch === "-")
      sign = -1;
    value = value.slice(1);
    ch = value[0];
  }
  if (value === "0")
    return 0;
  if (ch === "0") {
    if (value[1] === "b")
      return sign * parseInt(value.slice(2), 2);
    if (value[1] === "x")
      return sign * parseInt(value.slice(2), 16);
    if (value[1] === "o")
      return sign * parseInt(value.slice(2), 8);
  }
  return sign * parseInt(value, 10);
}
function isInteger(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 === 0 && !common.isNegativeZero(object));
}
function resolveYamlFloat(data) {
  if (data === null)
    return false;
  if (!YAML_FLOAT_PATTERN.test(data) || // Quick hack to not allow integers end with `_`
  // Probably should update regexp & check speed
  data[data.length - 1] === "_") {
    return false;
  }
  return true;
}
function constructYamlFloat(data) {
  var value, sign;
  value = data.replace(/_/g, "").toLowerCase();
  sign = value[0] === "-" ? -1 : 1;
  if ("+-".indexOf(value[0]) >= 0) {
    value = value.slice(1);
  }
  if (value === ".inf") {
    return sign === 1 ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
  } else if (value === ".nan") {
    return NaN;
  }
  return sign * parseFloat(value, 10);
}
function representYamlFloat(object, style) {
  var res;
  if (isNaN(object)) {
    switch (style) {
      case "lowercase":
        return ".nan";
      case "uppercase":
        return ".NAN";
      case "camelcase":
        return ".NaN";
    }
  } else if (Number.POSITIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return ".inf";
      case "uppercase":
        return ".INF";
      case "camelcase":
        return ".Inf";
    }
  } else if (Number.NEGATIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return "-.inf";
      case "uppercase":
        return "-.INF";
      case "camelcase":
        return "-.Inf";
    }
  } else if (common.isNegativeZero(object)) {
    return "-0.0";
  }
  res = object.toString(10);
  return SCIENTIFIC_WITHOUT_DOT.test(res) ? res.replace("e", ".e") : res;
}
function isFloat(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 !== 0 || common.isNegativeZero(object));
}
function resolveYamlTimestamp(data) {
  if (data === null)
    return false;
  if (YAML_DATE_REGEXP.exec(data) !== null)
    return true;
  if (YAML_TIMESTAMP_REGEXP.exec(data) !== null)
    return true;
  return false;
}
function constructYamlTimestamp(data) {
  var match, year, month, day, hour, minute, second, fraction = 0, delta = null, tz_hour, tz_minute, date;
  match = YAML_DATE_REGEXP.exec(data);
  if (match === null)
    match = YAML_TIMESTAMP_REGEXP.exec(data);
  if (match === null)
    throw new Error("Date resolve error");
  year = +match[1];
  month = +match[2] - 1;
  day = +match[3];
  if (!match[4]) {
    return new Date(Date.UTC(year, month, day));
  }
  hour = +match[4];
  minute = +match[5];
  second = +match[6];
  if (match[7]) {
    fraction = match[7].slice(0, 3);
    while (fraction.length < 3) {
      fraction += "0";
    }
    fraction = +fraction;
  }
  if (match[9]) {
    tz_hour = +match[10];
    tz_minute = +(match[11] || 0);
    delta = (tz_hour * 60 + tz_minute) * 6e4;
    if (match[9] === "-")
      delta = -delta;
  }
  date = new Date(Date.UTC(year, month, day, hour, minute, second, fraction));
  if (delta)
    date.setTime(date.getTime() - delta);
  return date;
}
function representYamlTimestamp(object) {
  return object.toISOString();
}
function resolveYamlMerge(data) {
  return data === "<<" || data === null;
}
function resolveYamlBinary(data) {
  if (data === null)
    return false;
  var code, idx, bitlen = 0, max = data.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    code = map2.indexOf(data.charAt(idx));
    if (code > 64)
      continue;
    if (code < 0)
      return false;
    bitlen += 6;
  }
  return bitlen % 8 === 0;
}
function constructYamlBinary(data) {
  var idx, tailbits, input = data.replace(/[\r\n=]/g, ""), max = input.length, map2 = BASE64_MAP, bits = 0, result = [];
  for (idx = 0; idx < max; idx++) {
    if (idx % 4 === 0 && idx) {
      result.push(bits >> 16 & 255);
      result.push(bits >> 8 & 255);
      result.push(bits & 255);
    }
    bits = bits << 6 | map2.indexOf(input.charAt(idx));
  }
  tailbits = max % 4 * 6;
  if (tailbits === 0) {
    result.push(bits >> 16 & 255);
    result.push(bits >> 8 & 255);
    result.push(bits & 255);
  } else if (tailbits === 18) {
    result.push(bits >> 10 & 255);
    result.push(bits >> 2 & 255);
  } else if (tailbits === 12) {
    result.push(bits >> 4 & 255);
  }
  return new Uint8Array(result);
}
function representYamlBinary(object) {
  var result = "", bits = 0, idx, tail, max = object.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    if (idx % 3 === 0 && idx) {
      result += map2[bits >> 18 & 63];
      result += map2[bits >> 12 & 63];
      result += map2[bits >> 6 & 63];
      result += map2[bits & 63];
    }
    bits = (bits << 8) + object[idx];
  }
  tail = max % 3;
  if (tail === 0) {
    result += map2[bits >> 18 & 63];
    result += map2[bits >> 12 & 63];
    result += map2[bits >> 6 & 63];
    result += map2[bits & 63];
  } else if (tail === 2) {
    result += map2[bits >> 10 & 63];
    result += map2[bits >> 4 & 63];
    result += map2[bits << 2 & 63];
    result += map2[64];
  } else if (tail === 1) {
    result += map2[bits >> 2 & 63];
    result += map2[bits << 4 & 63];
    result += map2[64];
    result += map2[64];
  }
  return result;
}
function isBinary(obj) {
  return Object.prototype.toString.call(obj) === "[object Uint8Array]";
}
function resolveYamlOmap(data) {
  if (data === null)
    return true;
  var objectKeys = [], index, length, pair, pairKey, pairHasKey, object = data;
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    pairHasKey = false;
    if (_toString$2.call(pair) !== "[object Object]")
      return false;
    for (pairKey in pair) {
      if (_hasOwnProperty$3.call(pair, pairKey)) {
        if (!pairHasKey)
          pairHasKey = true;
        else
          return false;
      }
    }
    if (!pairHasKey)
      return false;
    if (objectKeys.indexOf(pairKey) === -1)
      objectKeys.push(pairKey);
    else
      return false;
  }
  return true;
}
function constructYamlOmap(data) {
  return data !== null ? data : [];
}
function resolveYamlPairs(data) {
  if (data === null)
    return true;
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    if (_toString$1.call(pair) !== "[object Object]")
      return false;
    keys = Object.keys(pair);
    if (keys.length !== 1)
      return false;
    result[index] = [keys[0], pair[keys[0]]];
  }
  return true;
}
function constructYamlPairs(data) {
  if (data === null)
    return [];
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    keys = Object.keys(pair);
    result[index] = [keys[0], pair[keys[0]]];
  }
  return result;
}
function resolveYamlSet(data) {
  if (data === null)
    return true;
  var key, object = data;
  for (key in object) {
    if (_hasOwnProperty$2.call(object, key)) {
      if (object[key] !== null)
        return false;
    }
  }
  return true;
}
function constructYamlSet(data) {
  return data !== null ? data : {};
}
function _class(obj) {
  return Object.prototype.toString.call(obj);
}
function is_EOL(c) {
  return c === 10 || c === 13;
}
function is_WHITE_SPACE(c) {
  return c === 9 || c === 32;
}
function is_WS_OR_EOL(c) {
  return c === 9 || c === 32 || c === 10 || c === 13;
}
function is_FLOW_INDICATOR(c) {
  return c === 44 || c === 91 || c === 93 || c === 123 || c === 125;
}
function fromHexCode(c) {
  var lc;
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  lc = c | 32;
  if (97 <= lc && lc <= 102) {
    return lc - 97 + 10;
  }
  return -1;
}
function escapedHexLen(c) {
  if (c === 120) {
    return 2;
  }
  if (c === 117) {
    return 4;
  }
  if (c === 85) {
    return 8;
  }
  return 0;
}
function fromDecimalCode(c) {
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  return -1;
}
function simpleEscapeSequence(c) {
  return c === 48 ? "\0" : c === 97 ? "\x07" : c === 98 ? "\b" : c === 116 ? "	" : c === 9 ? "	" : c === 110 ? "\n" : c === 118 ? "\v" : c === 102 ? "\f" : c === 114 ? "\r" : c === 101 ? "\x1B" : c === 32 ? " " : c === 34 ? '"' : c === 47 ? "/" : c === 92 ? "\\" : c === 78 ? "\x85" : c === 95 ? "\xA0" : c === 76 ? "\u2028" : c === 80 ? "\u2029" : "";
}
function charFromCodepoint(c) {
  if (c <= 65535) {
    return String.fromCharCode(c);
  }
  return String.fromCharCode(
    (c - 65536 >> 10) + 55296,
    (c - 65536 & 1023) + 56320
  );
}
function State$1(input, options) {
  this.input = input;
  this.filename = options["filename"] || null;
  this.schema = options["schema"] || _default;
  this.onWarning = options["onWarning"] || null;
  this.legacy = options["legacy"] || false;
  this.json = options["json"] || false;
  this.listener = options["listener"] || null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.typeMap = this.schema.compiledTypeMap;
  this.length = input.length;
  this.position = 0;
  this.line = 0;
  this.lineStart = 0;
  this.lineIndent = 0;
  this.firstTabInLine = -1;
  this.documents = [];
}
function generateError(state, message) {
  var mark = {
    name: state.filename,
    buffer: state.input.slice(0, -1),
    // omit trailing \0
    position: state.position,
    line: state.line,
    column: state.position - state.lineStart
  };
  mark.snippet = snippet(mark);
  return new exception(message, mark);
}
function throwError(state, message) {
  throw generateError(state, message);
}
function throwWarning(state, message) {
  if (state.onWarning) {
    state.onWarning.call(null, generateError(state, message));
  }
}
function captureSegment(state, start, end, checkJson) {
  var _position, _length, _character, _result;
  if (start < end) {
    _result = state.input.slice(start, end);
    if (checkJson) {
      for (_position = 0, _length = _result.length; _position < _length; _position += 1) {
        _character = _result.charCodeAt(_position);
        if (!(_character === 9 || 32 <= _character && _character <= 1114111)) {
          throwError(state, "expected valid JSON character");
        }
      }
    } else if (PATTERN_NON_PRINTABLE.test(_result)) {
      throwError(state, "the stream contains non-printable characters");
    }
    state.result += _result;
  }
}
function mergeMappings(state, destination, source, overridableKeys) {
  var sourceKeys, key, index, quantity;
  if (!common.isObject(source)) {
    throwError(state, "cannot merge mappings; the provided source object is unacceptable");
  }
  sourceKeys = Object.keys(source);
  for (index = 0, quantity = sourceKeys.length; index < quantity; index += 1) {
    key = sourceKeys[index];
    if (!_hasOwnProperty$1.call(destination, key)) {
      destination[key] = source[key];
      overridableKeys[key] = true;
    }
  }
}
function storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, startLine, startLineStart, startPos) {
  var index, quantity;
  if (Array.isArray(keyNode)) {
    keyNode = Array.prototype.slice.call(keyNode);
    for (index = 0, quantity = keyNode.length; index < quantity; index += 1) {
      if (Array.isArray(keyNode[index])) {
        throwError(state, "nested arrays are not supported inside keys");
      }
      if (typeof keyNode === "object" && _class(keyNode[index]) === "[object Object]") {
        keyNode[index] = "[object Object]";
      }
    }
  }
  if (typeof keyNode === "object" && _class(keyNode) === "[object Object]") {
    keyNode = "[object Object]";
  }
  keyNode = String(keyNode);
  if (_result === null) {
    _result = {};
  }
  if (keyTag === "tag:yaml.org,2002:merge") {
    if (Array.isArray(valueNode)) {
      for (index = 0, quantity = valueNode.length; index < quantity; index += 1) {
        mergeMappings(state, _result, valueNode[index], overridableKeys);
      }
    } else {
      mergeMappings(state, _result, valueNode, overridableKeys);
    }
  } else {
    if (!state.json && !_hasOwnProperty$1.call(overridableKeys, keyNode) && _hasOwnProperty$1.call(_result, keyNode)) {
      state.line = startLine || state.line;
      state.lineStart = startLineStart || state.lineStart;
      state.position = startPos || state.position;
      throwError(state, "duplicated mapping key");
    }
    if (keyNode === "__proto__") {
      Object.defineProperty(_result, keyNode, {
        configurable: true,
        enumerable: true,
        writable: true,
        value: valueNode
      });
    } else {
      _result[keyNode] = valueNode;
    }
    delete overridableKeys[keyNode];
  }
  return _result;
}
function readLineBreak(state) {
  var ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 10) {
    state.position++;
  } else if (ch === 13) {
    state.position++;
    if (state.input.charCodeAt(state.position) === 10) {
      state.position++;
    }
  } else {
    throwError(state, "a line break is expected");
  }
  state.line += 1;
  state.lineStart = state.position;
  state.firstTabInLine = -1;
}
function skipSeparationSpace(state, allowComments, checkIndent) {
  var lineBreaks = 0, ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    while (is_WHITE_SPACE(ch)) {
      if (ch === 9 && state.firstTabInLine === -1) {
        state.firstTabInLine = state.position;
      }
      ch = state.input.charCodeAt(++state.position);
    }
    if (allowComments && ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (ch !== 10 && ch !== 13 && ch !== 0);
    }
    if (is_EOL(ch)) {
      readLineBreak(state);
      ch = state.input.charCodeAt(state.position);
      lineBreaks++;
      state.lineIndent = 0;
      while (ch === 32) {
        state.lineIndent++;
        ch = state.input.charCodeAt(++state.position);
      }
    } else {
      break;
    }
  }
  if (checkIndent !== -1 && lineBreaks !== 0 && state.lineIndent < checkIndent) {
    throwWarning(state, "deficient indentation");
  }
  return lineBreaks;
}
function testDocumentSeparator(state) {
  var _position = state.position, ch;
  ch = state.input.charCodeAt(_position);
  if ((ch === 45 || ch === 46) && ch === state.input.charCodeAt(_position + 1) && ch === state.input.charCodeAt(_position + 2)) {
    _position += 3;
    ch = state.input.charCodeAt(_position);
    if (ch === 0 || is_WS_OR_EOL(ch)) {
      return true;
    }
  }
  return false;
}
function writeFoldedLines(state, count) {
  if (count === 1) {
    state.result += " ";
  } else if (count > 1) {
    state.result += common.repeat("\n", count - 1);
  }
}
function readPlainScalar(state, nodeIndent, withinFlowCollection) {
  var preceding, following, captureStart, captureEnd, hasPendingContent, _line, _lineStart, _lineIndent, _kind = state.kind, _result = state.result, ch;
  ch = state.input.charCodeAt(state.position);
  if (is_WS_OR_EOL(ch) || is_FLOW_INDICATOR(ch) || ch === 35 || ch === 38 || ch === 42 || ch === 33 || ch === 124 || ch === 62 || ch === 39 || ch === 34 || ch === 37 || ch === 64 || ch === 96) {
    return false;
  }
  if (ch === 63 || ch === 45) {
    following = state.input.charCodeAt(state.position + 1);
    if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
      return false;
    }
  }
  state.kind = "scalar";
  state.result = "";
  captureStart = captureEnd = state.position;
  hasPendingContent = false;
  while (ch !== 0) {
    if (ch === 58) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
        break;
      }
    } else if (ch === 35) {
      preceding = state.input.charCodeAt(state.position - 1);
      if (is_WS_OR_EOL(preceding)) {
        break;
      }
    } else if (state.position === state.lineStart && testDocumentSeparator(state) || withinFlowCollection && is_FLOW_INDICATOR(ch)) {
      break;
    } else if (is_EOL(ch)) {
      _line = state.line;
      _lineStart = state.lineStart;
      _lineIndent = state.lineIndent;
      skipSeparationSpace(state, false, -1);
      if (state.lineIndent >= nodeIndent) {
        hasPendingContent = true;
        ch = state.input.charCodeAt(state.position);
        continue;
      } else {
        state.position = captureEnd;
        state.line = _line;
        state.lineStart = _lineStart;
        state.lineIndent = _lineIndent;
        break;
      }
    }
    if (hasPendingContent) {
      captureSegment(state, captureStart, captureEnd, false);
      writeFoldedLines(state, state.line - _line);
      captureStart = captureEnd = state.position;
      hasPendingContent = false;
    }
    if (!is_WHITE_SPACE(ch)) {
      captureEnd = state.position + 1;
    }
    ch = state.input.charCodeAt(++state.position);
  }
  captureSegment(state, captureStart, captureEnd, false);
  if (state.result) {
    return true;
  }
  state.kind = _kind;
  state.result = _result;
  return false;
}
function readSingleQuotedScalar(state, nodeIndent) {
  var ch, captureStart, captureEnd;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 39) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 39) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (ch === 39) {
        captureStart = state.position;
        state.position++;
        captureEnd = state.position;
      } else {
        return true;
      }
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a single quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a single quoted scalar");
}
function readDoubleQuotedScalar(state, nodeIndent) {
  var captureStart, captureEnd, hexLength, hexResult, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 34) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 34) {
      captureSegment(state, captureStart, state.position, true);
      state.position++;
      return true;
    } else if (ch === 92) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (is_EOL(ch)) {
        skipSeparationSpace(state, false, nodeIndent);
      } else if (ch < 256 && simpleEscapeCheck[ch]) {
        state.result += simpleEscapeMap[ch];
        state.position++;
      } else if ((tmp = escapedHexLen(ch)) > 0) {
        hexLength = tmp;
        hexResult = 0;
        for (; hexLength > 0; hexLength--) {
          ch = state.input.charCodeAt(++state.position);
          if ((tmp = fromHexCode(ch)) >= 0) {
            hexResult = (hexResult << 4) + tmp;
          } else {
            throwError(state, "expected hexadecimal character");
          }
        }
        state.result += charFromCodepoint(hexResult);
        state.position++;
      } else {
        throwError(state, "unknown escape sequence");
      }
      captureStart = captureEnd = state.position;
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a double quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a double quoted scalar");
}
function readFlowCollection(state, nodeIndent) {
  var readNext = true, _line, _lineStart, _pos, _tag = state.tag, _result, _anchor = state.anchor, following, terminator, isPair, isExplicitPair, isMapping, overridableKeys = /* @__PURE__ */ Object.create(null), keyNode, keyTag, valueNode, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 91) {
    terminator = 93;
    isMapping = false;
    _result = [];
  } else if (ch === 123) {
    terminator = 125;
    isMapping = true;
    _result = {};
  } else {
    return false;
  }
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(++state.position);
  while (ch !== 0) {
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === terminator) {
      state.position++;
      state.tag = _tag;
      state.anchor = _anchor;
      state.kind = isMapping ? "mapping" : "sequence";
      state.result = _result;
      return true;
    } else if (!readNext) {
      throwError(state, "missed comma between flow collection entries");
    } else if (ch === 44) {
      throwError(state, "expected the node content, but found ','");
    }
    keyTag = keyNode = valueNode = null;
    isPair = isExplicitPair = false;
    if (ch === 63) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following)) {
        isPair = isExplicitPair = true;
        state.position++;
        skipSeparationSpace(state, true, nodeIndent);
      }
    }
    _line = state.line;
    _lineStart = state.lineStart;
    _pos = state.position;
    composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
    keyTag = state.tag;
    keyNode = state.result;
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if ((isExplicitPair || state.line === _line) && ch === 58) {
      isPair = true;
      ch = state.input.charCodeAt(++state.position);
      skipSeparationSpace(state, true, nodeIndent);
      composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
      valueNode = state.result;
    }
    if (isMapping) {
      storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos);
    } else if (isPair) {
      _result.push(storeMappingPair(state, null, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos));
    } else {
      _result.push(keyNode);
    }
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === 44) {
      readNext = true;
      ch = state.input.charCodeAt(++state.position);
    } else {
      readNext = false;
    }
  }
  throwError(state, "unexpected end of the stream within a flow collection");
}
function readBlockScalar(state, nodeIndent) {
  var captureStart, folding, chomping = CHOMPING_CLIP, didReadContent = false, detectedIndent = false, textIndent = nodeIndent, emptyLines = 0, atMoreIndented = false, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 124) {
    folding = false;
  } else if (ch === 62) {
    folding = true;
  } else {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  while (ch !== 0) {
    ch = state.input.charCodeAt(++state.position);
    if (ch === 43 || ch === 45) {
      if (CHOMPING_CLIP === chomping) {
        chomping = ch === 43 ? CHOMPING_KEEP : CHOMPING_STRIP;
      } else {
        throwError(state, "repeat of a chomping mode identifier");
      }
    } else if ((tmp = fromDecimalCode(ch)) >= 0) {
      if (tmp === 0) {
        throwError(state, "bad explicit indentation width of a block scalar; it cannot be less than one");
      } else if (!detectedIndent) {
        textIndent = nodeIndent + tmp - 1;
        detectedIndent = true;
      } else {
        throwError(state, "repeat of an indentation width identifier");
      }
    } else {
      break;
    }
  }
  if (is_WHITE_SPACE(ch)) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (is_WHITE_SPACE(ch));
    if (ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (!is_EOL(ch) && ch !== 0);
    }
  }
  while (ch !== 0) {
    readLineBreak(state);
    state.lineIndent = 0;
    ch = state.input.charCodeAt(state.position);
    while ((!detectedIndent || state.lineIndent < textIndent) && ch === 32) {
      state.lineIndent++;
      ch = state.input.charCodeAt(++state.position);
    }
    if (!detectedIndent && state.lineIndent > textIndent) {
      textIndent = state.lineIndent;
    }
    if (is_EOL(ch)) {
      emptyLines++;
      continue;
    }
    if (state.lineIndent < textIndent) {
      if (chomping === CHOMPING_KEEP) {
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (chomping === CHOMPING_CLIP) {
        if (didReadContent) {
          state.result += "\n";
        }
      }
      break;
    }
    if (folding) {
      if (is_WHITE_SPACE(ch)) {
        atMoreIndented = true;
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (atMoreIndented) {
        atMoreIndented = false;
        state.result += common.repeat("\n", emptyLines + 1);
      } else if (emptyLines === 0) {
        if (didReadContent) {
          state.result += " ";
        }
      } else {
        state.result += common.repeat("\n", emptyLines);
      }
    } else {
      state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
    }
    didReadContent = true;
    detectedIndent = true;
    emptyLines = 0;
    captureStart = state.position;
    while (!is_EOL(ch) && ch !== 0) {
      ch = state.input.charCodeAt(++state.position);
    }
    captureSegment(state, captureStart, state.position, false);
  }
  return true;
}
function readBlockSequence(state, nodeIndent) {
  var _line, _tag = state.tag, _anchor = state.anchor, _result = [], following, detected = false, ch;
  if (state.firstTabInLine !== -1)
    return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    if (ch !== 45) {
      break;
    }
    following = state.input.charCodeAt(state.position + 1);
    if (!is_WS_OR_EOL(following)) {
      break;
    }
    detected = true;
    state.position++;
    if (skipSeparationSpace(state, true, -1)) {
      if (state.lineIndent <= nodeIndent) {
        _result.push(null);
        ch = state.input.charCodeAt(state.position);
        continue;
      }
    }
    _line = state.line;
    composeNode(state, nodeIndent, CONTEXT_BLOCK_IN, false, true);
    _result.push(state.result);
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a sequence entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "sequence";
    state.result = _result;
    return true;
  }
  return false;
}
function readBlockMapping(state, nodeIndent, flowIndent) {
  var following, allowCompact, _line, _keyLine, _keyLineStart, _keyPos, _tag = state.tag, _anchor = state.anchor, _result = {}, overridableKeys = /* @__PURE__ */ Object.create(null), keyTag = null, keyNode = null, valueNode = null, atExplicitKey = false, detected = false, ch;
  if (state.firstTabInLine !== -1)
    return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (!atExplicitKey && state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    following = state.input.charCodeAt(state.position + 1);
    _line = state.line;
    if ((ch === 63 || ch === 58) && is_WS_OR_EOL(following)) {
      if (ch === 63) {
        if (atExplicitKey) {
          storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
          keyTag = keyNode = valueNode = null;
        }
        detected = true;
        atExplicitKey = true;
        allowCompact = true;
      } else if (atExplicitKey) {
        atExplicitKey = false;
        allowCompact = true;
      } else {
        throwError(state, "incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line");
      }
      state.position += 1;
      ch = following;
    } else {
      _keyLine = state.line;
      _keyLineStart = state.lineStart;
      _keyPos = state.position;
      if (!composeNode(state, flowIndent, CONTEXT_FLOW_OUT, false, true)) {
        break;
      }
      if (state.line === _line) {
        ch = state.input.charCodeAt(state.position);
        while (is_WHITE_SPACE(ch)) {
          ch = state.input.charCodeAt(++state.position);
        }
        if (ch === 58) {
          ch = state.input.charCodeAt(++state.position);
          if (!is_WS_OR_EOL(ch)) {
            throwError(state, "a whitespace character is expected after the key-value separator within a block mapping");
          }
          if (atExplicitKey) {
            storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
            keyTag = keyNode = valueNode = null;
          }
          detected = true;
          atExplicitKey = false;
          allowCompact = false;
          keyTag = state.tag;
          keyNode = state.result;
        } else if (detected) {
          throwError(state, "can not read an implicit mapping pair; a colon is missed");
        } else {
          state.tag = _tag;
          state.anchor = _anchor;
          return true;
        }
      } else if (detected) {
        throwError(state, "can not read a block mapping entry; a multiline key may not be an implicit key");
      } else {
        state.tag = _tag;
        state.anchor = _anchor;
        return true;
      }
    }
    if (state.line === _line || state.lineIndent > nodeIndent) {
      if (atExplicitKey) {
        _keyLine = state.line;
        _keyLineStart = state.lineStart;
        _keyPos = state.position;
      }
      if (composeNode(state, nodeIndent, CONTEXT_BLOCK_OUT, true, allowCompact)) {
        if (atExplicitKey) {
          keyNode = state.result;
        } else {
          valueNode = state.result;
        }
      }
      if (!atExplicitKey) {
        storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _keyLine, _keyLineStart, _keyPos);
        keyTag = keyNode = valueNode = null;
      }
      skipSeparationSpace(state, true, -1);
      ch = state.input.charCodeAt(state.position);
    }
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a mapping entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (atExplicitKey) {
    storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "mapping";
    state.result = _result;
  }
  return detected;
}
function readTagProperty(state) {
  var _position, isVerbatim = false, isNamed = false, tagHandle, tagName, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 33)
    return false;
  if (state.tag !== null) {
    throwError(state, "duplication of a tag property");
  }
  ch = state.input.charCodeAt(++state.position);
  if (ch === 60) {
    isVerbatim = true;
    ch = state.input.charCodeAt(++state.position);
  } else if (ch === 33) {
    isNamed = true;
    tagHandle = "!!";
    ch = state.input.charCodeAt(++state.position);
  } else {
    tagHandle = "!";
  }
  _position = state.position;
  if (isVerbatim) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (ch !== 0 && ch !== 62);
    if (state.position < state.length) {
      tagName = state.input.slice(_position, state.position);
      ch = state.input.charCodeAt(++state.position);
    } else {
      throwError(state, "unexpected end of the stream within a verbatim tag");
    }
  } else {
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      if (ch === 33) {
        if (!isNamed) {
          tagHandle = state.input.slice(_position - 1, state.position + 1);
          if (!PATTERN_TAG_HANDLE.test(tagHandle)) {
            throwError(state, "named tag handle cannot contain such characters");
          }
          isNamed = true;
          _position = state.position + 1;
        } else {
          throwError(state, "tag suffix cannot contain exclamation marks");
        }
      }
      ch = state.input.charCodeAt(++state.position);
    }
    tagName = state.input.slice(_position, state.position);
    if (PATTERN_FLOW_INDICATORS.test(tagName)) {
      throwError(state, "tag suffix cannot contain flow indicator characters");
    }
  }
  if (tagName && !PATTERN_TAG_URI.test(tagName)) {
    throwError(state, "tag name cannot contain such characters: " + tagName);
  }
  try {
    tagName = decodeURIComponent(tagName);
  } catch (err) {
    throwError(state, "tag name is malformed: " + tagName);
  }
  if (isVerbatim) {
    state.tag = tagName;
  } else if (_hasOwnProperty$1.call(state.tagMap, tagHandle)) {
    state.tag = state.tagMap[tagHandle] + tagName;
  } else if (tagHandle === "!") {
    state.tag = "!" + tagName;
  } else if (tagHandle === "!!") {
    state.tag = "tag:yaml.org,2002:" + tagName;
  } else {
    throwError(state, 'undeclared tag handle "' + tagHandle + '"');
  }
  return true;
}
function readAnchorProperty(state) {
  var _position, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 38)
    return false;
  if (state.anchor !== null) {
    throwError(state, "duplication of an anchor property");
  }
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an anchor node must contain at least one character");
  }
  state.anchor = state.input.slice(_position, state.position);
  return true;
}
function readAlias(state) {
  var _position, alias, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 42)
    return false;
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an alias node must contain at least one character");
  }
  alias = state.input.slice(_position, state.position);
  if (!_hasOwnProperty$1.call(state.anchorMap, alias)) {
    throwError(state, 'unidentified alias "' + alias + '"');
  }
  state.result = state.anchorMap[alias];
  skipSeparationSpace(state, true, -1);
  return true;
}
function composeNode(state, parentIndent, nodeContext, allowToSeek, allowCompact) {
  var allowBlockStyles, allowBlockScalars, allowBlockCollections, indentStatus = 1, atNewLine = false, hasContent = false, typeIndex, typeQuantity, typeList, type2, flowIndent, blockIndent;
  if (state.listener !== null) {
    state.listener("open", state);
  }
  state.tag = null;
  state.anchor = null;
  state.kind = null;
  state.result = null;
  allowBlockStyles = allowBlockScalars = allowBlockCollections = CONTEXT_BLOCK_OUT === nodeContext || CONTEXT_BLOCK_IN === nodeContext;
  if (allowToSeek) {
    if (skipSeparationSpace(state, true, -1)) {
      atNewLine = true;
      if (state.lineIndent > parentIndent) {
        indentStatus = 1;
      } else if (state.lineIndent === parentIndent) {
        indentStatus = 0;
      } else if (state.lineIndent < parentIndent) {
        indentStatus = -1;
      }
    }
  }
  if (indentStatus === 1) {
    while (readTagProperty(state) || readAnchorProperty(state)) {
      if (skipSeparationSpace(state, true, -1)) {
        atNewLine = true;
        allowBlockCollections = allowBlockStyles;
        if (state.lineIndent > parentIndent) {
          indentStatus = 1;
        } else if (state.lineIndent === parentIndent) {
          indentStatus = 0;
        } else if (state.lineIndent < parentIndent) {
          indentStatus = -1;
        }
      } else {
        allowBlockCollections = false;
      }
    }
  }
  if (allowBlockCollections) {
    allowBlockCollections = atNewLine || allowCompact;
  }
  if (indentStatus === 1 || CONTEXT_BLOCK_OUT === nodeContext) {
    if (CONTEXT_FLOW_IN === nodeContext || CONTEXT_FLOW_OUT === nodeContext) {
      flowIndent = parentIndent;
    } else {
      flowIndent = parentIndent + 1;
    }
    blockIndent = state.position - state.lineStart;
    if (indentStatus === 1) {
      if (allowBlockCollections && (readBlockSequence(state, blockIndent) || readBlockMapping(state, blockIndent, flowIndent)) || readFlowCollection(state, flowIndent)) {
        hasContent = true;
      } else {
        if (allowBlockScalars && readBlockScalar(state, flowIndent) || readSingleQuotedScalar(state, flowIndent) || readDoubleQuotedScalar(state, flowIndent)) {
          hasContent = true;
        } else if (readAlias(state)) {
          hasContent = true;
          if (state.tag !== null || state.anchor !== null) {
            throwError(state, "alias node should not have any properties");
          }
        } else if (readPlainScalar(state, flowIndent, CONTEXT_FLOW_IN === nodeContext)) {
          hasContent = true;
          if (state.tag === null) {
            state.tag = "?";
          }
        }
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
      }
    } else if (indentStatus === 0) {
      hasContent = allowBlockCollections && readBlockSequence(state, blockIndent);
    }
  }
  if (state.tag === null) {
    if (state.anchor !== null) {
      state.anchorMap[state.anchor] = state.result;
    }
  } else if (state.tag === "?") {
    if (state.result !== null && state.kind !== "scalar") {
      throwError(state, 'unacceptable node kind for !<?> tag; it should be "scalar", not "' + state.kind + '"');
    }
    for (typeIndex = 0, typeQuantity = state.implicitTypes.length; typeIndex < typeQuantity; typeIndex += 1) {
      type2 = state.implicitTypes[typeIndex];
      if (type2.resolve(state.result)) {
        state.result = type2.construct(state.result);
        state.tag = type2.tag;
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
        break;
      }
    }
  } else if (state.tag !== "!") {
    if (_hasOwnProperty$1.call(state.typeMap[state.kind || "fallback"], state.tag)) {
      type2 = state.typeMap[state.kind || "fallback"][state.tag];
    } else {
      type2 = null;
      typeList = state.typeMap.multi[state.kind || "fallback"];
      for (typeIndex = 0, typeQuantity = typeList.length; typeIndex < typeQuantity; typeIndex += 1) {
        if (state.tag.slice(0, typeList[typeIndex].tag.length) === typeList[typeIndex].tag) {
          type2 = typeList[typeIndex];
          break;
        }
      }
    }
    if (!type2) {
      throwError(state, "unknown tag !<" + state.tag + ">");
    }
    if (state.result !== null && type2.kind !== state.kind) {
      throwError(state, "unacceptable node kind for !<" + state.tag + '> tag; it should be "' + type2.kind + '", not "' + state.kind + '"');
    }
    if (!type2.resolve(state.result, state.tag)) {
      throwError(state, "cannot resolve a node with !<" + state.tag + "> explicit tag");
    } else {
      state.result = type2.construct(state.result, state.tag);
      if (state.anchor !== null) {
        state.anchorMap[state.anchor] = state.result;
      }
    }
  }
  if (state.listener !== null) {
    state.listener("close", state);
  }
  return state.tag !== null || state.anchor !== null || hasContent;
}
function readDocument(state) {
  var documentStart = state.position, _position, directiveName, directiveArgs, hasDirectives = false, ch;
  state.version = null;
  state.checkLineBreaks = state.legacy;
  state.tagMap = /* @__PURE__ */ Object.create(null);
  state.anchorMap = /* @__PURE__ */ Object.create(null);
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if (state.lineIndent > 0 || ch !== 37) {
      break;
    }
    hasDirectives = true;
    ch = state.input.charCodeAt(++state.position);
    _position = state.position;
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      ch = state.input.charCodeAt(++state.position);
    }
    directiveName = state.input.slice(_position, state.position);
    directiveArgs = [];
    if (directiveName.length < 1) {
      throwError(state, "directive name must not be less than one character in length");
    }
    while (ch !== 0) {
      while (is_WHITE_SPACE(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      if (ch === 35) {
        do {
          ch = state.input.charCodeAt(++state.position);
        } while (ch !== 0 && !is_EOL(ch));
        break;
      }
      if (is_EOL(ch))
        break;
      _position = state.position;
      while (ch !== 0 && !is_WS_OR_EOL(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      directiveArgs.push(state.input.slice(_position, state.position));
    }
    if (ch !== 0)
      readLineBreak(state);
    if (_hasOwnProperty$1.call(directiveHandlers, directiveName)) {
      directiveHandlers[directiveName](state, directiveName, directiveArgs);
    } else {
      throwWarning(state, 'unknown document directive "' + directiveName + '"');
    }
  }
  skipSeparationSpace(state, true, -1);
  if (state.lineIndent === 0 && state.input.charCodeAt(state.position) === 45 && state.input.charCodeAt(state.position + 1) === 45 && state.input.charCodeAt(state.position + 2) === 45) {
    state.position += 3;
    skipSeparationSpace(state, true, -1);
  } else if (hasDirectives) {
    throwError(state, "directives end mark is expected");
  }
  composeNode(state, state.lineIndent - 1, CONTEXT_BLOCK_OUT, false, true);
  skipSeparationSpace(state, true, -1);
  if (state.checkLineBreaks && PATTERN_NON_ASCII_LINE_BREAKS.test(state.input.slice(documentStart, state.position))) {
    throwWarning(state, "non-ASCII line breaks are interpreted as content");
  }
  state.documents.push(state.result);
  if (state.position === state.lineStart && testDocumentSeparator(state)) {
    if (state.input.charCodeAt(state.position) === 46) {
      state.position += 3;
      skipSeparationSpace(state, true, -1);
    }
    return;
  }
  if (state.position < state.length - 1) {
    throwError(state, "end of the stream or a document separator is expected");
  } else {
    return;
  }
}
function loadDocuments(input, options) {
  input = String(input);
  options = options || {};
  if (input.length !== 0) {
    if (input.charCodeAt(input.length - 1) !== 10 && input.charCodeAt(input.length - 1) !== 13) {
      input += "\n";
    }
    if (input.charCodeAt(0) === 65279) {
      input = input.slice(1);
    }
  }
  var state = new State$1(input, options);
  var nullpos = input.indexOf("\0");
  if (nullpos !== -1) {
    state.position = nullpos;
    throwError(state, "null byte is not allowed in input");
  }
  state.input += "\0";
  while (state.input.charCodeAt(state.position) === 32) {
    state.lineIndent += 1;
    state.position += 1;
  }
  while (state.position < state.length - 1) {
    readDocument(state);
  }
  return state.documents;
}
function loadAll$1(input, iterator, options) {
  if (iterator !== null && typeof iterator === "object" && typeof options === "undefined") {
    options = iterator;
    iterator = null;
  }
  var documents = loadDocuments(input, options);
  if (typeof iterator !== "function") {
    return documents;
  }
  for (var index = 0, length = documents.length; index < length; index += 1) {
    iterator(documents[index]);
  }
}
function load$1(input, options) {
  var documents = loadDocuments(input, options);
  if (documents.length === 0) {
    return void 0;
  } else if (documents.length === 1) {
    return documents[0];
  }
  throw new exception("expected a single document in the stream, but found more");
}
function compileStyleMap(schema2, map2) {
  var result, keys, index, length, tag, style, type2;
  if (map2 === null)
    return {};
  result = {};
  keys = Object.keys(map2);
  for (index = 0, length = keys.length; index < length; index += 1) {
    tag = keys[index];
    style = String(map2[tag]);
    if (tag.slice(0, 2) === "!!") {
      tag = "tag:yaml.org,2002:" + tag.slice(2);
    }
    type2 = schema2.compiledTypeMap["fallback"][tag];
    if (type2 && _hasOwnProperty.call(type2.styleAliases, style)) {
      style = type2.styleAliases[style];
    }
    result[tag] = style;
  }
  return result;
}
function encodeHex(character) {
  var string, handle, length;
  string = character.toString(16).toUpperCase();
  if (character <= 255) {
    handle = "x";
    length = 2;
  } else if (character <= 65535) {
    handle = "u";
    length = 4;
  } else if (character <= 4294967295) {
    handle = "U";
    length = 8;
  } else {
    throw new exception("code point within a string may not be greater than 0xFFFFFFFF");
  }
  return "\\" + handle + common.repeat("0", length - string.length) + string;
}
function State(options) {
  this.schema = options["schema"] || _default;
  this.indent = Math.max(1, options["indent"] || 2);
  this.noArrayIndent = options["noArrayIndent"] || false;
  this.skipInvalid = options["skipInvalid"] || false;
  this.flowLevel = common.isNothing(options["flowLevel"]) ? -1 : options["flowLevel"];
  this.styleMap = compileStyleMap(this.schema, options["styles"] || null);
  this.sortKeys = options["sortKeys"] || false;
  this.lineWidth = options["lineWidth"] || 80;
  this.noRefs = options["noRefs"] || false;
  this.noCompatMode = options["noCompatMode"] || false;
  this.condenseFlow = options["condenseFlow"] || false;
  this.quotingType = options["quotingType"] === '"' ? QUOTING_TYPE_DOUBLE : QUOTING_TYPE_SINGLE;
  this.forceQuotes = options["forceQuotes"] || false;
  this.replacer = typeof options["replacer"] === "function" ? options["replacer"] : null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.explicitTypes = this.schema.compiledExplicit;
  this.tag = null;
  this.result = "";
  this.duplicates = [];
  this.usedDuplicates = null;
}
function indentString(string, spaces) {
  var ind = common.repeat(" ", spaces), position = 0, next = -1, result = "", line, length = string.length;
  while (position < length) {
    next = string.indexOf("\n", position);
    if (next === -1) {
      line = string.slice(position);
      position = length;
    } else {
      line = string.slice(position, next + 1);
      position = next + 1;
    }
    if (line.length && line !== "\n")
      result += ind;
    result += line;
  }
  return result;
}
function generateNextLine(state, level) {
  return "\n" + common.repeat(" ", state.indent * level);
}
function testImplicitResolving(state, str2) {
  var index, length, type2;
  for (index = 0, length = state.implicitTypes.length; index < length; index += 1) {
    type2 = state.implicitTypes[index];
    if (type2.resolve(str2)) {
      return true;
    }
  }
  return false;
}
function isWhitespace(c) {
  return c === CHAR_SPACE || c === CHAR_TAB;
}
function isPrintable(c) {
  return 32 <= c && c <= 126 || 161 <= c && c <= 55295 && c !== 8232 && c !== 8233 || 57344 <= c && c <= 65533 && c !== CHAR_BOM || 65536 <= c && c <= 1114111;
}
function isNsCharOrWhitespace(c) {
  return isPrintable(c) && c !== CHAR_BOM && c !== CHAR_CARRIAGE_RETURN && c !== CHAR_LINE_FEED;
}
function isPlainSafe(c, prev, inblock) {
  var cIsNsCharOrWhitespace = isNsCharOrWhitespace(c);
  var cIsNsChar = cIsNsCharOrWhitespace && !isWhitespace(c);
  return (
    // ns-plain-safe
    (inblock ? (
      // c = flow-in
      cIsNsCharOrWhitespace
    ) : cIsNsCharOrWhitespace && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET) && c !== CHAR_SHARP && !(prev === CHAR_COLON && !cIsNsChar) || isNsCharOrWhitespace(prev) && !isWhitespace(prev) && c === CHAR_SHARP || prev === CHAR_COLON && cIsNsChar
  );
}
function isPlainSafeFirst(c) {
  return isPrintable(c) && c !== CHAR_BOM && !isWhitespace(c) && c !== CHAR_MINUS && c !== CHAR_QUESTION && c !== CHAR_COLON && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET && c !== CHAR_SHARP && c !== CHAR_AMPERSAND && c !== CHAR_ASTERISK && c !== CHAR_EXCLAMATION && c !== CHAR_VERTICAL_LINE && c !== CHAR_EQUALS && c !== CHAR_GREATER_THAN && c !== CHAR_SINGLE_QUOTE && c !== CHAR_DOUBLE_QUOTE && c !== CHAR_PERCENT && c !== CHAR_COMMERCIAL_AT && c !== CHAR_GRAVE_ACCENT;
}
function isPlainSafeLast(c) {
  return !isWhitespace(c) && c !== CHAR_COLON;
}
function codePointAt(string, pos) {
  var first = string.charCodeAt(pos), second;
  if (first >= 55296 && first <= 56319 && pos + 1 < string.length) {
    second = string.charCodeAt(pos + 1);
    if (second >= 56320 && second <= 57343) {
      return (first - 55296) * 1024 + second - 56320 + 65536;
    }
  }
  return first;
}
function needIndentIndicator(string) {
  var leadingSpaceRe = /^\n* /;
  return leadingSpaceRe.test(string);
}
function chooseScalarStyle(string, singleLineOnly, indentPerLevel, lineWidth, testAmbiguousType, quotingType, forceQuotes, inblock) {
  var i;
  var char = 0;
  var prevChar = null;
  var hasLineBreak = false;
  var hasFoldableLine = false;
  var shouldTrackWidth = lineWidth !== -1;
  var previousLineBreak = -1;
  var plain = isPlainSafeFirst(codePointAt(string, 0)) && isPlainSafeLast(codePointAt(string, string.length - 1));
  if (singleLineOnly || forceQuotes) {
    for (i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
  } else {
    for (i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (char === CHAR_LINE_FEED) {
        hasLineBreak = true;
        if (shouldTrackWidth) {
          hasFoldableLine = hasFoldableLine || // Foldable line = too long, and not more-indented.
          i - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ";
          previousLineBreak = i;
        }
      } else if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
    hasFoldableLine = hasFoldableLine || shouldTrackWidth && (i - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ");
  }
  if (!hasLineBreak && !hasFoldableLine) {
    if (plain && !forceQuotes && !testAmbiguousType(string)) {
      return STYLE_PLAIN;
    }
    return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
  }
  if (indentPerLevel > 9 && needIndentIndicator(string)) {
    return STYLE_DOUBLE;
  }
  if (!forceQuotes) {
    return hasFoldableLine ? STYLE_FOLDED : STYLE_LITERAL;
  }
  return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
}
function writeScalar(state, string, level, iskey, inblock) {
  state.dump = function() {
    if (string.length === 0) {
      return state.quotingType === QUOTING_TYPE_DOUBLE ? '""' : "''";
    }
    if (!state.noCompatMode) {
      if (DEPRECATED_BOOLEANS_SYNTAX.indexOf(string) !== -1 || DEPRECATED_BASE60_SYNTAX.test(string)) {
        return state.quotingType === QUOTING_TYPE_DOUBLE ? '"' + string + '"' : "'" + string + "'";
      }
    }
    var indent = state.indent * Math.max(1, level);
    var lineWidth = state.lineWidth === -1 ? -1 : Math.max(Math.min(state.lineWidth, 40), state.lineWidth - indent);
    var singleLineOnly = iskey || state.flowLevel > -1 && level >= state.flowLevel;
    function testAmbiguity(string2) {
      return testImplicitResolving(state, string2);
    }
    switch (chooseScalarStyle(
      string,
      singleLineOnly,
      state.indent,
      lineWidth,
      testAmbiguity,
      state.quotingType,
      state.forceQuotes && !iskey,
      inblock
    )) {
      case STYLE_PLAIN:
        return string;
      case STYLE_SINGLE:
        return "'" + string.replace(/'/g, "''") + "'";
      case STYLE_LITERAL:
        return "|" + blockHeader(string, state.indent) + dropEndingNewline(indentString(string, indent));
      case STYLE_FOLDED:
        return ">" + blockHeader(string, state.indent) + dropEndingNewline(indentString(foldString(string, lineWidth), indent));
      case STYLE_DOUBLE:
        return '"' + escapeString(string) + '"';
      default:
        throw new exception("impossible error: invalid scalar style");
    }
  }();
}
function blockHeader(string, indentPerLevel) {
  var indentIndicator = needIndentIndicator(string) ? String(indentPerLevel) : "";
  var clip = string[string.length - 1] === "\n";
  var keep = clip && (string[string.length - 2] === "\n" || string === "\n");
  var chomp = keep ? "+" : clip ? "" : "-";
  return indentIndicator + chomp + "\n";
}
function dropEndingNewline(string) {
  return string[string.length - 1] === "\n" ? string.slice(0, -1) : string;
}
function foldString(string, width) {
  var lineRe = /(\n+)([^\n]*)/g;
  var result = function() {
    var nextLF = string.indexOf("\n");
    nextLF = nextLF !== -1 ? nextLF : string.length;
    lineRe.lastIndex = nextLF;
    return foldLine(string.slice(0, nextLF), width);
  }();
  var prevMoreIndented = string[0] === "\n" || string[0] === " ";
  var moreIndented;
  var match;
  while (match = lineRe.exec(string)) {
    var prefix = match[1], line = match[2];
    moreIndented = line[0] === " ";
    result += prefix + (!prevMoreIndented && !moreIndented && line !== "" ? "\n" : "") + foldLine(line, width);
    prevMoreIndented = moreIndented;
  }
  return result;
}
function foldLine(line, width) {
  if (line === "" || line[0] === " ")
    return line;
  var breakRe = / [^ ]/g;
  var match;
  var start = 0, end, curr = 0, next = 0;
  var result = "";
  while (match = breakRe.exec(line)) {
    next = match.index;
    if (next - start > width) {
      end = curr > start ? curr : next;
      result += "\n" + line.slice(start, end);
      start = end + 1;
    }
    curr = next;
  }
  result += "\n";
  if (line.length - start > width && curr > start) {
    result += line.slice(start, curr) + "\n" + line.slice(curr + 1);
  } else {
    result += line.slice(start);
  }
  return result.slice(1);
}
function escapeString(string) {
  var result = "";
  var char = 0;
  var escapeSeq;
  for (var i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
    char = codePointAt(string, i);
    escapeSeq = ESCAPE_SEQUENCES[char];
    if (!escapeSeq && isPrintable(char)) {
      result += string[i];
      if (char >= 65536)
        result += string[i + 1];
    } else {
      result += escapeSeq || encodeHex(char);
    }
  }
  return result;
}
function writeFlowSequence(state, level, object) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level, value, false, false) || typeof value === "undefined" && writeNode(state, level, null, false, false)) {
      if (_result !== "")
        _result += "," + (!state.condenseFlow ? " " : "");
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = "[" + _result + "]";
}
function writeBlockSequence(state, level, object, compact) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level + 1, value, true, true, false, true) || typeof value === "undefined" && writeNode(state, level + 1, null, true, true, false, true)) {
      if (!compact || _result !== "") {
        _result += generateNextLine(state, level);
      }
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        _result += "-";
      } else {
        _result += "- ";
      }
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = _result || "[]";
}
function writeFlowMapping(state, level, object) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, pairBuffer;
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (_result !== "")
      pairBuffer += ", ";
    if (state.condenseFlow)
      pairBuffer += '"';
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level, objectKey, false, false)) {
      continue;
    }
    if (state.dump.length > 1024)
      pairBuffer += "? ";
    pairBuffer += state.dump + (state.condenseFlow ? '"' : "") + ":" + (state.condenseFlow ? "" : " ");
    if (!writeNode(state, level, objectValue, false, false)) {
      continue;
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = "{" + _result + "}";
}
function writeBlockMapping(state, level, object, compact) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, explicitPair, pairBuffer;
  if (state.sortKeys === true) {
    objectKeyList.sort();
  } else if (typeof state.sortKeys === "function") {
    objectKeyList.sort(state.sortKeys);
  } else if (state.sortKeys) {
    throw new exception("sortKeys must be a boolean or a function");
  }
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (!compact || _result !== "") {
      pairBuffer += generateNextLine(state, level);
    }
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level + 1, objectKey, true, true, true)) {
      continue;
    }
    explicitPair = state.tag !== null && state.tag !== "?" || state.dump && state.dump.length > 1024;
    if (explicitPair) {
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        pairBuffer += "?";
      } else {
        pairBuffer += "? ";
      }
    }
    pairBuffer += state.dump;
    if (explicitPair) {
      pairBuffer += generateNextLine(state, level);
    }
    if (!writeNode(state, level + 1, objectValue, true, explicitPair)) {
      continue;
    }
    if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
      pairBuffer += ":";
    } else {
      pairBuffer += ": ";
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = _result || "{}";
}
function detectType(state, object, explicit) {
  var _result, typeList, index, length, type2, style;
  typeList = explicit ? state.explicitTypes : state.implicitTypes;
  for (index = 0, length = typeList.length; index < length; index += 1) {
    type2 = typeList[index];
    if ((type2.instanceOf || type2.predicate) && (!type2.instanceOf || typeof object === "object" && object instanceof type2.instanceOf) && (!type2.predicate || type2.predicate(object))) {
      if (explicit) {
        if (type2.multi && type2.representName) {
          state.tag = type2.representName(object);
        } else {
          state.tag = type2.tag;
        }
      } else {
        state.tag = "?";
      }
      if (type2.represent) {
        style = state.styleMap[type2.tag] || type2.defaultStyle;
        if (_toString.call(type2.represent) === "[object Function]") {
          _result = type2.represent(object, style);
        } else if (_hasOwnProperty.call(type2.represent, style)) {
          _result = type2.represent[style](object, style);
        } else {
          throw new exception("!<" + type2.tag + '> tag resolver accepts not "' + style + '" style');
        }
        state.dump = _result;
      }
      return true;
    }
  }
  return false;
}
function writeNode(state, level, object, block, compact, iskey, isblockseq) {
  state.tag = null;
  state.dump = object;
  if (!detectType(state, object, false)) {
    detectType(state, object, true);
  }
  var type2 = _toString.call(state.dump);
  var inblock = block;
  var tagStr;
  if (block) {
    block = state.flowLevel < 0 || state.flowLevel > level;
  }
  var objectOrArray = type2 === "[object Object]" || type2 === "[object Array]", duplicateIndex, duplicate;
  if (objectOrArray) {
    duplicateIndex = state.duplicates.indexOf(object);
    duplicate = duplicateIndex !== -1;
  }
  if (state.tag !== null && state.tag !== "?" || duplicate || state.indent !== 2 && level > 0) {
    compact = false;
  }
  if (duplicate && state.usedDuplicates[duplicateIndex]) {
    state.dump = "*ref_" + duplicateIndex;
  } else {
    if (objectOrArray && duplicate && !state.usedDuplicates[duplicateIndex]) {
      state.usedDuplicates[duplicateIndex] = true;
    }
    if (type2 === "[object Object]") {
      if (block && Object.keys(state.dump).length !== 0) {
        writeBlockMapping(state, level, state.dump, compact);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowMapping(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object Array]") {
      if (block && state.dump.length !== 0) {
        if (state.noArrayIndent && !isblockseq && level > 0) {
          writeBlockSequence(state, level - 1, state.dump, compact);
        } else {
          writeBlockSequence(state, level, state.dump, compact);
        }
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowSequence(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object String]") {
      if (state.tag !== "?") {
        writeScalar(state, state.dump, level, iskey, inblock);
      }
    } else if (type2 === "[object Undefined]") {
      return false;
    } else {
      if (state.skipInvalid)
        return false;
      throw new exception("unacceptable kind of an object to dump " + type2);
    }
    if (state.tag !== null && state.tag !== "?") {
      tagStr = encodeURI(
        state.tag[0] === "!" ? state.tag.slice(1) : state.tag
      ).replace(/!/g, "%21");
      if (state.tag[0] === "!") {
        tagStr = "!" + tagStr;
      } else if (tagStr.slice(0, 18) === "tag:yaml.org,2002:") {
        tagStr = "!!" + tagStr.slice(18);
      } else {
        tagStr = "!<" + tagStr + ">";
      }
      state.dump = tagStr + " " + state.dump;
    }
  }
  return true;
}
function getDuplicateReferences(object, state) {
  var objects = [], duplicatesIndexes = [], index, length;
  inspectNode(object, objects, duplicatesIndexes);
  for (index = 0, length = duplicatesIndexes.length; index < length; index += 1) {
    state.duplicates.push(objects[duplicatesIndexes[index]]);
  }
  state.usedDuplicates = new Array(length);
}
function inspectNode(object, objects, duplicatesIndexes) {
  var objectKeyList, index, length;
  if (object !== null && typeof object === "object") {
    index = objects.indexOf(object);
    if (index !== -1) {
      if (duplicatesIndexes.indexOf(index) === -1) {
        duplicatesIndexes.push(index);
      }
    } else {
      objects.push(object);
      if (Array.isArray(object)) {
        for (index = 0, length = object.length; index < length; index += 1) {
          inspectNode(object[index], objects, duplicatesIndexes);
        }
      } else {
        objectKeyList = Object.keys(object);
        for (index = 0, length = objectKeyList.length; index < length; index += 1) {
          inspectNode(object[objectKeyList[index]], objects, duplicatesIndexes);
        }
      }
    }
  }
}
function dump$1(input, options) {
  options = options || {};
  var state = new State(options);
  if (!state.noRefs)
    getDuplicateReferences(input, state);
  var value = input;
  if (state.replacer) {
    value = state.replacer.call({ "": value }, "", value);
  }
  if (writeNode(state, 0, value, true, true))
    return state.dump + "\n";
  return "";
}
function renamed(from, to) {
  return function() {
    throw new Error("Function yaml." + from + " is removed in js-yaml 4. Use yaml." + to + " instead, which is now safe by default.");
  };
}
var isNothing_1, isObject_1, toArray_1, repeat_1, isNegativeZero_1, extend_1, common, exception, snippet, TYPE_CONSTRUCTOR_OPTIONS, YAML_NODE_KINDS, type, schema, str, seq, map, failsafe, _null, bool, int, YAML_FLOAT_PATTERN, SCIENTIFIC_WITHOUT_DOT, float, json, core, YAML_DATE_REGEXP, YAML_TIMESTAMP_REGEXP, timestamp, merge, BASE64_MAP, binary, _hasOwnProperty$3, _toString$2, omap, _toString$1, pairs, _hasOwnProperty$2, set, _default, _hasOwnProperty$1, CONTEXT_FLOW_IN, CONTEXT_FLOW_OUT, CONTEXT_BLOCK_IN, CONTEXT_BLOCK_OUT, CHOMPING_CLIP, CHOMPING_STRIP, CHOMPING_KEEP, PATTERN_NON_PRINTABLE, PATTERN_NON_ASCII_LINE_BREAKS, PATTERN_FLOW_INDICATORS, PATTERN_TAG_HANDLE, PATTERN_TAG_URI, simpleEscapeCheck, simpleEscapeMap, i, directiveHandlers, loadAll_1, load_1, loader, _toString, _hasOwnProperty, CHAR_BOM, CHAR_TAB, CHAR_LINE_FEED, CHAR_CARRIAGE_RETURN, CHAR_SPACE, CHAR_EXCLAMATION, CHAR_DOUBLE_QUOTE, CHAR_SHARP, CHAR_PERCENT, CHAR_AMPERSAND, CHAR_SINGLE_QUOTE, CHAR_ASTERISK, CHAR_COMMA, CHAR_MINUS, CHAR_COLON, CHAR_EQUALS, CHAR_GREATER_THAN, CHAR_QUESTION, CHAR_COMMERCIAL_AT, CHAR_LEFT_SQUARE_BRACKET, CHAR_RIGHT_SQUARE_BRACKET, CHAR_GRAVE_ACCENT, CHAR_LEFT_CURLY_BRACKET, CHAR_VERTICAL_LINE, CHAR_RIGHT_CURLY_BRACKET, ESCAPE_SEQUENCES, DEPRECATED_BOOLEANS_SYNTAX, DEPRECATED_BASE60_SYNTAX, QUOTING_TYPE_SINGLE, QUOTING_TYPE_DOUBLE, STYLE_PLAIN, STYLE_SINGLE, STYLE_LITERAL, STYLE_FOLDED, STYLE_DOUBLE, dump_1, dumper, Type, Schema, FAILSAFE_SCHEMA, JSON_SCHEMA, CORE_SCHEMA, DEFAULT_SCHEMA, load, loadAll, dump, YAMLException, types, safeLoad, safeLoadAll, safeDump, jsYaml, js_yaml_default;
var init_js_yaml = __esm({
  "node_modules/js-yaml/dist/js-yaml.mjs"() {
    isNothing_1 = isNothing;
    isObject_1 = isObject;
    toArray_1 = toArray;
    repeat_1 = repeat;
    isNegativeZero_1 = isNegativeZero;
    extend_1 = extend;
    common = {
      isNothing: isNothing_1,
      isObject: isObject_1,
      toArray: toArray_1,
      repeat: repeat_1,
      isNegativeZero: isNegativeZero_1,
      extend: extend_1
    };
    YAMLException$1.prototype = Object.create(Error.prototype);
    YAMLException$1.prototype.constructor = YAMLException$1;
    YAMLException$1.prototype.toString = function toString(compact) {
      return this.name + ": " + formatError(this, compact);
    };
    exception = YAMLException$1;
    snippet = makeSnippet;
    TYPE_CONSTRUCTOR_OPTIONS = [
      "kind",
      "multi",
      "resolve",
      "construct",
      "instanceOf",
      "predicate",
      "represent",
      "representName",
      "defaultStyle",
      "styleAliases"
    ];
    YAML_NODE_KINDS = [
      "scalar",
      "sequence",
      "mapping"
    ];
    type = Type$1;
    Schema$1.prototype.extend = function extend2(definition) {
      var implicit = [];
      var explicit = [];
      if (definition instanceof type) {
        explicit.push(definition);
      } else if (Array.isArray(definition)) {
        explicit = explicit.concat(definition);
      } else if (definition && (Array.isArray(definition.implicit) || Array.isArray(definition.explicit))) {
        if (definition.implicit)
          implicit = implicit.concat(definition.implicit);
        if (definition.explicit)
          explicit = explicit.concat(definition.explicit);
      } else {
        throw new exception("Schema.extend argument should be a Type, [ Type ], or a schema definition ({ implicit: [...], explicit: [...] })");
      }
      implicit.forEach(function(type$1) {
        if (!(type$1 instanceof type)) {
          throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
        }
        if (type$1.loadKind && type$1.loadKind !== "scalar") {
          throw new exception("There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.");
        }
        if (type$1.multi) {
          throw new exception("There is a multi type in the implicit list of a schema. Multi tags can only be listed as explicit.");
        }
      });
      explicit.forEach(function(type$1) {
        if (!(type$1 instanceof type)) {
          throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
        }
      });
      var result = Object.create(Schema$1.prototype);
      result.implicit = (this.implicit || []).concat(implicit);
      result.explicit = (this.explicit || []).concat(explicit);
      result.compiledImplicit = compileList(result, "implicit");
      result.compiledExplicit = compileList(result, "explicit");
      result.compiledTypeMap = compileMap(result.compiledImplicit, result.compiledExplicit);
      return result;
    };
    schema = Schema$1;
    str = new type("tag:yaml.org,2002:str", {
      kind: "scalar",
      construct: function(data) {
        return data !== null ? data : "";
      }
    });
    seq = new type("tag:yaml.org,2002:seq", {
      kind: "sequence",
      construct: function(data) {
        return data !== null ? data : [];
      }
    });
    map = new type("tag:yaml.org,2002:map", {
      kind: "mapping",
      construct: function(data) {
        return data !== null ? data : {};
      }
    });
    failsafe = new schema({
      explicit: [
        str,
        seq,
        map
      ]
    });
    _null = new type("tag:yaml.org,2002:null", {
      kind: "scalar",
      resolve: resolveYamlNull,
      construct: constructYamlNull,
      predicate: isNull,
      represent: {
        canonical: function() {
          return "~";
        },
        lowercase: function() {
          return "null";
        },
        uppercase: function() {
          return "NULL";
        },
        camelcase: function() {
          return "Null";
        },
        empty: function() {
          return "";
        }
      },
      defaultStyle: "lowercase"
    });
    bool = new type("tag:yaml.org,2002:bool", {
      kind: "scalar",
      resolve: resolveYamlBoolean,
      construct: constructYamlBoolean,
      predicate: isBoolean,
      represent: {
        lowercase: function(object) {
          return object ? "true" : "false";
        },
        uppercase: function(object) {
          return object ? "TRUE" : "FALSE";
        },
        camelcase: function(object) {
          return object ? "True" : "False";
        }
      },
      defaultStyle: "lowercase"
    });
    int = new type("tag:yaml.org,2002:int", {
      kind: "scalar",
      resolve: resolveYamlInteger,
      construct: constructYamlInteger,
      predicate: isInteger,
      represent: {
        binary: function(obj) {
          return obj >= 0 ? "0b" + obj.toString(2) : "-0b" + obj.toString(2).slice(1);
        },
        octal: function(obj) {
          return obj >= 0 ? "0o" + obj.toString(8) : "-0o" + obj.toString(8).slice(1);
        },
        decimal: function(obj) {
          return obj.toString(10);
        },
        /* eslint-disable max-len */
        hexadecimal: function(obj) {
          return obj >= 0 ? "0x" + obj.toString(16).toUpperCase() : "-0x" + obj.toString(16).toUpperCase().slice(1);
        }
      },
      defaultStyle: "decimal",
      styleAliases: {
        binary: [2, "bin"],
        octal: [8, "oct"],
        decimal: [10, "dec"],
        hexadecimal: [16, "hex"]
      }
    });
    YAML_FLOAT_PATTERN = new RegExp(
      // 2.5e4, 2.5 and integers
      "^(?:[-+]?(?:[0-9][0-9_]*)(?:\\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|\\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?\\.(?:inf|Inf|INF)|\\.(?:nan|NaN|NAN))$"
    );
    SCIENTIFIC_WITHOUT_DOT = /^[-+]?[0-9]+e/;
    float = new type("tag:yaml.org,2002:float", {
      kind: "scalar",
      resolve: resolveYamlFloat,
      construct: constructYamlFloat,
      predicate: isFloat,
      represent: representYamlFloat,
      defaultStyle: "lowercase"
    });
    json = failsafe.extend({
      implicit: [
        _null,
        bool,
        int,
        float
      ]
    });
    core = json;
    YAML_DATE_REGEXP = new RegExp(
      "^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])$"
    );
    YAML_TIMESTAMP_REGEXP = new RegExp(
      "^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:[Tt]|[ \\t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\\.([0-9]*))?(?:[ \\t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?$"
    );
    timestamp = new type("tag:yaml.org,2002:timestamp", {
      kind: "scalar",
      resolve: resolveYamlTimestamp,
      construct: constructYamlTimestamp,
      instanceOf: Date,
      represent: representYamlTimestamp
    });
    merge = new type("tag:yaml.org,2002:merge", {
      kind: "scalar",
      resolve: resolveYamlMerge
    });
    BASE64_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r";
    binary = new type("tag:yaml.org,2002:binary", {
      kind: "scalar",
      resolve: resolveYamlBinary,
      construct: constructYamlBinary,
      predicate: isBinary,
      represent: representYamlBinary
    });
    _hasOwnProperty$3 = Object.prototype.hasOwnProperty;
    _toString$2 = Object.prototype.toString;
    omap = new type("tag:yaml.org,2002:omap", {
      kind: "sequence",
      resolve: resolveYamlOmap,
      construct: constructYamlOmap
    });
    _toString$1 = Object.prototype.toString;
    pairs = new type("tag:yaml.org,2002:pairs", {
      kind: "sequence",
      resolve: resolveYamlPairs,
      construct: constructYamlPairs
    });
    _hasOwnProperty$2 = Object.prototype.hasOwnProperty;
    set = new type("tag:yaml.org,2002:set", {
      kind: "mapping",
      resolve: resolveYamlSet,
      construct: constructYamlSet
    });
    _default = core.extend({
      implicit: [
        timestamp,
        merge
      ],
      explicit: [
        binary,
        omap,
        pairs,
        set
      ]
    });
    _hasOwnProperty$1 = Object.prototype.hasOwnProperty;
    CONTEXT_FLOW_IN = 1;
    CONTEXT_FLOW_OUT = 2;
    CONTEXT_BLOCK_IN = 3;
    CONTEXT_BLOCK_OUT = 4;
    CHOMPING_CLIP = 1;
    CHOMPING_STRIP = 2;
    CHOMPING_KEEP = 3;
    PATTERN_NON_PRINTABLE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
    PATTERN_NON_ASCII_LINE_BREAKS = /[\x85\u2028\u2029]/;
    PATTERN_FLOW_INDICATORS = /[,\[\]\{\}]/;
    PATTERN_TAG_HANDLE = /^(?:!|!!|![a-z\-]+!)$/i;
    PATTERN_TAG_URI = /^(?:!|[^,\[\]\{\}])(?:%[0-9a-f]{2}|[0-9a-z\-#;\/\?:@&=\+\$,_\.!~\*'\(\)\[\]])*$/i;
    simpleEscapeCheck = new Array(256);
    simpleEscapeMap = new Array(256);
    for (i = 0; i < 256; i++) {
      simpleEscapeCheck[i] = simpleEscapeSequence(i) ? 1 : 0;
      simpleEscapeMap[i] = simpleEscapeSequence(i);
    }
    directiveHandlers = {
      YAML: function handleYamlDirective(state, name, args) {
        var match, major, minor;
        if (state.version !== null) {
          throwError(state, "duplication of %YAML directive");
        }
        if (args.length !== 1) {
          throwError(state, "YAML directive accepts exactly one argument");
        }
        match = /^([0-9]+)\.([0-9]+)$/.exec(args[0]);
        if (match === null) {
          throwError(state, "ill-formed argument of the YAML directive");
        }
        major = parseInt(match[1], 10);
        minor = parseInt(match[2], 10);
        if (major !== 1) {
          throwError(state, "unacceptable YAML version of the document");
        }
        state.version = args[0];
        state.checkLineBreaks = minor < 2;
        if (minor !== 1 && minor !== 2) {
          throwWarning(state, "unsupported YAML version of the document");
        }
      },
      TAG: function handleTagDirective(state, name, args) {
        var handle, prefix;
        if (args.length !== 2) {
          throwError(state, "TAG directive accepts exactly two arguments");
        }
        handle = args[0];
        prefix = args[1];
        if (!PATTERN_TAG_HANDLE.test(handle)) {
          throwError(state, "ill-formed tag handle (first argument) of the TAG directive");
        }
        if (_hasOwnProperty$1.call(state.tagMap, handle)) {
          throwError(state, 'there is a previously declared suffix for "' + handle + '" tag handle');
        }
        if (!PATTERN_TAG_URI.test(prefix)) {
          throwError(state, "ill-formed tag prefix (second argument) of the TAG directive");
        }
        try {
          prefix = decodeURIComponent(prefix);
        } catch (err) {
          throwError(state, "tag prefix is malformed: " + prefix);
        }
        state.tagMap[handle] = prefix;
      }
    };
    loadAll_1 = loadAll$1;
    load_1 = load$1;
    loader = {
      loadAll: loadAll_1,
      load: load_1
    };
    _toString = Object.prototype.toString;
    _hasOwnProperty = Object.prototype.hasOwnProperty;
    CHAR_BOM = 65279;
    CHAR_TAB = 9;
    CHAR_LINE_FEED = 10;
    CHAR_CARRIAGE_RETURN = 13;
    CHAR_SPACE = 32;
    CHAR_EXCLAMATION = 33;
    CHAR_DOUBLE_QUOTE = 34;
    CHAR_SHARP = 35;
    CHAR_PERCENT = 37;
    CHAR_AMPERSAND = 38;
    CHAR_SINGLE_QUOTE = 39;
    CHAR_ASTERISK = 42;
    CHAR_COMMA = 44;
    CHAR_MINUS = 45;
    CHAR_COLON = 58;
    CHAR_EQUALS = 61;
    CHAR_GREATER_THAN = 62;
    CHAR_QUESTION = 63;
    CHAR_COMMERCIAL_AT = 64;
    CHAR_LEFT_SQUARE_BRACKET = 91;
    CHAR_RIGHT_SQUARE_BRACKET = 93;
    CHAR_GRAVE_ACCENT = 96;
    CHAR_LEFT_CURLY_BRACKET = 123;
    CHAR_VERTICAL_LINE = 124;
    CHAR_RIGHT_CURLY_BRACKET = 125;
    ESCAPE_SEQUENCES = {};
    ESCAPE_SEQUENCES[0] = "\\0";
    ESCAPE_SEQUENCES[7] = "\\a";
    ESCAPE_SEQUENCES[8] = "\\b";
    ESCAPE_SEQUENCES[9] = "\\t";
    ESCAPE_SEQUENCES[10] = "\\n";
    ESCAPE_SEQUENCES[11] = "\\v";
    ESCAPE_SEQUENCES[12] = "\\f";
    ESCAPE_SEQUENCES[13] = "\\r";
    ESCAPE_SEQUENCES[27] = "\\e";
    ESCAPE_SEQUENCES[34] = '\\"';
    ESCAPE_SEQUENCES[92] = "\\\\";
    ESCAPE_SEQUENCES[133] = "\\N";
    ESCAPE_SEQUENCES[160] = "\\_";
    ESCAPE_SEQUENCES[8232] = "\\L";
    ESCAPE_SEQUENCES[8233] = "\\P";
    DEPRECATED_BOOLEANS_SYNTAX = [
      "y",
      "Y",
      "yes",
      "Yes",
      "YES",
      "on",
      "On",
      "ON",
      "n",
      "N",
      "no",
      "No",
      "NO",
      "off",
      "Off",
      "OFF"
    ];
    DEPRECATED_BASE60_SYNTAX = /^[-+]?[0-9_]+(?::[0-9_]+)+(?:\.[0-9_]*)?$/;
    QUOTING_TYPE_SINGLE = 1;
    QUOTING_TYPE_DOUBLE = 2;
    STYLE_PLAIN = 1;
    STYLE_SINGLE = 2;
    STYLE_LITERAL = 3;
    STYLE_FOLDED = 4;
    STYLE_DOUBLE = 5;
    dump_1 = dump$1;
    dumper = {
      dump: dump_1
    };
    Type = type;
    Schema = schema;
    FAILSAFE_SCHEMA = failsafe;
    JSON_SCHEMA = json;
    CORE_SCHEMA = core;
    DEFAULT_SCHEMA = _default;
    load = loader.load;
    loadAll = loader.loadAll;
    dump = dumper.dump;
    YAMLException = exception;
    types = {
      binary,
      float,
      map,
      null: _null,
      pairs,
      set,
      timestamp,
      bool,
      int,
      merge,
      omap,
      seq,
      str
    };
    safeLoad = renamed("safeLoad", "load");
    safeLoadAll = renamed("safeLoadAll", "loadAll");
    safeDump = renamed("safeDump", "dump");
    jsYaml = {
      Type,
      Schema,
      FAILSAFE_SCHEMA,
      JSON_SCHEMA,
      CORE_SCHEMA,
      DEFAULT_SCHEMA,
      load,
      loadAll,
      dump,
      YAMLException,
      types,
      safeLoad,
      safeLoadAll,
      safeDump
    };
    js_yaml_default = jsYaml;
  }
});

// node_modules/@foundryvtt/foundryvtt-cli/lib/package.mjs
import fs from "fs";
import path from "path";
import { ClassicLevel } from "/usr/local/lib/node_modules/classic-level/index.js";
async function compilePack(src, dest, {
  nedb = false,
  yaml = false,
  recursive = false,
  log = false,
  transformEntry
} = {}) {
  if (nedb && path.extname(dest) !== ".db") {
    throw new Error("The nedb option was passed to compilePacks, but the target pack does not have a .db extension.");
  }
  const files = findSourceFiles(src, { yaml, recursive });
  if (nedb)
    return compileNedb(dest, files, { log, transformEntry });
  return compileClassicLevel(dest, files, { log, transformEntry });
}
async function compileNedb(pack, files, { log, transformEntry } = {}) {
  try {
    fs.unlinkSync(pack);
  } catch (err) {
    if (err.code !== "ENOENT")
      throw err;
  }
  const db = import_nedb_promises.default.create(pack);
  const packDoc = applyHierarchy((doc) => delete doc._key);
  for (const file of files) {
    try {
      const contents = fs.readFileSync(file, "utf8");
      const doc = path.extname(file) === ".yml" ? js_yaml_default.load(contents) : JSON.parse(contents);
      const key = doc._key;
      const [, collection] = key.split("!");
      if (key.startsWith("!folders"))
        continue;
      if (await transformEntry?.(doc) === false)
        continue;
      await packDoc(doc, collection);
      await db.insert(doc);
      if (log)
        console.log(`Packed ${source_default.blue(doc._id)}${source_default.blue(doc.name ? ` (${doc.name})` : "")}`);
    } catch (err) {
      if (log)
        console.error(`Failed to parse ${source_default.red(file)}. See error below.`);
      throw err;
    }
  }
  db.stopAutocompaction();
  await new Promise((resolve2) => db.compactDatafile(resolve2));
}
async function compileClassicLevel(pack, files, { log, transformEntry } = {}) {
  fs.mkdirSync(pack, { recursive: true });
  const db = new ClassicLevel(pack, { keyEncoding: "utf8", valueEncoding: "json" });
  const batch = db.batch();
  const seenKeys = /* @__PURE__ */ new Set();
  const packDoc = applyHierarchy(async (doc, collection) => {
    const key = doc._key;
    delete doc._key;
    seenKeys.add(key);
    const value = structuredClone(doc);
    await mapHierarchy(value, collection, (d) => d._id);
    batch.put(key, value);
  });
  for (const file of files) {
    try {
      const contents = fs.readFileSync(file, "utf8");
      const doc = path.extname(file) === ".yml" ? js_yaml_default.load(contents) : JSON.parse(contents);
      const [, collection] = doc._key.split("!");
      if (await transformEntry?.(doc) === false)
        continue;
      await packDoc(doc, collection);
      if (log)
        console.log(`Packed ${source_default.blue(doc._id)}${source_default.blue(doc.name ? ` (${doc.name})` : "")}`);
    } catch (err) {
      if (log)
        console.error(`Failed to parse ${source_default.red(file)}. See error below.`);
      throw err;
    }
  }
  for (const key of await db.keys().all()) {
    if (!seenKeys.has(key)) {
      batch.del(key);
      if (log)
        console.log(`Removed ${source_default.blue(key)}`);
    }
  }
  await batch.write();
  await compactClassicLevel(db);
  await db.close();
}
async function compactClassicLevel(db) {
  const forwardIterator = db.keys({ limit: 1, fillCache: false });
  const firstKey = await forwardIterator.next();
  await forwardIterator.close();
  const backwardIterator = db.keys({ limit: 1, reverse: true, fillCache: false });
  const lastKey = await backwardIterator.next();
  await backwardIterator.close();
  if (firstKey && lastKey)
    return db.compactRange(firstKey, lastKey, { keyEncoding: "utf8" });
}
async function extractPack(src, dest, {
  nedb = false,
  yaml = false,
  log = false,
  documentType,
  collection,
  transformEntry,
  transformName
} = {}) {
  if (nedb && path.extname(src) !== ".db") {
    throw new Error("The nedb option was passed to extractPacks, but the target pack does not have a .db extension.");
  }
  collection ??= TYPE_COLLECTION_MAP[documentType];
  if (nedb && !collection) {
    throw new Error("For NeDB operations, a documentType or collection must be provided.");
  }
  fs.mkdirSync(dest, { recursive: true });
  if (nedb)
    return extractNedb(src, dest, { yaml, log, collection, transformEntry, transformName });
  return extractClassicLevel(src, dest, { yaml, log, transformEntry, transformName });
}
async function extractNedb(pack, dest, { yaml: asYaml, log, collection, transformEntry, transformName } = {}) {
  const db = new import_nedb_promises.default({ filename: pack, autoload: true });
  const unpackDoc = applyHierarchy((doc, collection2, { sublevelPrefix, idPrefix } = {}) => {
    const sublevel = keyJoin(sublevelPrefix, collection2);
    const id = keyJoin(idPrefix, doc._id);
    doc._key = `!${sublevel}!${id}`;
    return { sublevelPrefix: sublevel, idPrefix: id };
  });
  const docs = await db.find({});
  for (const doc of docs) {
    await unpackDoc(doc, collection);
    if (await transformEntry?.(doc) === false)
      continue;
    let name = await transformName?.(doc);
    if (!name) {
      name = `${doc.name ? `${getSafeFilename(doc.name)}_${doc._id}` : doc._id}.${asYaml ? "yml" : "json"}`;
    }
    const filename = path.join(dest, name);
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    fs.writeFileSync(filename, asYaml ? js_yaml_default.dump(doc) : JSON.stringify(doc, null, 2) + "\n");
    if (log)
      console.log(`Wrote ${source_default.blue(name)}`);
  }
}
async function extractClassicLevel(pack, dest, { yaml: asYaml, log, transformEntry, transformName }) {
  const db = new ClassicLevel(pack, { keyEncoding: "utf8", valueEncoding: "json" });
  const unpackDoc = applyHierarchy(async (doc, collection, { sublevelPrefix, idPrefix } = {}) => {
    const sublevel = keyJoin(sublevelPrefix, collection);
    const id = keyJoin(idPrefix, doc._id);
    doc._key = `!${sublevel}!${id}`;
    await mapHierarchy(doc, collection, (embeddedId, embeddedCollectionName) => {
      return db.get(`!${sublevel}.${embeddedCollectionName}!${id}.${embeddedId}`);
    });
    return { sublevelPrefix: sublevel, idPrefix: id };
  });
  for await (const [key, doc] of db.iterator()) {
    const [, collection, id] = key.split("!");
    if (collection.includes("."))
      continue;
    await unpackDoc(doc, collection);
    if (await transformEntry?.(doc) === false)
      continue;
    let name = await transformName?.(doc);
    if (!name) {
      name = `${doc.name ? `${getSafeFilename(doc.name)}_${id}` : key}.${asYaml ? "yml" : "json"}`;
    }
    const filename = path.join(dest, name);
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    fs.writeFileSync(filename, asYaml ? js_yaml_default.dump(doc) : JSON.stringify(doc, null, 2) + "\n");
    if (log)
      console.log(`Wrote ${source_default.blue(name)}`);
  }
  await db.close();
}
function applyHierarchy(fn) {
  const apply = async (doc, collection, options = {}) => {
    const newOptions = await fn(doc, collection, options);
    for (const [embeddedCollectionName, type2] of Object.entries(HIERARCHY[collection] ?? {})) {
      const embeddedValue = doc[embeddedCollectionName];
      if (Array.isArray(type2) && Array.isArray(embeddedValue)) {
        for (const embeddedDoc of embeddedValue)
          await apply(embeddedDoc, embeddedCollectionName, newOptions);
      } else if (embeddedValue)
        await apply(embeddedValue, embeddedCollectionName, newOptions);
    }
  };
  return apply;
}
async function mapHierarchy(doc, collection, fn) {
  for (const [embeddedCollectionName, type2] of Object.entries(HIERARCHY[collection] ?? {})) {
    const embeddedValue = doc[embeddedCollectionName];
    if (Array.isArray(type2)) {
      if (Array.isArray(embeddedValue)) {
        doc[embeddedCollectionName] = await Promise.all(embeddedValue.map((entry) => {
          return fn(entry, embeddedCollectionName);
        }));
      } else
        doc[embeddedCollectionName] = [];
    } else {
      if (embeddedValue)
        doc[embeddedCollectionName] = await fn(embeddedValue, embeddedCollectionName);
      else
        doc[embeddedCollectionName] = null;
    }
  }
}
function findSourceFiles(root, { yaml = false, recursive = false } = {}) {
  const files = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const name = path.join(root, entry.name);
    if (entry.isDirectory() && recursive) {
      files.push(...findSourceFiles(name, { yaml, recursive }));
      continue;
    }
    if (!entry.isFile())
      continue;
    const ext = path.extname(name);
    if (yaml && ext === ".yml")
      files.push(name);
    else if (!yaml && ext === ".json")
      files.push(name);
  }
  return files;
}
function keyJoin(...args) {
  return args.filter((_) => _).join(".");
}
function getSafeFilename(filename) {
  return filename.replace(/[^a-zA-Z0-9А-я]/g, "_");
}
var import_nedb_promises, HIERARCHY, TYPE_COLLECTION_MAP;
var init_package = __esm({
  "node_modules/@foundryvtt/foundryvtt-cli/lib/package.mjs"() {
    import_nedb_promises = __toESM(require_nedb_promises(), 1);
    init_source();
    init_js_yaml();
    HIERARCHY = {
      actors: {
        items: [],
        effects: []
      },
      cards: {
        cards: []
      },
      combats: {
        combatants: []
      },
      delta: {
        items: [],
        effects: []
      },
      items: {
        effects: []
      },
      journal: {
        pages: []
      },
      playlists: {
        sounds: []
      },
      tables: {
        results: []
      },
      tokens: {
        delta: {}
      },
      scenes: {
        drawings: [],
        tokens: [],
        lights: [],
        notes: [],
        sounds: [],
        templates: [],
        tiles: [],
        walls: []
      }
    };
    TYPE_COLLECTION_MAP = {
      Actor: "actors",
      Adventure: "adventures",
      Cards: "cards",
      ChatMessage: "messages",
      Combat: "combats",
      FogExploration: "fog",
      Folder: "folders",
      Item: "items",
      JournalEntry: "journal",
      Macro: "macros",
      Playlist: "playlists",
      RollTable: "tables",
      Scene: "scenes",
      Setting: "settings",
      User: "users"
    };
  }
});

// node_modules/@foundryvtt/foundryvtt-cli/index.mjs
var foundryvtt_cli_exports = {};
__export(foundryvtt_cli_exports, {
  compilePack: () => compilePack,
  extractPack: () => extractPack
});
var init_foundryvtt_cli = __esm({
  "node_modules/@foundryvtt/foundryvtt-cli/index.mjs"() {
    init_package();
  }
});

// src/index.ts
var import_core2 = __toESM(require_core(), 1);
import { existsSync } from "node:fs";
import { resolve } from "node:path";

// src/utils.ts
var import_core = __toESM(require_core(), 1);
import { statSync } from "node:fs";
import { readdir } from "node:fs/promises";
async function createDB({
  inputdir,
  packsdir,
  packNeDB,
  packClassicLevel
}) {
  const { compilePack: compilePack2 } = await Promise.resolve().then(() => (init_foundryvtt_cli(), foundryvtt_cli_exports));
  return readdir(inputdir).then(async (dir) => {
    for (const subdir of dir) {
      if (statSync(`${inputdir}/${subdir}`).isDirectory()) {
        if (packClassicLevel)
          await compilePack2(`${inputdir}/${subdir}`, `${packsdir}/${subdir}`, {
            log: true,
            recursive: true
          }).then(() => {
            (0, import_core.info)(`Packed ${subdir} as a classic LevelDB`);
          }).catch((err) => {
            (0, import_core.error)(`Error packing ${subdir} as a classic LevelDB`);
            throw err;
          });
        if (packNeDB)
          await compilePack2(`${inputdir}/${subdir}`, `${packsdir}/${subdir}.db`, {
            log: true,
            recursive: true,
            nedb: true
          }).then(() => {
            (0, import_core.info)(`Packed ${subdir} as a NeDB`);
          }).catch((err) => {
            (0, import_core.error)(`Error packing ${subdir} as a NeDB`);
            throw err;
          });
      }
    }
  }).catch((err) => {
    (0, import_core.error)("Error reading input directory");
    throw err;
  });
}

// src/index.ts
async function main() {
  try {
    const inputDirInput = (0, import_core2.getInput)("inputdir");
    const inputdir = resolve(process.cwd(), inputDirInput);
    if (!inputDirInput)
      throw new Error("No packs directory specified");
    const packsInput = (0, import_core2.getInput)("packsdir") || "packs";
    const packsdir = resolve(process.cwd(), packsInput);
    if (!existsSync(inputdir))
      throw new Error(`Input directory ${inputdir} does not exist`);
    if (!existsSync(packsdir))
      throw new Error(`Packs directory ${packsdir} does not exist`);
    const packNeDB = (0, import_core2.getBooleanInput)("pack_nedb");
    const packClassicLevel = (0, import_core2.getBooleanInput)("pack_classiclevel");
    await createDB({
      inputdir,
      packsdir,
      packNeDB,
      packClassicLevel
    });
  } catch (error2) {
    if (error2 instanceof Error)
      (0, import_core2.setFailed)(error2.message);
    else
      (0, import_core2.setFailed)("Unknown error");
    process.exit(1);
  }
}
main();
/*! Bundled license information:

js-yaml/dist/js-yaml.mjs:
  (*! js-yaml 4.1.0 https://github.com/nodeca/js-yaml @license MIT *)
*/
