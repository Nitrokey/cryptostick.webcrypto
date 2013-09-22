/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is DOMCrypt API code.
 *
 * The Initial Developer of the Original Code is
 * the Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *  David Dahl <ddahl@mozilla.com>  (Original Author)
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

let Cu = Components.utils;
let Ci = Components.interfaces;
let Cc = Components.classes;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/ctypes.jsm");

XPCOMUtils.defineLazyServiceGetter(this, "promptSvc",
                                   "@mozilla.org/embedcomp/prompt-service;1",
                                   "nsIPromptService");

XPCOMUtils.defineLazyServiceGetter(this, "secretDecoderRing",
                                   "@mozilla.org/security/sdr;1",
                                   "nsISecretDecoderRing");

function log(aMessage) {
  var _msg = "*** CryptoStickMethods: " + aMessage + "\n";
  dump(_msg);
}

var EXPORTED_SYMBOLS = ["CryptoStickMethods"];

// We use NSS for the crypto ops, which needs to be initialized before
// use. By convention, PSM is required to be the module that
// initializes NSS. So, make sure PSM is initialized in order to
// implicitly initialize NSS.
Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);

// We can call ChromeWorkers from this JSM
XPCOMUtils.defineLazyGetter(this, "worker", function (){
  return new ChromeWorker("cryptostick_worker.js");
});

const SHA256_COMPLETE     = "SHA256Complete";
const WORKER_ERROR        = "error";

function CryptoStickWebKey()
{
  this.name = null;
  this.id = null;

  this.extractable = null;
  this.algorithm = {
    name: null,
    __exposedProps__: {
      name:	'r'
    }
  };
  this.keyUsage = [];
  this.type = null;

  this.cs_pkcs11id = null;
  this.cs_numBits = null;

  this.__exposedProps__ = {
    name:	'r',
    id:		'r',

    extractable:'r',
    algorithm:	'r',
    keyUsage:	'r',
    type:	'r',

    cs_pkcs11id:'r',
    cs_numBits:	'r'
  };

  this.fromChromeKey = function (k)
  {
    for (var f in this.__exposedProps__)
      if (f != "algorithm")
	this[f] = k[f];
    this.algorithm.name = k.algorithm;
    return this;
  }
}

function CryptoStickWebKeyArray(arr)
{
  this.arr = arr;

  this.count = function() { return this.arr.length; }
  this.get = function(i) { return this.arr[i]; }

  this.__exposedProps__ = {
    count: 'r',
    get: 'r'
  };
}

function buildTarget(obj)
{
  return {
    target: {
      result: obj,
      __exposedProps__: { result: 'r' }
    },
    __exposedProps__: { target: 'r' }
  };
}

worker.onmessage = function DCM_worker_onmessage(aEvent) {
  switch (aEvent.data.action) {
  case "done_getKeyByName":
    keys = aEvent.data.data;
    var res = resultPop(aEvent.data.result);
    if (keys.ok) {
      var exposed = [];
      for (i = 0; i < keys.data.length; i++)
	exposed[exposed.length] = new CryptoStickWebKey().fromChromeKey(keys.data[i]);
      res._oncomplete(buildTarget(new CryptoStickWebKeyArray(exposed)));
    } else {
      res._onerror(buildTarget(keys.data));
    }
    break;
  case "done_exportKey":
    exp = aEvent.data.data;
    var res = resultPop(aEvent.data.result);
    if (exp.ok) {
      var d = exp.data, len = exp.data.length;
      var arr = [];
      for (var i = 0; i < len; i++)
	arr[arr.length] = d.charCodeAt(i);
      res._oncomplete(buildTarget(arr));
    } else {
      res._onerror(buildTarget(exp.data));
    }
    break;
  case "done_sign":
    exp = aEvent.data.data;
    var res = resultPop(aEvent.data.result);
    if (exp.ok) {
      dump("RDBG done_sign: " + exp.data.length + " things: " + exp.data + "\n");
      res._oncomplete(buildTarget(exp.data));
    } else {
      res._onerror(buildTarget(exp.data));
    }
    break;
  case "done_decrypt":
    exp = aEvent.data.data;
    var res = resultPop(aEvent.data.result);
    if (exp.ok) {
      dump("RDBG done_decrypt: " + exp.data.length + " things: " + exp.data + "\n");
      res._oncomplete(buildTarget(exp.data));
    } else {
      res._onerror(buildTarget(exp.data));
    }
    break;
  case SHA256_COMPLETE:
    Callbacks.handleSHA256(aEvent.data.hashedString);
    break;
  case WORKER_ERROR:
    if (aEvent.data.notify) {
      notifyUser(aEvent.data);
    }
  default:
    break;
  }
};

worker.onerror = function DCM_onerror(aError) {
  log("Worker Error: " + aError.message);
  log("Worker Error filename: " + aError.filename);
  log("Worker Error line no: " + aError.lineno);
};

// Constants to describe all operations
const SHA256            = "SHA256";
const INITIALIZE_WORKER = "init";

const BLANK_CONFIG_OBJECT = {};

/**
 * CryptoStickMethods
 *
 * This Object handles all input from content scripts via the CryptoStick
 * nsIDOMGlobalPropertyInitializer and sends calls to the Worker that
 * handles all NSS calls
 *
 * The basic work flow:
 *
 * A content script calls one of the CryptoStick window API methods, at minimum,
 * a callback function is passed into the window API method.
 *
 * The window API method calls the corresponding method in this JSM
 * (CryptoStickMethods), which sets up the callback and sandbox.
 *
 * The CryptoStickMethod API calls into the ChromeWorker which initializes NSS and
 * provides the js-ctypes wrapper obejct which is a slightly edited and expanded
 * WeaveCrypto Object.
 *
 * The crypto operations are run in the worker, and the return value sent back to
 * the CryptoStickMethods object via a postMessage.
 *
 * CryptoStickMethods' onmessage chooses which callback to execute in the original
 * content window's sandbox.
 */

var results = {};
var resultSerial = 0;

function resultRegister(res)
{
  var serial = resultSerial++;
  results[serial] = res;
  return serial;
}

function resultPop(idx)
{
  var res = results[idx];
  delete results[idx];
  return res;
}

function resultGet(idx)
{
  return results[idx];
}

var CryptoStickMethods = {

  xullWindow: null,

  setXULWindow: function DCM_setXULWindow(aWindow)
  {
    this.xulWindow = aWindow;
  },

  /**
   * The config object that is created by reading the contents of
   * <profile>/.mozCipher.json
   */
  config: BLANK_CONFIG_OBJECT,

  /**
   * Initialize the CryptoStickMethods object: set the callback and
   * configuration objects
   *
   * @param Object aConfigObject
   * @param String aSharedObjectPath
   *        The full path to the NSS shared object
   * @param String aSharedObjectName
   *        The name of the NSS shared object
   * @returns void
   */
  init: function DCM_init(aConfigObject, aSharedObjectPath, aSharedObjectName)
  {
    this.config = aConfigObject;
    worker.postMessage({ action: INITIALIZE_WORKER,
                         fullPath: aSharedObjectPath,
                         libName: aSharedObjectName });
  },

  /**
   * Remove all references to windows on window close or browser shutdown
   *
   * @returns void
   */
  shutdown: function DCM_shutdown()
  {
    worker.postMessage({ action: "shutdown" });

    this.sandbox = null;
    this.xulWindow = null;

    for (let prop in Callbacks) {
      Callbacks[prop].callback = null;
      Callbacks[prop].sandbox = null;
    }
    Callbacks = null;
  },

  callbacks: null,

  /////////////////////////////////////////////////////////////////////////
  // CryptoStick API methods exposed via the nsIDOMGlobalPropertyInitializer
  /////////////////////////////////////////////////////////////////////////

  /**
   * This is the internal SHA256 hash function, it does the actual hashing
   *
   * @param string aPlainText
   * @returns string
   */
  _SHA256: function DCM__SHA256(aPlainText)
  {
    // stolen from weave/util.js
    let converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"].
                      createInstance(Ci.nsIScriptableUnicodeConverter);
    converter.charset = "UTF-8";

    let hasher = Cc["@mozilla.org/security/hash;1"].
                   createInstance(Ci.nsICryptoHash);
    hasher.init(hasher.SHA256);

    let data = converter.convertToByteArray(aPlainText, {});
    hasher.update(data, data.length);
    let rawHash = hasher.finish(false);

    // return the two-digit hexadecimal code for a byte
    function toHexString(charCode) {
      return ("0" + charCode.toString(16)).slice(-2);
    }

    let hash = [toHexString(rawHash.charCodeAt(i)) for (i in rawHash)].join("");
    return hash;
  },

  /**
   * SHA256 API hash function
   * This is synchronous for the time being. TODO: wrap NSS SHA* functions
   * with js-ctypes so we can run in a worker
   *
   * @param string aPlainTextMessage
   * @returns void
   */
  SHA256: function DCM_SHA256(aPlainText, aCallback, aSandbox)
  {
    Callbacks.register(SHA256, aCallback, aSandbox);
    let hash = this._SHA256(aPlainText);
    let callback = Callbacks.makeSHA256Callback(hash);
    let sandbox = Callbacks.SHA256.sandbox;
    sandbox.importFunction(callback, "SHA256Callback");
    Cu.evalInSandbox("SHA256Callback();", sandbox, "1.8", "CryptoStick", 1);
  },

  getKeyByName: function CSM_getKeyByName(name, res)
  {
    var resultIdx = resultRegister(res);
    worker.postMessage({ action: "getKeyByName"/*GET_KEY_BY_NAME*/,
			 name: name,
			 result: resultIdx });
  },

  exportKey: function CSM_exportKey(format, key, res)
  {
    var resultIdx = resultRegister(res);
    worker.postMessage({ action: "exportKey",
			 format: format,
			 key: key,
			 result: resultIdx });
  },

  sign: function CSM_sign(algo, key, data, res)
  {
    var resultIdx = resultRegister(res);
    worker.postMessage({ action: "sign",
			 algo: algo,
			 key: key,
			 data: data,
			 result: resultIdx });
  },

  decrypt: function CSM_decrypt(algo, key, data, res)
  {
    var resultIdx = resultRegister(res);
    worker.postMessage({ action: "decrypt",
			 algo: algo,
			 key: key,
			 data: data,
			 result: resultIdx });
  },

  config: BLANK_CONFIG_OBJECT
};

/**
 * Creates a unique callback registry for each CryptoStickMethods object
 *
 * @returns Object
 */
function GenerateCallbackObject() {
  log("GenerateCallbackObject() constructor");
}

GenerateCallbackObject.prototype = {

  SHA256: { callback: null, sandbox: null },

  sandbox: null,

  /**
   * Register a callback for any API method
   *
   * @param string aLabel
   * @param function aCallback
   * @param Object aSandbox
   * @returns void
   */
  register: function GCO_register(aLabel, aCallback, aSandbox)
  {
    // we need a 'fall back' sandbox for prompts, etc. when we are unsure what
    // method is in play
    this.sandbox = aSandbox;

    this[aLabel].callback = aCallback;
    this[aLabel].sandbox = aSandbox;
  },

  /**
   * Wraps the content callback script which deals with SHA256 hashing
   *
   * @param string aHash
   * @returns void
   */
  makeSHA256Callback: function GCO_makeSHA256Callback(aHash)
  {
    let callback = function hash256_callback()
                   {
                     this.SHA256.callback(aHash);
                   };
    return callback.bind(this);
    // Note: we don't need a handleSHA256Callback function as there is
    // no round trip to the worker yet, we are using the callback in the
    // same manner in order to mock an async API for the time being
  }
};


var Callbacks = new GenerateCallbackObject();

/**
 * Initialize the CryptoStickMethods object by getting the configuration object
 * and creating the callbacks object
 * @returns void
 */
function initializeCryptoStick()
{
  // Full path to NSS via js-ctypes
  let path = Services.dirsvc.get("GreD", Ci.nsILocalFile);
  let libName = ctypes.libraryName("nss3"); // platform specific library name
  path.append(libName);
  let fullPath = path.path;
  CryptoStickMethods.init({}, fullPath, libName);
}

initializeCryptoStick();
