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
let Cr = Components.results;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Services.jsm");

function log(aMessage) {
  var _msg = "CryptoStickAPI: " + aMessage + "\n";
  dump(_msg);
}

XPCOMUtils.defineLazyGetter(this, "crypto", function (){
  Cu.import("resource://cryptostick.webcrypto/CryptoStickMethods.jsm");
  return CryptoStickMethods;
});

/**
 * CryptoStick/cryptostick API
 *
 * This is a shim (nsIDOMGlobalPropertyInitializer) object that wraps the
 * CryptoStickMethods.jsm 'crypto' object
 *
 * CryptoStick's init method returns the API that is content JS accessible.
 *
 * CryptoStickAPI imports CryptoStickMethods, CryptoStickMethods generates the ChromeWorker
 * that runs all WeaveCrypto (NSS) functions off main thread via ctypes
 */

Cu.import("resource://cryptostick.webcrypto/CryptoStickPromise.jsm");

function CryptoStickAPI() {}

CryptoStickAPI.prototype = {

  classID: Components.ID("{64bdef9e-1f0f-11e3-b537-d703fecd4198}"),

  QueryInterface: XPCOMUtils.generateQI([Ci.nsIDOMGlobalPropertyInitializer,
                                         Ci.nsIObserver,]),

  sandbox: null,

  /**
   * We must free the sandbox and window references every time an
   * innerwindow is destroyed
   * TODO: must listen for back/forward events to reinstate the window object
   *
   * @param object aSubject
   * @param string aTopic
   * @param string aData
   *
   * @returns void
   */
  observe: function DA_observe(aSubject, aTopic, aData)
  {
    if (aTopic == "inner-window-destroyed") {
      let windowID = aSubject.QueryInterface(Ci.nsISupportsPRUint64).data;
      let innerWindowID = this.window.QueryInterface(Ci.nsIInterfaceRequestor).
                            getInterface(Ci.nsIDOMWindowUtils).currentInnerWindowID;
      if (windowID == innerWindowID) {
        crypto.shutdown();
        delete this.sandbox;
        delete this.window;
        Services.obs.removeObserver(this, "inner-window-destroyed");
      }
    }
  },

  /**
   * This method sets up the crypto API and returns the object that is
   * accessible from the DOM
   *
   * @param nsIDOMWindow aWindow
   * @returns object
   *          The object returned is the API object called 'window.mozCipher'
   */
  init: function DA_init(aWindow) {

    let self = this;

    this.window = XPCNativeWrapper.unwrap(aWindow);

    this.sandbox = Cu.Sandbox(this.window,
                              { sandboxPrototype: this.window, wantXrays: false });

    // we need a xul window reference for the CryptoStickMethods
    this.xulWindow = aWindow.QueryInterface(Ci.nsIDOMWindow)
      .QueryInterface(Ci.nsIInterfaceRequestor)
      .getInterface(Ci.nsIWebNavigation)
      .QueryInterface(Ci.nsIDocShellTreeItem)
      .rootTreeItem
      .QueryInterface(Ci.nsIInterfaceRequestor)
      .getInterface(Ci.nsIDOMWindow)
      .QueryInterface(Ci.nsIDOMChromeWindow);

    crypto.setXULWindow(this.xulWindow);

    Services.obs.addObserver(this, "inner-window-destroyed", false);

    let api = {

      crypto: {
	subtle: {
	  decrypt: self.decrypt.bind(self),
	  exportKey: self.exportKey.bind(self),
	  sign: self.sign.bind(self),
	  __exposedProps__: {
	    decrypt: "r",
	    exportKey: "r",
	    sign: "r"
	  }
	},
	__exposedProps__: {
	  subtle: "r"
	}
      },

      cryptokeys: {
	getKeyByName: self.getKeyByName.bind(self),
	__exposedProps__: {
	  getKeyByName: "r"
	}
      },

      __exposedProps__: {
        crypto: "r",
        cryptokeys: "r",
      },
    };

    return api;
  },

  /**
   * A wrapper that calls CryptoStickMethods.SHA256()
   *
   * @param string aPlainText
   *        The plaintext string to be hashed
   * @param function aCallback
   *        This callback will run in the content sandbox when the operation
   *        is complete
   * @returns void
   */
  SHA256: function DA_SHA256(aPlainText, aCallback)
  {
    if (!(typeof aPlainText == "string")) {
      let exception =
        new Components.Exception("First argument (aPlainText) should be a String",
                                 Cr.NS_ERROR_INVALID_ARG,
                                 Components.stack.caller);
      throw exception;
    }

    if (!(typeof aCallback == "function")) {
      let exception =
        new Components.Exception("Second argument should be a Function",
                                 Cr.NS_ERROR_INVALID_ARG,
                                 Components.stack.caller);
      throw exception;
    }
    crypto.SHA256(aPlainText, aCallback, this.sandbox);
  },

  getKeyByName: function CS_GetKeyByName(name)
  {
    var res = new CryptoStickPromise();

    if (name != null && !(typeof name == "string")) {
      res._onerror("The getKeyByName() argument should be a string");
      return res;
    }

    try {
      crypto.getKeyByName(name, res, this.sandbox);
    } catch (err) {
      res._onerror("CryptoStick.cryptokeys.getKeyByName() exception: " + err);
    }
    return res;
  },

  exportKey: function CS_ExportKey(format, key)
  {
    var res = new CryptoStickPromise();

    if (format == null || typeof(format) != "string") {
      res._onerror("The exportKey() 'format' argument should be a string");
      return res;
    }
    if (key == null || typeof(key) != "object" || key.cs_pkcs11id == null) {
      res._onerror("The exportKey() 'key' argument should be a cryptostick.webcrypto key");
      return res;
    }

    try {
      crypto.exportKey(format, JSON.stringify(key), res, this.sandbox);
    } catch (err) {
      res._onerror("CryptoStick.crypto.subtle.exportKey() exception: " + err);
    }
    return res;
  },

  _buildTarget: function CS_BuildTarget(data)
  {
    return {
      target: {
	result: data,
	__exposedProps__: {
	  result: "r"
	}
      },
      __exposedProps__: {
	target: "r"
      }
    };
  },

  decrypt: function CS_Decrypt(algo, key, data)
  {
    var res = new CryptoStickPromise();

    dump("RDBG CS_Decrypt, algo " + algo + " key " + key + " data " + data + "\n");
    if (algo == null || typeof(algo) != "object" || algo.name == null ||
	typeof(algo.name) != "string") {
      res._onerror(this._buildTarget("The sign() 'algorithm' argument should have a 'name' string property"));
    } else if (key == null || typeof(key) != "object" || key.cs_pkcs11id == null) {
      res._onerror(this._buildTarget("The sign() 'key' argument should be a cryptostick.webcrypto key"));
    } else if (data == null) {
      res._onerror(this._buildTarget("The sign() 'data' argument should be an array of integers"));
    } else {
      try {
	/* Pff.  Convert a Uint8Array to a string. */
	crypto.decrypt(algo, JSON.stringify(key), JSON.stringify(data), res, this.sandbox);
      } catch (err) {
	res._onerror(this._buildTarget("CryptoStick.crypto.subtle.decrypt() exception: " + err));
      }
    }
    return res;
  },

  sign: function CS_Sign(algo, key, data)
  {
    var res = new CryptoStickPromise();

    dump("RDBG CS_Sign, algo " + algo + " key " + key + " data " + data + "\n");
    if (algo == null || typeof(algo) != "object" || algo.name == null ||
	typeof(algo.name) != "string") {
      res._onerror(this._buildTarget("The sign() 'algorithm' argument should have a 'name' string property"));
    } else if (key == null || typeof(key) != "object" || key.cs_pkcs11id == null) {
      res._onerror(this._buildTarget("The sign() 'key' argument should be a cryptostick.webcrypto key"));
    } else if (data == null) {
      res._onerror(this._buildTarget("The sign() 'data' argument should be an array of integers"));
    } else {
      try {
	/* Pff.  Convert a Uint8Array to a string. */
	crypto.sign(algo, JSON.stringify(key), JSON.stringify(data), res, this.sandbox);
      } catch (err) {
	res._onerror(this._buildTarget("CryptoStick.crypto.subtle.sign() exception: " + err));
      }
    }
    return res;
  }
};


var NSGetFactory = XPCOMUtils.generateNSGetFactory([CryptoStickAPI]);
