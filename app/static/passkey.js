/* Passkey (WebAuthn) flows — Phase C item 22.
 *
 * Loaded only on the login page (sign-in button) and the settings
 * page (registration form). No dependencies: the base64url helpers
 * and the options/response conversions are ~60 lines, and the
 * panel is offline-first (no CDN).
 *
 * The server sends options as JSON with base64url strings
 * (challenge, user.id, credential ids); the WebAuthn API wants
 * ArrayBuffers, so this file converts both ways. The server's
 * challenge token travels in the finish POST body (it is an
 * HMAC-signed secret, not a cookie). Registration posts the CSRF
 * token in the X-CSRF-Token header (read from the form's hidden
 * field); the login flow has no session yet, so no CSRF token.
 */
(function () {
  "use strict";

  function b64urlToBuffer(value) {
    var s = value.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function setStatus(text) {
    var el = document.getElementById("passkey-status");
    if (el) el.textContent = text || "";
  }

  function postJson(url, body, csrfToken) {
    var headers = { "Content-Type": "application/json" };
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
    return fetch(url, {
      method: "POST",
      headers: headers,
      credentials: "same-origin",
      body: JSON.stringify(body || {}),
    }).then(function (resp) {
      var contentType = resp.headers.get("content-type") || "";
      if (contentType.indexOf("application/json") === -1) {
        // A non-JSON answer (e.g. the HTML CSRF error page) is a
        // failure with no usable detail — the caller shows the
        // generic message.
        throw new Error("bad response: HTTP " + resp.status);
      }
      return resp.json().then(function (data) {
        if (!resp.ok) throw new Error((data && data.detail) || ("HTTP " + resp.status));
        return data;
      });
    });
  }

  function supported() {
    return !!(
      window.PublicKeyCredential &&
      window.navigator &&
      window.navigator.credentials &&
      window.navigator.credentials.create &&
      window.navigator.credentials.get
    );
  }

  function disableUnsupported(button) {
    if (supported()) return false;
    if (button) {
      button.disabled = true;
      setStatus(button.getAttribute("data-unsupported") || "");
    }
    return true;
  }

  /* --- Registration (settings page) --- */

  var registerBtn = document.getElementById("passkey-register-btn");
  if (registerBtn) {
    registerBtn.addEventListener("click", function () {
      if (disableUnsupported(registerBtn)) return;
      var form = document.getElementById("passkey-register-form");
      var csrfToken = registerBtn.getAttribute("data-csrf-token") || "";
      var nameInput = document.getElementById("passkey-name");
      var name = nameInput ? nameInput.value.trim() : "";
      setStatus("");
      registerBtn.disabled = true;
      postJson(registerBtn.getAttribute("data-begin-url"), {}, csrfToken)
        .then(function (data) {
          // The server's options are the bare PublicKeyCredential-
          // CreationOptions (no "publicKey" wrapper — that is the
          // browser API's argument shape, applied below).
          var options = data.options;
          options.challenge = b64urlToBuffer(options.challenge);
          if (options.user && options.user.id) {
            options.user.id = b64urlToBuffer(options.user.id);
          }
          (options.excludeCredentials || []).forEach(function (cred) {
            cred.id = b64urlToBuffer(cred.id);
          });
          return navigator.credentials
            .create({ publicKey: options })
            .then(function (credential) {
              return { credential: credential, token: data.challenge_token };
            });
        })
        .then(function (pair) {
          var credential = pair.credential;
          var response = {
            id: credential.id,
            rawId: bufferToB64url(credential.rawId),
            type: credential.type,
            response: {
              attestationObject: bufferToB64url(credential.response.attestationObject),
              clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
            },
          };
          if (credential.response.getTransports) {
            try {
              response.response.transports = credential.response.getTransports();
            } catch (e) {
              /* transports are advisory — ignore */
            }
          }
          return postJson(
            registerBtn.getAttribute("data-finish-url"),
            { credential: response, challenge_token: pair.token, name: name },
            csrfToken
          );
        })
        .then(function () {
          setStatus(registerBtn.getAttribute("data-done") || "");
          window.location.reload();
        })
        .catch(function () {
          setStatus(registerBtn.getAttribute("data-error") || "");
          registerBtn.disabled = false;
        });
    });
  }

  /* --- Login (login page) --- */

  var loginBtn = document.getElementById("passkey-login-btn");
  if (loginBtn) {
    loginBtn.addEventListener("click", function () {
      if (disableUnsupported(loginBtn)) return;
      setStatus("");
      loginBtn.disabled = true;
      postJson(loginBtn.getAttribute("data-begin-url"), {})
        .then(function (data) {
          // Bare PublicKeyCredentialRequestOptions (see the
          // registration flow above for why there is no wrapper).
          var options = data.options;
          options.challenge = b64urlToBuffer(options.challenge);
          (options.allowCredentials || []).forEach(function (cred) {
            cred.id = b64urlToBuffer(cred.id);
          });
          return navigator.credentials
            .get({ publicKey: options })
            .then(function (credential) {
              return { credential: credential, token: data.challenge_token };
            });
        })
        .then(function (pair) {
          var credential = pair.credential;
          var response = {
            id: credential.id,
            rawId: bufferToB64url(credential.rawId),
            type: credential.type,
            response: {
              authenticatorData: bufferToB64url(credential.response.authenticatorData),
              clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
              signature: bufferToB64url(credential.response.signature),
            },
          };
          if (credential.response.userHandle) {
            response.response.userHandle = bufferToB64url(credential.response.userHandle);
          }
          return postJson(loginBtn.getAttribute("data-finish-url"), {
            credential: response,
            challenge_token: pair.token,
          });
        })
        .then(function (data) {
          window.location = data.redirect || "/";
        })
        .catch(function () {
          setStatus(loginBtn.getAttribute("data-error") || "");
          loginBtn.disabled = false;
        });
    });
  }
})();
