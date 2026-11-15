/* sparky-manager service worker (Phase A item 5).

   Minimal and honest: it precaches the panel's own static assets
   (CSS, JS, icons, manifest) so the installed app shell loads
   offline, and serves /static/* cache-first. Pages are always
   network-first — a stale cached dashboard would be worse than no
   dashboard, and there is NO fake offline page: when the network
   is down, the browser shows its own offline message.

   Bump CACHE_NAME whenever a cached static file changes, or
   installed apps keep serving the old asset until the worker
   updates (the browser re-checks this file on every navigation).
*/
"use strict";

var CACHE_NAME = "sparky-manager-v2";

self.addEventListener("install", function (event) {
  // The scope is the panel root (the per-install web path) — the
  // precache list is built from it, never hardcoded.
  var scope = self.registration.scope;
  var assets = [
    "static/style.css",
    "static/app.js",
    "static/icons/icon.svg",
    "manifest.webmanifest",
  ];
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      // One failed asset must not fail the whole install.
      return Promise.allSettled(
        assets.map(function (path) { return cache.add(scope + path); })
      );
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (key) { return key !== CACHE_NAME; })
          .map(function (key) { return caches.delete(key); })
      );
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (event) {
  var request = event.request;
  if (request.method !== "GET") return;
  var url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  // The panel's static assets live under {scope}static/ (the
  // scope is the per-install web path).
  var staticPrefix = new URL(self.registration.scope).pathname + "static/";

  // Static assets: cache-first, refreshing the cache in the
  // background on a network hit.
  if (url.pathname.indexOf(staticPrefix) === 0) {
    event.respondWith(
      caches.match(request).then(function (cached) {
        var network = fetch(request).then(function (response) {
          if (response && response.ok) {
            var copy = response.clone();
            caches.open(CACHE_NAME).then(function (cache) {
              cache.put(request, copy);
            });
          }
          return response;
        }).catch(function () { return cached; });
        return cached || network;
      })
    );
    return;
  }

  // Everything else (pages, feeds): network-first, no fallback.
  // A failed page load is the browser's honest offline message,
  // never a stale or fake page.
  event.respondWith(fetch(request));
});
