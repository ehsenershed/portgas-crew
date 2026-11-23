// portgas crew — the service worker. It makes the page installable and is
// how phones show its notifications. Everything is fetched fresh: prices and
// the desk are live, so there is nothing worth serving from a cache.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window" }).then((list) =>
    list.length ? list[0].focus() : self.clients.openWindow("./")));
});
