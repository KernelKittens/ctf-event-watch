"use strict";
const CACHE = "flagwatch-shell-fallbacks-v2";
const SHELL = ["/", "/app.js", "/app.css", "/config.js"];
self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) =>
    key.startsWith("flagwatch-shell-") && key !== CACHE).map((key) => caches.delete(key))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== self.location.origin) return;
  const key = url.pathname === "/index.html" ? "/" : url.pathname;
  if (!SHELL.includes(key)) return;
  event.respondWith((async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(event.request, {signal: controller.signal});
      if (!response.ok) throw new Error("Shell fetch failed");
      return response;
    } catch (_) {
      const saved = await (await caches.open(CACHE)).match(key);
      if (saved) return saved;
      return new Response("Calendar unavailable offline. Reconnect and reload.", {status: 503});
    } finally {
      clearTimeout(timer);
    }
  })());
});
