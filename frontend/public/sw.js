// Kill-switch: desativa este SW e todos os caches imediatamente
self.addEventListener('install', function() {
  self.skipWaiting();
});

self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys()
      .then(function(names) {
        return Promise.all(names.map(function(n) { return caches.delete(n); }));
      })
      .then(function() { return self.registration.unregister(); })
      .then(function() { return self.clients.matchAll({ type: 'window' }); })
      .then(function(clients) {
        clients.forEach(function(c) { c.navigate(c.url); });
      })
  );
});

// Enquanto ativo: deixa todas as requisições passarem sem interceptar
self.addEventListener('fetch', function(event) {
  event.respondWith(fetch(event.request).catch(function() {
    return new Response('', { status: 503 });
  }));
});
