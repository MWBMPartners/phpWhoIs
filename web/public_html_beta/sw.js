// Service Worker — offline shell cache
var CACHE_NAME = 'mwwhois-v1';
var SHELL_ASSETS = [
    '/',
    'assets/css/style.css',
    'assets/images/favicon.svg',
    'assets/images/logo-notext.svg'
];

self.addEventListener('install', function (e) {
    e.waitUntil(
        caches.open(CACHE_NAME).then(function (cache) {
            return cache.addAll(SHELL_ASSETS);
        })
    );
    self.skipWaiting();
});

self.addEventListener('activate', function (e) {
    e.waitUntil(
        caches.keys().then(function (names) {
            return Promise.all(
                names.filter(function (n) { return n !== CACHE_NAME; })
                    .map(function (n) { return caches.delete(n); })
            );
        })
    );
    self.clients.claim();
});

self.addEventListener('fetch', function (e) {
    // Network-first for API calls, cache-first for static assets
    if (e.request.method !== 'GET' || e.request.url.indexOf('lookup.php') !== -1) {
        return; // Let network handle POST and API requests
    }

    e.respondWith(
        fetch(e.request).then(function (response) {
            // Cache successful responses
            if (response.ok) {
                var clone = response.clone();
                caches.open(CACHE_NAME).then(function (cache) {
                    cache.put(e.request, clone);
                });
            }
            return response;
        }).catch(function () {
            // Fall back to cache when offline
            return caches.match(e.request);
        })
    );
});
