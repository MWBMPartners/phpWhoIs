// Service Worker — offline shell cache
// Bumped to v2 (Issue #214): the activate handler below purges any cache
// whose name doesn't match CACHE_NAME, so bumping this on future changes
// evicts stale entries instead of letting them accumulate forever.
var CACHE_NAME = 'mwwhois-v2';
var SHELL_ASSETS = [
    '/',
    'assets/css/style.css',
    'assets/images/favicon.svg',
    'assets/images/logo-notext.svg'
];

// Issue #214: URLs like lang/xx.json?v=<Date.now()> are unique on every
// single load, so caching them keyed by the full URL (including query
// string) grows the cache without bound. Strip the query string when
// forming the cache key so repeated cache-busted fetches of the same
// resource overwrite one entry instead of piling up new ones.
function cacheKeyFor(request) {
    var url = new URL(request.url);
    if (url.search) {
        url.search = '';
    }
    return url.toString();
}

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
    if (e.request.method !== 'GET' || e.request.url.indexOf('/lookup') !== -1) {
        return; // Let network handle POST and API requests
    }

    e.respondWith(
        fetch(e.request).then(function (response) {
            // Cache successful responses, keyed without the query string so
            // cache-busted URLs (?v=..., ?nocache=...) don't grow the cache
            // unbounded (Issue #214).
            if (response.ok) {
                var clone = response.clone();
                var cacheKey = cacheKeyFor(e.request);
                caches.open(CACHE_NAME).then(function (cache) {
                    cache.put(cacheKey, clone);
                });
            }
            return response;
        }).catch(function () {
            // Fall back to cache when offline; for page navigations fall
            // back further to the cached app shell ('/') so we never hand
            // back a possibly-undefined match (Issue #214).
            return caches.match(cacheKeyFor(e.request)).then(function (cached) {
                if (cached) {
                    return cached;
                }
                if (e.request.mode === 'navigate') {
                    return caches.match('/');
                }
                return undefined;
            });
        })
    );
});
