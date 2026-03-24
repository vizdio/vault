const CACHE_NAME = 'password-vault-v1'
const toAbsoluteUrl = (path) => new URL(path, self.registration.scope).toString()

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      cache.addAll([
        toAbsoluteUrl('./'),
        toAbsoluteUrl('./index.html'),
        toAbsoluteUrl('./manifest.webmanifest'),
      ]),
    ),
  )
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))),
      )
      .then(() => self.clients.claim()),
  )
})

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') {
    return
  }

  const isHttp = event.request.url.startsWith('http')
  if (!isHttp) {
    return
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse
      }

      return fetch(event.request)
        .then((networkResponse) => {
          const clonedResponse = networkResponse.clone()
          void caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, clonedResponse)
          })
          return networkResponse
        })
        .catch(async () => {
          const fallback = await caches.match(toAbsoluteUrl('./index.html'))
          return fallback || new Response('Offline', { status: 503, statusText: 'Offline' })
        })
    }),
  )
})
