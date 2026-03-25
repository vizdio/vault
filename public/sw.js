const CACHE_NAME = 'password-vault-v2'
const toAbsoluteUrl = (path) => new URL(path, self.registration.scope).toString()
const APP_SHELL_URLS = [
  toAbsoluteUrl('./'),
  toAbsoluteUrl('./index.html'),
  toAbsoluteUrl('./manifest.webmanifest'),
  toAbsoluteUrl('./icons/icon-192.svg'),
  toAbsoluteUrl('./icons/icon-512.svg'),
]
const CACHEABLE_DESTINATIONS = new Set(['style', 'script', 'worker', 'image', 'font'])

const cacheResponse = async (request, response) => {
  if (!response.ok || response.type !== 'basic') {
    return response
  }

  const cache = await caches.open(CACHE_NAME)
  await cache.put(request, response.clone())
  return response
}

const networkFirst = async (request) => {
  try {
    const response = await fetch(request)
    await cacheResponse(request, response)

    if (request.mode === 'navigate') {
      const cache = await caches.open(CACHE_NAME)
      await cache.put(toAbsoluteUrl('./index.html'), response.clone())
    }

    return response
  } catch {
    const cachedResponse = await caches.match(request)
    if (cachedResponse) {
      return cachedResponse
    }

    const appShell = await caches.match(toAbsoluteUrl('./index.html'))
    return appShell || new Response('Offline', { status: 503, statusText: 'Offline' })
  }
}

const cacheFirst = async (request) => {
  const cachedResponse = await caches.match(request)
  if (cachedResponse) {
    return cachedResponse
  }

  const response = await fetch(request)
  return cacheResponse(request, response)
}

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL_URLS)))
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

  const requestUrl = new URL(event.request.url)
  if (requestUrl.protocol !== 'http:' && requestUrl.protocol !== 'https:') {
    return
  }

  if (event.request.mode === 'navigate') {
    event.respondWith(networkFirst(event.request))
    return
  }

  const isSameOrigin = requestUrl.origin === self.location.origin
  const shouldCacheAsset =
    isSameOrigin &&
    (CACHEABLE_DESTINATIONS.has(event.request.destination) ||
      requestUrl.pathname.endsWith('/manifest.webmanifest'))

  if (shouldCacheAsset) {
    event.respondWith(cacheFirst(event.request))
  }
})
