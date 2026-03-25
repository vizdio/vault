import type { StoredVault, StoredVaultMeta } from './vaultStorage'

export const PBKDF2_ITERATIONS = 250000

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

const base64ToBytes = (base64: string): Uint8Array => {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const clone = new Uint8Array(bytes.length)
  clone.set(bytes)
  return clone.buffer
}

const deriveKeyFromSaltBytes = async (
  masterPassword: string,
  saltBytes: Uint8Array,
  iterations: number,
): Promise<CryptoKey> => {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey'],
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(saltBytes),
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export const createVaultKey = async (
  masterPassword: string,
  iterations = PBKDF2_ITERATIONS,
): Promise<{ key: CryptoKey; meta: StoredVaultMeta }> => {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16))
  const key = await deriveKeyFromSaltBytes(masterPassword, saltBytes, iterations)

  return {
    key,
    meta: {
      salt: bytesToBase64(saltBytes),
      iterations,
    },
  }
}

export const deriveVaultKey = async (
  masterPassword: string,
  salt: string,
  iterations: number,
): Promise<CryptoKey> => {
  return deriveKeyFromSaltBytes(masterPassword, base64ToBytes(salt), iterations)
}

export const encryptVaultData = async <T>(
  data: T,
  key: CryptoKey,
): Promise<Pick<StoredVault, 'iv' | 'ciphertext'>> => {
  const ivBytes = crypto.getRandomValues(new Uint8Array(12))
  const plainBytes = textEncoder.encode(JSON.stringify(data))
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivBytes },
    key,
    plainBytes,
  )

  return {
    iv: bytesToBase64(ivBytes),
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
  }
}

export const decryptVaultData = async <T>(
  storedVault: StoredVault,
  key: CryptoKey,
): Promise<T> => {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(base64ToBytes(storedVault.iv)),
    },
    key,
    toArrayBuffer(base64ToBytes(storedVault.ciphertext)),
  )

  return JSON.parse(textDecoder.decode(decrypted)) as T
}

export const buildStoredVault = async <T>(
  data: T,
  key: CryptoKey,
  meta: StoredVaultMeta,
): Promise<StoredVault> => {
  const encrypted = await encryptVaultData(data, key)

  return {
    version: 1,
    salt: meta.salt,
    iterations: meta.iterations,
    ...encrypted,
  }
}