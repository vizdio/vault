export type StoredVault = {
  version: 1
  salt: string
  iterations: number
  iv: string
  ciphertext: string
}

export type StoredVaultMeta = Pick<StoredVault, 'salt' | 'iterations'>

export type EncryptedVaultBackup = {
  backupVersion: 1
  exportedAt: string
  vault: StoredVault
}

export const STORAGE_KEY = 'password-vault:v1'

export const loadStoredVault = (storageKey = STORAGE_KEY): StoredVault | null => {
  const raw = localStorage.getItem(storageKey)
  if (!raw) {
    return null
  }

  try {
    const parsed = JSON.parse(raw) as StoredVault
    if (!isStoredVaultShape(parsed)) {
      return null
    }
    return parsed
  } catch {
    return null
  }
}

export const saveStoredVault = (
  storedVault: StoredVault,
  storageKey = STORAGE_KEY,
): void => {
  localStorage.setItem(storageKey, JSON.stringify(storedVault))
}

export const isStoredVaultShape = (value: unknown): value is StoredVault => {
  if (!value || typeof value !== 'object') {
    return false
  }

  const candidate = value as Record<string, unknown>
  return (
    candidate.version === 1 &&
    typeof candidate.salt === 'string' &&
    typeof candidate.iv === 'string' &&
    typeof candidate.ciphertext === 'string' &&
    typeof candidate.iterations === 'number'
  )
}