import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'

type VaultEntry = {
  id: string
  siteName: string
  userName: string
  password: string
  notes: string
  createdAt: string
}

type StoredVault = {
  version: 1
  salt: string
  iterations: number
  iv: string
  ciphertext: string
}

type AccessMode = 'setup' | 'login' | 'unlocked'

const STORAGE_KEY = 'password-vault:v1'
const PBKDF2_ITERATIONS = 250000

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

const deriveKey = async (
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

const encryptEntries = async (
  entries: VaultEntry[],
  key: CryptoKey,
): Promise<Pick<StoredVault, 'iv' | 'ciphertext'>> => {
  const ivBytes = crypto.getRandomValues(new Uint8Array(12))
  const plainBytes = textEncoder.encode(JSON.stringify(entries))
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

const decryptEntries = async (
  storedVault: StoredVault,
  key: CryptoKey,
): Promise<VaultEntry[]> => {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(base64ToBytes(storedVault.iv)),
    },
    key,
    toArrayBuffer(base64ToBytes(storedVault.ciphertext)),
  )

  const parsed = JSON.parse(textDecoder.decode(decrypted)) as VaultEntry[]
  return parsed
}

const loadStoredVault = (): StoredVault | null => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    return null
  }

  try {
    const parsed = JSON.parse(raw) as StoredVault
    if (
      parsed.version !== 1 ||
      !parsed.salt ||
      !parsed.iv ||
      !parsed.ciphertext ||
      typeof parsed.iterations !== 'number'
    ) {
      return null
    }
    return parsed
  } catch {
    return null
  }
}

function App() {
  const [accessMode, setAccessMode] = useState<AccessMode>('login')
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [unlockError, setUnlockError] = useState('')

  const [entries, setEntries] = useState<VaultEntry[]>([])
  const [entrySiteName, setEntrySiteName] = useState('')
  const [entryUserName, setEntryUserName] = useState('')
  const [entryPassword, setEntryPassword] = useState('')
  const [entryNotes, setEntryNotes] = useState('')

  const [cryptoKey, setCryptoKey] = useState<CryptoKey | null>(null)
  const [vaultMeta, setVaultMeta] = useState<
    Pick<StoredVault, 'salt' | 'iterations'> | null
  >(null)

  useEffect(() => {
    const existing = loadStoredVault()
    if (existing) {
      setAccessMode('login')
    } else {
      setAccessMode('setup')
    }
  }, [])

  const saveEntries = async (
    nextEntries: VaultEntry[],
    key: CryptoKey,
    meta: Pick<StoredVault, 'salt' | 'iterations'>,
  ) => {
    const encrypted = await encryptEntries(nextEntries, key)
    const payload: StoredVault = {
      version: 1,
      salt: meta.salt,
      iterations: meta.iterations,
      ...encrypted,
    }

    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload))
    setEntries(nextEntries)
  }

  const handleSetup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setUnlockError('')

    if (masterPassword.length < 10) {
      setUnlockError('Use at least 10 characters for your master password.')
      return
    }

    if (masterPassword !== confirmPassword) {
      setUnlockError('Master password and confirmation do not match.')
      return
    }

    const saltBytes = crypto.getRandomValues(new Uint8Array(16))
    const salt = bytesToBase64(saltBytes)
    const key = await deriveKey(masterPassword, saltBytes, PBKDF2_ITERATIONS)
    const meta = { salt, iterations: PBKDF2_ITERATIONS }

    await saveEntries([], key, meta)
    setCryptoKey(key)
    setVaultMeta(meta)
    setEntries([])
    setAccessMode('unlocked')
    setMasterPassword('')
    setConfirmPassword('')
  }

  const handleUnlock = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setUnlockError('')

    const storedVault = loadStoredVault()
    if (!storedVault) {
      setUnlockError('Vault was not found. Create a new one.')
      setAccessMode('setup')
      return
    }

    try {
      const saltBytes = base64ToBytes(storedVault.salt)
      const key = await deriveKey(
        masterPassword,
        saltBytes,
        storedVault.iterations,
      )
      const decryptedEntries = await decryptEntries(storedVault, key)

      setCryptoKey(key)
      setVaultMeta({
        salt: storedVault.salt,
        iterations: storedVault.iterations,
      })
      setEntries(decryptedEntries)
      setAccessMode('unlocked')
      setMasterPassword('')
    } catch {
      setUnlockError('Incorrect master password or corrupted vault data.')
    }
  }

  const handleLock = () => {
    setCryptoKey(null)
    setVaultMeta(null)
    setEntries([])
    setAccessMode('login')
    setMasterPassword('')
    setConfirmPassword('')
    setUnlockError('')
  }

  const handleAddEntry = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    if (!cryptoKey || !vaultMeta) {
      return
    }

    const nextEntry: VaultEntry = {
      id: crypto.randomUUID(),
      siteName: entrySiteName.trim(),
      userName: entryUserName.trim(),
      password: entryPassword,
      notes: entryNotes.trim(),
      createdAt: new Date().toISOString(),
    }

    const nextEntries = [nextEntry, ...entries]
    await saveEntries(nextEntries, cryptoKey, vaultMeta)

    setEntrySiteName('')
    setEntryUserName('')
    setEntryPassword('')
    setEntryNotes('')
  }

  const handleDeleteEntry = async (id: string) => {
    if (!cryptoKey || !vaultMeta) {
      return
    }

    const nextEntries = entries.filter((entry) => entry.id !== id)
    await saveEntries(nextEntries, cryptoKey, vaultMeta)
  }

  const sortedEntries = useMemo(() => {
    return [...entries].sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  }, [entries])

  return (
    <main className="app-shell">
      <header className="hero-card">
        <p className="eyebrow">Offline Password Vault</p>
        <h1>Private passwords on your device.</h1>
        <p className="subtitle">
          Data is encrypted in your browser before it is saved to local storage.
        </p>
      </header>

      {(accessMode === 'setup' || accessMode === 'login') && (
        <section className="panel auth-panel">
          <h2>{accessMode === 'setup' ? 'Create master password' : 'Unlock vault'}</h2>
          <p>
            {accessMode === 'setup'
              ? 'This password unlocks and encrypts your vault. It is never stored as plain text.'
              : 'Enter your master password to decrypt saved entries.'}
          </p>

          <form
            onSubmit={accessMode === 'setup' ? handleSetup : handleUnlock}
            className="stack"
          >
            <label>
              Master Password
              <input
                type="password"
                autoComplete="current-password"
                value={masterPassword}
                onChange={(event) => setMasterPassword(event.target.value)}
                required
                minLength={10}
              />
            </label>

            {accessMode === 'setup' && (
              <label>
                Confirm Master Password
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                  minLength={10}
                />
              </label>
            )}

            {unlockError && <p className="error">{unlockError}</p>}

            <button type="submit" className="primary-btn">
              {accessMode === 'setup' ? 'Create Vault' : 'Unlock'}
            </button>
          </form>
        </section>
      )}

      {accessMode === 'unlocked' && (
        <>
          <section className="panel">
            <div className="panel-title-row">
              <h2>Add Entry</h2>
              <button type="button" className="ghost-btn" onClick={handleLock}>
                Lock
              </button>
            </div>

            <form onSubmit={handleAddEntry} className="entry-form">
              <label>
                Site Name
                <input
                  type="text"
                  value={entrySiteName}
                  onChange={(event) => setEntrySiteName(event.target.value)}
                  required
                />
              </label>

              <label>
                User Name
                <input
                  type="text"
                  value={entryUserName}
                  onChange={(event) => setEntryUserName(event.target.value)}
                />
              </label>

              <label>
                Password
                <input
                  type="text"
                  value={entryPassword}
                  onChange={(event) => setEntryPassword(event.target.value)}
                  required
                />
              </label>

              <label className="notes-label">
                Notes
                <textarea
                  value={entryNotes}
                  onChange={(event) => setEntryNotes(event.target.value)}
                  rows={3}
                />
              </label>

              <button type="submit" className="primary-btn">
                Save Entry
              </button>
            </form>
          </section>

          <section className="panel">
            <h2>Saved Entries ({entries.length})</h2>

            {sortedEntries.length === 0 ? (
              <p>No entries yet. Add your first site credential above.</p>
            ) : (
              <ul className="entry-list">
                {sortedEntries.map((entry) => (
                  <li key={entry.id} className="entry-item">
                    <div className="entry-row">
                      <span className="label">Site</span>
                      <span className="value">{entry.siteName}</span>
                    </div>
                    <div className="entry-row">
                      <span className="label">User</span>
                      <span className="value">{entry.userName || '-'}</span>
                    </div>
                    <div className="entry-row">
                      <span className="label">Password</span>
                      <span className="value secret">{entry.password}</span>
                    </div>
                    <div className="entry-row notes">
                      <span className="label">Notes</span>
                      <span className="value">{entry.notes || '-'}</span>
                    </div>
                    <button
                      type="button"
                      className="danger-btn"
                      onClick={() => void handleDeleteEntry(entry.id)}
                    >
                      Delete
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </main>
  )
}

export default App
