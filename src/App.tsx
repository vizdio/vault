import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import {
    faBan,
    faBriefcase,
    faCartShopping,
    faCheck,
    faCircle,
    faCopy,
    faEye,
    faFileArrowDown,
    faFileLines,
    faPhotoFilm,
    faHouse,
    faLink,
    faMinus,
    faPenToSquare,
    faPlus,
    faScrewdriverWrench,
    faUnlock,
    faUser,
    faUsers,
    faMoneyBillWave,
    faXmark,
    faTrash,
    faTriangleExclamation,
    faChevronDown,
    faChevronUp,
    faStarOfLife,
} from '@fortawesome/free-solid-svg-icons'
import {
    buildStoredVault,
    createVaultKey,
    decryptVaultData,
    deriveVaultKey,
    PBKDF2_ITERATIONS,
} from './lib/vaultCrypto'
import { isStoredVaultShape, loadStoredVault, saveStoredVault } from './lib/vaultStorage'
import type { EncryptedVaultBackup, StoredVaultMeta } from './lib/vaultStorage'
import './App.less'

const GROUP_OPTIONS = [
    { value: 'Private', icon: faUser },
    { value: 'Work', icon: faBriefcase },
    { value: 'Home', icon: faHouse },
    { value: 'Money', icon: faMoneyBillWave },
    { value: 'Social', icon: faUsers },
    { value: 'Media', icon: faPhotoFilm },
    { value: 'Shop', icon: faCartShopping },
    { value: 'Tools', icon: faScrewdriverWrench },
    { value: 'Other', icon: faStarOfLife },
] as const

type GroupName = (typeof GROUP_OPTIONS)[number]['value']

const GROUP_ICON_BY_NAME: Record<GroupName, (typeof GROUP_OPTIONS)[number]['icon']> =
    Object.fromEntries(GROUP_OPTIONS.map((group) => [group.value, group.icon])) as Record<
        GroupName,
        (typeof GROUP_OPTIONS)[number]['icon']
    >

const isGroupName = (value: unknown): value is GroupName => {
    return typeof value === 'string' && GROUP_OPTIONS.some((group) => group.value === value)
}

const normalizeGroupName = (value: unknown): GroupName => {
    return isGroupName(value) ? value : 'Other'
}

type VaultEntry = {
    id: string
    siteName: string
    siteUrl: string
    userName: string
    password: string
    notes: string
    group?: GroupName
    createdAt: string
}

type AccessMode = 'setup' | 'login' | 'unlocked'
const INACTIVITY_LOCK_MS = 5 * 60 * 1000
const GENERATED_PASSWORD_LENGTH = 20
const LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz'
const UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const DIGIT_CHARS = '0123456789'
const SYMBOL_CHARS = '!@#$%^&*()-_=+[]{};:,.?'
const ALL_PASSWORD_CHARS = `${LOWERCASE_CHARS}${UPPERCASE_CHARS}${DIGIT_CHARS}${SYMBOL_CHARS}`

type PasswordStrengthLevel = 'very-weak' | 'weak' | 'fair' | 'good' | 'strong'

type PasswordStrength = {
    score: 0 | 1 | 2 | 3 | 4
    label: string
    level: PasswordStrengthLevel
}

const getPasswordStrength = (password: string): PasswordStrength => {
    if (!password) {
        return { score: 0, label: '', level: 'very-weak' }
    }

    let rawScore = 0
    if (password.length >= 8) rawScore += 1
    if (password.length >= 12) rawScore += 1
    if (/[a-z]/.test(password)) rawScore += 1
    if (/[A-Z]/.test(password)) rawScore += 1
    if (/\d/.test(password)) rawScore += 1
    if (/[^A-Za-z0-9]/.test(password)) rawScore += 1

    if (rawScore <= 1) {
        return { score: 1, label: 'Very weak', level: 'very-weak' }
    }
    if (rawScore <= 2) {
        return { score: 1, label: 'Weak', level: 'weak' }
    }
    if (rawScore === 3) {
        return { score: 2, label: 'Fair', level: 'fair' }
    }
    if (rawScore === 4) {
        return { score: 3, label: 'Good', level: 'good' }
    }
    return { score: 4, label: 'Strong', level: 'strong' }
}

const normalizeSiteUrl = (url: string): string => {
    const trimmed = url.trim()
    if (!trimmed) {
        return ''
    }

    if (/^https?:\/\//i.test(trimmed)) {
        return trimmed
    }

    return `https://${trimmed}`
}

const getDisplaySiteUrl = (url: string): string => {
    return url.replace(/^https?:\/\//i, '')
}

const clearClipboardBestEffort = async (): Promise<void> => {
    if (!navigator.clipboard) {
        return
    }

    try {
        await navigator.clipboard.writeText('')
    } catch {
        // Clipboard write may fail if browser permissions are restricted.
    }
}

const getSecureRandomIndex = (maxExclusive: number): number => {
    const randomBuffer = new Uint32Array(1)
    const maxUint32 = 0xffffffff
    const threshold = maxUint32 - (maxUint32 % maxExclusive)

    while (true) {
        crypto.getRandomValues(randomBuffer)
        const randomValue = randomBuffer[0]
        if (randomValue < threshold) {
            return randomValue % maxExclusive
        }
    }
}

const pickRandomChar = (charset: string): string => {
    return charset[getSecureRandomIndex(charset.length)]
}

const shuffleString = (value: string): string => {
    const chars = value.split('')
    for (let i = chars.length - 1; i > 0; i -= 1) {
        const j = getSecureRandomIndex(i + 1)
        ;[chars[i], chars[j]] = [chars[j], chars[i]]
    }
    return chars.join('')
}

const generateStrongPassword = (length = GENERATED_PASSWORD_LENGTH): string => {
    const safeLength = Math.max(length, 12)
    const requiredChars = [
        pickRandomChar(LOWERCASE_CHARS),
        pickRandomChar(UPPERCASE_CHARS),
        pickRandomChar(DIGIT_CHARS),
        pickRandomChar(SYMBOL_CHARS),
    ]

    while (requiredChars.length < safeLength) {
        requiredChars.push(pickRandomChar(ALL_PASSWORD_CHARS))
    }

    return shuffleString(requiredChars.join(''))
}

function App() {
    const [accessMode, setAccessMode] = useState<AccessMode>('login')
    const [masterPassword, setMasterPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [unlockError, setUnlockError] = useState('')

    const [entries, setEntries] = useState<VaultEntry[]>([])
    const [entrySiteName, setEntrySiteName] = useState('')
    const [entrySiteUrl, setEntrySiteUrl] = useState('')
    const [entryUserName, setEntryUserName] = useState('')
    const [entryPassword, setEntryPassword] = useState('')
    const [entryNotes, setEntryNotes] = useState('')
    const [entryGroup, setEntryGroup] = useState<GroupName>('Private')
    const [addEntryOpen, setAddEntryOpen] = useState(false)
    const [editingEntryId, setEditingEntryId] = useState<string | null>(null)
    const [copiedId, setCopiedId] = useState<string | null>(null)
    const [pendingDeleteEntry, setPendingDeleteEntry] = useState<VaultEntry | null>(null)
    const addEntrySectionRef = useRef<HTMLElement | null>(null)
    const importFileInputRef = useRef<HTMLInputElement | null>(null)
    const [transferMessage, setTransferMessage] = useState('')
    const [pasteImportOpen, setPasteImportOpen] = useState(false)
    const [pasteImportText, setPasteImportText] = useState('')
    const [authMessage, setAuthMessage] = useState('')
    const [revealedPasswordIds, setRevealedPasswordIds] = useState<Set<string>>(() => new Set())
    const [importWarningTarget, setImportWarningTarget] = useState<'file' | 'paste' | null>(null)
    const [searchQuery, setSearchQuery] = useState('')
    const [collapsedGroups, setCollapsedGroups] = useState<Set<GroupName>>(
        () => new Set(GROUP_OPTIONS.map(({ value }) => value)),
    )

    const [cryptoKey, setCryptoKey] = useState<CryptoKey | null>(null)
    const [vaultMeta, setVaultMeta] = useState<StoredVaultMeta | null>(null)

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
        meta: StoredVaultMeta,
    ) => {
        const payload = await buildStoredVault(nextEntries, key, meta)
        saveStoredVault(payload)
        setEntries(nextEntries)
    }

    const handleSetup = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault()
        setUnlockError('')
        setAuthMessage('')

        if (masterPassword.length < 10) {
            setUnlockError('Use at least 10 characters for your master password.')
            return
        }

        if (masterPassword !== confirmPassword) {
            setUnlockError('Master password and confirmation do not match.')
            return
        }

        const { key, meta } = await createVaultKey(masterPassword, PBKDF2_ITERATIONS)

        await saveEntries([], key, meta)
        setCryptoKey(key)
        setVaultMeta(meta)
        setEntries([])
        setAccessMode('unlocked')
        setAddEntryOpen(false)
        setEditingEntryId(null)
        setMasterPassword('')
        setConfirmPassword('')
    }

    const handleUnlock = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault()
        setUnlockError('')
        setAuthMessage('')

        const storedVault = loadStoredVault()
        if (!storedVault) {
            setUnlockError('Vault was not found. Create a new one.')
            setAccessMode('setup')
            return
        }

        try {
            const key = await deriveVaultKey(
                masterPassword,
                storedVault.salt,
                storedVault.iterations,
            )
            const decryptedEntries = await decryptVaultData<VaultEntry[]>(storedVault, key)

            setCryptoKey(key)
            setVaultMeta({
                salt: storedVault.salt,
                iterations: storedVault.iterations,
            })
            setEntries(
                decryptedEntries.map((entry) => ({
                    ...entry,
                    group: normalizeGroupName(entry.group),
                })),
            )
            setAccessMode('unlocked')
            setAddEntryOpen(false)
            setEditingEntryId(null)
            setMasterPassword('')
        } catch {
            setUnlockError('Incorrect master password.')
        }
    }

    const toggleGroupCollapsed = (group: GroupName) => {
        setCollapsedGroups((prev) => {
            const next = new Set(prev)
            if (next.has(group)) {
                next.delete(group)
            } else {
                next.add(group)
            }
            return next
        })
    }

    const lockVault = useCallback((message?: string) => {
        void clearClipboardBestEffort()
        setCryptoKey(null)
        setVaultMeta(null)
        setEntries([])
        setCopiedId(null)
        setRevealedPasswordIds(new Set())
        setAccessMode('login')
        setMasterPassword('')
        setConfirmPassword('')
        setUnlockError('')
        setEditingEntryId(null)
        if (message) {
            setAuthMessage(message)
        }
    }, [])

    const handleLock = () => {
        setAuthMessage('')
        lockVault()
    }

    useEffect(() => {
        if (accessMode !== 'unlocked') {
            return
        }

        let inactivityTimer: number

        const resetInactivityTimer = () => {
            window.clearTimeout(inactivityTimer)
            inactivityTimer = window.setTimeout(() => {
                lockVault('Locked after 5 minutes of inactivity.')
            }, INACTIVITY_LOCK_MS)
        }

        const activityEvents: Array<keyof WindowEventMap> = [
            'pointerdown',
            'pointermove',
            'keydown',
            'scroll',
            'touchstart',
        ]

        for (const eventName of activityEvents) {
            window.addEventListener(eventName, resetInactivityTimer, { passive: true })
        }

        resetInactivityTimer()

        return () => {
            window.clearTimeout(inactivityTimer)
            for (const eventName of activityEvents) {
                window.removeEventListener(eventName, resetInactivityTimer)
            }
        }
    }, [accessMode, lockVault])

    const resetEntryForm = () => {
        setEntrySiteName('')
        setEntrySiteUrl('')
        setEntryUserName('')
        setEntryPassword('')
        setEntryNotes('')
        setEntryGroup('Private')
        setEditingEntryId(null)
    }

    const handleAddEntry = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault()

        if (!cryptoKey || !vaultMeta) {
            return
        }

        const nextEntryData = {
            siteName: entrySiteName.trim(),
            siteUrl: normalizeSiteUrl(entrySiteUrl),
            userName: entryUserName.trim(),
            password: entryPassword,
            notes: entryNotes.trim(),
            group: entryGroup,
        }

        const nextEntries = editingEntryId
            ? entries.map((entry) =>
                  entry.id === editingEntryId
                      ? {
                            ...entry,
                            ...nextEntryData,
                        }
                      : entry,
              )
            : [
                  {
                      id: crypto.randomUUID(),
                      ...nextEntryData,
                      createdAt: new Date().toISOString(),
                  },
                  ...entries,
              ]

        await saveEntries(nextEntries, cryptoKey, vaultMeta)
        resetEntryForm()
    }

    const handleDeleteEntry = async (id: string) => {
        if (!cryptoKey || !vaultMeta) {
            return
        }

        const nextEntries = entries.filter((entry) => entry.id !== id)
        await saveEntries(nextEntries, cryptoKey, vaultMeta)

        if (editingEntryId === id) {
            resetEntryForm()
        }
    }

    const cancelEntryEdit = () => {
        resetEntryForm()
    }

    const requestEditEntry = (entry: VaultEntry) => {
        setEntrySiteName(entry.siteName)
        setEntrySiteUrl(entry.siteUrl)
        setEntryUserName(entry.userName)
        setEntryPassword(entry.password)
        setEntryNotes(entry.notes)
        setEntryGroup(normalizeGroupName(entry.group))
        setEditingEntryId(entry.id)
        setAddEntryOpen(true)

        requestAnimationFrame(() => {
            addEntrySectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
        })
    }

    const requestDeleteEntry = (entry: VaultEntry) => {
        setPendingDeleteEntry(entry)
    }

    const cancelDeleteEntry = () => {
        setPendingDeleteEntry(null)
    }

    const confirmDeleteEntry = () => {
        if (!pendingDeleteEntry) {
            return
        }

        void handleDeleteEntry(pendingDeleteEntry.id)
        setPendingDeleteEntry(null)
    }

    const handleCopy = (text: string, key: string) => {
        void navigator.clipboard.writeText(text).then(() => {
            setCopiedId(key)
            setTimeout(() => setCopiedId((prev) => (prev === key ? null : prev)), 1500)
        })
    }

    const handleGenerateEntryPassword = () => {
        setEntryPassword(generateStrongPassword())
    }

    const requestImportWarning = (target: 'file' | 'paste') => {
        setTransferMessage('')
        setImportWarningTarget(target)
    }

    const cancelImportWarning = () => {
        setImportWarningTarget(null)
    }

    const confirmImportWarning = () => {
        if (!importWarningTarget) {
            return
        }

        if (importWarningTarget === 'file') {
            importFileInputRef.current?.click()
        } else {
            setPasteImportOpen(true)
        }

        setImportWarningTarget(null)
    }

    const togglePasswordReveal = (entryId: string) => {
        setRevealedPasswordIds((previous) => {
            const next = new Set(previous)
            if (next.has(entryId)) {
                next.delete(entryId)
            } else {
                next.add(entryId)
            }
            return next
        })
    }

    const downloadText = (filename: string, content: string, mimeType: string) => {
        const blob = new Blob([content], { type: mimeType })
        const downloadUrl = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = downloadUrl
        link.download = filename
        document.body.append(link)
        link.click()
        link.remove()
        URL.revokeObjectURL(downloadUrl)
    }

    const exportEncryptedBackup = () => {
        const stored = loadStoredVault()
        setTransferMessage('')
        if (!stored) {
            setTransferMessage('No vault data found to export.')
            return
        }

        const payload: EncryptedVaultBackup = {
            backupVersion: 1,
            exportedAt: new Date().toISOString(),
            vault: stored,
        }

        const stamp = new Date().toISOString().slice(0, 10)
        downloadText(
            `password-vault-backup-${stamp}.json`,
            JSON.stringify(payload, null, 2),
            'application/json',
        )

        setTransferMessage('')
    }

    const exportUnencryptedText = () => {
        setTransferMessage('')

        const stamp = new Date().toISOString().slice(0, 10)
        const sortedEntries = [...entries].sort((a, b) =>
            a.siteName.localeCompare(b.siteName, undefined, { sensitivity: 'base' }),
        )

        const lines: string[] = [
            'Password Vault Unencrypted Export',
            `Exported At: ${new Date().toISOString()}`,
            `Entry Count: ${sortedEntries.length}`,
            '',
        ]

        sortedEntries.forEach((entry) => {
            lines.push(`${entry.siteName}`)
            lines.push(`- URL: ${entry.siteUrl || '-'}`)
            lines.push(`- User: ${entry.userName || '-'}`)
            lines.push(`- Password: ${entry.password || '-'}`)
            lines.push(`- Group: ${normalizeGroupName(entry.group)}`)
            lines.push(`- Notes: ${entry.notes || '-'}`)
            lines.push('')
        })

        downloadText(
            `password-vault-plaintext-${stamp}.txt`,
            lines.join('\n'),
            'text/plain;charset=utf-8',
        )

        setTransferMessage('Unencrypted text export downloaded. Keep this file secure.')
    }

    const restoreEncryptedBackupText = (text: string): void => {
        const parsed = JSON.parse(text) as Record<string, unknown>

        // Accept both the envelope format {backupVersion, vault} and a raw StoredVault
        const vaultData = parsed.backupVersion === 1 && parsed.vault ? parsed.vault : parsed

        if (!isStoredVaultShape(vaultData)) {
            throw new Error('Invalid encrypted backup format.')
        }

        saveStoredVault(vaultData)
        setCryptoKey(null)
        setVaultMeta(null)
        setEntries([])
        setAccessMode('login')
        setMasterPassword('')
        resetEntryForm()
        setAuthMessage('Your vault has been restored. Enter your master password to unlock it.')
    }

    const importEncryptedBackup = async (event: FormEvent<HTMLInputElement>) => {
        const file = event.currentTarget.files?.[0]
        if (!file) {
            return
        }

        try {
            restoreEncryptedBackupText(await file.text())
        } catch {
            setTransferMessage('Import failed. Choose a valid encrypted backup JSON file.')
        } finally {
            event.currentTarget.value = ''
        }
    }

    const handlePasteImport = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault()

        try {
            restoreEncryptedBackupText(pasteImportText)
            setPasteImportOpen(false)
            setPasteImportText('')
        } catch {
            setTransferMessage('Import failed. Make sure the pasted text is valid backup JSON.')
            setPasteImportOpen(false)
            setPasteImportText('')
        }
    }

    const groupedEntries = useMemo(() => {
        const grouped = Object.fromEntries(
            GROUP_OPTIONS.map(({ value }) => [value, [] as VaultEntry[]]),
        ) as Record<GroupName, VaultEntry[]>

        entries.forEach((entry) => {
            const group = normalizeGroupName(entry.group)
            grouped[group].push(entry)
        })

        GROUP_OPTIONS.forEach(({ value }) => {
            grouped[value].sort((a, b) =>
                a.siteName.localeCompare(b.siteName, undefined, { sensitivity: 'base' }),
            )
        })

        return grouped
    }, [entries])

    const filteredEntries = useMemo(() => {
        const q = searchQuery.trim().toLowerCase()
        if (!q) return null
        return entries
            .filter((entry) => entry.siteName.toLowerCase().includes(q))
            .sort((a, b) =>
                a.siteName.localeCompare(b.siteName, undefined, { sensitivity: 'base' }),
            )
    }, [entries, searchQuery])

    const setupPasswordStrength = useMemo(
        () => getPasswordStrength(masterPassword),
        [masterPassword],
    )

    const entryPasswordStrength = useMemo(() => getPasswordStrength(entryPassword), [entryPassword])

    const renderEntryItem = (entry: VaultEntry) => (
        <li key={entry.id} className="entry-item">
            <div className="entry-header">
                <span className="entry-site-name">{entry.siteName}</span>
                <div className="entry-actions">
                    <button
                        type="button"
                        className="icon-btn icon-btn--entry-action"
                        title="Edit entry"
                        onClick={() => requestEditEntry(entry)}
                    >
                        <FontAwesomeIcon icon={faPenToSquare} />
                        <span className="sr-only">Edit entry</span>
                    </button>
                    <button
                        type="button"
                        className="icon-btn icon-btn--entry-action"
                        title="Delete entry"
                        onClick={() => requestDeleteEntry(entry)}
                    >
                        <FontAwesomeIcon icon={faTrash} />
                        <span className="sr-only">Delete entry</span>
                    </button>
                </div>
            </div>
            {entry.siteUrl && (
                <div className="entry-row">
                    <span className="label">
                        <FontAwesomeIcon icon={faLink} />
                        <span className="sr-only">URL</span>
                    </span>
                    <span className="value">
                        <a
                            href={entry.siteUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="site-link"
                        >
                            {getDisplaySiteUrl(entry.siteUrl)}
                        </a>
                    </span>
                </div>
            )}
            <div className="entry-row">
                <span className="label">
                    <FontAwesomeIcon icon={faUser} />
                    <span className="sr-only">User</span>
                </span>
                <span className="value copy-row">
                    {entry.userName || '-'}
                    {entry.userName && (
                        <button
                            type="button"
                            className={`icon-btn icon-btn--copy ${copiedId === `user-${entry.id}` ? 'copy-btn--copied' : ''}`}
                            title="Copy username"
                            onClick={() => handleCopy(entry.userName, `user-${entry.id}`)}
                        >
                            {copiedId === `user-${entry.id}` ? (
                                <FontAwesomeIcon icon={faCheck} />
                            ) : (
                                <FontAwesomeIcon icon={faCopy} />
                            )}
                        </button>
                    )}
                </span>
            </div>
            <div className="entry-row">
                <span className="label">
                    <FontAwesomeIcon icon={faUnlock} />
                    <span className="sr-only">Password</span>
                </span>
                <span className="value secret copy-row">
                    {revealedPasswordIds.has(entry.id) ? (
                        entry.password
                    ) : (
                        <>
                            <span className="password-mask" aria-hidden="true">
                                {Array.from({ length: Math.max(1, entry.password.length) }).map(
                                    (_, index) => (
                                        <FontAwesomeIcon
                                            key={`${entry.id}-mask-${index}`}
                                            icon={faCircle}
                                        />
                                    ),
                                )}
                            </span>
                            <span className="sr-only">Hidden password</span>
                        </>
                    )}
                    <button
                        type="button"
                        className="icon-btn icon-btn--copy"
                        title={
                            revealedPasswordIds.has(entry.id) ? 'Hide password' : 'Show password'
                        }
                        aria-label={
                            revealedPasswordIds.has(entry.id) ? 'Hide password' : 'Show password'
                        }
                        onClick={() => togglePasswordReveal(entry.id)}
                    >
                        {revealedPasswordIds.has(entry.id) ? (
                            <>
                                <FontAwesomeIcon icon={faBan} />
                                <span className="sr-only">Hide password</span>
                            </>
                        ) : (
                            <>
                                <FontAwesomeIcon icon={faEye} />
                                <span className="sr-only">Show password</span>
                            </>
                        )}
                    </button>
                    <button
                        type="button"
                        className={`icon-btn icon-btn--copy ${copiedId === `pw-${entry.id}` ? 'copy-btn--copied' : ''}`}
                        title="Copy password"
                        onClick={() => handleCopy(entry.password, `pw-${entry.id}`)}
                    >
                        {copiedId === `pw-${entry.id}` ? (
                            <FontAwesomeIcon icon={faCheck} />
                        ) : (
                            <FontAwesomeIcon icon={faCopy} />
                        )}
                    </button>
                </span>
            </div>
            {entry.notes && (
                <div className="entry-row notes">
                    <span className="label">
                        <FontAwesomeIcon icon={faFileLines} />
                        <span className="sr-only">Notes</span>
                    </span>
                    <span className="value-notes">{entry.notes}</span>
                </div>
            )}
        </li>
    )

    return (
        <main className="app-shell">
            <header className="hero-card">
                <div className="panel-title-row">
                    <h1 className="brand-title">
                        <img
                            src={`${import.meta.env.BASE_URL}icons/apple-touch-icon-180-v4.png`}
                            alt=""
                            aria-hidden="true"
                            className="brand-logo"
                        />
                        <span>PASSWORD VAULT</span>
                    </h1>
                    {accessMode === 'unlocked' && (
                        <button
                            type="button"
                            className="lock-btn"
                            onClick={handleLock}
                            aria-label="Lock vault"
                            title="Lock vault"
                        >
                            <FontAwesomeIcon icon={faXmark} />
                        </button>
                    )}
                </div>
            </header>

            {(accessMode === 'setup' || accessMode === 'login') && (
                <section className="panel auth-panel">
                    <h2>{accessMode === 'setup' ? 'Create Master Password' : 'Unlock Vault'}</h2>
                    {authMessage && <p className="auth-message">{authMessage}</p>}
                    <form
                        onSubmit={accessMode === 'setup' ? handleSetup : handleUnlock}
                        className="stack"
                    >
                        <input
                            type="password"
                            autoComplete="current-password"
                            value={masterPassword}
                            onChange={(event) => setMasterPassword(event.target.value)}
                            placeholder="Master Password"
                            aria-label="Master Password"
                            required
                            minLength={10}
                        />

                        {accessMode === 'setup' && masterPassword && (
                            <div className="strength-meter" role="status" aria-live="polite">
                                <div className="strength-meter__track" aria-hidden="true">
                                    <div
                                        className={`strength-meter__fill strength-meter__fill--${setupPasswordStrength.level}`}
                                        style={{ width: `${setupPasswordStrength.score * 25}%` }}
                                    />
                                </div>
                                <p className="strength-meter__label">
                                    Strength: {setupPasswordStrength.label}
                                </p>
                            </div>
                        )}

                        {accessMode === 'setup' && (
                            <input
                                type="password"
                                autoComplete="new-password"
                                value={confirmPassword}
                                onChange={(event) => setConfirmPassword(event.target.value)}
                                placeholder="Confirm Master Password"
                                aria-label="Confirm Master Password"
                                required
                                minLength={10}
                            />
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
                    <section className="panel" ref={addEntrySectionRef}>
                        <button
                            type="button"
                            className="add-entry-toggle"
                            onClick={() => setAddEntryOpen((open) => !open)}
                            aria-expanded={addEntryOpen}
                        >
                            <span className="add-entry-icon" aria-hidden="true">
                                <FontAwesomeIcon icon={addEntryOpen ? faMinus : faPlus} />
                            </span>
                            <h2>{editingEntryId ? 'Update' : 'Add'}</h2>
                        </button>

                        {addEntryOpen && (
                            <form onSubmit={handleAddEntry} className="entry-form">
                                <input
                                    type="text"
                                    value={entrySiteName}
                                    onChange={(event) => setEntrySiteName(event.target.value)}
                                    placeholder="Site Name"
                                    aria-label="Site Name"
                                    required
                                />

                                <input
                                    type="url"
                                    value={entrySiteUrl}
                                    onChange={(event) => setEntrySiteUrl(event.target.value)}
                                    onBlur={() =>
                                        setEntrySiteUrl((value) => normalizeSiteUrl(value))
                                    }
                                    placeholder="Site URL"
                                    aria-label="Site URL"
                                />

                                <input
                                    type="text"
                                    value={entryUserName}
                                    onChange={(event) => setEntryUserName(event.target.value)}
                                    placeholder="User Name"
                                    aria-label="User Name"
                                    required
                                />

                                <div className="password-input-row">
                                    <input
                                        type="password"
                                        value={entryPassword}
                                        onChange={(event) => setEntryPassword(event.target.value)}
                                        placeholder="Password"
                                        aria-label="Password"
                                        required
                                    />
                                    <button
                                        type="button"
                                        className="ghost-btn generate-password-btn"
                                        onClick={handleGenerateEntryPassword}
                                    >
                                        Generate
                                    </button>
                                </div>

                                {entryPassword && (
                                    <div
                                        className="strength-meter"
                                        role="status"
                                        aria-live="polite"
                                    >
                                        <div className="strength-meter__track" aria-hidden="true">
                                            <div
                                                className={`strength-meter__fill strength-meter__fill--${entryPasswordStrength.level}`}
                                                style={{
                                                    width: `${entryPasswordStrength.score * 25}%`,
                                                }}
                                            />
                                        </div>
                                        <p className="strength-meter__label">
                                            Strength: {entryPasswordStrength.label}
                                        </p>
                                    </div>
                                )}

                                <textarea
                                    value={entryNotes}
                                    onChange={(event) => setEntryNotes(event.target.value)}
                                    rows={3}
                                    placeholder="Notes"
                                    aria-label="Notes"
                                />

                                <fieldset className="group-selector">
                                    <div className="group-options">
                                        {GROUP_OPTIONS.map((group) => (
                                            <label
                                                key={group.value}
                                                className={`group-option ${entryGroup === group.value ? 'group-option--selected' : ''}`}
                                            >
                                                <input
                                                    type="radio"
                                                    name="entryGroup"
                                                    value={group.value}
                                                    checked={entryGroup === group.value}
                                                    onChange={(event) =>
                                                        setEntryGroup(
                                                            event.target.value as GroupName,
                                                        )
                                                    }
                                                />
                                                <FontAwesomeIcon icon={group.icon} />
                                                <span>{group.value}</span>
                                            </label>
                                        ))}
                                    </div>
                                </fieldset>
                                <div className="entry-form-actions">
                                    {editingEntryId && (
                                        <button
                                            type="button"
                                            className="ghost-btn"
                                            onClick={cancelEntryEdit}
                                        >
                                            Cancel
                                        </button>
                                    )}
                                    <button type="submit" className="primary-btn">
                                        {editingEntryId ? 'Update' : 'Save'}
                                    </button>
                                </div>
                            </form>
                        )}
                    </section>

                    <section className="panel">
                        <h2 className="section-title-with-icon">
                            <FontAwesomeIcon icon={faUnlock} />
                            <span>Passwords</span>
                        </h2>
                        {entries.length > 0 && (
                            <div className="search-bar">
                                <input
                                    type="search"
                                    className="search-input"
                                    placeholder="Search by site name…"
                                    aria-label="Search entries by site name"
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                />
                                {searchQuery && (
                                    <button
                                        type="button"
                                        className="icon-btn search-clear-btn"
                                        aria-label="Clear search"
                                        onClick={() => setSearchQuery('')}
                                    >
                                        <FontAwesomeIcon icon={faXmark} />
                                    </button>
                                )}
                            </div>
                        )}
                        {entries.length === 0 ? (
                            <p>No entries yet.</p>
                        ) : filteredEntries !== null ? (
                            filteredEntries.length === 0 ? (
                                <p className="search-no-results">
                                    No matches for &ldquo;{searchQuery}&rdquo;.
                                </p>
                            ) : (
                                <ul className="entry-list">
                                    {filteredEntries.map(renderEntryItem)}
                                </ul>
                            )
                        ) : (
                            <>
                                {GROUP_OPTIONS.map(
                                    ({ value: group }) =>
                                        groupedEntries[group].length > 0 && (
                                            <div key={group}>
                                                <button
                                                    type="button"
                                                    className="group-heading"
                                                    aria-expanded={!collapsedGroups.has(group)}
                                                    onClick={() => toggleGroupCollapsed(group)}
                                                >
                                                    <FontAwesomeIcon
                                                        icon={GROUP_ICON_BY_NAME[group]}
                                                    />
                                                    <span>{group}</span>
                                                    <span className="group-heading__count">
                                                        {groupedEntries[group].length}
                                                    </span>
                                                    <FontAwesomeIcon
                                                        className="group-heading__chevron"
                                                        icon={
                                                            collapsedGroups.has(group)
                                                                ? faChevronDown
                                                                : faChevronUp
                                                        }
                                                    />
                                                </button>
                                                {!collapsedGroups.has(group) && (
                                                    <ul className="entry-list">
                                                        {groupedEntries[group].map(renderEntryItem)}
                                                    </ul>
                                                )}
                                            </div>
                                        ),
                                )}
                            </>
                        )}
                    </section>

                    <section className="panel transfer-panel">
                        <h2 className="section-title-with-icon">
                            <FontAwesomeIcon icon={faFileArrowDown} />
                            <span>Backup & Restore</span>
                        </h2>
                        <div className="transfer-actions">
                            <button
                                type="button"
                                className="primary-btn"
                                onClick={exportEncryptedBackup}
                            >
                                Export Encrypted File
                            </button>
                            <button
                                type="button"
                                className="primary-btn"
                                onClick={exportUnencryptedText}
                            >
                                <FontAwesomeIcon icon={faTriangleExclamation} /> Export Unencrypted
                                Text
                            </button>
                            <button
                                type="button"
                                className="primary-btn"
                                onClick={() => requestImportWarning('file')}
                            >
                                Import File
                            </button>
                            <button
                                type="button"
                                className="primary-btn"
                                onClick={() => requestImportWarning('paste')}
                            >
                                Import by Pasting
                            </button>
                            <input
                                ref={importFileInputRef}
                                type="file"
                                accept="application/json,.json"
                                onChange={importEncryptedBackup}
                                className="sr-only"
                            />
                        </div>
                        {transferMessage && (
                            <div className="transfer-warning">
                                <FontAwesomeIcon icon={faTriangleExclamation} />{' '}
                                <span className="transfer-message">{transferMessage}</span>
                            </div>
                        )}
                    </section>
                </>
            )}

            {pasteImportOpen && (
                <div
                    className="modal-overlay"
                    role="presentation"
                    onClick={() => setPasteImportOpen(false)}
                >
                    <section
                        className="modal-card"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="paste-import-title"
                        onClick={(event) => event.stopPropagation()}
                    >
                        <h2 id="paste-import-title">Import by Pasting</h2>
                        <form onSubmit={handlePasteImport} className="stack">
                            <textarea
                                value={pasteImportText}
                                onChange={(event) => setPasteImportText(event.target.value)}
                                rows={10}
                                placeholder='{"backupVersion":1,"vault":{...}}'
                                required
                                autoFocus
                                className="paste-import-textarea"
                            />
                            <div className="modal-actions">
                                <button
                                    type="button"
                                    className="ghost-btn"
                                    onClick={() => {
                                        setPasteImportOpen(false)
                                        setPasteImportText('')
                                    }}
                                >
                                    Cancel
                                </button>
                                <button type="submit" className="primary-btn">
                                    Import
                                </button>
                            </div>
                        </form>
                    </section>
                </div>
            )}

            {pendingDeleteEntry && (
                <div className="modal-overlay" role="presentation" onClick={cancelDeleteEntry}>
                    <section
                        className="modal-card"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="delete-dialog-title"
                        onClick={(event) => event.stopPropagation()}
                    >
                        <h2 id="delete-dialog-title">Delete Entry?</h2>
                        <p>
                            This will permanently remove{' '}
                            <strong>{pendingDeleteEntry.siteName}</strong> from your vault.
                        </p>
                        <div className="modal-actions">
                            <button type="button" className="ghost-btn" onClick={cancelDeleteEntry}>
                                Cancel
                            </button>
                            <button
                                type="button"
                                className="danger-action-btn"
                                onClick={confirmDeleteEntry}
                            >
                                Delete
                            </button>
                        </div>
                    </section>
                </div>
            )}

            {importWarningTarget && (
                <div className="modal-overlay" role="presentation" onClick={cancelImportWarning}>
                    <section
                        className="modal-card"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="import-warning-title"
                        onClick={(event) => event.stopPropagation()}
                    >
                        <h2 id="import-warning-title">Restore Warning</h2>
                        <FontAwesomeIcon
                            className="transfer-warning"
                            icon={faTriangleExclamation}
                        />
                        <span className="transfer-warning">
                            {' '}
                            Importing a backup will overwrite your current vault on this device.
                        </span>
                        <br />
                        <br />
                        <p>
                            Make sure you have exported your latest vault first if you want to keep
                            it.
                        </p>
                        <div className="modal-actions">
                            <button
                                type="button"
                                className="ghost-btn"
                                onClick={cancelImportWarning}
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                className="danger-action-btn"
                                onClick={confirmImportWarning}
                            >
                                Continue Import
                            </button>
                        </div>
                    </section>
                </div>
            )}
        </main>
    )
}

export default App
