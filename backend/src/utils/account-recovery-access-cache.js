const toInt = (value, fallback) => {
  const parsed = Number.parseInt(String(value ?? ''), 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

const ACCOUNT_RECOVERY_ACCESS_CACHE_TTL_MS = Math.max(
  0,
  toInt(process.env.ACCOUNT_RECOVERY_ACCESS_CACHE_TTL_MS, 60_000)
)
const ACCOUNT_RECOVERY_ACCESS_CACHE_MAX_SIZE = 2000
const accountRecoveryAccessCache = new Map()

const normalizeAccountId = (value) => {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null
}

export const getAccountRecoveryAccessCache = (accountId) => {
  const normalizedAccountId = normalizeAccountId(accountId)
  if (!normalizedAccountId || ACCOUNT_RECOVERY_ACCESS_CACHE_TTL_MS <= 0) return null

  const entry = accountRecoveryAccessCache.get(normalizedAccountId)
  if (!entry) return null

  if (Date.now() - entry.checkedAt > ACCOUNT_RECOVERY_ACCESS_CACHE_TTL_MS) {
    accountRecoveryAccessCache.delete(normalizedAccountId)
    return null
  }

  return entry
}

export const setAccountRecoveryAccessCache = (accountId, entry) => {
  const normalizedAccountId = normalizeAccountId(accountId)
  if (!normalizedAccountId || ACCOUNT_RECOVERY_ACCESS_CACHE_TTL_MS <= 0 || !entry) return

  if (accountRecoveryAccessCache.size >= ACCOUNT_RECOVERY_ACCESS_CACHE_MAX_SIZE) {
    const firstKey = accountRecoveryAccessCache.keys().next().value
    if (firstKey != null) accountRecoveryAccessCache.delete(firstKey)
  }

  accountRecoveryAccessCache.set(normalizedAccountId, { ...entry, checkedAt: Date.now() })
}

export const invalidateAccountRecoveryAccessCache = (accountId) => {
  const normalizedAccountId = normalizeAccountId(accountId)
  if (!normalizedAccountId) return false
  return accountRecoveryAccessCache.delete(normalizedAccountId)
}

export const invalidateAccountRecoveryAccessCaches = (accountIds) => {
  if (!Array.isArray(accountIds) || accountIds.length === 0) return 0

  let invalidatedCount = 0
  for (const accountId of accountIds) {
    if (invalidateAccountRecoveryAccessCache(accountId)) {
      invalidatedCount += 1
    }
  }

  return invalidatedCount
}
