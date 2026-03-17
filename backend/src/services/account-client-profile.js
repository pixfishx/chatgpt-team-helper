import crypto from 'crypto'

export const CHATGPT_OAI_CLIENT_VERSION = 'prod-eddc2f6ff65fee2d0d6439e379eab94fe3047f72'

const LEGACY_CHATGPT_ADMIN_PROFILE = Object.freeze({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
  acceptLanguage: 'zh-CN,zh;q=0.9',
  oaiLanguage: 'zh-CN'
})

const CHATGPT_ADMIN_PROFILE_PRESETS = Object.freeze([
  Object.freeze({
    key: 'win_chrome_zhcn_v1',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
    acceptLanguage: 'zh-CN,zh;q=0.9,en;q=0.8',
    oaiLanguage: 'zh-CN'
  }),
  Object.freeze({
    key: 'win_chrome_enus_v1',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
    acceptLanguage: 'en-US,en;q=0.9',
    oaiLanguage: 'en-US'
  }),
  Object.freeze({
    key: 'mac_chrome_zhcn_v1',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
    acceptLanguage: 'zh-CN,zh;q=0.9,en;q=0.8',
    oaiLanguage: 'zh-CN'
  }),
  Object.freeze({
    key: 'mac_chrome_enus_v1',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
    acceptLanguage: 'en-US,en;q=0.9',
    oaiLanguage: 'en-US'
  })
])

const ACTION_REFERERS = Object.freeze({
  listUsers: 'https://chatgpt.com/admin/members?tab=members',
  deleteUser: 'https://chatgpt.com/admin/members?tab=members',
  listInvites: 'https://chatgpt.com/admin/members?tab=invites',
  deleteInvite: 'https://chatgpt.com/admin/members?tab=invites',
  inviteUser: 'https://chatgpt.com/admin/members'
})

const normalizeOptionalString = (value) => {
  if (value == null) return ''
  return String(value).trim()
}

const readAccountField = (account, camelKey, snakeKey) =>
  normalizeOptionalString(account?.[camelKey] ?? account?.[snakeKey])

export const getAccountToken = (account) => readAccountField(account, 'token', 'token')
export const getAccountChatgptId = (account) => readAccountField(account, 'chatgptAccountId', 'chatgpt_account_id')
export const getAccountOaiDeviceId = (account) => readAccountField(account, 'oaiDeviceId', 'oai_device_id')

const getPersistedClientProfile = (account) => ({
  clientProfileKey: readAccountField(account, 'clientProfileKey', 'client_profile_key'),
  clientUserAgent: readAccountField(account, 'clientUserAgent', 'client_user_agent'),
  clientAcceptLanguage: readAccountField(account, 'clientAcceptLanguage', 'client_accept_language'),
  clientOaiLanguage: readAccountField(account, 'clientOaiLanguage', 'client_oai_language')
})

export const hasPersistedClientProfile = (account) => {
  const profile = getPersistedClientProfile(account)
  return Boolean(
    profile.clientProfileKey &&
    profile.clientUserAgent &&
    profile.clientAcceptLanguage &&
    profile.clientOaiLanguage
  )
}

export const generateAccountClientProfile = (email, providedOaiDeviceId = '') => {
  const normalizedEmail = normalizeOptionalString(email).toLowerCase() || crypto.randomUUID()
  const digest = crypto.createHash('sha256').update(normalizedEmail).digest()
  const presetIndex = digest.readUInt32BE(0) % CHATGPT_ADMIN_PROFILE_PRESETS.length
  const preset = CHATGPT_ADMIN_PROFILE_PRESETS[presetIndex] || CHATGPT_ADMIN_PROFILE_PRESETS[0]
  const normalizedOaiDeviceId = normalizeOptionalString(providedOaiDeviceId)

  return {
    clientProfileKey: preset.key,
    clientUserAgent: preset.userAgent,
    clientAcceptLanguage: preset.acceptLanguage,
    clientOaiLanguage: preset.oaiLanguage,
    oaiDeviceId: normalizedOaiDeviceId || crypto.randomUUID()
  }
}

export const resolveAccountClientProfile = (account) => {
  if (hasPersistedClientProfile(account)) {
    const profile = getPersistedClientProfile(account)
    return {
      ...profile,
      oaiDeviceId: getAccountOaiDeviceId(account)
    }
  }

  return {
    clientProfileKey: '',
    clientUserAgent: LEGACY_CHATGPT_ADMIN_PROFILE.userAgent,
    clientAcceptLanguage: LEGACY_CHATGPT_ADMIN_PROFILE.acceptLanguage,
    clientOaiLanguage: LEGACY_CHATGPT_ADMIN_PROFILE.oaiLanguage,
    oaiDeviceId: getAccountOaiDeviceId(account)
  }
}

export const buildChatgptAdminHeaders = (account, { action = 'listUsers', contentType = '', origin = '' } = {}) => {
  const token = getAccountToken(account)
  const chatgptAccountId = getAccountChatgptId(account)
  const profile = resolveAccountClientProfile(account)
  const referer = ACTION_REFERERS[action] || ACTION_REFERERS.listUsers

  const headers = {
    accept: '*/*',
    'accept-language': profile.clientAcceptLanguage,
    authorization: `Bearer ${token}`,
    'chatgpt-account-id': chatgptAccountId,
    'oai-client-version': CHATGPT_OAI_CLIENT_VERSION,
    'oai-device-id': profile.oaiDeviceId || '',
    'oai-language': profile.clientOaiLanguage,
    referer,
    'user-agent': profile.clientUserAgent
  }

  if (contentType) {
    headers['content-type'] = contentType
  }
  if (origin) {
    headers.origin = origin
  }

  return headers
}
