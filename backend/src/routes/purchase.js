import express from 'express'
import crypto from 'crypto'
import axios from 'axios'
import jwt from 'jsonwebtoken'
import { getDatabase, saveDatabase } from '../database/init.js'
import { authenticateToken } from '../middleware/auth.js'
import { requireMenu } from '../middleware/rbac.js'
import { withLocks } from '../utils/locks.js'
import { sendPurchaseOrderEmail } from '../services/email-service.js'
import { redeemCodeInternal, RedemptionError } from './redemption-codes.js'
import { getChannels, normalizeChannelKey } from '../utils/channels.js'
import { getPurchaseProductByKey, listPurchaseProducts, normalizeCodeChannels, normalizeProductKey } from '../services/purchase-products.js'
import { safeInsertPointsLedgerEntry } from '../utils/points-ledger.js'
import { getZpaySettings } from '../utils/zpay-settings.js'
import { sendTelegramBotNotification } from '../services/telegram-notifier.js'
import { requireFeatureEnabled } from '../middleware/feature-flags.js'
import { getUpstreamSettings } from '../utils/upstream-settings.js'
import { getUpstreamProviderReadiness } from '../services/upstream-provider.js'
import { getPublicBaseUrlSettings, resolvePublicBaseUrl } from '../utils/public-base-url.js'
import { consumeRateLimit, getRequestClientIp } from '../utils/request-guard.js'
import {
  generateDownstreamPublicCode,
  getDownstreamOrderItemRefundState,
  listDownstreamOrderItems,
  listReservedRedemptionCodesByOrderNo,
  releaseReservedCodesByOrderNo,
  revokeDownstreamOrderItems
} from '../utils/downstream-order-items.js'

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production'
const ORDER_BIND_TOKEN_SECRET = `${JWT_SECRET}::purchase-bind`
const ORDER_BIND_TOKEN_SCOPE = 'purchase_order_bind'
const ORDER_BIND_TOKEN_EXPIRES_IN = String(process.env.PURCHASE_ORDER_BIND_TOKEN_EXPIRES_IN || '10m').trim() || '10m'

router.use(requireFeatureEnabled('payment'))

router.use('/admin', authenticateToken, requireMenu('purchase_orders'))

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const normalizeEmail = (value) => String(value ?? '').trim().toLowerCase()

const safeSnippet = (value, limit = 420) => {
  if (value == null) return ''
  const raw = typeof value === 'string' ? value : (() => {
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  })()
  const normalized = raw.replace(/\s+/g, ' ').trim()
  if (normalized.length <= limit) return normalized
  return `${normalized.slice(0, limit)}…`
}

const toInt = (value, fallback) => {
  const parsed = Number.parseInt(String(value ?? ''), 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

const md5 = (value) => crypto.createHash('md5').update(String(value), 'utf8').digest('hex')

const normalizeZpayResponseData = (raw) => {
  if (raw == null) return { data: null, rawText: '' }
  if (typeof raw === 'string') {
    const trimmed = raw.trim()
    if (!trimmed) return { data: null, rawText: '' }
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed)
        return { data: parsed, rawText: trimmed }
      } catch {
        return { data: null, rawText: trimmed }
      }
    }
    return { data: null, rawText: trimmed }
  }
  return { data: raw, rawText: '' }
}

const buildZpaySign = (params, key) => {
  const entries = Object.entries(params || {})
    .filter(([k, v]) => {
      if (!k) return false
      if (k === 'sign' || k === 'sign_type') return false
      if (v === undefined || v === null) return false
      const str = String(v).trim()
      return str.length > 0
    })
    .sort(([a], [b]) => (a === b ? 0 : a > b ? 1 : -1))
    .map(([k, v]) => `${k}=${String(v).trim()}`)
    .join('&')

  return md5(`${entries}${key}`)
}

const parseMoney = (value) => {
  const parsed = Number.parseFloat(String(value ?? ''))
  if (!Number.isFinite(parsed)) return null
  return Math.round(parsed * 100) / 100
}

const formatMoney = (value) => {
  const parsed = parseMoney(value)
  if (parsed === null) return null
  return parsed.toFixed(2)
}

const generateOrderNo = () => {
  const now = new Date()
  const pad = (n) => String(n).padStart(2, '0')
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`
  const rand = Math.floor(Math.random() * 1e6).toString().padStart(6, '0')
  return `${stamp}${rand}`
}

const ORDER_TYPE_WARRANTY = 'warranty'
const ORDER_TYPE_NO_WARRANTY = 'no_warranty'
const ORDER_TYPE_ANTI_BAN = 'anti_ban'
const ORDER_TYPE_SET = new Set([ORDER_TYPE_WARRANTY, ORDER_TYPE_NO_WARRANTY, ORDER_TYPE_ANTI_BAN])
const NO_WARRANTY_REWARD_POINTS = 1
const CODE_CHANNEL_COMMON = 'common'
const CODE_CHANNEL_PAYPAL = 'paypal'
const SUPPLIER_STATUS_INVALID = 'invalid'
const SUPPLIER_STATUS_USED = 'used'
const SUPPLIER_STATUS_PROCESSING = 'processing'
export const ORDER_SCENE_RETAIL = 'retail'
export const ORDER_SCENE_DOWNSTREAM = 'downstream'
const ORDER_SCENE_SET = new Set([ORDER_SCENE_RETAIL, ORDER_SCENE_DOWNSTREAM])

const parseOrderType = (value) => {
  const normalized = String(value || '').trim().toLowerCase()
  return ORDER_TYPE_SET.has(normalized) ? normalized : null
}

const normalizeOrderType = (value) => parseOrderType(value) || ORDER_TYPE_WARRANTY
const normalizeOrderScene = (value) => {
  const normalized = String(value || '').trim().toLowerCase()
  return ORDER_SCENE_SET.has(normalized) ? normalized : ORDER_SCENE_RETAIL
}

const resolvePurchaseCodeChannel = (orderType) => (
  normalizeOrderType(orderType) === ORDER_TYPE_WARRANTY ? CODE_CHANNEL_PAYPAL : CODE_CHANNEL_COMMON
)

const PURCHASE_ENABLED_ORDER_TYPES_DEFAULT = Object.freeze([ORDER_TYPE_WARRANTY, ORDER_TYPE_NO_WARRANTY])
const normalizePurchaseEnabledOrderTypes = (value) => {
  if (value === undefined || value === null) return PURCHASE_ENABLED_ORDER_TYPES_DEFAULT
  const raw = String(value).trim()
  if (!raw) return PURCHASE_ENABLED_ORDER_TYPES_DEFAULT

  const normalized = raw.toLowerCase()
  if (['all', '*', 'true', '1', 'yes', 'on'].includes(normalized)) return PURCHASE_ENABLED_ORDER_TYPES_DEFAULT
  if (['none', '0', 'false', 'off', 'no'].includes(normalized)) return []

  const tokens = normalized.split(/[\s,|]+/).filter(Boolean)
  const enabled = new Set()
  for (const token of tokens) {
    if (token === 'warranty' || token === '质保') enabled.add(ORDER_TYPE_WARRANTY)
    if (token === 'no_warranty' || token === 'no-warranty' || token === 'nowarranty' || token === '无质保') {
      enabled.add(ORDER_TYPE_NO_WARRANTY)
    }
  }

  const resolved = PURCHASE_ENABLED_ORDER_TYPES_DEFAULT.filter(type => enabled.has(type))
  return resolved.length ? resolved : PURCHASE_ENABLED_ORDER_TYPES_DEFAULT
}

const getEnabledPurchaseOrderTypes = () => normalizePurchaseEnabledOrderTypes(process.env.PURCHASE_ENABLED_ORDER_TYPES)
const getDefaultPurchaseOrderType = (enabledOrderTypes) => {
  const enabled = Array.isArray(enabledOrderTypes) ? enabledOrderTypes : getEnabledPurchaseOrderTypes()
  if (enabled.includes(ORDER_TYPE_WARRANTY)) return ORDER_TYPE_WARRANTY
  if (enabled.includes(ORDER_TYPE_NO_WARRANTY)) return ORDER_TYPE_NO_WARRANTY
  return ORDER_TYPE_WARRANTY
}

const getPurchasePlans = () => {
  const productName = String(process.env.PURCHASE_PRODUCT_NAME || '通用渠道激活码').trim() || '通用渠道激活码'
  const amount = formatMoney(process.env.PURCHASE_PRICE ?? '1.00') || '1.00'
  const serviceDays = Math.max(1, toInt(process.env.PURCHASE_SERVICE_DAYS, 30))
  const expireMinutes = Math.max(5, toInt(process.env.PURCHASE_ORDER_EXPIRE_MINUTES, 15))

  const noWarrantyAmount = formatMoney(process.env.PURCHASE_NO_WARRANTY_PRICE ?? '5.00') || '5.00'
  const noWarrantyServiceDays = Math.max(1, toInt(process.env.PURCHASE_NO_WARRANTY_SERVICE_DAYS, serviceDays))
  const noWarrantyProductName = String(
    process.env.PURCHASE_NO_WARRANTY_PRODUCT_NAME || `${productName}（无质保）`
  ).trim() || `${productName}（无质保）`

  return {
    expireMinutes,
    plans: {
      warranty: {
        key: ORDER_TYPE_WARRANTY,
        productName,
        amount,
        serviceDays
      },
      noWarranty: {
        key: ORDER_TYPE_NO_WARRANTY,
        productName: noWarrantyProductName,
        amount: noWarrantyAmount,
        serviceDays: noWarrantyServiceDays
      }
    }
  }
}

const getPurchaseOrderExpireMinutes = () => Math.max(5, toInt(process.env.PURCHASE_ORDER_EXPIRE_MINUTES, 15))

const parseProductCodeChannels = (product, channelsByKey) => {
  const { list } = normalizeCodeChannels(product?.codeChannels)
  const resolved = []
  const seen = new Set()
  for (const token of list) {
    const key = normalizeChannelKey(token, '')
    if (!key || seen.has(key)) continue
    const channel = channelsByKey?.get?.(key)
    if (!channel || !channel.isActive) continue
    seen.add(key)
    resolved.push(key)
  }
  return resolved
}

const isExternalCardChannel = (channelConfig) => (
  String(channelConfig?.redeemMode || '').trim().toLowerCase() === 'external-card'
)

const getPurchaseChannelAvailability = ({ channelConfig, upstreamSettings }) => {
  if (!channelConfig?.isActive) {
    return {
      ready: false,
      message: '渠道已停用'
    }
  }

  if (!isExternalCardChannel(channelConfig)) {
    return {
      ready: true,
      message: ''
    }
  }

  const readiness = getUpstreamProviderReadiness(upstreamSettings, channelConfig?.providerType)
  return {
    ready: Boolean(readiness.ready),
    message: readiness.message || '当前商品暂不可售，请联系管理员'
  }
}

const getPurchasePlan = (orderType) => {
  const normalized = normalizeOrderType(orderType)
  const { plans } = getPurchasePlans()
  if (normalized === ORDER_TYPE_NO_WARRANTY) return plans.noWarranty
  return plans.warranty
}

const isNoWarrantyOrderType = (orderType) => normalizeOrderType(orderType) === ORDER_TYPE_NO_WARRANTY
const isAntiBanOrderType = (orderType) => normalizeOrderType(orderType) === ORDER_TYPE_ANTI_BAN

const getInviteOrderRewardPoints = () => Math.max(0, toInt(process.env.INVITE_ORDER_REWARD_POINTS, 5))
const getPurchaseOrderRewardPoints = () => Math.max(0, toInt(process.env.PURCHASE_ORDER_REWARD_POINTS, 3))

const getZpayConfig = async (db, options) => {
  const settings = await getZpaySettings(db, options)
  return {
    pid: String(settings.pid || '').trim(),
    key: String(settings.key || '').trim(),
    baseUrl: String(settings.baseUrl || '').trim().replace(/\/+$/, '') || 'https://zpayz.cn'
  }
}

const getInviterUserId = (db, userId) => {
  if (!db) return null
  const normalizedUserId = Number(userId)
  if (!Number.isFinite(normalizedUserId) || normalizedUserId <= 0) return null

  const result = db.exec(
    'SELECT invited_by_user_id FROM users WHERE id = ? LIMIT 1',
    [normalizedUserId]
  )
  const inviter = result[0]?.values?.length ? Number(result[0].values[0][0]) : null
  return Number.isFinite(inviter) && inviter > 0 ? inviter : null
}

const awardInvitePointsForPaidOrderLocked = (db, orderNo, order) => {
  if (!db || !orderNo) return { ok: false, skipped: true, reason: 'missing_input' }

  const current = order || fetchOrder(db, orderNo)
  if (!current) return { ok: false, skipped: true, reason: 'not_found' }

  const rewardPoints = isNoWarrantyOrderType(current.orderType)
    ? NO_WARRANTY_REWARD_POINTS
    : getInviteOrderRewardPoints()
  if (!rewardPoints) return { ok: true, skipped: true, reason: 'disabled' }

  if (current.inviteRewardedAt || current.inviteRewardToUserId) {
    return { ok: true, skipped: true, reason: 'already_rewarded' }
  }

  const userId = current.userId != null ? Number(current.userId) : null
  if (!userId || !Number.isFinite(userId) || userId <= 0) {
    return { ok: true, skipped: true, reason: 'missing_user_id' }
  }

  if (String(current.status) !== 'paid') {
    return { ok: true, skipped: true, reason: 'not_paid' }
  }

  const inviterUserId = getInviterUserId(db, userId)
  if (!inviterUserId) return { ok: true, skipped: true, reason: 'no_inviter' }
  if (inviterUserId === userId) return { ok: true, skipped: true, reason: 'self_invite' }

  const inviterExists = db.exec('SELECT 1 FROM users WHERE id = ? LIMIT 1', [inviterUserId])
  if (!inviterExists[0]?.values?.length) {
    return { ok: true, skipped: true, reason: 'inviter_not_found' }
  }

  const inviterPointsRow = db.exec('SELECT COALESCE(points, 0) FROM users WHERE id = ? LIMIT 1', [inviterUserId])[0]?.values?.[0]
  const pointsBefore = Number(inviterPointsRow?.[0] || 0)
  const pointsAfter = pointsBefore + rewardPoints

  db.run(
    'UPDATE users SET points = COALESCE(points, 0) + ? WHERE id = ?',
    [rewardPoints, inviterUserId]
  )
  safeInsertPointsLedgerEntry(db, {
    userId: inviterUserId,
    deltaPoints: rewardPoints,
    pointsBefore,
    pointsAfter,
    action: 'purchase_invite_reward',
    refType: 'purchase_order',
    refId: orderNo,
    remark: '邀请奖励'
  })
  db.run(
    `
      UPDATE purchase_orders
      SET invite_reward_to_user_id = ?,
          invite_reward_points = ?,
          invite_rewarded_at = DATETIME('now', 'localtime'),
          updated_at = DATETIME('now', 'localtime')
      WHERE order_no = ?
    `,
    [inviterUserId, rewardPoints, orderNo]
  )
  saveDatabase()

  return { ok: true, rewarded: true, inviterUserId, rewardPoints }
}

const awardBuyerPointsForPaidOrderLocked = (db, orderNo, order) => {
  if (!db || !orderNo) return { ok: false, skipped: true, reason: 'missing_input' }

  const current = order || fetchOrder(db, orderNo)
  if (!current) return { ok: false, skipped: true, reason: 'not_found' }

  const rewardPoints = isNoWarrantyOrderType(current.orderType)
    ? NO_WARRANTY_REWARD_POINTS
    : getPurchaseOrderRewardPoints()
  if (!rewardPoints) return { ok: true, skipped: true, reason: 'disabled' }

  if (current.refundedAt || current.status === 'refunded') {
    return { ok: true, skipped: true, reason: 'refunded' }
  }

  if (current.buyerRewardedAt || current.buyerRewardPoints != null) {
    return { ok: true, skipped: true, reason: 'already_rewarded' }
  }

  const userId = current.userId != null ? Number(current.userId) : null
  if (!userId || !Number.isFinite(userId) || userId <= 0) {
    return { ok: true, skipped: true, reason: 'missing_user_id' }
  }

  if (String(current.status) !== 'paid') {
    return { ok: true, skipped: true, reason: 'not_paid' }
  }

  const userExists = db.exec('SELECT 1 FROM users WHERE id = ? LIMIT 1', [userId])
  if (!userExists[0]?.values?.length) {
    return { ok: true, skipped: true, reason: 'user_not_found' }
  }

  const buyerPointsRow = db.exec('SELECT COALESCE(points, 0) FROM users WHERE id = ? LIMIT 1', [userId])[0]?.values?.[0]
  const pointsBefore = Number(buyerPointsRow?.[0] || 0)
  const pointsAfter = pointsBefore + rewardPoints

  db.run(
    'UPDATE users SET points = COALESCE(points, 0) + ? WHERE id = ?',
    [rewardPoints, userId]
  )
  safeInsertPointsLedgerEntry(db, {
    userId,
    deltaPoints: rewardPoints,
    pointsBefore,
    pointsAfter,
    action: 'purchase_buyer_reward',
    refType: 'purchase_order',
    refId: orderNo,
    remark: '购买奖励'
  })
  db.run(
    `
      UPDATE purchase_orders
      SET buyer_reward_points = ?,
          buyer_rewarded_at = DATETIME('now', 'localtime'),
          updated_at = DATETIME('now', 'localtime')
      WHERE order_no = ?
    `,
    [rewardPoints, orderNo]
  )
  saveDatabase()

  return { ok: true, rewarded: true, userId, rewardPoints }
}

export const cleanupExpiredOrders = (db, { expireMinutes }) => {
  const threshold = `-${Math.max(5, expireMinutes)} minutes`
  const result = db.exec(
    `
      SELECT order_no
      FROM purchase_orders
      WHERE paid_at IS NULL
        AND status IN ('created', 'pending_payment')
        AND created_at <= DATETIME('now', 'localtime', ?)
    `,
    [threshold]
  )

  const rows = result[0]?.values || []
  if (!rows.length) return 0

  let released = 0
  for (const row of rows) {
    const orderNo = row[0]
    db.run(
      `UPDATE purchase_orders SET status = 'expired', updated_at = DATETIME('now', 'localtime') WHERE order_no = ? AND paid_at IS NULL`,
      [orderNo]
    )
    released += releaseReservedCodesByOrderNo(db, orderNo)
  }
  return released
}

const getInternalAvailableCodeCount = (db, { channel } = {}) => {
  const resolvedChannel = String(channel || CODE_CHANNEL_COMMON).trim().toLowerCase() || CODE_CHANNEL_COMMON
  const result = db.exec(
    `
	      SELECT COUNT(*)
	      FROM redemption_codes rc
	      JOIN gpt_accounts ga ON lower(trim(ga.email)) = lower(trim(rc.account_email))
	      WHERE rc.is_redeemed = 0
	        AND COALESCE(NULLIF(lower(trim(rc.channel)), ''), 'common') = ?
	        AND rc.account_email IS NOT NULL
        AND ga.is_open = 1
        AND ga.user_count < 6
        AND DATE(ga.created_at) = DATE('now', 'localtime')
        AND COALESCE(rc.is_downstream_sold, 0) = 0
        AND (rc.reserved_for_order_no IS NULL OR rc.reserved_for_order_no = '')
        AND (rc.reserved_for_entry_id IS NULL OR rc.reserved_for_entry_id = 0)
    `,
    [resolvedChannel]
  )
  return Number(result[0]?.values?.[0]?.[0] || 0)
}

const getExternalAvailableCodeCount = (db, { channel } = {}) => {
  const resolvedChannel = String(channel || CODE_CHANNEL_COMMON).trim().toLowerCase() || CODE_CHANNEL_COMMON
  const result = db.exec(
    `
      SELECT COUNT(*)
      FROM redemption_codes rc
      WHERE rc.is_redeemed = 0
        AND COALESCE(NULLIF(lower(trim(rc.channel)), ''), 'common') = ?
        AND COALESCE(rc.is_downstream_sold, 0) = 0
        AND (rc.reserved_for_order_no IS NULL OR rc.reserved_for_order_no = '')
        AND (rc.reserved_for_entry_id IS NULL OR rc.reserved_for_entry_id = 0)
        AND COALESCE(NULLIF(lower(trim(rc.supplier_status)), ''), 'pending') NOT IN (?, ?, ?)
    `,
    [resolvedChannel, SUPPLIER_STATUS_INVALID, SUPPLIER_STATUS_USED, SUPPLIER_STATUS_PROCESSING]
  )
  return Number(result[0]?.values?.[0]?.[0] || 0)
}

const getAvailableCodeCount = (db, { channel, channelConfig } = {}) => (
  isExternalCardChannel(channelConfig)
    ? getExternalAvailableCodeCount(db, { channel })
    : getInternalAvailableCodeCount(db, { channel })
)

const reserveInternalCode = (db, { orderNo, email, channel } = {}) => {
  const resolvedChannel = String(channel || CODE_CHANNEL_COMMON).trim().toLowerCase() || CODE_CHANNEL_COMMON
  const row = db.exec(
    `
	      SELECT rc.id, rc.code, rc.account_email
	      FROM redemption_codes rc
	      JOIN gpt_accounts ga ON lower(trim(ga.email)) = lower(trim(rc.account_email))
	      WHERE rc.is_redeemed = 0
	        AND COALESCE(NULLIF(lower(trim(rc.channel)), ''), 'common') = ?
	        AND rc.account_email IS NOT NULL
        AND ga.is_open = 1
        AND ga.user_count < 6
        AND DATE(ga.created_at) = DATE('now', 'localtime')
        AND COALESCE(rc.is_downstream_sold, 0) = 0
        AND (rc.reserved_for_order_no IS NULL OR rc.reserved_for_order_no = '')
        AND (rc.reserved_for_entry_id IS NULL OR rc.reserved_for_entry_id = 0)
      ORDER BY rc.created_at ASC
      LIMIT 1
    `,
    [resolvedChannel]
  )[0]?.values?.[0]

  if (!row) return null
  const [codeId, code, accountEmail] = row

  db.run(
    `
      UPDATE redemption_codes
      SET reserved_for_order_no = ?,
          reserved_for_order_email = ?,
          reserved_at = DATETIME('now', 'localtime'),
          updated_at = DATETIME('now', 'localtime')
      WHERE id = ?
        AND is_redeemed = 0
        AND COALESCE(is_downstream_sold, 0) = 0
        AND (reserved_for_order_no IS NULL OR reserved_for_order_no = '')
    `,
    [orderNo, email, codeId]
  )

  return { codeId, code, accountEmail }
}

const reserveExternalCode = (db, { orderNo, email, channel } = {}) => {
  const resolvedChannel = String(channel || CODE_CHANNEL_COMMON).trim().toLowerCase() || CODE_CHANNEL_COMMON
  const row = db.exec(
    `
      SELECT rc.id, rc.code, rc.account_email
      FROM redemption_codes rc
      WHERE rc.is_redeemed = 0
        AND COALESCE(NULLIF(lower(trim(rc.channel)), ''), 'common') = ?
        AND COALESCE(rc.is_downstream_sold, 0) = 0
        AND (rc.reserved_for_order_no IS NULL OR rc.reserved_for_order_no = '')
        AND (rc.reserved_for_entry_id IS NULL OR rc.reserved_for_entry_id = 0)
        AND COALESCE(NULLIF(lower(trim(rc.supplier_status)), ''), 'pending') NOT IN (?, ?, ?)
      ORDER BY rc.created_at ASC, rc.id ASC
      LIMIT 1
    `,
    [resolvedChannel, SUPPLIER_STATUS_INVALID, SUPPLIER_STATUS_USED, SUPPLIER_STATUS_PROCESSING]
  )[0]?.values?.[0]

  if (!row) return null
  const [codeId, code, accountEmail] = row

  db.run(
    `
      UPDATE redemption_codes
      SET reserved_for_order_no = ?,
          reserved_for_order_email = ?,
          reserved_at = DATETIME('now', 'localtime'),
          updated_at = DATETIME('now', 'localtime')
      WHERE id = ?
        AND is_redeemed = 0
        AND COALESCE(is_downstream_sold, 0) = 0
        AND (reserved_for_order_no IS NULL OR reserved_for_order_no = '')
        AND COALESCE(NULLIF(lower(trim(supplier_status)), ''), 'pending') NOT IN (?, ?, ?)
    `,
    [orderNo, email, codeId, SUPPLIER_STATUS_INVALID, SUPPLIER_STATUS_USED, SUPPLIER_STATUS_PROCESSING]
  )

  return { codeId, code, accountEmail }
}

const reserveAvailableCode = (db, { orderNo, email, channel, channelConfig } = {}) => (
  isExternalCardChannel(channelConfig)
    ? reserveExternalCode(db, { orderNo, email, channel })
    : reserveInternalCode(db, { orderNo, email, channel })
)

export const resolvePurchaseOrderNoByZpayTradeNo = (db, tradeNo) => {
  if (!db) return ''
  const normalized = String(tradeNo || '').trim()
  if (!normalized) return ''
  const result = db.exec(
    `
      SELECT order_no
      FROM purchase_orders
      WHERE zpay_trade_no = ?
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [normalized]
  )
  const row = result[0]?.values?.[0]
  return row?.[0] ? String(row[0]).trim() : ''
}

const getUserIdFromAuthorization = (req) => {
  const authHeader = req.headers?.authorization
  if (typeof authHeader !== 'string' || !authHeader.trim()) return null
  const parts = authHeader.trim().split(' ')
  if (parts.length !== 2) return null
  if (parts[0]?.toLowerCase() !== 'bearer') return null
  const token = String(parts[1] || '').trim()
  if (!token) return null

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })
    const id = decoded?.id
    const userId = Number(id)
    return Number.isFinite(userId) && userId > 0 ? userId : null
  } catch {
    return null
  }
}

const getPurchaseCreateRateLimitWindowMs = () => Math.max(60 * 1000, toInt(process.env.PURCHASE_CREATE_RATE_LIMIT_WINDOW_MS, 10 * 60 * 1000))
const getPurchaseCreateRateLimitMaxPerIp = () => Math.max(1, toInt(process.env.PURCHASE_CREATE_RATE_LIMIT_MAX_PER_IP, 20))
const getPurchasePendingOrderLimitPerEmail = () => Math.max(1, toInt(process.env.PURCHASE_PENDING_ORDER_LIMIT_PER_EMAIL, 3))
const getPurchasePendingOrderLimitPerIp = () => Math.max(1, toInt(process.env.PURCHASE_PENDING_ORDER_LIMIT_PER_IP, 8))

const countPendingOrdersByEmail = (db, { email, orderScene }) => {
  const normalizedEmail = normalizeEmail(email)
  if (!db || !normalizedEmail) return 0

  const result = db.exec(
    `
      SELECT COUNT(*)
      FROM purchase_orders
      WHERE paid_at IS NULL
        AND status IN ('created', 'pending_payment')
        AND order_scene = ?
        AND LOWER(TRIM(email)) = ?
    `,
    [normalizeOrderScene(orderScene), normalizedEmail]
  )

  return Number(result[0]?.values?.[0]?.[0] || 0)
}

const countPendingOrdersByClientIp = (db, { clientIp, orderScene }) => {
  const normalizedClientIp = String(clientIp || '').trim()
  if (!db || !normalizedClientIp) return 0

  const result = db.exec(
    `
      SELECT COUNT(*)
      FROM purchase_orders
      WHERE paid_at IS NULL
        AND status IN ('created', 'pending_payment')
        AND order_scene = ?
        AND TRIM(COALESCE(client_ip, '')) = ?
    `,
    [normalizeOrderScene(orderScene), normalizedClientIp]
  )

  return Number(result[0]?.values?.[0]?.[0] || 0)
}

const buildOrderBindToken = (order) => {
  const orderNo = String(order?.orderNo || '').trim()
  const email = normalizeEmail(order?.email)
  if (!orderNo || !email) return ''

  return jwt.sign(
    {
      scope: ORDER_BIND_TOKEN_SCOPE,
      orderNo,
      email
    },
    ORDER_BIND_TOKEN_SECRET,
    {
      expiresIn: ORDER_BIND_TOKEN_EXPIRES_IN,
      algorithm: 'HS256'
    }
  )
}

const verifyOrderBindToken = (token) => {
  const rawToken = String(token || '').trim()
  if (!rawToken) return null

  try {
    const decoded = jwt.verify(rawToken, ORDER_BIND_TOKEN_SECRET, { algorithms: ['HS256'] })
    if (decoded?.scope !== ORDER_BIND_TOKEN_SCOPE) return null

    const orderNo = String(decoded?.orderNo || '').trim()
    const email = normalizeEmail(decoded?.email)
    if (!orderNo || !email) return null

    return { orderNo, email }
  } catch {
    return null
  }
}

export const fetchOrder = (db, orderNo) => {
  const result = db.exec(
    `
	      SELECT order_no, email, product_name, amount, service_days, order_type, pay_type, status,
	             zpay_oid, zpay_trade_no, zpay_payurl, zpay_qrcode, zpay_img,
	             query_at, query_status,
	             code_id, code, code_account_email,
	             created_at, updated_at, paid_at, redeemed_at, invite_status, redeem_account_email, redeem_user_count, redeem_error,
	             refunded_at, refund_amount, refund_message, email_sent_at, telegram_sent_at,
	             user_id,
	             invite_reward_to_user_id,
	             invite_reward_points,
	             invite_rewarded_at,
	             buyer_reward_points,
	             buyer_rewarded_at,
               product_key,
               code_channel,
               order_scene,
               quantity
	      FROM purchase_orders
	      WHERE order_no = ?
	      LIMIT 1
	    `,
    [orderNo]
  )
  const row = result[0]?.values?.[0]
  if (!row) return null
  return {
    orderNo: row[0],
    email: row[1],
    productName: row[2],
    amount: row[3],
    serviceDays: Number(row[4]) || 30,
    orderType: normalizeOrderType(row[5]),
    payType: row[6] || null,
    status: row[7],
    zpayOid: row[8] || null,
    zpayTradeNo: row[9] || null,
    payUrl: row[10] || null,
    qrcode: row[11] || null,
    img: row[12] || null,
    queryAt: row[13] || null,
    queryStatus: row[14] != null ? Number(row[14]) : null,
    codeId: row[15] ?? null,
    code: row[16] || null,
    codeAccountEmail: row[17] || null,
	    createdAt: row[18],
	    updatedAt: row[19],
	    paidAt: row[20] || null,
	    redeemedAt: row[21] || null,
	    inviteStatus: row[22] || null,
	    redeemAccountEmail: row[23] || null,
	    redeemUserCount: row[24] != null ? Number(row[24]) : null,
	    redeemError: row[25] || null,
	    refundedAt: row[26] || null,
	    refundAmount: row[27] || null,
	    refundMessage: row[28] || null,
	    emailSentAt: row[29] || null,
	    telegramSentAt: row[30] || null,
	    userId: row[31] ?? null,
	    inviteRewardToUserId: row[32] ?? null,
	    inviteRewardPoints: row[33] != null ? Number(row[33]) : null,
	    inviteRewardedAt: row[34] || null,
	    buyerRewardPoints: row[35] != null ? Number(row[35]) : null,
	    buyerRewardedAt: row[36] || null,
      productKey: row[37] || null,
      codeChannel: row[38] || null,
      orderScene: normalizeOrderScene(row[39]),
      quantity: Math.max(1, Number(row[40]) || 1)
	  }
	}

const loadReservedLegacyDownstreamCode = (db, order) => {
  const codeId = Number(order?.codeId || 0)
  if (!db || !codeId) return []

  const result = db.exec(
    `
      SELECT id,
             code,
             account_email,
             COALESCE(NULLIF(LOWER(TRIM(channel)), ''), 'common') AS channel_key,
             is_redeemed,
             COALESCE(is_downstream_sold, 0) AS is_downstream_sold,
             downstream_sold_at,
             order_type,
             created_at
      FROM redemption_codes
      WHERE id = ?
      LIMIT 1
    `,
    [codeId]
  )

  const row = result[0]?.values?.[0]
  if (!row) return []

  return [{
    codeId: Number(row[0]),
    code: row[1] ? String(row[1]) : '',
    accountEmail: row[2] ? String(row[2]).trim() : '',
    channelKey: row[3] ? String(row[3]).trim().toLowerCase() : 'common',
    isRedeemed: Number(row[4] || 0) === 1,
    isDownstreamSold: Number(row[5] || 0) === 1,
    downstreamSoldAt: row[6] || null,
    orderType: row[7] ? String(row[7]).trim() : '',
    createdAt: row[8] || null
  }]
}

const finalizeDownstreamPaidOrder = (db, orderNo, order, { paidAt } = {}) => {
  const quantity = Math.max(1, Number(order?.quantity) || 1)
  const normalizedPaidAt = normalizeZpayDatetime(paidAt)
  const existingItems = listDownstreamOrderItems(db, orderNo)
  const existingItemCodeIds = new Set(existingItems.map(item => item.codeId))

  if (existingItems.length >= quantity) {
    const codeIds = existingItems.map(item => Number(item.codeId || 0)).filter(codeId => codeId > 0)
    if (codeIds.length > 0) {
      const placeholders = codeIds.map(() => '?').join(', ')
      db.run(
        `
          UPDATE redemption_codes
          SET is_downstream_sold = 1,
              downstream_sold_at = COALESCE(downstream_sold_at, COALESCE(?, DATETIME('now', 'localtime'))),
              updated_at = DATETIME('now', 'localtime')
          WHERE id IN (${placeholders})
        `,
        [normalizedPaidAt, ...codeIds]
      )
    }
    db.run(
      `
        UPDATE purchase_orders
        SET invite_status = ?,
            redeem_error = NULL,
            updated_at = DATETIME('now', 'localtime')
        WHERE order_no = ?
      `,
      ['下游已售出', orderNo]
    )
    return { ok: true, changed: true }
  }

  let reservedCodes = listReservedRedemptionCodesByOrderNo(db, orderNo)
  if (!reservedCodes.length) {
    reservedCodes = loadReservedLegacyDownstreamCode(db, order)
  }

  const availableCodeIds = new Set([
    ...Array.from(existingItemCodeIds),
    ...reservedCodes.map(codeRow => Number(codeRow.codeId || 0)).filter(codeId => codeId > 0)
  ])
  if (availableCodeIds.size < quantity) {
    db.run(
      `
        UPDATE purchase_orders
        SET redeem_error = ?,
            updated_at = DATETIME('now', 'localtime')
        WHERE order_no = ?
      `,
      ['downstream_reserved_code_mismatch', orderNo]
    )
    return { ok: false, changed: true, error: 'downstream_reserved_code_mismatch' }
  }

  const pendingCodes = []
  for (const codeRow of reservedCodes) {
    if (existingItemCodeIds.has(codeRow.codeId)) continue
    pendingCodes.push(codeRow)
    if (existingItems.length + pendingCodes.length >= quantity) break
  }

  const invalidCode = pendingCodes.find(codeRow => codeRow.isRedeemed && !codeRow.isDownstreamSold)
  if (invalidCode) {
    db.run(
      `
        UPDATE purchase_orders
        SET redeem_error = ?,
            updated_at = DATETIME('now', 'localtime')
        WHERE order_no = ?
      `,
      ['该兑换码已被使用', orderNo]
    )
    return { ok: false, changed: true, error: 'code_already_redeemed' }
  }

  if (pendingCodes.length > 0) {
    const codeIds = pendingCodes.map(codeRow => codeRow.codeId)
    const placeholders = codeIds.map(() => '?').join(', ')
    db.run(
      `
        UPDATE redemption_codes
        SET is_downstream_sold = 1,
            downstream_sold_at = COALESCE(downstream_sold_at, COALESCE(?, DATETIME('now', 'localtime'))),
            updated_at = DATETIME('now', 'localtime')
        WHERE id IN (${placeholders})
          AND is_redeemed = 0
      `,
      [normalizedPaidAt, ...codeIds]
    )

    for (const codeRow of pendingCodes) {
      db.run(
        `
          INSERT INTO downstream_order_items (
            order_no, code_id, public_code, created_at, updated_at
          ) VALUES (?, ?, ?, DATETIME('now', 'localtime'), DATETIME('now', 'localtime'))
        `,
        [orderNo, codeRow.codeId, generateDownstreamPublicCode(db)]
      )
    }
  }

  db.run(
    `
      UPDATE purchase_orders
      SET invite_status = ?,
          redeem_error = NULL,
          updated_at = DATETIME('now', 'localtime')
      WHERE order_no = ?
    `,
    ['下游已售出', orderNo]
  )

  return { ok: true, changed: true }
}

const computeRefund = ({ amount, startAt, serviceDays }) => {
  const parsedAmount = parseMoney(amount)
  if (parsedAmount === null) return { refundable: false, refundAmount: '0.00', reason: 'invalid_amount' }

  const start = Date.parse(String(startAt || ''))
  if (!Number.isFinite(start)) return { refundable: false, refundAmount: '0.00', reason: 'invalid_start' }

  const totalDays = Math.max(1, Number(serviceDays) || 30)
  const elapsedMs = Date.now() - start
  if (elapsedMs < 0) return { refundable: true, refundAmount: parsedAmount.toFixed(2), remainingDays: totalDays, usedDays: 0 }

  const usedDays = Math.floor(elapsedMs / (24 * 60 * 60 * 1000))
  const remainingDays = Math.max(0, totalDays - usedDays)
  if (remainingDays <= 0) return { refundable: false, refundAmount: '0.00', remainingDays, usedDays }

  const refund = Math.max(0, (parsedAmount * remainingDays) / totalDays)
  const refundAmount = Math.round(refund * 100) / 100
  if (refundAmount <= 0) return { refundable: false, refundAmount: '0.00', remainingDays, usedDays }

  return {
    refundable: true,
    refundAmount: refundAmount.toFixed(2),
    remainingDays,
    usedDays,
    totalDays
  }
}

const normalizeZpayDatetime = (value) => {
  const raw = String(value || '').trim()
  if (!raw) return null
  return raw
}

const summarizeZpayNotifyPayload = (payload) => {
  const data = payload && typeof payload === 'object' ? payload : {}
  const keys = Object.keys(data).sort()
  return {
    outTradeNo: data.out_trade_no ? String(data.out_trade_no).trim() : '',
    tradeStatus: data.trade_status ? String(data.trade_status).trim() : '',
    money: data.money != null ? String(data.money).trim() : '',
    type: data.type ? String(data.type).trim() : '',
    tradeNo: data.trade_no ? String(data.trade_no).trim() : '',
    param: data.param != null ? safeSnippet(String(data.param), 160) : '',
    name: data.name != null ? safeSnippet(String(data.name), 160) : '',
    pid: data.pid ? String(data.pid).trim() : '',
    signType: data.sign_type ? String(data.sign_type).trim() : '',
    hasSign: Boolean(String(data.sign || '').trim()),
    keys
  }
}

const queryZpayOrder = async ({ tradeNo, outTradeNo }) => {
  const { pid, key, baseUrl } = await getZpayConfig()
  if (!pid || !key) {
    return { ok: false, error: 'missing_config' }
  }

  const normalizedTradeNo = String(tradeNo || '').trim()
  const normalizedOutTradeNo = String(outTradeNo || '').trim()
  if (!normalizedTradeNo && !normalizedOutTradeNo) {
    return { ok: false, error: 'missing_order_no' }
  }

  const params = {
    act: 'order',
    pid,
    key,
    ...(normalizedTradeNo ? { trade_no: normalizedTradeNo } : {}),
    ...(normalizedOutTradeNo ? { out_trade_no: normalizedOutTradeNo } : {})
  }

  try {
    const response = await axios.get(`${baseUrl}/api.php`, {
      params,
      timeout: 15000,
      validateStatus: () => true
    })

    const contentType = String(response?.headers?.['content-type'] || '')
    const normalized = normalizeZpayResponseData(response?.data)
    const data = normalized.data
    const rawText = normalized.rawText

    if (response.status !== 200) {
      return {
        ok: false,
        error: `http_${response.status}`,
        contentType,
        bodySnippet: safeSnippet(rawText || response?.data)
      }
    }

    if (!data || typeof data !== 'object') {
      return {
        ok: false,
        error: 'invalid_response',
        contentType,
        bodySnippet: safeSnippet(rawText || response?.data)
      }
    }

    const code = Number(data.code)
    if (code !== 1) {
      return {
        ok: false,
        error: 'query_failed',
        code,
        msg: data.msg ? String(data.msg) : '',
        data
      }
    }

    return { ok: true, data }
  } catch (error) {
    return {
      ok: false,
      error: 'network_error',
      message: error?.message || String(error)
    }
  }
}

const refundZpayOrder = async ({ outTradeNo, tradeNo, money }) => {
  const { pid, key, baseUrl } = await getZpayConfig()
  if (!pid || !key) {
    return { ok: false, error: 'missing_config' }
  }

  const form = new URLSearchParams()
  form.append('pid', pid)
  form.append('key', key)

  const normalizedTradeNo = String(tradeNo || '').trim()
  const normalizedOutTradeNo = String(outTradeNo || '').trim()
  if (normalizedTradeNo) {
    form.append('trade_no', normalizedTradeNo)
  } else if (normalizedOutTradeNo) {
    form.append('out_trade_no', normalizedOutTradeNo)
  } else {
    return { ok: false, error: 'missing_order_no' }
  }

  const refundMoney = formatMoney(money)
  if (!refundMoney) {
    return { ok: false, error: 'invalid_money' }
  }
  form.append('money', refundMoney)

  try {
    const response = await axios.post(`${baseUrl}/api.php?act=refund`, form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000,
      validateStatus: () => true
    })

    const contentType = String(response?.headers?.['content-type'] || '')
    const normalized = normalizeZpayResponseData(response?.data)
    const data = normalized.data
    const rawText = normalized.rawText

    if (response.status !== 200) {
      return {
        ok: false,
        error: `http_${response.status}`,
        contentType,
        bodySnippet: safeSnippet(rawText || response?.data)
      }
    }

    if (!data || typeof data !== 'object') {
      return {
        ok: false,
        error: 'invalid_response',
        contentType,
        bodySnippet: safeSnippet(rawText || response?.data)
      }
    }

    const code = Number(data.code)
    if (code !== 1) {
      return {
        ok: false,
        error: 'refund_failed',
        code,
        msg: data.msg ? String(data.msg) : '',
        data
      }
    }

    return { ok: true, data }
  } catch (error) {
    return {
      ok: false,
      error: 'network_error',
      message: error?.message || String(error)
    }
  }
}

const persistZpayQueryResult = (db, orderNo, queryResult) => {
  if (!db || !orderNo) return
  const payload = queryResult?.ok ? queryResult.data : queryResult
  const queryStatus = queryResult?.ok ? Number(queryResult?.data?.status ?? null) : null
  db.run(
    `
      UPDATE purchase_orders
      SET query_payload = ?,
          query_at = DATETIME('now', 'localtime'),
          query_status = ?,
          updated_at = DATETIME('now', 'localtime')
      WHERE order_no = ?
    `,
    [payload ? JSON.stringify(payload) : null, Number.isFinite(queryStatus) ? queryStatus : null, orderNo]
  )
}

const handlePaidOrder = async (db, orderNo, { payType, tradeNo, paidAt, notifyPayload, source }) => {
  const initialOrder = fetchOrder(db, orderNo)
  const lockKeys = [`purchase:${orderNo}`]
  if (initialOrder?.orderScene === ORDER_SCENE_DOWNSTREAM) {
    lockKeys.push('purchase')
    const codesToLock = listReservedRedemptionCodesByOrderNo(db, orderNo)
      .map(item => String(item.code || '').trim())
      .filter(Boolean)
    if (!codesToLock.length && initialOrder.code) {
      codesToLock.push(String(initialOrder.code).trim())
    }
    for (const code of new Set(codesToLock)) {
      lockKeys.push(`redemption-code:${code}`)
    }
  }

  await withLocks(lockKeys, async () => {
    const order = fetchOrder(db, orderNo)
    if (!order) return

    if (order.refundedAt || order.status === 'refunded') {
      return
    }

    if (notifyPayload) {
      db.run(
        `UPDATE purchase_orders SET notify_payload = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
        [JSON.stringify({ source: source || 'notify', payload: notifyPayload }), orderNo]
      )
    }

    if (order.status !== 'paid') {
      const normalizedPaidAt = normalizeZpayDatetime(paidAt)
      db.run(
        `
          UPDATE purchase_orders
          SET status = 'paid',
              paid_at = COALESCE(?, DATETIME('now', 'localtime')),
              zpay_trade_no = COALESCE(?, zpay_trade_no),
              pay_type = COALESCE(?, pay_type),
              updated_at = DATETIME('now', 'localtime')
          WHERE order_no = ?
        `,
        [normalizedPaidAt, tradeNo || null, payType || null, orderNo]
      )
    } else {
      db.run(
        `
          UPDATE purchase_orders
          SET zpay_trade_no = COALESCE(?, zpay_trade_no),
              pay_type = COALESCE(?, pay_type),
              updated_at = DATETIME('now', 'localtime')
          WHERE order_no = ?
        `,
        [tradeNo || null, payType || null, orderNo]
      )
    }

    saveDatabase()

    const updatedOrder = fetchOrder(db, orderNo)
    if (updatedOrder?.status === 'paid') {
      if (updatedOrder.orderScene !== ORDER_SCENE_DOWNSTREAM) {
        awardInvitePointsForPaidOrderLocked(db, orderNo, updatedOrder)
        awardBuyerPointsForPaidOrderLocked(db, orderNo, updatedOrder)
      }
    }
    if (updatedOrder?.status === 'paid' && updatedOrder.orderScene === ORDER_SCENE_DOWNSTREAM) {
      const downstreamResult = finalizeDownstreamPaidOrder(db, orderNo, updatedOrder, { paidAt })
      if (downstreamResult.changed) {
        saveDatabase()
      }
    } else if (updatedOrder?.status === 'paid' && !updatedOrder.redeemedAt) {
      if (!updatedOrder.code) {
        db.run(
          `UPDATE purchase_orders SET redeem_error = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
          ['missing_code', orderNo]
        )
        saveDatabase()
      } else {
        try {
          const lockedChannel = updatedOrder.codeChannel
            ? String(updatedOrder.codeChannel).trim().toLowerCase()
            : resolvePurchaseCodeChannel(updatedOrder.orderType)
          const redemption = await withLocks(['purchase', `redemption-code:${updatedOrder.code}`], () => (
            redeemCodeInternal({
              email: updatedOrder.email,
              code: updatedOrder.code,
              channel: lockedChannel,
              orderType: updatedOrder.orderType
            })
          ))
          db.run(
            `
              UPDATE purchase_orders
              SET redeemed_at = DATETIME('now', 'localtime'),
                  invite_status = ?,
                  redeem_account_email = ?,
                  redeem_user_count = ?,
                  redeem_error = NULL,
                  updated_at = DATETIME('now', 'localtime')
              WHERE order_no = ?
            `,
            [
              redemption?.data?.inviteStatus
                || (redemption?.data?.fulfillmentMode === 'external_api'
                  ? String(redemption?.data?.message || '兑换成功，权益已开通').trim()
                  : null),
              redemption?.data?.accountEmail || null,
              redemption?.data?.userCount != null ? Number(redemption.data.userCount) : null,
              orderNo
            ]
          )
          saveDatabase()
        } catch (error) {
          let resolvedError = error
          if (error instanceof RedemptionError && error.message === '该兑换码已被使用') {
            const rawCode = String(updatedOrder.code || '').trim()
            let row = null
            if (rawCode) {
              const exactResult = db.exec(
                `SELECT redeemed_by, redeemed_at FROM redemption_codes WHERE code = ? LIMIT 1`,
                [rawCode]
              )
              row = exactResult[0]?.values?.[0] || null

              if (!row) {
                const upperCode = rawCode.toUpperCase()
                if (upperCode !== rawCode) {
                  const upperResult = db.exec(
                    `SELECT redeemed_by, redeemed_at FROM redemption_codes WHERE code = ? LIMIT 1`,
                    [upperCode]
                  )
                  row = upperResult[0]?.values?.[0] || null
                }
              }
            }
            const redeemedBy = row?.[0] ? String(row[0]).trim() : ''
            const redeemedAt = row?.[1] || null
            if (redeemedBy && normalizeEmail(redeemedBy) === normalizeEmail(updatedOrder.email)) {
              db.run(
                `
                  UPDATE purchase_orders
                  SET redeemed_at = COALESCE(?, DATETIME('now', 'localtime')),
                      invite_status = COALESCE(invite_status, '已处理'),
                      redeem_error = NULL,
                      updated_at = DATETIME('now', 'localtime')
                  WHERE order_no = ?
                `,
                [redeemedAt, orderNo]
              )
              saveDatabase()
              resolvedError = null
            }
          }

          if (resolvedError) {
            const message = resolvedError instanceof RedemptionError
              ? resolvedError.message
              : resolvedError?.message || String(resolvedError)
            console.warn('[Purchase] auto redeem failed', { orderNo, message })
            db.run(
              `UPDATE purchase_orders SET redeem_error = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
              [message, orderNo]
            )
            saveDatabase()
          }
        }
      }
    }

    const orderForEmail = fetchOrder(db, orderNo)
    if (orderForEmail?.email && !orderForEmail.emailSentAt) {
      const emailPayload = { ...orderForEmail }
      if (orderForEmail.orderScene === ORDER_SCENE_DOWNSTREAM) {
        const downstreamItems = listDownstreamOrderItems(db, orderNo)
        const publicBaseUrlSettings = await getPublicBaseUrlSettings(db)
        const publicBaseUrl = String(publicBaseUrlSettings.baseUrl || '').trim().replace(/\/+$/, '')
        emailPayload.items = downstreamItems.map(item => ({
          publicCode: item.publicCode,
          redeemedAt: item.redeemedAt || null,
          status: item.redeemedAt ? 'redeemed' : 'unused'
        }))
        emailPayload.orderQueryUrl = publicBaseUrl
          ? `${publicBaseUrl}/downstream/order?orderNo=${encodeURIComponent(orderForEmail.orderNo)}&email=${encodeURIComponent(orderForEmail.email)}`
          : ''
      }

      const sent = await sendPurchaseOrderEmail(emailPayload)
      if (sent) {
        db.run(
          `UPDATE purchase_orders SET email_sent_at = DATETIME('now', 'localtime'), updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
          [orderNo]
        )
        saveDatabase()
      }
    }

    const orderForTelegram = fetchOrder(db, orderNo)
    if (orderForTelegram?.status === 'paid' && !orderForTelegram.telegramSentAt) {
      const lines = [
        '✅ 订单支付成功',
        `订单号：${orderForTelegram.orderNo}`,
        `邮箱：${orderForTelegram.email}`,
        `商品：${orderForTelegram.productName}`,
        `金额：${orderForTelegram.amount}`,
        orderForTelegram.payType ? `支付方式：${orderForTelegram.payType}` : null,
        orderForTelegram.zpayTradeNo ? `交易号：${orderForTelegram.zpayTradeNo}` : null,
        orderForTelegram.paidAt ? `支付时间：${orderForTelegram.paidAt}` : null,
        orderForTelegram.redeemedAt ? `兑换时间：${orderForTelegram.redeemedAt}` : null,
        orderForTelegram.redeemError ? `兑换失败：${orderForTelegram.redeemError}` : null
      ].filter(Boolean)

      const notifyResult = await sendTelegramBotNotification(lines.join('\n'), { db }).catch(error => ({
        ok: false,
        error: error?.message || String(error)
      }))

      if (notifyResult?.ok) {
        db.run(
          `
            UPDATE purchase_orders
            SET telegram_sent_at = DATETIME('now', 'localtime'),
                updated_at = DATETIME('now', 'localtime')
            WHERE order_no = ?
              AND telegram_sent_at IS NULL
          `,
          [orderNo]
        )
        saveDatabase()
      }
    }
  })
}

const shouldSyncOrderWithZpay = (order, { force = false } = {}) => {
  if (!order) return false
  if (order.status === 'paid' || order.status === 'refunded' || order.status === 'expired' || order.status === 'failed') return false
  if (force) return true
  const last = order.queryAt ? Date.parse(String(order.queryAt)) : 0
  const minIntervalMs = Math.max(2000, toInt(process.env.PURCHASE_ORDER_QUERY_MIN_INTERVAL_MS, 8000))
  return !last || Number.isNaN(last) || Date.now() - last > minIntervalMs
}

export const syncOrderStatusFromZpay = async (db, orderNo, { force = false } = {}) => {
  const order = fetchOrder(db, orderNo)
  if (!order) return { ok: false, reason: 'not_found' }
  if (!shouldSyncOrderWithZpay(order, { force })) return { ok: true, skipped: true }

  // 查询时优先仅用 out_trade_no（我方订单号），避免 trade_no 不一致时影响查询结果
  const query = await queryZpayOrder({ tradeNo: '', outTradeNo: orderNo })

  try {
    persistZpayQueryResult(db, orderNo, query)
    saveDatabase()
  } catch (error) {
    console.warn('[Purchase] persist query payload failed', { orderNo, message: error?.message || String(error) })
  }

  if (!query.ok) {
    if (force) {
      console.warn('[Purchase] zpay order sync failed', {
        orderNo,
        error: query.error || 'query_failed',
        message: query.message || query.msg || null,
        status: query.status || null,
        contentType: query.contentType || null,
        bodySnippet: query.bodySnippet || null
      })
    } else if (query.error && query.error !== 'query_failed') {
      console.warn('[Purchase] zpay order query failed', { orderNo, error: query.error, message: query.message })
    }
    return { ok: false, reason: query.error || 'query_failed' }
  }

  const data = query.data || {}
  const zpayStatus = Number(data.status || 0)
  if (!Number.isFinite(zpayStatus) || zpayStatus !== 1) {
    if (force) {
      console.info('[Purchase] zpay order not paid', {
        orderNo,
        zpayStatus: Number.isFinite(zpayStatus) ? zpayStatus : null,
        tradeNo: data.trade_no || null,
        outTradeNo: data.out_trade_no || null
      })
    }
    return { ok: true, paid: false }
  }

  const notifyMoney = formatMoney(data.money)
  const orderMoney = formatMoney(order.amount)
  if (notifyMoney && orderMoney && notifyMoney !== orderMoney) {
    console.warn('[Purchase] zpay order money mismatch', { orderNo, notifyMoney, orderMoney })
    db.run(
      `UPDATE purchase_orders SET refund_message = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
      [`money_mismatch:${notifyMoney}`, orderNo]
    )
    saveDatabase()
    return { ok: false, reason: 'money_mismatch' }
  }

  await handlePaidOrder(db, orderNo, {
    payType: data.type || null,
    tradeNo: data.trade_no || null,
    paidAt: data.endtime || null,
    notifyPayload: data,
    source: 'query'
  })

  return { ok: true, paid: true }
}

router.get('/meta', async (req, res) => {
  try {
    const expireMinutes = getPurchaseOrderExpireMinutes()
    const db = await getDatabase()
    await withLocks(['purchase'], async () => {
      const released = cleanupExpiredOrders(db, { expireMinutes })
      if (released) {
        saveDatabase()
      }
    })
    const products = await listPurchaseProducts(db, { activeOnly: true })
    const { byKey: channelsByKey } = await getChannels(db)
    const upstreamSettings = await getUpstreamSettings(db)

    const responsePlans = []
    for (const product of products) {
      if (!product?.productKey) continue

      const orderType = normalizeOrderType(product.orderType)
      if (orderType === ORDER_TYPE_ANTI_BAN) continue

      const codeChannels = parseProductCodeChannels(product, channelsByKey)
      let availableCount = 0
      for (const channel of codeChannels) {
        const channelConfig = channelsByKey.get(channel) || null
        const availability = getPurchaseChannelAvailability({
          channelConfig,
          upstreamSettings
        })
        if (!availability.ready) continue
        availableCount += getAvailableCodeCount(db, {
          channel,
          channelConfig
        })
      }

      const isNoWarranty = orderType === ORDER_TYPE_NO_WARRANTY
      responsePlans.push({
        key: product.productKey,
        productName: product.productName,
        amount: product.amount,
        serviceDays: product.serviceDays,
        orderType,
        availableCount,
        buyerRewardPoints: isNoWarranty ? NO_WARRANTY_REWARD_POINTS : getPurchaseOrderRewardPoints(),
        inviteRewardPoints: isNoWarranty ? NO_WARRANTY_REWARD_POINTS : getInviteOrderRewardPoints()
      })
    }

    if (!responsePlans.length) {
      const allConfiguredProducts = products.length
        ? products
        : await listPurchaseProducts(db, { activeOnly: false })

      if (allConfiguredProducts.length > 0) {
        return res.json({
          plans: [],
          productName: '',
          amount: '',
          serviceDays: 30,
          availableCount: 0
        })
      }

      const legacy = getPurchasePlans()
      const legacyWarrantyCount = getAvailableCodeCount(db, { channel: CODE_CHANNEL_PAYPAL })
      const legacyNoWarrantyCount = getAvailableCodeCount(db, { channel: CODE_CHANNEL_COMMON })
      return res.json({
        plans: [
          {
            key: ORDER_TYPE_WARRANTY,
            productName: legacy.plans.warranty.productName,
            amount: legacy.plans.warranty.amount,
            serviceDays: legacy.plans.warranty.serviceDays,
            orderType: ORDER_TYPE_WARRANTY,
            availableCount: legacyWarrantyCount,
            buyerRewardPoints: getPurchaseOrderRewardPoints(),
            inviteRewardPoints: getInviteOrderRewardPoints()
          },
          {
            key: ORDER_TYPE_NO_WARRANTY,
            productName: legacy.plans.noWarranty.productName,
            amount: legacy.plans.noWarranty.amount,
            serviceDays: legacy.plans.noWarranty.serviceDays,
            orderType: ORDER_TYPE_NO_WARRANTY,
            availableCount: legacyNoWarrantyCount,
            buyerRewardPoints: NO_WARRANTY_REWARD_POINTS,
            inviteRewardPoints: NO_WARRANTY_REWARD_POINTS
          }
        ],
        productName: legacy.plans.warranty.productName,
        amount: legacy.plans.warranty.amount,
        serviceDays: legacy.plans.warranty.serviceDays,
        availableCount: legacyWarrantyCount
      })
    }

    const defaultPlan = responsePlans[0] || null
    res.json({
      plans: responsePlans,
      productName: defaultPlan?.productName ?? '',
      amount: defaultPlan?.amount ?? '',
      serviceDays: defaultPlan?.serviceDays ?? 30,
      availableCount: defaultPlan?.availableCount ?? 0
    })
  } catch (error) {
    console.error('[Purchase] meta error:', error)
    res.status(500).json({ error: '内部服务器错误' })
  }
})

router.post('/orders', async (req, res) => {
  const email = normalizeEmail(req.body?.email)
  const payType = String(req.body?.type || req.body?.payType || '').trim()
  const rawProductKey = req.body?.productKey ?? req.body?.product_key
  const productKey = rawProductKey == null || String(rawProductKey).trim() === '' ? '' : normalizeProductKey(rawProductKey)
  const requestedOrderType = parseOrderType(req.body?.orderType || req.body?.order_type)
  const userIdFromToken = getUserIdFromAuthorization(req)
  const clientIp = getRequestClientIp(req)

  if (!email) return res.status(400).json({ error: '请输入邮箱地址' })
  if (!EMAIL_REGEX.test(email)) return res.status(400).json({ error: '请输入有效的邮箱地址' })
  if (!['alipay', 'wxpay'].includes(payType)) return res.status(400).json({ error: '请选择支付方式' })
  if (rawProductKey != null && String(rawProductKey).trim() && !productKey) {
    return res.status(400).json({ error: 'productKey 不合法' })
  }

  const createRateLimit = consumeRateLimit({
    key: clientIp ? `purchase:create:${clientIp}` : '',
    limit: getPurchaseCreateRateLimitMaxPerIp(),
    windowMs: getPurchaseCreateRateLimitWindowMs()
  })
  if (!createRateLimit.ok) {
    const retryAfterSeconds = Math.max(1, Math.ceil(Number(createRateLimit.retryAfterMs || 0) / 1000))
    res.set('Retry-After', String(retryAfterSeconds))
    return res.status(429).json({ error: '下单过于频繁，请稍后再试' })
  }

  const { pid, key, baseUrl } = await getZpayConfig()
  if (!pid || !key) {
    console.warn('[Purchase] missing zpay config', { hasPid: !!pid, hasKey: !!key })
    return res.status(500).json({ error: '支付未配置，请联系管理员' })
  }

  const orderNo = generateOrderNo()

  try {
    const db = await getDatabase()

    const reservation = await withLocks(['purchase'], async () => {
      cleanupExpiredOrders(db, { expireMinutes: getPurchaseOrderExpireMinutes() })

      const pendingOrdersForEmail = countPendingOrdersByEmail(db, {
        email,
        orderScene: ORDER_SCENE_RETAIL
      })
      if (pendingOrdersForEmail >= getPurchasePendingOrderLimitPerEmail()) {
        return { ok: false, status: 429, error: '当前邮箱待支付订单过多，请先完成支付或等待旧订单过期' }
      }

      const pendingOrdersForClientIp = countPendingOrdersByClientIp(db, {
        clientIp,
        orderScene: ORDER_SCENE_RETAIL
      })
      if (pendingOrdersForClientIp >= getPurchasePendingOrderLimitPerIp()) {
        return { ok: false, status: 429, error: '当前网络待支付订单过多，请稍后再试' }
      }

      const { byKey: channelsByKey } = await getChannels(db)
      const upstreamSettings = await getUpstreamSettings(db)
      let product = null

      if (productKey) {
        product = await getPurchaseProductByKey(db, productKey)
      } else if (requestedOrderType) {
        product = await getPurchaseProductByKey(db, requestedOrderType)
      }

      if (!product) {
        const products = await listPurchaseProducts(db, { activeOnly: true })
        product = products?.[0] || null
      }

      if (!product || !product.isActive) {
        return { ok: false, status: 400, error: '该商品已下架' }
      }

      const orderType = normalizeOrderType(product.orderType)
      if (isAntiBanOrderType(orderType)) {
        return { ok: false, status: 400, error: '防封禁方案已下线' }
      }

      const candidateChannels = parseProductCodeChannels(product, channelsByKey)
      if (!candidateChannels.length) {
        return { ok: false, status: 500, error: '商品渠道配置错误，请联系管理员' }
      }

      let reserved = null
      let lockedChannel = ''
      let saleReadyChannelCount = 0
      for (const channel of candidateChannels) {
        const channelConfig = channelsByKey.get(channel) || null
        const availability = getPurchaseChannelAvailability({
          channelConfig,
          upstreamSettings
        })
        if (!availability.ready) continue
        saleReadyChannelCount += 1
        reserved = reserveAvailableCode(db, {
          orderNo,
          email,
          channel,
          channelConfig
        })
        if (reserved) {
          lockedChannel = channel
          break
        }
      }
      if (saleReadyChannelCount === 0) {
        return { ok: false, status: 503, error: '当前商品暂不可售，请联系管理员' }
      }
      if (!reserved) {
        return { ok: false, status: 409, error: '可用库存不足，请稍后再试' }
      }

      db.run(
        `
          INSERT INTO purchase_orders (
            user_id, order_no, email, product_name, amount, service_days, order_type, order_scene, product_key, code_channel, client_ip, pay_type, status,
            quantity, code_id, code, code_account_email, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, ?, ?, ?, DATETIME('now', 'localtime'), DATETIME('now', 'localtime'))
        `,
        [
          userIdFromToken,
          orderNo,
          email,
          product.productName,
          product.amount,
          product.serviceDays,
          orderType,
          ORDER_SCENE_RETAIL,
          product.productKey,
          lockedChannel,
          clientIp || null,
          payType,
          1,
          reserved.codeId,
          reserved.code,
          reserved.accountEmail
        ]
      )
      saveDatabase()

      return { ok: true, reserved, product, orderType, codeChannel: lockedChannel }
    })

    if (!reservation.ok) {
      return res.status(reservation.status || 409).json({ error: reservation.error })
    }

    const purchasePlan = {
      productName: reservation.product.productName,
      amount: reservation.product.amount,
      serviceDays: reservation.product.serviceDays
    }
    const orderType = reservation.orderType
    const productKeyUsed = reservation.product.productKey

    // ZPAY 异步通知为 GET，会把支付结果参数拼在 notify_url 后面（示例：/notify?pid=...&trade_no=...）
    const notifyUrl = `${await resolvePublicBaseUrl(req, db)}/notify`

    const payParams = {
      pid,
      type: payType,
      out_trade_no: orderNo,
      notify_url: notifyUrl,
      return_url: notifyUrl,
      name: purchasePlan.productName,
      money: purchasePlan.amount,
      clientip: clientIp,
      device: 'pc',
      param: `email=${email}`
    }

    const sign = buildZpaySign({ ...payParams, sign_type: 'MD5' }, key)
    const form = new URLSearchParams()
    Object.entries({ ...payParams, sign, sign_type: 'MD5' }).forEach(([k, v]) => form.append(k, String(v)))

    const zpayResponse = await axios.post(`${baseUrl}/mapi.php`, form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000,
      validateStatus: () => true
    })

    const contentType = String(zpayResponse?.headers?.['content-type'] || '')
    const normalized = normalizeZpayResponseData(zpayResponse?.data)
    const data = normalized.data
    const rawText = normalized.rawText

    if (zpayResponse.status !== 200) {
      const msg = `支付通道异常（HTTP ${zpayResponse.status}）`
      console.warn('[Purchase] zpay http error', {
        orderNo,
        status: zpayResponse.status,
        contentType,
        bodySnippet: safeSnippet(rawText || zpayResponse?.data)
      })
      await withLocks([`purchase:${orderNo}`], async () => {
        db.run(
          `UPDATE purchase_orders SET status = 'failed', refund_message = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
          [msg, orderNo]
        )
        releaseReservedCodesByOrderNo(db, orderNo)
        saveDatabase()
      })
      return res.status(502).json({ error: msg })
    }

    if (!data || String(data.code) !== '1') {
      const codeValue = data?.code != null ? String(data.code) : ''
      const msg = data?.msg
        ? String(data.msg)
        : codeValue
          ? `支付下单失败（code=${codeValue}）`
          : rawText
            ? '支付下单失败（响应格式异常）'
            : '支付下单失败'

      console.warn('[Purchase] zpay create failed', {
        orderNo,
        contentType,
        parsedCode: codeValue || null,
        parsedMsg: data?.msg ? String(data.msg) : null,
        bodySnippet: safeSnippet(rawText || data)
      })
      await withLocks([`purchase:${orderNo}`], async () => {
        db.run(
          `UPDATE purchase_orders SET status = 'failed', refund_message = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
          [msg, orderNo]
        )
        releaseReservedCodesByOrderNo(db, orderNo)
        saveDatabase()
      })
      return res.status(502).json({ error: msg })
    }

    db.run(
      `
        UPDATE purchase_orders
        SET status = 'pending_payment',
            zpay_oid = ?,
            zpay_trade_no = ?,
            zpay_payurl = ?,
            zpay_qrcode = ?,
            zpay_img = ?,
            updated_at = DATETIME('now', 'localtime')
        WHERE order_no = ?
      `,
      [data.O_id || null, data.trade_no || null, data.payurl || null, data.qrcode || null, data.img || null, orderNo]
    )
    saveDatabase()

    res.json({
      orderNo,
      amount: purchasePlan.amount,
      productName: purchasePlan.productName,
      orderType,
      productKey: productKeyUsed,
      payType,
      payUrl: data.payurl || null,
      qrcode: data.qrcode || null,
      img: data.img || null
    })
  } catch (error) {
    console.error('[Purchase] create order error:', {
      orderNo,
      message: error?.message || String(error),
      code: error?.code,
      status: error?.response?.status,
      responseSnippet: safeSnippet(error?.response?.data)
    })

    const normalizedErrorResponse = normalizeZpayResponseData(error?.response?.data)
    const derivedMessage = normalizedErrorResponse?.data?.msg
      ? String(normalizedErrorResponse.data.msg)
      : error?.response?.status
        ? `支付通道异常（HTTP ${error.response.status}）`
        : error?.code
          ? `支付通道异常（${String(error.code)}）`
          : 'create_order_exception'
    try {
      const db = await getDatabase()
      await withLocks([`purchase:${orderNo}`], async () => {
        db.run(
          `UPDATE purchase_orders SET status = 'failed', refund_message = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ? AND paid_at IS NULL`,
          [derivedMessage, orderNo]
        )
        releaseReservedCodesByOrderNo(db, orderNo)
        saveDatabase()
      })
    } catch {
      // ignore
    }
    res.status(500).json({ error: derivedMessage === 'create_order_exception' ? '创建订单失败，请稍后再试' : derivedMessage })
  }
})

const processZpayNotify = async (orderNo, payload) => {
  const startedAt = Date.now()
  try {
    console.info('[Purchase] notify async received', { orderNo, payload: summarizeZpayNotifyPayload(payload) })
    const db = await getDatabase()
    const order = fetchOrder(db, orderNo)
    if (!order) {
      console.warn('[Purchase] notify async order not found', { orderNo })
      return
    }

    console.info('[Purchase] notify async order loaded', {
      orderNo,
      status: order.status,
      amount: order.amount,
      paidAt: order.paidAt,
      refundedAt: order.refundedAt
    })

    const notifyMoney = formatMoney(payload.money)
    const orderMoney = formatMoney(order.amount)
    if (notifyMoney && orderMoney && notifyMoney !== orderMoney) {
      console.warn('[Purchase] notify money mismatch', { orderNo, notifyMoney, orderMoney })
      db.run(
        `
          UPDATE purchase_orders
          SET notify_payload = ?,
              refund_message = ?,
              updated_at = DATETIME('now', 'localtime')
          WHERE order_no = ?
        `,
        [JSON.stringify(payload), `money_mismatch:${notifyMoney}`, orderNo]
      )
      saveDatabase()
      return
    }

    await handlePaidOrder(db, orderNo, {
      payType: payload.type || null,
      tradeNo: payload.trade_no || null,
      paidAt: null,
      notifyPayload: payload,
      source: 'notify'
    })

    const updated = fetchOrder(db, orderNo)
    console.info('[Purchase] notify async handled', {
      orderNo,
      beforeStatus: order.status,
      afterStatus: updated?.status || null,
      paidAt: updated?.paidAt || null,
      redeemedAt: updated?.redeemedAt || null,
      inviteStatus: updated?.inviteStatus || null,
      redeemError: updated?.redeemError || null,
      emailSentAt: updated?.emailSentAt || null,
      durationMs: Date.now() - startedAt
    })
  } catch (error) {
    console.error('[Purchase] notify async error:', { orderNo, message: error?.message || String(error) })
  }
}

router.all('/notify', async (req, res) => {
  const payload = { ...(req.query || {}), ...(req.body || {}) }
	const outTradeNo = String(payload.out_trade_no || '').trim()
	const tradeNo = String(payload.trade_no || '').trim()
	const orderNo = outTradeNo || String(payload.order_no || '').trim()
	const ip = getRequestClientIp(req)
	const summary = summarizeZpayNotifyPayload(payload)
	const ua = safeSnippet(req.headers['user-agent'] || '', 180)
	const originalUrl = safeSnippet(req.originalUrl || '', 420)
	const referer = safeSnippet(req.headers.referer || req.headers.referrer || '', 180)

	console.info('[Purchase] notify received', {
	  method: req.method,
	  path: req.path,
	  ip,
	  orderNo: orderNo || summary.outTradeNo || '',
	  tradeNo: tradeNo || summary.tradeNo || '',
	  ua: ua || null,
	  referer: referer || null,
	  url: originalUrl || null,
	  queryKeys: Object.keys(req.query || {}).length,
	  bodyKeys: Object.keys(req.body || {}).length,
	  payload: summary
	})
  // epay 要求返回纯字符串 "success"
  const replySuccess = () => res.set('Content-Type', 'text/plain; charset=utf-8').status(200).end('success')
  const replyFail = () => res.set('Content-Type', 'text/plain; charset=utf-8').status(200).end('fail')

	  if (!orderNo && !tradeNo) {
	    console.warn('[Purchase] notify missing orderNo', { method: req.method, ip, payload: summary })
	    replySuccess()
	    return
	  }

	  const { pid, key } = await getZpayConfig()
	  if (!pid || !key) {
	    console.warn('[Purchase] notify missing config', { orderNo, method: req.method, ip, hasPid: Boolean(pid), hasKey: Boolean(key) })
	    replyFail()
	    return
	  }

  const signature = String(payload.sign || '').trim().toLowerCase()
  const expected = buildZpaySign(payload, key).toLowerCase()

  if (String(payload.pid || '').trim() !== pid) {
    console.warn('[Purchase] notify pid mismatch', { orderNo, method: req.method, ip, providedPid: String(payload.pid || '').trim() })
    replyFail()
    return
  }

  if (!signature || signature !== expected) {
    console.warn('[Purchase] notify sign mismatch', {
      orderNo,
      method: req.method,
      ip,
      signType: String(payload.sign_type || '').trim() || null,
      hasSignature: Boolean(signature),
      signatureLength: signature.length || 0,
      signaturePrefix: signature ? signature.slice(0, 8) : null,
      expectedPrefix: expected ? expected.slice(0, 8) : null
    })
    replyFail()
    return
  }

  const tradeStatus = String(payload.trade_status || '').trim()
  if (tradeStatus !== 'TRADE_SUCCESS') {
    console.info('[Purchase] notify trade not success', { orderNo, method: req.method, ip, tradeStatus })
    replySuccess()
    return
  }

  replySuccess()

  queueMicrotask(() => {
    console.info('[Purchase] notify accepted', { orderNo: orderNo || '', tradeNo: tradeNo || '', method: req.method, ip, tradeStatus })
    void (async () => {
      let resolvedOrderNo = orderNo
      if (!resolvedOrderNo && tradeNo) {
        try {
          const db = await getDatabase()
          resolvedOrderNo = resolvePurchaseOrderNoByZpayTradeNo(db, tradeNo)
        } catch (error) {
          console.warn('[Purchase] resolve order_no by trade_no failed', { tradeNo, message: error?.message || String(error) })
        }
      }
      if (!resolvedOrderNo) {
        console.warn('[Purchase] notify order not resolved', { orderNo: orderNo || '', tradeNo: tradeNo || '' })
        return
      }
      await processZpayNotify(resolvedOrderNo, payload)
    })()
  })
})

router.get('/orders/:orderNo', async (req, res) => {
  const requestedOrderNo = String(req.params.orderNo || '').trim()
  const email = normalizeEmail(req.query?.email)
  if (!requestedOrderNo) return res.status(400).json({ error: '缺少订单号' })
  if (!email) return res.status(400).json({ error: '缺少邮箱' })
  if (!EMAIL_REGEX.test(email)) return res.status(400).json({ error: '邮箱格式不正确' })

  try {
    const db = await getDatabase()
    let resolvedOrderNo = requestedOrderNo
    let order = fetchOrder(db, requestedOrderNo)
    if (!order) {
      const mapped = resolvePurchaseOrderNoByZpayTradeNo(db, requestedOrderNo)
      if (mapped) {
        resolvedOrderNo = mapped
        order = fetchOrder(db, mapped)
      }
    }
    if (!order) return res.status(404).json({ error: '订单不存在' })
    if (normalizeEmail(order.email) !== email) return res.status(403).json({ error: '订单信息不匹配' })

    const syncParam = String(req.query?.sync || '').trim().toLowerCase()
    const forceSync = ['1', 'true', 'yes'].includes(syncParam)
	    const fallbackDelayMs = Math.max(0, toInt(process.env.PURCHASE_ORDER_QUERY_FALLBACK_DELAY_MS, 60000))
	    const createdAtMs = Date.parse(String(order.createdAt || ''))
	    const orderAgeMs = Number.isFinite(createdAtMs) ? Date.now() - createdAtMs : 0
	    const allowFallbackSync = !forceSync && fallbackDelayMs > 0 && orderAgeMs >= fallbackDelayMs

    if ((order.status === 'created' || order.status === 'pending_payment') && (forceSync || allowFallbackSync)) {
      try {
        await syncOrderStatusFromZpay(db, resolvedOrderNo, { force: forceSync })
        order = fetchOrder(db, resolvedOrderNo) || order
      } catch (error) {
        console.warn('[Purchase] sync order status failed', { orderNo: resolvedOrderNo, message: error?.message || String(error) })
      }
    }

    const isNoWarrantyOrder = isNoWarrantyOrderType(order.orderType)
    const refund = order.paidAt && !isNoWarrantyOrder
      ? computeRefund({ amount: order.amount, startAt: order.createdAt, serviceDays: order.serviceDays })
      : { refundable: false, refundAmount: '0.00', reason: isNoWarrantyOrder ? 'no_warranty' : 'unpaid' }
    const bindToken = order.userId == null ? buildOrderBindToken(order) : ''

    res.json({
      order: {
        orderNo: order.orderNo,
        tradeNo: order.zpayTradeNo || null,
        email: order.email,
        productName: order.productName,
        amount: order.amount,
        serviceDays: order.serviceDays,
        orderType: order.orderType,
        orderScene: order.orderScene,
        quantity: order.quantity,
        payType: order.payType,
        status: order.status,
        createdAt: order.createdAt,
        paidAt: order.paidAt,
        redeemedAt: order.redeemedAt,
        inviteStatus: order.inviteStatus,
        redeemError: order.redeemError,
        refundedAt: order.refundedAt,
        refundAmount: order.refundAmount,
        refundMessage: order.refundMessage,
        emailSentAt: order.emailSentAt
      },
      bindToken: bindToken || null,
      refundable: refund.refundable,
      computedRefundAmount: refund.refundAmount,
      refundMeta: refund
    })
  } catch (error) {
    console.error('[Purchase] get order error:', error)
    res.status(500).json({ error: '查询失败，请稍后再试' })
  }
})

router.post('/orders/:orderNo/refund', async (req, res) => {
  res.status(403).json({ error: '退款仅支持后台操作' })
})

router.get('/my/orders/summary', authenticateToken, async (req, res) => {
  const userId = req.user?.id
  if (!userId) {
    return res.status(401).json({ error: 'Access denied. No user provided.' })
  }

  try {
    const db = await getDatabase()

    const summaryResult = db.exec(
      `
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) AS paid,
          SUM(CASE WHEN status IN ('created', 'pending_payment') THEN 1 ELSE 0 END) AS pending,
          SUM(CASE WHEN status = 'refunded' THEN 1 ELSE 0 END) AS refunded,
          SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) AS expired,
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
        FROM purchase_orders
        WHERE user_id = ?
      `,
      [userId]
    )
    const summaryRow = summaryResult[0]?.values?.[0] || []

    const recentResult = db.exec(
      `
        SELECT order_no, status, amount, product_name, created_at, paid_at
        FROM purchase_orders
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 3
      `,
      [userId]
    )
    const recentRows = recentResult[0]?.values || []

    res.json({
      total: Number(summaryRow[0] || 0),
      paid: Number(summaryRow[1] || 0),
      pending: Number(summaryRow[2] || 0),
      refunded: Number(summaryRow[3] || 0),
      expired: Number(summaryRow[4] || 0),
      failed: Number(summaryRow[5] || 0),
      recentOrders: recentRows.map(row => ({
        orderNo: row[0],
        status: row[1],
        amount: row[2],
        productName: row[3],
        createdAt: row[4],
        paidAt: row[5] || null,
      }))
    })
  } catch (error) {
    console.error('[Purchase] my orders summary error:', error)
    res.status(500).json({ error: '查询失败，请稍后再试' })
  }
})

router.get('/my/orders', authenticateToken, async (req, res) => {
  const userId = req.user?.id
  if (!userId) {
    return res.status(401).json({ error: 'Access denied. No user provided.' })
  }

  try {
    const db = await getDatabase()
    const page = Math.max(1, Number(req.query.page) || 1)
    const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize) || 20))
    const offset = (page - 1) * pageSize

    const countResult = db.exec(
      'SELECT COUNT(*) FROM purchase_orders WHERE user_id = ?',
      [userId]
    )
    const total = Number(countResult[0]?.values?.[0]?.[0] || 0)

    const result = db.exec(
      `
        SELECT order_no, zpay_trade_no, email, product_name, amount, service_days, order_type, order_scene, pay_type, status,
               created_at, paid_at, redeemed_at, invite_status, redeem_error,
               refunded_at, refund_amount, refund_message, email_sent_at, zpay_img, quantity
        FROM purchase_orders
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `,
      [userId, pageSize, offset]
    )

    const rows = result[0]?.values || []
    res.json({
      orders: rows.map(row => ({
        orderNo: row[0],
        tradeNo: row[1] || null,
        email: row[2],
        productName: row[3],
        amount: row[4],
        serviceDays: Number(row[5]) || 30,
        orderType: normalizeOrderType(row[6]),
        orderScene: normalizeOrderScene(row[7]),
        payType: row[8] || null,
        img: row[19] || null,
        status: row[9],
        createdAt: row[10],
        paidAt: row[11] || null,
        redeemedAt: row[12] || null,
        inviteStatus: row[13] || null,
        redeemError: row[14] || null,
        refundedAt: row[15] || null,
        refundAmount: row[16] || null,
        refundMessage: row[17] || null,
        emailSentAt: row[18] || null,
        quantity: Math.max(1, Number(row[20]) || 1)
      })),
      pagination: { page, pageSize, total }
    })
  } catch (error) {
    console.error('[Purchase] my orders error:', error)
    res.status(500).json({ error: '查询失败，请稍后再试' })
  }
})

router.post('/my/orders/bind', authenticateToken, async (req, res) => {
  const userId = req.user?.id
  if (!userId) {
    return res.status(401).json({ error: 'Access denied. No user provided.' })
  }

  const requestedOrderNo = String(req.body?.orderNo || '').trim()
  const bindToken = String(req.body?.bindToken || '').trim()
  if (!requestedOrderNo) {
    return res.status(400).json({ error: '缺少订单号' })
  }

  try {
    const db = await getDatabase()
    let resolvedOrderNo = requestedOrderNo
    let order = fetchOrder(db, requestedOrderNo)
    if (!order) {
      const mapped = resolvePurchaseOrderNoByZpayTradeNo(db, requestedOrderNo)
      if (mapped) {
        resolvedOrderNo = mapped
        order = fetchOrder(db, mapped)
      }
    }
    if (!order) return res.status(404).json({ error: '订单不存在' })

    const result = await withLocks([`purchase:${resolvedOrderNo}`], async () => {
      const current = fetchOrder(db, resolvedOrderNo)
      if (!current) return { ok: false, status: 404, error: '订单不存在' }

      const boundUserId = current.userId != null ? Number(current.userId) : null
      if (boundUserId && boundUserId !== Number(userId)) {
        return { ok: false, status: 409, error: '订单已被其他用户关联' }
      }

      if (boundUserId === Number(userId)) {
        return { ok: true, message: '订单已关联', order: current }
      }

      const verifiedBindPayload = verifyOrderBindToken(bindToken)
      if (!verifiedBindPayload) {
        return { ok: false, status: 400, error: '绑定凭证无效或已过期，请重新查询订单后再试' }
      }
      if (verifiedBindPayload.orderNo !== resolvedOrderNo) {
        return { ok: false, status: 400, error: '绑定凭证与订单不匹配，请重新查询订单后再试' }
      }
      if (verifiedBindPayload.email !== normalizeEmail(current.email)) {
        return { ok: false, status: 400, error: '绑定凭证与订单不匹配，请重新查询订单后再试' }
      }

      db.run(
        `UPDATE purchase_orders SET user_id = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
        [userId, resolvedOrderNo]
      )
      saveDatabase()

      const updated = fetchOrder(db, resolvedOrderNo) || current
      if (updated.orderScene !== ORDER_SCENE_DOWNSTREAM) {
        awardInvitePointsForPaidOrderLocked(db, resolvedOrderNo, updated)
        awardBuyerPointsForPaidOrderLocked(db, resolvedOrderNo, updated)
      }

      return { ok: true, message: '关联成功', order: updated }
    })

    if (!result.ok) return res.status(result.status || 400).json({ error: result.error })
    res.json({ message: result.message, order: result.order })
  } catch (error) {
    console.error('[Purchase] bind order error:', error)
    res.status(500).json({ error: '关联失败，请稍后再试' })
  }
})

router.get('/admin/orders', async (req, res) => {
  try {
    const db = await getDatabase()
    const page = Math.max(1, Number(req.query.page) || 1)
    const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize) || 10))
    const search = (req.query.search || '').trim().toLowerCase()
    const status = req.query.status // 'pending_payment' | 'paid' | 'refunded' | 'expired' | 'failed' | undefined

    // 构建 WHERE 条件
    const conditions = []
    const params = []

    if (search) {
      conditions.push(`(LOWER(order_no) LIKE ? OR LOWER(email) LIKE ? OR LOWER(product_name) LIKE ?)`)
      const searchPattern = `%${search}%`
      params.push(searchPattern, searchPattern, searchPattern)
    }

    if (status && status !== 'all') {
      conditions.push('status = ?')
      params.push(status)
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

    // 查询总数
    const countResult = db.exec(`SELECT COUNT(*) FROM purchase_orders ${whereClause}`, params)
    const total = countResult[0]?.values?.[0]?.[0] || 0

    // 查询分页数据
    const offset = (page - 1) * pageSize
    const result = db.exec(
      `
        SELECT po.order_no,
               po.email,
               po.product_name,
               po.amount,
               po.service_days,
               po.order_type,
               po.order_scene,
               po.pay_type,
               po.status,
               po.created_at,
               po.paid_at,
               po.refunded_at,
               po.refund_amount,
               po.zpay_payurl,
               po.quantity,
               CASE
                 WHEN COALESCE(NULLIF(TRIM(po.order_scene), ''), 'retail') = 'downstream'
                   THEN (SELECT COUNT(*) FROM downstream_order_items doi WHERE doi.order_no = po.order_no)
                 ELSE 0
               END AS downstream_item_count,
               CASE
                 WHEN COALESCE(NULLIF(TRIM(po.order_scene), ''), 'retail') = 'downstream'
                   THEN (SELECT COUNT(*) FROM downstream_order_items doi WHERE doi.order_no = po.order_no AND doi.redeemed_at IS NOT NULL)
                 ELSE 0
               END AS downstream_redeemed_count
        FROM purchase_orders po
        ${whereClause}
        ORDER BY po.created_at DESC
        LIMIT ? OFFSET ?
      `,
      [...params, pageSize, offset]
    )
    const rows = result[0]?.values || []
    res.json({
      orders: rows.map(row => ({
        orderNo: row[0],
        email: row[1],
        productName: row[2],
        amount: row[3],
        serviceDays: Number(row[4]) || 30,
        orderType: normalizeOrderType(row[5]),
        orderScene: normalizeOrderScene(row[6]),
        payType: row[7] || null,
        status: row[8],
        createdAt: row[9],
        paidAt: row[10] || null,
        refundedAt: row[11] || null,
        refundAmount: row[12] || null,
        payUrl: row[13] || null,
        quantity: Math.max(1, Number(row[14]) || 1),
        downstreamItemCount: Number(row[15] || 0),
        downstreamRedeemedCount: Number(row[16] || 0)
      })),
      pagination: { page, pageSize, total }
    })
  } catch (error) {
    console.error('[Purchase] admin list error:', error)
    res.status(500).json({ error: '查询失败' })
  }
})

router.get('/admin/orders/:orderNo', async (req, res) => {
  try {
    const db = await getDatabase()
    const order = fetchOrder(db, String(req.params.orderNo || '').trim())
    if (!order) return res.status(404).json({ error: '订单不存在' })
    res.json({ order })
  } catch (error) {
    console.error('[Purchase] admin detail error:', error)
    res.status(500).json({ error: '查询失败' })
  }
})

router.post('/admin/orders/:orderNo/refund', async (req, res) => {
  const orderNo = String(req.params.orderNo || '').trim()
  if (!orderNo) return res.status(400).json({ error: '缺少订单号' })
  const { pid, key } = await getZpayConfig()
  if (!pid || !key) {
    return res.status(500).json({ error: '支付未配置，请联系管理员' })
  }

  try {
    const db = await getDatabase()
    const initialOrder = fetchOrder(db, orderNo)
    if (!initialOrder) return res.status(404).json({ error: '订单不存在' })

    const downstreamRefundState = initialOrder.orderScene === ORDER_SCENE_DOWNSTREAM
      ? getDownstreamOrderItemRefundState(db, orderNo)
      : null

    const refundLockKeys = ['purchase', `purchase:${orderNo}`]
    if (downstreamRefundState?.items?.length) {
      for (const item of downstreamRefundState.items) {
        if (item.publicCode) refundLockKeys.push(`downstream-public-code:${item.publicCode}`)
        if (item.realCode) {
          if (item.publicCode) refundLockKeys.push(`upstream-redeem:${item.publicCode}`)
          refundLockKeys.push(`redemption-code:${item.realCode}`)
        }
      }
    }

    const result = await withLocks(Array.from(new Set(refundLockKeys)), async () => {
      const order = fetchOrder(db, orderNo)
      if (!order) return { ok: false, status: 404, error: '订单不存在' }
      if (order.status !== 'paid') return { ok: false, status: 400, error: '订单未支付或状态异常' }
      if (order.refundedAt || order.status === 'refunded') return { ok: false, status: 400, error: '订单已退款' }
      if (isNoWarrantyOrderType(order.orderType)) {
        return { ok: false, status: 400, error: '无质保订单不支持退款' }
      }

      if (order.orderScene === ORDER_SCENE_DOWNSTREAM) {
        const currentRefundState = getDownstreamOrderItemRefundState(db, orderNo)
        if (currentRefundState.redeemedCount > 0) {
          return {
            ok: false,
            status: 400,
            error: `下游订单已有 ${currentRefundState.redeemedCount} 个卡密被兑换，不能自动退款`
          }
        }
      }

      const refund = computeRefund({ amount: order.amount, startAt: order.createdAt, serviceDays: order.serviceDays })
      if (!refund.refundable) return { ok: false, status: 400, error: '已超过可退款期限', refund }

      const refundResult = await refundZpayOrder({
        outTradeNo: orderNo,
        tradeNo: order.zpayTradeNo || null,
        money: refund.refundAmount
      })

      if (!refundResult.ok) {
        const msg = refundResult.msg
          ? String(refundResult.msg)
          : refundResult.error === 'invalid_money'
            ? '退款金额异常'
            : refundResult.error === 'missing_order_no'
              ? '缺少支付订单号'
              : refundResult.error === 'missing_config'
                ? '支付未配置，请联系管理员'
                : refundResult.error?.startsWith('http_')
                  ? `支付通道异常（HTTP ${refundResult.error.slice(5)}）`
                  : refundResult.message
                    ? `支付通道异常（${String(refundResult.message)}）`
                    : '退款失败'

        console.warn('[Purchase] admin refund failed', { orderNo, error: refundResult.error, message: msg })
        db.run(
          `UPDATE purchase_orders SET refund_message = ?, updated_at = DATETIME('now', 'localtime') WHERE order_no = ?`,
          [String(msg), orderNo]
        )
        saveDatabase()
        return { ok: false, status: 502, error: msg, refund }
      }

      const successMsg = refundResult?.data?.msg ? String(refundResult.data.msg) : '退款成功'
      if (order.orderScene === ORDER_SCENE_DOWNSTREAM) {
        const revokeResult = revokeDownstreamOrderItems(db, orderNo)
        if (!revokeResult.ok) {
          return {
            ok: false,
            status: 400,
            error: `下游订单已有 ${revokeResult.blockedRedeemedCount || 0} 个卡密被兑换，不能自动退款`,
            refund
          }
        }
      }

      // 退款后应释放未实际使用的预留码，避免外部卡密或自动开通失败订单被永久锁死。
      releaseReservedCodesByOrderNo(db, orderNo)

      db.run(
        `
          UPDATE purchase_orders
          SET status = 'refunded',
              refunded_at = DATETIME('now', 'localtime'),
              refund_amount = ?,
              refund_message = ?,
              invite_status = CASE WHEN order_scene = 'downstream' THEN '已退款' ELSE invite_status END,
              redeem_error = CASE WHEN order_scene = 'downstream' THEN NULL ELSE redeem_error END,
              updated_at = DATETIME('now', 'localtime')
          WHERE order_no = ?
        `,
        [refund.refundAmount, successMsg, orderNo]
      )
      saveDatabase()
      return { ok: true, message: successMsg, refund }
    })

    if (!result.ok) return res.status(result.status || 400).json({ error: result.error, refund: result.refund || null })
    res.json({ message: result.message, refund: result.refund })
  } catch (error) {
    console.error('[Purchase] admin refund error:', error)
    res.status(500).json({ error: '退款失败' })
  }
})

export default router
