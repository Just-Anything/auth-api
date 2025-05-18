import { createLogger } from 'bunyan'

const logger = createLogger({
  name: 'token-blacklist'
})

// In-memory store for blacklisted tokens
// In production, consider using Redis or another persistent store
const blacklistedTokens = new Set()

// Add token to blacklist
export const blacklistToken = (token) => {
  blacklistedTokens.add(token)
  logger.info(`Token blacklisted: ${token.substring(0, 10)}...`) // Log only first 10 chars for security
}

// Check if token is blacklisted
export const isTokenBlacklisted = (token) => {
  return blacklistedTokens.has(token)
}

// Clean up expired tokens (run periodically)
export const cleanupExpiredTokens = () => {
  // In a real application, you'd implement actual cleanup logic here
  // For this example, we'll just log the cleanup
  logger.info('Cleaning up expired tokens')
}

// Export the blacklist for testing
export { blacklistedTokens }
