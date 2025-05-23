import express from "express"
import dotenv from "dotenv"
import jwt from "jsonwebtoken"
import cors from "cors"
import rateLimit from "express-rate-limit"
import bcrypt from "bcryptjs"
import helmet from "helmet"
import bunyan from 'bunyan'
import rfs from 'rotating-file-stream'
import { blacklistToken, cleanupExpiredTokens } from './utils/token-blacklist.js'

// Load environment variables
dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

// Enable trust proxy
app.set('trust proxy', 1); // Trust the first proxy

// Create Bunyan logger
const logger = bunyan.createLogger({
  name: 'auth-api',
  streams: [
    {
      level: 'error',
      stream: rfs.createStream('error.log', {
        size: '10M', // rotate every 10 Megabytes written
        compress: 'gzip', // compress rotated files
        maxFiles: 10 // keep 10 rotated files
      })
    }
  ]
})

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'USER1_USERNAME', 'USER1_PASSWORD', 'USER2_USERNAME', 'USER2_PASSWORD']
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    logger.error(`Missing required environment variable: ${varName}`)
    process.exit(1)
  }
})

// Validate JWT secret
if (process.env.JWT_SECRET === 'secret') {
  logger.error('JWT_SECRET is using default value. Please set a strong secret key.')
  process.exit(1)
}

// Middleware
app.use(express.json({ limit: '50kb' }))
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false
}))
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost'];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    // Allow if origin matches any allowed origin (case-insensitive)
    if (allowedOrigins.some(o => o.toLowerCase() === origin.toLowerCase())) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Configure rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per hour
  message: "Too many requests from this IP, please try again after 1 hour",
  standardHeaders: true,
  legacyHeaders: true
})

// Apply rate limiting to all requests
app.use(limiter)

// Get credentials from environment variables
const users = [
  {
    username: process.env.USER1_USERNAME,
    password: process.env.USER1_PASSWORD,
  },
  {
    username: process.env.USER2_USERNAME,
    password: process.env.USER2_PASSWORD,
  },
]

// Filter out any undefined users (in case some env vars aren't set)
const validUsers = users.filter((user) => user.username && user.password)

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is required")
}

// Hash passwords for all users
const hashedUsers = await Promise.all(validUsers.map(async user => {
  const hashedPassword = await bcrypt.hash(user.password, 10)
  return {
    username: user.username,
    password: hashedPassword
  }
}))

// Authentication endpoint with enhanced security
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body
    logger.info(`Login attempt for user: ${username}`)

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" })
    }

    // Find user
    const user = hashedUsers.find(u => u.username === username)

    if (!user) {
      logger.warn(`Login attempt failed - user not found: ${username}`)
      return res.status(401).json({ message: "Invalid credentials" })
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword) {
      logger.warn(`Login attempt failed - invalid password for user: ${username}`)
      return res.status(401).json({ message: "Invalid credentials" })
    }

    // Generate JWT token
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { 
      expiresIn: "1h",
      algorithm: "HS256"
    })

    logger.info(`Successful login for user: ${username}`)
    res.json({
      token,
      user: { username: user.username }
    })
  } catch (error) {
    logger.error(`Login error: ${error.message}`)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Middleware to verify JWT with enhanced security
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ message: "Authentication required" })
  }

  jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }, (err, user) => {
    if (err) {
      logger.warn(`JWT verification failed: ${err.message}`)
      return res.status(403).json({ message: "Invalid or expired token" })
    }
    req.user = user
    next()
  })
}

// Middleware to check referrer with enhanced security
const checkReferrer = (req, res, next) => {
  const referer = req.headers.referer
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000']

  // Check if referer exists and is in allowed list
  if (!referer || !allowedOrigins.some(origin => referer.startsWith(origin))) {
    logger.warn(`Referrer check failed: ${referer}`)
    return res.status(403).json({
      message: "Access denied. Unauthorized origin"
    })
  }

  next()
}

// Protected route with referrer check
app.get("/api/protected", authenticateToken, checkReferrer, (req, res) => {
  res.json({
    message: "Protected content",
    user: req.user.username,
  })
})

// User info route (doesn't require referrer check)
app.get("/api/user", authenticateToken, (req, res) => {
  res.json({
    username: req.user.username,
    isAuthenticated: true,
  })
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString()
  })
})

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Error: ${err.message}`, { stack: err.stack })
  res.status(500).json({
    message: "Internal server error"
  })
})

// Logout endpoint
app.post('/api/logout', authenticateToken, (req, res) => {
  try {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
      return res.status(400).json({ message: "No token provided" })
    }

    blacklistToken(token)
    logger.info(`User ${req.user.username} logged out successfully`)
    res.json({ message: "Successfully logged out" })
  } catch (error) {
    logger.error(`Logout error: ${error.message}`)
    res.status(500).json({ message: "Internal server error" })
  }
})

// Start server
app.listen(PORT, () => {
  logger.info(`Server is running on port ${PORT}`)
  cleanupExpiredTokens() // Run initial cleanup
})