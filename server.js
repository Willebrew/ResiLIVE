/**
 * @file server.js
 * @description This file contains the main server code for the application, including routes, middleware, and utility functions.
 */
require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cookieSession = require('cookie-session');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const path = require('path');
const RateLimit = require('express-rate-limit');
const lusca = require('lusca');
const axios = require('axios'); // Added axios
const https = require('https'); // Added https module
const app = express();
const port = 3000;
const cors = require('cors');
const lastAccessTimes = {};

// VERCEL_URL constant
const VERCEL_URL = process.env.VERCEL_URL || 'http://localhost:3000';

// Initialize Firebase
admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL
    }),
    databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`
});

// Create the Firestore instance
const db = admin.firestore();

// Initialize collections after the database is created
const collections = {
    users: db.collection('users'),
    communities: db.collection('communities'),
    accessLogs: db.collection('access_logs')
};

// Rate limiter configurations
const generalLimiter = RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // max 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const strictLimiter = RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // max 5 attempts per windowMs
    message: 'Too many attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = RateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // max 30 requests per minute
    message: 'API rate limit exceeded.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.set('trust proxy', 1);

// Enforce HTTPS in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// Middleware setup
app.use(express.json());
app.use(express.static('public', {
    index: false
}));

// Add cookie-session configuration
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
    console.error('FATAL ERROR: SESSION_SECRET is not defined. Please set a strong, unique secret in your .env file.');
    console.error('Generate one using: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
    process.exit(1);
}

// API_SECRET_KEY configuration and validation
// IMPORTANT: For production, API_SECRET_KEY must be a strong, unique, randomly generated string.
// It should be different from other secrets like SESSION_SECRET.
const apiSecretKey = process.env.API_SECRET_KEY; // This is for general API access, not ResiLive
const commonApiPlaceholders = ['YOUR_API_SECRET_KEY_HERE', 'changeme', 'secret', 'ENTER_YOUR_API_KEY'];

if (process.env.NODE_ENV === 'production') {
    if (!apiSecretKey || apiSecretKey.trim() === '' || commonApiPlaceholders.includes(apiSecretKey)) {
        console.error('FATAL ERROR: API_SECRET_KEY is not defined, is empty, or uses a common placeholder in production. Please set a strong, unique secret in your .env file.');
        process.exit(1); // Exit the application
    }
} else {
    // In development, if API_SECRET_KEY is not set or is a placeholder, log a warning
    if (!apiSecretKey || commonApiPlaceholders.includes(apiSecretKey)) {
        console.warn('WARNING: API_SECRET_KEY is not set or is using a placeholder. For production, ensure a strong, unique secret is set in your .env file.');
    }
}

// The RESILIVE_API_KEY block has been removed as per instructions.
// The existing apiSecretKey (process.env.API_SECRET_KEY) will be used.

app.use(cookieSession({
    name: 'session',
    keys: [sessionSecret],
    maxAge: 30 * 60 * 1000, // 30 minutes
    rolling: true, // Reset maxAge on every response
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict' // Changed from 'lax' to 'strict' for better security
}));

// Security Headers Middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce; // Make nonce available for templates if needed

    const cspDirectives = [
        "default-src 'self'",
        `script-src-elem 'self' https://cdn.jsdelivr.net 'nonce-${nonce}'`, // Allow self and scripts with the correct nonce
        "style-src 'self' https://cdn.jsdelivr.net 'sha256-lOLzuHiC/tzyOWpOjSY2MqilBHMQkoUoON+GTXvMbi0='",
        `style-src-elem 'self' https://cdn.jsdelivr.net 'nonce-${nonce}'`,  // Allow self and styles with the correct nonce
        "img-src 'self' data:",              // Allow images from self and data URIs
        "font-src 'self' https://www.perplexity.ai data:", // Allow fonts from self, perplexity.ai, and data URIs
        "object-src 'none'",                 // Disallow plugins (Flash, etc.)
        "frame-ancestors 'none'",            // Disallow embedding in iframes
        "connect-src 'self' https://*.firebaseio.com wss://*.firebaseio.com" // Allowed connection sources
    ];
    res.setHeader('Content-Security-Policy', cspDirectives.join('; '));

    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    next();
});

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'];
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
}));

// Input Validation Utilities
const validators = {
    username: (value) => {
        if (typeof value !== 'string') return false;
        return /^[a-zA-Z0-9_]{3,20}$/.test(value);
    },
    password: (value) => {
        if (typeof value !== 'string') return false;
        // Minimum 12 characters, at least one uppercase, one lowercase, one number, one special char
        return value.length >= 12 &&
               /[A-Z]/.test(value) &&
               /[a-z]/.test(value) &&
               /[0-9]/.test(value) &&
               /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value);
    },
    communityName: (value) => {
        if (typeof value !== 'string') return false;
        return /^[a-zA-Z0-9\s\-]{3,50}$/.test(value.trim());
    },
    streetAddress: (value) => {
        if (typeof value !== 'string') return false;
        return value.trim().length >= 3 && value.trim().length <= 100;
    },
    playerId: (value) => {
        if (typeof value !== 'string') return false;
        return /^[a-zA-Z0-9\-_]{1,50}$/.test(value);
    },
    accessCode: (value) => {
        if (typeof value !== 'string') return false;
        return /^[0-9]{4,8}$/.test(value);
    },
    description: (value) => {
        if (typeof value !== 'string') return false;
        return value.trim().length >= 1 && value.trim().length <= 200;
    }
};

// Sanitization function to prevent XSS
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return input.replace(/[<>\"']/g, (char) => {
        const entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;'
        };
        return entities[char];
    });
};

// Apply rate limiting to all API routes
app.use('/api', apiLimiter);

// Apply CSRF protection to all other routes
app.use((req, res, next) => {
    if (req.path !== '/api/log-access') {
        lusca.csrf()(req, res, next);
    } else {
        next();
    }
});

// Route to update a community's remote gate control status
app.put('/api/communities/:communityId/remote-gate-control', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { communityId } = req.params;
        const { enabled } = req.body; // Expecting 'enabled' from the client-side code

        // Validation for enabled
        if (typeof enabled !== 'boolean') {
            return res.status(400).json({ error: 'enabled field is required and must be a boolean.' });
        }

        const communityRef = db.collection('communities').doc(communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        await communityRef.update({
            remoteGateControlEnabled: enabled, // Update the correct field name
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Fetch the updated document to include in the response
        const updatedCommunityDoc = await communityRef.get();

        res.status(200).json({
            message: 'Remote gate control status updated successfully',
            community: { id: updatedCommunityDoc.id, ...updatedCommunityDoc.data() }
        });

    } catch (error) {
        // console.error('Error updating remote gate control status:', error); // errorHandler already logs
        errorHandler(res, error, 'Error updating remote gate control status');
    }
});

// Route to update a community's name
app.put('/api/communities/:communityId/name', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { communityId } = req.params;
        const { name } = req.body;

        // Validation for name
        if (!validators.communityName(name)) {
            return res.status(400).json({ 
                error: 'Invalid community name. Must be 3-50 characters, alphanumeric, spaces, and hyphens only.' 
            });
        }

        // Check for duplicate name (excluding the current community if its name isn't changing)
        const communitiesRef = db.collection('communities');
        const snapshot = await communitiesRef.where('name', '==', name.trim()).get();
        
        let duplicateExists = false;
        if (!snapshot.empty) {
            snapshot.forEach(doc => {
                if (doc.id !== communityId) { // If a different community has this name
                    duplicateExists = true;
                }
            });
        }
        if (duplicateExists) {
            return res.status(409).json({ error: 'A community with this name already exists.' });
        }

        const communityRef = db.collection('communities').doc(communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        await communityRef.update({
            name: name,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Fetch the updated document to include in the response
        const updatedCommunityDoc = await communityRef.get();
        const responseCommunityData = { 
            id: updatedCommunityDoc.id, 
            ...updatedCommunityDoc.data(),
            // Ensure createdAt and updatedAt are consistently formatted if needed,
            // Firestore timestamps are objects, convert to ISO string for client if necessary.
            // For now, sending what Firestore returns is fine.
        };


        res.status(200).json({
            message: 'Community name updated successfully',
            community: responseCommunityData
        });

    } catch (error) {
        // console.error('Error updating community name:', error); // errorHandler already logs
        errorHandler(res, error, 'Error updating community name');
    }
});

// Route to open a gate
app.post('/api/command/open-gate', requireAuth, async (req, res) => {
    const { community, address } = req.body; // address is optional

    if (!community) {
        return res.status(400).json({ error: 'Community is required' });
    }

    // Validate user's access to the community
    try {
        const communitySnapshot = await db.collection('communities')
            .where('name', '==', community)
            .get();

        if (communitySnapshot.empty) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityDoc = communitySnapshot.docs[0];
        const communityData = communityDoc.data();

        // Check if user is admin/superuser or if user is in allowedUsers for this community
        const isAdminOrSuperuser = req.session.userRole === 'admin' || req.session.userRole === 'superuser';
        const isAllowedUser = communityData.allowedUsers && communityData.allowedUsers.includes(req.session.username);

        if (!isAdminOrSuperuser && !isAllowedUser) {
            return res.status(403).json({ error: 'You do not have permission to send commands to this community.' });
        }

        // If address is provided, validate it belongs to the community (optional enhancement, depends on Roblox script needs)
        // For now, we'll pass it directly to sendCommandToRoblox

        const success = await sendCommandToRoblox('open_gate', community, address);

        if (success) {
            // Log the successful command attempt
            let logMessage;
            if (address) {
                logMessage = `Sent command: open_gate (Address: ${address})`;
            } else {
                logMessage = `Sent command: open_gate for community`;
            }
            await logAccess(community, req.session.username, logMessage);
            res.json({ message: 'Gate command sent successfully' });
        } else {
            res.json({ message: 'Gate command sent successfully' });
        }
    } catch (error) {
        console.error('Error processing open-gate command:', error);
        res.status(500).json({ error: 'Internal server error while sending gate command' });
    }
});

// Route for pairing mode (10 second relay hold for RFID tag pairing)
app.post('/api/command/pairing-mode', requireAuth, async (req, res) => {
    const { community, address } = req.body;

    if (!community || !address) {
        return res.status(400).json({ error: 'Community and address are required for pairing mode' });
    }

    try {
        const communitySnapshot = await db.collection('communities')
            .where('name', '==', community)
            .get();

        if (communitySnapshot.empty) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityDoc = communitySnapshot.docs[0];
        const communityData = communityDoc.data();

        // Check if user is admin/superuser or if user is in allowedUsers for this community
        const isAdminOrSuperuser = req.session.userRole === 'admin' || req.session.userRole === 'superuser';
        const isAllowedUser = communityData.allowedUsers && communityData.allowedUsers.includes(req.session.username);

        if (!isAdminOrSuperuser && !isAllowedUser) {
            return res.status(403).json({ error: 'You do not have permission to activate pairing mode for this community.' });
        }

        const success = await sendCommandToRoblox('pairing_mode', community, address);

        if (success) {
            await logAccess(community, req.session.username, `Pairing mode activated (Address: ${address})`);
            res.json({ message: 'Pairing mode activated successfully' });
        } else {
            res.json({ message: 'Pairing mode command sent' });
        }
    } catch (error) {
        console.error('Error processing pairing-mode command:', error);
        res.status(500).json({ error: 'Internal server error while activating pairing mode' });
    }
});

// Route to get CSRF token
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

/**
 * SECURITY: Initial superuser creation has been removed.
 * To create an initial admin user, use the secure setup script or admin CLI tool.
 * Never use hardcoded credentials in production.
 */

/**
 * Reads data from a specified file.
 * @param {string} collection - The path to the file.
 * @returns {Promise<Object>} The parsed JSON data from the file.
 */
async function readData(collection) {
    try {
        const snapshot = await collections[collection].get();
        const data = {};
        data[collection] = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        return data;
    } catch (error) {
        console.error(`Error reading ${collection}:`, error);
        return { [collection]: [] };
    }
}

/**
 * Writes data to a specified file.
 * @param {string} collection - The path to the file.
 * @param {Object} data - The data to write to the file.
 */
async function writeData(collection, data) {
    try {
        const batch = db.batch();

        // Delete existing data
        const existingDocs = await collections[collection].get();
        existingDocs.docs.forEach(doc => {
            batch.delete(doc.ref);
        });

        // Add new data
        data[collection].forEach(item => {
            const docRef = collections[collection].doc(item.id);
            batch.set(docRef, item);
        });

        await batch.commit();
    } catch (error) {
        console.error(`Error writing to ${collection}:`, error);
        throw error;
    }
}

/**
 * Handles errors by logging them and sending a response with a 500 status code.
 * @param {Object} res - The response object.
 * @param {Error} error - The error object.
 * @param {string} message - The error message to send in the response.
 */
function errorHandler(res, error, message) {
    console.error(`${message}:`, error);
    res.status(500).json({ error: message });
}

/**
 * Middleware to require authentication.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function.
 */
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

/**
 * Middleware to require admin access.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function.
 */
function requireAdmin(req, res, next) {
    if (req.session.userId && (req.session.userRole === 'admin' || req.session.userRole === 'superuser')) {
        next();
    } else {
        res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    }
}

/**
 * Middleware to require API key authentication.
 * It checks for the 'x-api-key' header and validates it against the API_SECRET_KEY.
 * IMPORTANT: API_SECRET_KEY must be a strong, unique, randomly generated string for production.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function.
 */
function requireApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key']; // Or 'Authorization' if you prefer Bearer tokens
    // Use the validated apiSecretKey from the startup check
    if (apiKey && apiSecretKey && apiKey === apiSecretKey) {
        next();
    } else {
        // Generic error message to avoid leaking information about the key's existence
        res.status(401).json({ error: 'Unauthorized. Invalid or missing API Key.' });
    }
}

// Route to register a new user
app.post('/api/register', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Input validation
        if (!validators.username(username)) {
            return res.status(400).json({ 
                error: 'Invalid username. Must be 3-20 characters, alphanumeric and underscores only.' 
            });
        }
        
        if (!validators.password(password)) {
            return res.status(400).json({ 
                error: 'Password must be at least 12 characters with uppercase, lowercase, number, and special character.' 
            });
        }
        
        const usersRef = db.collection('users');

        const existingUser = await usersRef
            .where('username', '==', username)
            .get();

        if (!existingUser.empty) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: crypto.randomBytes(16).toString('hex'),
            username: sanitizeInput(username),
            password: hashedPassword,
            role: 'user',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await usersRef.doc(newUser.id).set(newUser);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error registering user');
    }
});

/**
 * Adds a community to the access logs.
 * @param {string} communityName - The name of the community.
 */
async function addCommunityToAccessLogs(communityName) {
    try {
        let logs = await readData('access_logs');
        if (!logs.communities) {
            logs.communities = [];
        }
        if (!logs.communities.some(c => c.name === communityName)) {
            logs.communities.push({ name: communityName, logs: [] });
            await writeData('access_logs', logs);
        }
    } catch (error) {
        console.error('Error adding community to access logs:', error);
    }
}

/**
 * Removes a community from the access logs.
 * @param {string} communityName - The name of the community.
 */
async function removeCommunityFromAccessLogs(communityName) {
    try {
        let logs = await readData('access_logs');
        if (logs.communities) {
            logs.communities = logs.communities.filter(c => c.name !== communityName);
            await writeData('access_logs', logs);
        }
    } catch (error) {
        console.error('Error removing community from access logs:', error);
    }
}

// Route to log in a user
app.post('/api/login', strictLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Input validation
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        if (typeof username !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ error: 'Invalid input format' });
        }
        
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('username', '==', username).get();

        if (snapshot.empty) {
            // Use same error message to prevent username enumeration
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();
        const isValidPassword = await bcrypt.compare(password, userData.password);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Set session data directly
        req.session.userId = userDoc.id;
        req.session.username = userData.username;
        req.session.userRole = userData.role;

        res.json({
            message: 'Logged in successfully',
            user: {
                username: userData.username,
                role: userData.role,
                theme: userData.theme || 'dark'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Error during login' });
    }
});

// Route to log out a user
app.post('/api/logout', (req, res) => {
    req.session = null;
    res.json({ message: 'Logged out successfully' });
});

// Route to add a new community
app.post('/api/communities', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { name } = req.body;
        
        // Input validation
        if (!validators.communityName(name)) {
            return res.status(400).json({ 
                error: 'Invalid community name. Must be 3-50 characters, alphanumeric, spaces, and hyphens only.' 
            });
        }
        
        // Get all communities to check count
        const snapshot = await db.collection('communities').get();
        if (snapshot.size >= 8) {
            return res.status(400).json({ error: 'Maximum number of communities (8) reached' });
        }
        
        // Check for duplicate names
        const duplicateCheck = await db.collection('communities')
            .where('name', '==', name.trim())
            .get();
        
        if (!duplicateCheck.empty) {
            return res.status(409).json({ error: 'A community with this name already exists' });
        }

        // Create new community
        const newCommunity = {
            name: sanitizeInput(name.trim()),
            addresses: [],
            allowedUsers: req.body.allowedUsers || [],
            remoteGateControlEnabled: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        // Add to Firestore and get the reference
        const docRef = await db.collection('communities').add(newCommunity);

        // Get the created document
        const createdDoc = await docRef.get();
        const communityData = {
            id: docRef.id,
            ...createdDoc.data()
        };

        // Return the complete community data
        res.status(201).json({
            message: 'Community added successfully',
            community: communityData
        });
    } catch (error) {
        console.error('Error adding community:', error);
        res.status(500).json({ error: 'Error adding community' });
    }
});

// Route to delete a community
app.delete('/api/communities/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const communityName = communityData.name;

        // Start a batch write
        const batch = db.batch();

        // Delete the community
        batch.delete(communityRef);

        // Get all access logs for this community
        const logsSnapshot = await db.collection('access_logs')
            .where('community', '==', communityName)
            .get();

        // Add all log deletions to the batch
        logsSnapshot.docs.forEach(doc => {
            batch.delete(doc.ref);
        });

        // Commit the batch (deletes community and all its logs atomically)
        await batch.commit();

        res.status(200).json({ message: 'Community and associated logs deleted successfully' });
    } catch (error) {
        console.error('Error deleting community:', error);
        res.status(500).json({ error: 'Error deleting community' });
    }
});

// Route to get all communities visible to the authenticated user
app.get('/api/communities', requireAuth, async (req, res) => {
    try {
        const snapshot = await db.collection('communities').get();
        const communities = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // Filter communities based on user role
        const visibleCommunities = communities.filter(community => {
            if (req.session.userRole === 'admin' || req.session.userRole === 'superuser') {
                return true;
            }
            return community.allowedUsers.includes(req.session.username);
        });

        res.json(visibleCommunities);
    } catch (error) {
        console.error('Error fetching communities:', error);
        res.status(500).json({ error: 'Error fetching communities' });
    }
});

// Route to check if the user is authenticated
app.get('/api/check-auth', async (req, res) => {
    if (req.session.userId) {
        try {
            // Fetch user's theme preference
            const userRef = db.collection('users').doc(req.session.userId);
            const userDoc = await userRef.get();
            const userData = userDoc.exists ? userDoc.data() : {};
            
            res.json({
                authenticated: true,
                userId: req.session.userId,
                username: req.session.username,
                role: req.session.userRole,
                theme: userData.theme || 'dark' // Include theme with default
            });
        } catch (error) {
            console.error('Error in check-auth:', error);
            // Still return auth info even if theme fetch fails
            res.json({
                authenticated: true,
                userId: req.session.userId,
                username: req.session.username,
                role: req.session.userRole,
                theme: 'dark' // Default theme on error
            });
        }
    } else {
        res.status(401).json({ authenticated: false });
    }
});

// Get all users (admin only)
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('users').get();
        const users = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            password: undefined
        }));
        res.json(users);
    } catch (error) {
        errorHandler(res, error, 'Error fetching users');
    }
});

// Add a new user (admin only)
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Input validation
        if (!validators.username(username)) {
            return res.status(400).json({ 
                error: 'Invalid username. Must be 3-20 characters, alphanumeric and underscores only.' 
            });
        }
        
        if (!validators.password(password)) {
            return res.status(400).json({ 
                error: 'Password must be at least 12 characters with uppercase, lowercase, number, and special character.' 
            });
        }

        const existingUser = await db.collection('users')
            .where('username', '==', username)
            .get();

        if (!existingUser.empty) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            username: sanitizeInput(username),
            password: hashedPassword,
            role: 'user',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('users').add(newUser);
        res.status(201).json({ message: 'User added successfully', id: docRef.id });
    } catch (error) {
        errorHandler(res, error, 'Error adding user');
    }
});

// Remove a user (admin only)
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const userRef = db.collection('users').doc(req.params.id);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userData = userDoc.data();

        // Prevent removal of superuser
        if (userData.role === 'superuser') {
            return res.status(403).json({ error: 'Cannot remove superuser account' });
        }

        // Remove user from all communities' allowedUsers arrays
        const communitiesSnapshot = await db.collection('communities').get();
        const batch = db.batch();

        communitiesSnapshot.docs.forEach(doc => {
            const community = doc.data();
            if (community.allowedUsers && community.allowedUsers.includes(userData.username)) {
                const updatedAllowedUsers = community.allowedUsers.filter(
                    username => username !== userData.username
                );
                batch.update(doc.ref, { allowedUsers: updatedAllowedUsers });
            }
        });

        // Delete the user
        batch.delete(userRef);

        // Commit all changes
        await batch.commit();

        res.json({
            message: 'User removed successfully',
            updatedCommunities: communitiesSnapshot.docs
                .map(doc => ({
                    id: doc.id,
                    ...doc.data()
                }))
                .filter(community => community.allowedUsers &&
                    community.allowedUsers.includes(userData.username))
        });

    } catch (error) {
        console.error('Error removing user:', error);
        res.status(500).json({ error: 'Error removing user' });
    }
});

// Route to add a new user by an admin
app.post('/api/admin/add-user', requireAuth, async (req, res) => {
    try {
        if (req.session.userRole !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
        }

        const { username, password } = req.body;
        let users = await readData('users');

        if (!users.users) {
            users.users = [];
        }

        if (users.users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { id: Date.now().toString(), username, password: hashedPassword };
        users.users.push(newUser);
        await writeData('users', users);

        res.status(201).json({ message: 'User added successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error adding user');
    }
});

app.post('/api/change-password', requireAuth, strictLimiter, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        // Input validation
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new passwords are required' });
        }
        
        if (!validators.password(newPassword)) {
            return res.status(400).json({ 
                error: 'New password must be at least 12 characters with uppercase, lowercase, number, and special character.' 
            });
        }
        
        // Prevent reusing the same password
        if (currentPassword === newPassword) {
            return res.status(400).json({ error: 'New password must be different from current password' });
        }
        
        const userRef = db.collection('users').doc(req.session.userId);
        const userDoc = await userRef.get();
        
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userData = userDoc.data();

        if (!(await bcrypt.compare(currentPassword, userData.password))) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await userRef.update({ 
            password: hashedPassword,
            passwordChangedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error changing password');
    }
});

// Route to delete a community (duplicate, should be removed)
app.delete('/api/communities/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        await db.collection('communities').doc(req.params.id).delete();
        res.sendStatus(204);
    } catch (error) {
        errorHandler(res, error, 'Error removing community');
    }
});

// Route to update allowed users for a community
app.put('/api/communities/:id/allowed-users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { allowedUsers } = req.body;
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        // Get all users to validate against
        const usersSnapshot = await db.collection('users').get();
        const users = usersSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        const validUsers = [];
        const invalidUsers = [];

        // Validate each user
        for (const username of allowedUsers) {
            // Find user with exact case match
            const user = users.find(u => u.username === username);
            if (user && user.role !== 'admin' && user.role !== 'superuser') {
                // Add the username
                if (!validUsers.includes(user.username)) {
                    validUsers.push(user.username);
                }
            } else {
                invalidUsers.push(username);
            }
        }

        // Update the community with valid users
        await communityRef.update({
            allowedUsers: validUsers,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        if (invalidUsers.length > 0) {
            res.status(200).json({
                warning: `The following users were not added: ${invalidUsers.join(', ')}`,
                validUsers
            });
        } else {
            res.status(200).json({
                message: 'Allowed users updated successfully',
                validUsers
            });
        }
    } catch (error) {
        console.error('Error updating allowed users:', error);
        res.status(500).json({ error: 'Error updating allowed users' });
    }
});

// Route to toggle user role (admin only)
app.put('/api/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
    try {
        const targetUserId = req.params.id;

        // Prevent self-modification
        if (targetUserId === req.session.userId) {
            return res.status(403).json({ error: 'Cannot modify your own role' });
        }

        // Get user document reference
        const userRef = db.collection('users').doc(targetUserId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userData = userDoc.data();

        // Prevent modifying superuser
        if (userData.role === 'superuser') {
            return res.status(403).json({ error: 'Cannot modify superuser role' });
        }

        // Toggle role
        const newRole = userData.role === 'admin' ? 'user' : 'admin';

        // Update user role
        await userRef.update({ role: newRole });

        // If user is being made admin, remove them from all communities' allowed users
        if (newRole === 'admin') {
            const communitiesSnapshot = await db.collection('communities').get();
            const batch = db.batch();

            communitiesSnapshot.docs.forEach(doc => {
                const community = doc.data();
                if (community.allowedUsers && community.allowedUsers.includes(userData.username)) {
                    const updatedAllowedUsers = community.allowedUsers.filter(
                        username => username !== userData.username
                    );
                    batch.update(doc.ref, { allowedUsers: updatedAllowedUsers });
                }
            });

            await batch.commit();
        }

        res.json({
            message: 'User role updated successfully',
            newRole: newRole,
            username: userData.username
        });
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ error: 'Error updating user role' });
    }
});

// Route to get addresses for a community
app.get('/api/communities/:id/addresses', requireAuth, async (req, res) => {
    try {
        const jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.id);
        if (community) {
            res.json(community.addresses);
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error reading addresses');
    }
});

// Route to add an address to a community
app.post('/api/communities/:id/addresses', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const addresses = communityData.addresses || [];

        // Create new address
        const newAddress = {
            id: Date.now().toString(),
            street: req.body.street,
            hasGate: typeof req.body.hasGate === 'boolean' ? req.body.hasGate : false, // Added this line
            people: [],
            codes: [],
            createdAt: new Date().toISOString() // Use ISO string instead of serverTimestamp
        };

        // Add new address to the array
        addresses.push(newAddress);

        // Update the community document with the new addresses array
        await communityRef.update({
            addresses: addresses,
            updatedAt: admin.firestore.FieldValue.serverTimestamp() // Add timestamp to the root document
        });

        // Return the new address
        res.status(201).json(newAddress);
    } catch (error) {
        console.error('Error adding address:', error);
        res.status(500).json({ error: 'Error adding address' });
    }
});

// Route to delete an address from a community
app.delete('/api/communities/:id/addresses/:addressId', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const addresses = communityData.addresses || [];

        // Filter out the address to delete
        const updatedAddresses = addresses.filter(addr => addr.id !== req.params.addressId);

        // Update the community document with the new addresses array
        await communityRef.update({
            addresses: updatedAddresses,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ message: 'Address deleted successfully' });
    } catch (error) {
        console.error('Error deleting address:', error);
        res.status(500).json({ error: 'Error deleting address' });
    }
});

/**
 * Logs access to a community by a player.
 * @param {string} communityName - The name of the community.
 * @param {string} playerName - The name of the player.
 * @param {string} action - The action performed by the player.
 */
async function logAccess(communityName, playerName, action) {
    try {
        await db.collection('access_logs').add({
            community: communityName,
            player: playerName,
            action: action,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
    } catch (error) {
        console.error('Error logging access:', error);
    }
}

/**
 * Sends a command to the Roblox game server.
 * @param {string} command - The command to send (e.g., "open_gate").
 * @param {string} community - The name of the community.
 * @param {string} [address] - Optional: The specific address within the community.
 * @returns {Promise<boolean>} True if the command was sent successfully, false otherwise.
 */
async function sendCommandToRoblox(command, community, address) {
    // Write command to Firestore - Pi listens in real-time
    const payload = {
        command,
        community,
        address: address || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    try {
        console.log(`Sending command via Firestore: ${JSON.stringify({ command, community, address })}`);
        const docRef = await db.collection('commands').add(payload);
        console.log(`Command written to Firestore with ID: ${docRef.id}`);

        // Auto-cleanup: delete command after 30 seconds (gives Pi time to process)
        setTimeout(async () => {
            try {
                await docRef.delete();
                console.log(`Auto-deleted command ${docRef.id} after 30s`);
            } catch (err) {
                // Command may already be deleted by Pi - that's fine
                if (err.code !== 5) { // 5 = NOT_FOUND
                    console.error(`Failed to auto-delete command ${docRef.id}:`, err.message);
                }
            }
        }, 30000);

        return true;
    } catch (error) {
        console.error('Error sending command to Firestore:', error.message);
        return false;
    }
}

// Route to log access to a community
app.post('/api/log-access', requireApiKey, async (req, res) => {
    const { community, player, action } = req.body;

    try {
        const communityRef = await db.collection('communities')
            .where('name', '==', community)
            .get();

        if (communityRef.empty) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const currentTime = Date.now();
        const lastAccessKey = `${community}-${player}`;
        const lastAccessTime = lastAccessTimes[lastAccessKey] || 0;

        if (currentTime - lastAccessTime < 5000) {
            return res.status(429).json({ error: 'Access attempt too soon. Please wait 5 seconds between attempts.' });
        }

        lastAccessTimes[lastAccessKey] = currentTime;

        await db.collection('access_logs').add({
            community,
            player,
            action,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ message: 'Access logged successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error logging access');
    }
});

// Route to add a person to an address in a community
app.post('/api/communities/:communityId/addresses/:addressId/people', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }

        const newPerson = {
            id: Date.now().toString(),
            username: req.body.username,
            playerId: req.body.playerId
        };

        // Add the new person to the address's people array
        if (!address.people) {
            address.people = [];
        }
        address.people.push(newPerson);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(201).json(newPerson);
    } catch (error) {
        console.error('Error adding person:', error);
        res.status(500).json({ error: 'Error adding person' });
    }
});

// Route to delete a person from an address in a community
app.delete('/api/communities/:communityId/addresses/:addressId/people/:personId', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }

        // Remove the person from the address's people array
        address.people = address.people.filter(person => person.id !== req.params.personId);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(200).json({ message: 'Person removed successfully' });
    } catch (error) {
        console.error('Error removing person:', error);
        res.status(500).json({ error: 'Error removing person' });
    }
});

// Route to add a code to an address in a community
app.post('/api/communities/:communityId/addresses/:addressId/codes', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }

        const newCode = {
            id: Date.now().toString(),
            description: req.body.description,
            code: req.body.code,
            expiresAt: req.body.expiresAt
        };

        // Add the new code to the address's codes array
        if (!address.codes) {
            address.codes = [];
        }
        address.codes.push(newCode);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(201).json(newCode);
    } catch (error) {
        console.error('Error adding code:', error);
        res.status(500).json({ error: 'Error adding code' });
    }
});

// Route to delete a code from an address in a community
app.delete('/api/communities/:communityId/addresses/:addressId/codes/:codeId', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address || !address.codes) {
            return res.status(404).json({ error: 'Address or codes not found' });
        }

        // Remove the code from the address's codes array
        address.codes = address.codes.filter(code => code.id !== req.params.codeId);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(200).json({ message: 'Code removed successfully' });
    } catch (error) {
        console.error('Error removing code:', error);
        res.status(500).json({ error: 'Error removing code' });
    }
});

// Route to get logs for a community
app.get('/api/logs/today-count', requireAuth, async (req, res) => {
    try {
        // Get today's start and end timestamps
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);
        
        // Query Firestore for today's logs count
        const logsSnapshot = await db.collection('access_logs')
            .where('timestamp', '>=', admin.firestore.Timestamp.fromDate(today))
            .where('timestamp', '<', admin.firestore.Timestamp.fromDate(tomorrow))
            .get();
        
        res.json({ count: logsSnapshot.size });
    } catch (error) {
        console.error('Error fetching today\'s access count:', error);
        res.status(500).json({ error: 'Failed to fetch access count' });
    }
});

app.get('/api/communities/:name/logs', requireAuth, async (req, res) => {
    const communityName = req.params.name;
    try {
        // Query Firestore for logs
        const logsSnapshot = await db.collection('access_logs')
            .where('community', '==', communityName)
            .orderBy('timestamp', 'desc')
            .limit(100) // Limit to last 100 logs
            .get();

        const logs = logsSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            timestamp: doc.data().timestamp?.toDate() // Convert Firestore Timestamp to JS Date
        }));

        res.json(logs);
    } catch (error) {
        console.error('Error retrieving logs:', error);
        res.status(500).json({ error: 'Error retrieving logs' });
    }
});

/**
 * Removes expired codes from all addresses in all communities.
 * This function reads the data from the specified data file, iterates through all communities and their addresses,
 * and filters out any codes that have expired. If any expired codes are found and removed, the updated data is written
 * back to the data file. The function logs a message to the console if expired codes are removed.
 * @async
 * @function removeExpiredCodes
 * @returns {Promise<void>}
 */
async function removeExpiredCodes() {
    try {
        let jsonData = await readData('communities');
        const now = new Date();
        let codesRemoved = false;

        jsonData.communities.forEach(community => {
            community.addresses.forEach(address => {
                if (address.codes) {
                    const initialLength = address.codes.length;
                    address.codes = address.codes.filter(code => {
                        // Keep codes with no expiration date (never expire)
                        if (!code.expiresAt) {
                            return true;
                        }
                        return new Date(code.expiresAt) > now;
                    });
                    if (address.codes.length < initialLength) {
                        codesRemoved = true;
                    }
                }
            });
        });

        if (codesRemoved) {
            await writeData('communities', jsonData);
            console.log('Expired codes removed');
        }
    } catch (error) {
        console.error('Error removing expired codes:', error);
    }
}

// Set interval to remove expired codes every 60 seconds
setInterval(removeExpiredCodes, 60000);

// Route to get user theme preference
app.get('/api/user/theme', requireAuth, async (req, res) => {
    try {
        const userRef = db.collection('users').doc(req.session.userId);
        const userDoc = await userRef.get();
        
        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userData = userDoc.data();
        res.json({ theme: userData.theme || 'dark' }); // Default to dark theme
    } catch (error) {
        console.error('Error fetching user theme:', error);
        res.status(500).json({ error: 'Error fetching theme preference' });
    }
});

// Route to update user theme preference
app.put('/api/user/theme', requireAuth, async (req, res) => {
    try {
        const { theme } = req.body;
        
        // Validate theme
        const validThemes = ['dark', 'light', 'ocean', 'forest'];
        if (!validThemes.includes(theme)) {
            return res.status(400).json({ error: 'Invalid theme' });
        }
        
        const userRef = db.collection('users').doc(req.session.userId);
        await userRef.update({ theme });
        
        res.json({ message: 'Theme updated successfully', theme });
    } catch (error) {
        console.error('Error updating user theme:', error);
        res.status(500).json({ error: 'Error updating theme preference' });
    }
});

// Route to serve the main API data file
app.get('/api', generalLimiter, requireApiKey, async (req, res) => {
    try {
        const snapshot = await db.collection('communities').get();
        const communities = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        res.json({ communities });
    } catch (error) {
        console.error('Error fetching communities:', error);
        res.status(500).json({ error: 'Error fetching data' });
    }
});

// Route to serve the login page
app.get('/', generalLimiter, (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route to serve the login page
app.get('/login.html', generalLimiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route to serve the index page
app.get('/index.html', generalLimiter, (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
