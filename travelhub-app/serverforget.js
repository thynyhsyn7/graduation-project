require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Connection String
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/travelhub';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.static('public'));

// Rate Limiting - Prevent brute force attacks
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts. Please try again after 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false,
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 registrations
    message: 'Too many accounts created. Please try again after 1 hour.',
});

const passwordResetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // 3 attempts
    message: 'Too many password reset requests. Please try again after 15 minutes.',
});

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'travelhub-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        touchAfter: 24 * 3600
    }),
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        httpOnly: true,
        secure: false, // set to true in production with HTTPS
        sameSite: 'lax'
    }
}));

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Email Transporter Configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verify email configuration
transporter.verify(function(error, success) {
    if (error) {
        console.error('❌ Email configuration error:', error);
    } else {
        console.log('✅ Email server is ready to send messages');
    }
});

// Enhanced User Schema with Email Verification and Password Reset
const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true
    },
    lastName: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        validate: [validator.isEmail, 'Invalid email address']
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    phone: {
        type: String,
        trim: true
    },
    country: {
        type: String,
        trim: true
    },
    // Email Verification Fields
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    emailVerificationToken: {
        type: String
    },
    emailVerificationExpires: {
        type: Date
    },
    // Password Reset Fields
    passwordResetToken: {
        type: String
    },
    passwordResetExpires: {
        type: Date
    },
    // Security Fields
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date
    },
    passwordChangedAt: {
        type: Date
    },
    // Timestamps
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    }
});

// Virtual for account locked
userSchema.virtual('isLocked').get(function() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        
        if (this.isModified('password') && !this.isNew) {
            this.passwordChangedAt = Date.now() - 1000;
        }
        
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $set: { loginAttempts: 1 },
            $unset: { lockUntil: 1 }
        });
    }
    
    const updates = { $inc: { loginAttempts: 1 } };
    const maxAttempts = 5;
    const lockTime = 2 * 60 * 60 * 1000; // 2 hours
    
    if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
        updates.$set = { lockUntil: Date.now() + lockTime };
    }
    
    return this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
    return this.updateOne({
        $set: { loginAttempts: 0 },
        $unset: { lockUntil: 1 }
    });
};

// Method to create email verification token
userSchema.methods.createEmailVerificationToken = function() {
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    this.emailVerificationToken = crypto
        .createHash('sha256')
        .update(verificationToken)
        .digest('hex');
    
    this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    
    return verificationToken;
};

// Method to create password reset token
userSchema.methods.createPasswordResetToken = function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    this.passwordResetToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
    
    this.passwordResetExpires = Date.now() + 60 * 60 * 1000; // 1 hour
    
    return resetToken;
};

const User = mongoose.model('User', userSchema);

// ==================== EMAIL FUNCTIONS ====================

// Send verification email
async function sendVerificationEmail(user, verificationToken) {
    const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;
    
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: '✅ Verify Your TravelHub Account',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
                    .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🌍 Welcome to TravelHub!</h1>
                    </div>
                    <div class="content">
                        <h2>Hi ${user.firstName},</h2>
                        <p>Thank you for registering with TravelHub! We're excited to have you on board.</p>
                        <p>To complete your registration and verify your email address, please click the button below:</p>
                        <center>
                            <a href="${verificationUrl}" class="button">Verify Email Address</a>
                        </center>
                        <p>Or copy and paste this link in your browser:</p>
                        <p style="background: white; padding: 10px; border-radius: 5px; word-break: break-all;">${verificationUrl}</p>
                        <p><strong>This link will expire in 24 hours.</strong></p>
                        <p>If you didn't create an account with TravelHub, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 TravelHub. All rights reserved.</p>
                        <p>Created by Hussein Tarhini - Computer Science Graduation Project</p>
                    </div>
                </div>
            </body>
            </html>
        `
    };
    
    try {
        await transporter.sendMail(mailOptions);
        console.log('✅ Verification email sent to:', user.email);
        return true;
    } catch (error) {
        console.error('❌ Error sending verification email:', error);
        return false;
    }
}

// Send welcome email after verification
async function sendWelcomeEmail(user) {
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: '🎉 Welcome to TravelHub - Email Verified!',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
                    .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🎉 Email Verified Successfully!</h1>
                    </div>
                    <div class="content">
                        <h2>Welcome aboard, ${user.firstName}!</h2>
                        <p>Your email has been verified successfully. You can now enjoy all the features of TravelHub!</p>
                        <p>Start exploring amazing destinations, book your dream vacation, and create unforgettable memories.</p>
                        <center>
                            <a href="${process.env.BASE_URL}/login" class="button">Login to Your Account</a>
                        </center>
                        <p>Happy travels! 🌍✈️</p>
                    </div>
                </div>
            </body>
            </html>
        `
    };
    
    try {
        await transporter.sendMail(mailOptions);
        console.log('✅ Welcome email sent to:', user.email);
    } catch (error) {
        console.error('❌ Error sending welcome email:', error);
    }
}

// Send login notification email
async function sendLoginNotification(user) {
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: '🔐 New Login to Your TravelHub Account',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
                    .alert { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Login Notification</h1>
                    </div>
                    <div class="content">
                        <h2>Hi ${user.firstName},</h2>
                        <p>We detected a new login to your TravelHub account.</p>
                        <p><strong>Login Details:</strong></p>
                        <ul>
                            <li>Time: ${new Date().toLocaleString()}</li>
                            <li>Email: ${user.email}</li>
                        </ul>
                        <div class="alert">
                            <strong>⚠️ Didn't log in?</strong><br>
                            If this wasn't you, please secure your account immediately by changing your password.
                        </div>
                    </div>
                </div>
            </body>
            </html>
        `
    };
    
    try {
        await transporter.sendMail(mailOptions);
        console.log('✅ Login notification sent to:', user.email);
    } catch (error) {
        console.error('❌ Error sending login notification:', error);
    }
}

// Send password reset email
async function sendPasswordResetEmail(user, resetToken) {
    const resetUrl = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
    
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: '🔑 Password Reset Request - TravelHub',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
                    .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .alert { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔑 Password Reset Request</h1>
                    </div>
                    <div class="content">
                        <h2>Hi ${user.firstName},</h2>
                        <p>We received a request to reset your password for your TravelHub account.</p>
                        <p>Click the button below to reset your password:</p>
                        <center>
                            <a href="${resetUrl}" class="button">Reset Password</a>
                        </center>
                        <p>Or copy and paste this link in your browser:</p>
                        <p style="background: white; padding: 10px; border-radius: 5px; word-break: break-all;">${resetUrl}</p>
                        <p><strong>This link will expire in 1 hour.</strong></p>
                        <div class="alert">
                            <strong>⚠️ Important:</strong><br>
                            If you didn't request a password reset, please ignore this email. Your password will remain unchanged.
                        </div>
                        <p>For security reasons, this link can only be used once.</p>
                    </div>
                    <div class="footer">
                        <p>© 2025 TravelHub. All rights reserved.</p>
                        <p>Created by Hussein Tarhini - Computer Science Graduation Project</p>
                    </div>
                </div>
            </body>
            </html>
        `
    };
    
    try {
        await transporter.sendMail(mailOptions);
        console.log('✅ Password reset email sent to:', user.email);
        return true;
    } catch (error) {
        console.error('❌ Error sending password reset email:', error);
        return false;
    }
}

// Send password changed confirmation email
async function sendPasswordChangedEmail(user) {
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: '✅ Password Changed Successfully - TravelHub',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
                    .success { background: #d1fae5; border-left: 4px solid #10b981; padding: 15px; margin: 20px 0; }
                    .alert { background: #fee2e2; border-left: 4px solid #ef4444; padding: 15px; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>✅ Password Changed</h1>
                    </div>
                    <div class="content">
                        <h2>Hi ${user.firstName},</h2>
                        <div class="success">
                            <strong>Success!</strong><br>
                            Your password has been changed successfully.
                        </div>
                        <p><strong>Change Details:</strong></p>
                        <ul>
                            <li>Time: ${new Date().toLocaleString()}</li>
                            <li>Email: ${user.email}</li>
                        </ul>
                        <div class="alert">
                            <strong>⚠️ Didn't change your password?</strong><br>
                            If you didn't make this change, please contact us immediately. Your account may have been compromised.
                        </div>
                        <p>You can now log in with your new password.</p>
                    </div>
                </div>
            </body>
            </html>
        `
    };
    
    try {
        await transporter.sendMail(mailOptions);
        console.log('✅ Password changed confirmation sent to:', user.email);
    } catch (error) {
        console.error('❌ Error sending password changed email:', error);
    }
}

// ==================== ROUTES ====================

// Root route - Redirect to login
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Login page
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Register page
app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Forgot password page
app.get('/forgot-password', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

// Reset password page
app.get('/reset-password', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// Email verification page
app.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        
        if (!token) {
            return res.send(`
                <html>
                <head>
                    <style>
                        body { font-family: Arial; text-align: center; padding: 50px; }
                        .error { color: #ef4444; }
                    </style>
                </head>
                <body>
                    <h1 class="error">❌ Invalid Verification Link</h1>
                    <p>The verification link is invalid or has expired.</p>
                    <a href="/register">Go to Registration</a>
                </body>
                </html>
            `);
        }
        
        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');
        
        const user = await User.findOne({
            emailVerificationToken: hashedToken,
            emailVerificationExpires: { $gt: Date.now() }
        });
        
        if (!user) {
            return res.send(`
                <html>
                <head>
                    <style>
                        body { font-family: Arial; text-align: center; padding: 50px; }
                        .error { color: #ef4444; }
                    </style>
                </head>
                <body>
                    <h1 class="error">❌ Invalid or Expired Token</h1>
                    <p>The verification link is invalid or has expired.</p>
                    <a href="/register">Register Again</a>
                </body>
                </html>
            `);
        }
        
        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        await user.save();
        
        await sendWelcomeEmail(user);
        
        res.send(`
            <html>
            <head>
                <style>
                    body { font-family: Arial; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
                    .success { background: white; color: #10b981; padding: 50px; border-radius: 20px; max-width: 500px; margin: 0 auto; }
                    .button { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
                </style>
            </head>
            <body>
                <div class="success">
                    <h1>✅ Email Verified Successfully!</h1>
                    <p>Your email has been verified. You can now login to your account.</p>
                    <a href="/login" class="button">Go to Login</a>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).send('Error verifying email');
    }
});

// Dashboard page (protected)
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Check authentication status
app.get('/api/auth/check', (req, res) => {
    if (req.session.userId) {
        res.json({ 
            authenticated: true, 
            userId: req.session.userId,
            userName: req.session.userName 
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Registration endpoint with email verification
app.post('/api/auth/register', registerLimiter, async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword, phone, country } = req.body;

        if (!firstName || !lastName || !email || !password || !confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'All required fields must be filled' 
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please provide a valid email address' 
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Passwords do not match' 
            });
        }

        if (password.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 8 characters long' 
            });
        }

        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/.test(password)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number' 
            });
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email already registered' 
            });
        }

        const user = new User({
            firstName,
            lastName,
            email: email.toLowerCase(),
            password,
            phone,
            country
        });

        const verificationToken = user.createEmailVerificationToken();
        await user.save();

        const emailSent = await sendVerificationEmail(user, verificationToken);

        if (!emailSent) {
            return res.status(500).json({
                success: false,
                message: 'User created but failed to send verification email. Please try again later.'
            });
        }

        res.json({ 
            success: true, 
            message: 'Registration successful! Please check your email to verify your account.',
            requiresVerification: true,
            email: user.email
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error. Please try again later.' 
        });
    }
});

// Resend verification email
app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'No account found with this email'
            });
        }

        if (user.isEmailVerified) {
            return res.status(400).json({
                success: false,
                message: 'Email is already verified'
            });
        }

        const verificationToken = user.createEmailVerificationToken();
        await user.save();

        await sendVerificationEmail(user, verificationToken);

        res.json({
            success: true,
            message: 'Verification email sent! Please check your inbox.'
        });
    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Login endpoint with security
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { email, password, remember } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        if (user.isLocked) {
            return res.status(423).json({
                success: false,
                message: 'Account is temporarily locked due to too many failed login attempts. Please try again later.'
            });
        }

        const isMatch = await user.comparePassword(password);
        
        if (!isMatch) {
            await user.incLoginAttempts();
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }

        if (!user.isEmailVerified) {
            return res.status(403).json({
                success: false,
                message: 'Please verify your email address before logging in. Check your inbox for the verification link.',
                requiresVerification: true,
                email: user.email
            });
        }

        if (user.loginAttempts > 0) {
            await user.resetLoginAttempts();
        }

        user.lastLogin = new Date();
        await user.save();

        req.session.userId = user._id;
        req.session.userName = `${user.firstName} ${user.lastName}`;
        req.session.userEmail = user.email;

        if (remember) {
            req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30; // 30 days
        }

        await sendLoginNotification(user);

        res.json({ 
            success: true, 
            message: 'Login successful!',
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error. Please try again later.' 
        });
    }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', passwordResetLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });

        // Don't reveal if user exists or not (security best practice)
        if (!user) {
            return res.json({
                success: true,
                message: 'If an account exists with this email, you will receive a password reset link shortly.'
            });
        }

        // Generate reset token
        const resetToken = user.createPasswordResetToken();
        await user.save({ validateBeforeSave: false });

        // Send reset email
        const emailSent = await sendPasswordResetEmail(user, resetToken);

        if (!emailSent) {
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save({ validateBeforeSave: false });

            return res.status(500).json({
                success: false,
                message: 'Error sending email. Please try again later.'
            });
        }

        res.json({
            success: true,
            message: 'If an account exists with this email, you will receive a password reset link shortly.'
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, password, confirmPassword } = req.body;

        if (!token || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }

        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/.test(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
            });
        }

        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }

        // Update password
        user.password = password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        user.passwordChangedAt = Date.now();
        await user.save();

        // Send confirmation email
        await sendPasswordChangedEmail(user);

        res.json({
            success: true,
            message: 'Password reset successful! You can now login with your new password.'
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ 
                success: false, 
                message: 'Logout failed' 
            });
        }
        res.clearCookie('connect.sid');
        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    });
});

// Get user profile
app.get('/api/user/profile', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ 
            success: false, 
            message: 'Not authenticated' 
        });
    }

    try {
        const user = await User.findById(req.session.userId).select('-password');
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        res.json({ 
            success: true, 
            user: {
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                phone: user.phone,
                country: user.country,
                isEmailVerified: user.isEmailVerified,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }
        });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log('');
    console.log('====================================');
    console.log('🚀 TravelHub Server Started');
    console.log('====================================');
    console.log('✅ MongoDB Connected');
    console.log(`📧 Email Service: ${process.env.EMAIL_USER}`);
    console.log(`🌐 Server: http://localhost:${PORT}`);
    console.log(`📝 Login: http://localhost:${PORT}/login`);
    console.log(`📝 Register: http://localhost:${PORT}/register`);
    console.log(`🔑 Forgot Password: http://localhost:${PORT}/forgot-password`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log('====================================');
    console.log('');
});