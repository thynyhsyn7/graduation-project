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

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/travelhub';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.static('public'));

// Session
app.use(session({
    secret: process.env.SESSION_SECRET || 'travelhub-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true, secure: false }
}));

// MongoDB Connection
mongoose.connect(MONGODB_URI)
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Error:', err));

// Email Setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// USER ROLES
const USER_ROLES = {
    ADMIN: 'admin',
    HOTEL_OWNER: 'hotel_owner',
    TICKET_OWNER: 'ticket_owner',
    TOUR_COMPANY: 'tour_company',
    CUSTOMER: 'customer'
};

// SCHEMAS
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    phone: String,
    country: String,
    role: { type: String, enum: Object.values(USER_ROLES), default: 'customer' },
    hotelName: String,
    hotelAddress: String,
    hotelLicense: String,
    airlineName: String,
    airlineLicense: String,
    companyName: String,
    companyLicense: String,
    companyAddress: String,
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: String,
    emailVerificationExpires: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    isActive: { type: Boolean, default: true },
    isApproved: { type: Boolean, default: function() { return this.role === 'customer'; } },
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

userSchema.methods.comparePassword = async function(pass) {
    return await bcrypt.compare(pass, this.password);
};

userSchema.methods.createEmailVerificationToken = function() {
    const token = crypto.randomBytes(32).toString('hex');
    this.emailVerificationToken = crypto.createHash('sha256').update(token).digest('hex');
    this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;
    return token;
};

const hotelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    address: String,
    city: String,
    country: String,
    stars: { type: Number, default: 3 },
    images: [String],
    amenities: [String],
    rooms: [{ type: String, price: Number, available: Number, maxGuests: Number }],
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const flightSchema = new mongoose.Schema({
    flightNumber: { type: String, required: true, unique: true },
    airline: { type: String, required: true },
    from: { type: String, required: true },
    to: { type: String, required: true },
    departureDate: { type: Date, required: true },
    departureTime: String,
    arrivalDate: Date,
    arrivalTime: String,
    price: { type: Number, required: true },
    availableSeats: { type: Number, required: true },
    totalSeats: Number,
    class: { type: String, default: 'Economy' },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const tourSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: String,
    destination: { type: String, required: true },
    duration: Number,
    price: { type: Number, required: true },
    maxPeople: Number,
    availableSpots: Number,
    startDate: Date,
    endDate: Date,
    includes: [String],
    images: [String],
    itinerary: [{ day: Number, title: String, description: String }],
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const bookingSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    bookingType: { type: String, enum: ['hotel', 'flight', 'tour'], required: true },
    hotel: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel' },
    roomType: String,
    checkIn: Date,
    checkOut: Date,
    guests: Number,
    flight: { type: mongoose.Schema.Types.ObjectId, ref: 'Flight' },
    passengers: Number,
    seatNumbers: [String],
    tour: { type: mongoose.Schema.Types.ObjectId, ref: 'Tour' },
    numberOfPeople: Number,
    totalPrice: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
    paymentStatus: { type: String, enum: ['pending', 'paid', 'refunded'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Hotel = mongoose.model('Hotel', hotelSchema);
const Flight = mongoose.model('Flight', flightSchema);
const Tour = mongoose.model('Tour', tourSchema);
const Booking = mongoose.model('Booking', bookingSchema);

// MIDDLEWARE
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) return next();
    res.status(401).json({ success: false, message: 'Please login' });
};

const hasRole = (...roles) => {
    return async (req, res, next) => {
        const user = await User.findById(req.session.userId);
        if (!user) return res.status(401).json({ success: false, message: 'User not found' });
        if (roles.includes(user.role)) { req.user = user; return next(); }
        res.status(403).json({ success: false, message: 'Access denied' });
    };
};

// EMAIL FUNCTION
async function sendVerificationEmail(user, token) {
    const url = `${process.env.BASE_URL || 'http://localhost:3000'}/verify-email?token=${token}`;
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Verify Your Email - TravelHub',
        html: `<h2>Hi ${user.firstName},</h2><p>Click to verify: <a href="${url}">Verify Email</a></p>`
    });
}

// ROUTES
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));

app.get('/verify-email', async (req, res) => {
    const hashedToken = crypto.createHash('sha256').update(req.query.token).digest('hex');
    const user = await User.findOne({ emailVerificationToken: hashedToken, emailVerificationExpires: { $gt: Date.now() } });
    if (!user) return res.send('<h1>Invalid or Expired Token</h1>');
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();
    res.send('<h1>✅ Email Verified! <a href="/login">Login</a></h1>');
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    const dashboards = { admin: 'admin-dashboard.html', hotel_owner: 'hotel-dashboard.html', ticket_owner: 'ticket-dashboard.html', tour_company: 'tour-dashboard.html', customer: 'customer-dashboard.html' };
    res.sendFile(path.join(__dirname, 'public', dashboards[user.role]));
});

// AUTH
app.post('/api/auth/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, role, hotelName, hotelAddress, hotelLicense, airlineName, airlineLicense, companyName, companyLicense, companyAddress } = req.body;
        if (await User.findOne({ email: email.toLowerCase() })) return res.status(400).json({ success: false, message: 'Email exists' });
        const user = new User({ firstName, lastName, email: email.toLowerCase(), password, role: role || 'customer', hotelName, hotelAddress, hotelLicense, airlineName, airlineLicense, companyName, companyLicense, companyAddress });
        const token = user.createEmailVerificationToken();
        await user.save();
        await sendVerificationEmail(user, token);
        res.json({ success: true, message: 'Check your email!' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email.toLowerCase() });
        if (!user || !(await user.comparePassword(req.body.password))) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        if (!user.isEmailVerified) return res.status(403).json({ success: false, message: 'Verify email first' });
        if (!user.isApproved && user.role !== 'customer') return res.status(403).json({ success: false, message: 'Pending approval' });
        if (!user.isActive) return res.status(403).json({ success: false, message: 'Account deactivated' });
        user.lastLogin = new Date();
        await user.save();
        req.session.userId = user._id;
        req.session.userRole = user.role;
        res.json({ success: true, user: { id: user._id, role: user.role, name: `${user.firstName} ${user.lastName}` } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Error' });
    }
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/user/profile', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId).select('-password');
    res.json({ success: true, user });
});

// ADMIN ROUTES
app.get('/api/admin/users', isAuthenticated, hasRole('admin'), async (req, res) => {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ success: true, users });
});

app.post('/api/admin/approve/:userId', isAuthenticated, hasRole('admin'), async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.userId, { isApproved: true }, { new: true });
    res.json({ success: true, user });
});

app.post('/api/admin/deactivate/:userId', isAuthenticated, hasRole('admin'), async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.userId, { isActive: false }, { new: true });
    res.json({ success: true, user });
});

app.post('/api/admin/activate/:userId', isAuthenticated, hasRole('admin'), async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.userId, { isActive: true }, { new: true }).select('-password');
    res.json({ success: true, message: 'User activated', user });
});

app.get('/api/admin/users/:userId', isAuthenticated, hasRole('admin'), async (req, res) => {
    const user = await User.findById(req.params.userId).select('-password');
    res.json({ success: true, user });
});

app.put('/api/admin/users/:userId', isAuthenticated, hasRole('admin'), async (req, res) => {
    const { firstName, lastName, email, phone, country, isActive, isApproved } = req.body;
    const updateData = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email.toLowerCase();
    if (phone) updateData.phone = phone;
    if (country) updateData.country = country;
    if (typeof isActive !== 'undefined') updateData.isActive = isActive;
    if (typeof isApproved !== 'undefined') updateData.isApproved = isApproved;
    const user = await User.findByIdAndUpdate(req.params.userId, updateData, { new: true }).select('-password');
    res.json({ success: true, message: 'User updated', user });
});

app.delete('/api/admin/users/:userId', isAuthenticated, hasRole('admin'), async (req, res) => {
    const user = await User.findByIdAndDelete(req.params.userId);
    if (user.role === 'hotel_owner') await Hotel.deleteMany({ owner: user._id });
    if (user.role === 'ticket_owner') await Flight.deleteMany({ owner: user._id });
    if (user.role === 'tour_company') await Tour.deleteMany({ owner: user._id });
    if (user.role === 'customer') await Booking.deleteMany({ user: user._id });
    res.json({ success: true, message: 'User deleted' });
});

app.get('/api/admin/bookings', isAuthenticated, hasRole('admin'), async (req, res) => {
    const bookings = await Booking.find().populate('user', 'firstName lastName email phone').populate('hotel', 'name').populate('flight', 'flightNumber from to').populate('tour', 'name destination').sort({ createdAt: -1 });
    res.json({ success: true, bookings });
});

// USER PROFILE ROUTES
app.post('/api/user/change-password', isAuthenticated, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ success: false, message: 'All fields required' });
    if (newPassword.length < 8) return res.status(400).json({ success: false, message: 'Password must be 8+ chars' });
    const user = await User.findById(req.session.userId);
    if (!(await user.comparePassword(currentPassword))) return res.status(401).json({ success: false, message: 'Wrong password' });
    user.password = newPassword;
    await user.save();
    res.json({ success: true, message: 'Password changed' });
});

app.put('/api/user/profile', isAuthenticated, async (req, res) => {
    const { firstName, lastName, email, phone, country } = req.body;
    const updateData = {};
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email.toLowerCase();
    if (phone) updateData.phone = phone;
    if (country) updateData.country = country;
    if (email) {
        const exists = await User.findOne({ email: email.toLowerCase(), _id: { $ne: req.session.userId } });
        if (exists) return res.status(400).json({ success: false, message: 'Email in use' });
    }
    const user = await User.findByIdAndUpdate(req.session.userId, updateData, { new: true }).select('-password');
    res.json({ success: true, message: 'Profile updated', user });
});

// HOTEL ROUTES
app.post('/api/hotels', isAuthenticated, hasRole('hotel_owner', 'admin'), async (req, res) => {
    const hotel = new Hotel({ ...req.body, owner: req.session.userId });
    await hotel.save();
    res.json({ success: true, hotel });
});

app.get('/api/hotels/my', isAuthenticated, hasRole('hotel_owner'), async (req, res) => {
    const hotels = await Hotel.find({ owner: req.session.userId });
    res.json({ success: true, hotels });
});

app.put('/api/hotels/:id', isAuthenticated, hasRole('hotel_owner', 'admin'), async (req, res) => {
    const hotel = await Hotel.findOneAndUpdate({ _id: req.params.id, owner: req.session.userId }, req.body, { new: true });
    res.json({ success: true, hotel });
});

app.delete('/api/hotels/:id', isAuthenticated, hasRole('hotel_owner', 'admin'), async (req, res) => {
    await Hotel.findOneAndDelete({ _id: req.params.id, owner: req.session.userId });
    res.json({ success: true });
});

app.get('/api/hotels/bookings', isAuthenticated, hasRole('hotel_owner'), async (req, res) => {
    const hotels = await Hotel.find({ owner: req.session.userId }).select('_id');
    const hotelIds = hotels.map(h => h._id);
    const bookings = await Booking.find({ hotel: { $in: hotelIds }, bookingType: 'hotel' }).populate('user', 'firstName lastName email phone').populate('hotel', 'name');
    res.json({ success: true, bookings });
});

app.get('/api/hotels', async (req, res) => {
    const hotels = await Hotel.find({ isActive: true });
    res.json({ success: true, hotels });
});

// FLIGHT ROUTES
app.post('/api/flights', isAuthenticated, hasRole('ticket_owner', 'admin'), async (req, res) => {
    const flight = new Flight({ ...req.body, owner: req.session.userId });
    await flight.save();
    res.json({ success: true, flight });
});

app.get('/api/flights/my', isAuthenticated, hasRole('ticket_owner'), async (req, res) => {
    const flights = await Flight.find({ owner: req.session.userId });
    res.json({ success: true, flights });
});

app.put('/api/flights/:id', isAuthenticated, hasRole('ticket_owner', 'admin'), async (req, res) => {
    const flight = await Flight.findOneAndUpdate({ _id: req.params.id, owner: req.session.userId }, req.body, { new: true });
    res.json({ success: true, flight });
});

app.get('/api/flights/bookings', isAuthenticated, hasRole('ticket_owner'), async (req, res) => {
    const flights = await Flight.find({ owner: req.session.userId }).select('_id');
    const flightIds = flights.map(f => f._id);
    const bookings = await Booking.find({ flight: { $in: flightIds }, bookingType: 'flight' }).populate('user', 'firstName lastName email phone').populate('flight', 'flightNumber from to');
    res.json({ success: true, bookings });
});

app.get('/api/flights', async (req, res) => {
    const flights = await Flight.find({ isActive: true });
    res.json({ success: true, flights });
});

// TOUR ROUTES
app.post('/api/tours', isAuthenticated, hasRole('tour_company', 'admin'), async (req, res) => {
    const tour = new Tour({ ...req.body, owner: req.session.userId });
    await tour.save();
    res.json({ success: true, tour });
});

app.get('/api/tours/my', isAuthenticated, hasRole('tour_company'), async (req, res) => {
    const tours = await Tour.find({ owner: req.session.userId });
    res.json({ success: true, tours });
});

app.put('/api/tours/:id', isAuthenticated, hasRole('tour_company', 'admin'), async (req, res) => {
    const tour = await Tour.findOneAndUpdate({ _id: req.params.id, owner: req.session.userId }, req.body, { new: true });
    res.json({ success: true, tour });
});

app.get('/api/tours/bookings', isAuthenticated, hasRole('tour_company'), async (req, res) => {
    const tours = await Tour.find({ owner: req.session.userId }).select('_id');
    const tourIds = tours.map(t => t._id);
    const bookings = await Booking.find({ tour: { $in: tourIds }, bookingType: 'tour' }).populate('user', 'firstName lastName email phone').populate('tour', 'name destination');
    res.json({ success: true, bookings });
});

app.get('/api/tours', async (req, res) => {
    const tours = await Tour.find({ isActive: true });
    res.json({ success: true, tours });
});

// BOOKING ROUTES
app.post('/api/bookings', isAuthenticated, hasRole('customer'), async (req, res) => {
    const booking = new Booking({ ...req.body, user: req.session.userId });
    await booking.save();
    res.json({ success: true, booking });
});

app.get('/api/bookings/my', isAuthenticated, hasRole('customer'), async (req, res) => {
    const bookings = await Booking.find({ user: req.session.userId }).populate('hotel', 'name address').populate('flight', 'flightNumber from to').populate('tour', 'name destination').sort({ createdAt: -1 });
    res.json({ success: true, bookings });
});

app.post('/api/bookings/:id/cancel', isAuthenticated, hasRole('customer'), async (req, res) => {
    const booking = await Booking.findOneAndUpdate({ _id: req.params.id, user: req.session.userId }, { status: 'cancelled' }, { new: true });
    res.json({ success: true, booking });
});

// START SERVER
app.listen(PORT, () => {
    console.log('');
    console.log('=================================');
    console.log('🚀 TravelHub Server Running');
    console.log('=================================');
    console.log(`🌐 http://localhost:${PORT}`);
    console.log('=================================');
});