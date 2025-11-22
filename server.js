const express = require('express');
const app = express();
const { MongoClient, ObjectId } = require('mongodb');
const session = require('express-session');
const formidable = require('express-formidable');
const methodOverride = require('method-override');
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(formidable());
app.use(session({
    secret: process.env.SESSION_SECRET || 'comps381f-2025-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' } // Render 用 HTTPS
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

const uri = process.env.MONGODB_URI || 'mongodb+srv://123:123456dllm@cluster0.xovjzrh.mongodb.net/flightdb';
const client = new MongoClient(uri);
const dbName = 'flightdb';
let db;

client.connect().then(() => {
    db = client.db(dbName);
    console.log('MongoDB connected');
}).catch(err => console.error('MongoDB connection error:', err));

// Middleware
const requireLogin = (req, res, next) => {
    if (req.session.user) next();
    else res.redirect('/login');
};

// === Google OAuth ===
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID || '687093134190-btasb8hs3bg050cqm5muna8kokjeat8c.apps.googleusercontent.com',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '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',
    callbackURL: (process.env.RENDER_EXTERNAL_URL || 'http://localhost:3000') + '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    let user = await db.collection('users').findOne({ googleId: profile.id });
    if (!user) {
        user = {
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            userId: 'google_' + Date.now(),
            createdAt: new Date()
        };
        await db.collection('users').insertOne(user);
    }
    return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.userId));
passport.deserializeUser(async (id, done) => {
    const user = await db.collection('users').findOne({ userId: id });
    done(null, user);
});

// === Register & Login ===
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
    const { username, password, name } = req.fields;
    if (!username || !password || !name) return res.render('register', { error: 'All fields required' });
    const existing = await db.collection('users').findOne({ username });
    if (existing) return res.render('register', { error: 'Username exists' });
    const hash = await bcrypt.hash(password, 10);
    const user = { username, password: hash, name, userId: 'u' + Date.now() };
    await db.collection('users').insertOne(user);
    res.render('login', { error: 'Registered! Please login.' });
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
    const { username, password } = req.fields;
    const user = await db.collection('users').findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = { id: user.userId, name: user.name };
        res.redirect('/list');
    } else {
        res.render('login', { error: 'Invalid credentials' });
    }
});

// Google Login Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        req.session.user = { id: req.user.userId, name: req.user.name };
        res.redirect('/list');
    }
);

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

// === CRUD Web ===
app.get('/list', requireLogin, async (req, res) => {
    const flights = await db.collection('flights').find({ userid: req.session.user.id }).sort({ createdAt: -1 }).toArray();
    res.render('list', { flights, user: req.session.user, success: req.query.success });
});

app.get('/details', requireLogin, async (req, res) => {
    const flight = await db.collection('flights').findOne({ _id: new ObjectId(req.query._id), userid: req.session.user.id });
    if (!flight) return res.render('info', { message: 'Flight not found', user: req.session.user });
    res.render('details', { flight, user: req.session.user });
});

app.post('/flights', requireLogin, async (req, res) => {
    const newFlight = {
        userid: req.session.user.id,
        flightNumber: req.fields.flightNumber,
        destination: req.fields.destination,
        hours: req.fields.hours,
        minutes: req.fields.minutes,
        gate: req.fields.gate || 'N/A',
        status: req.fields.status || 'On Time',
        airline: req.fields.airline || '',
        departureAirport: req.fields.departureAirport || '',
        arrivalAirport: req.fields.arrivalAirport || '',
        departureTime: req.fields.departureTime || '',
        createdAt: new Date()
    };
    if (req.files?.filetoupload?.size > 0) {
        const data = await fs.readFile(req.files.filetoupload.path);
        newFlight.photo = data.toString('base64');
    }
    await db.collection('flights').insertOne(newFlight);
    res.redirect('/list?success=Flight added successfully');
});

app.get('/edit', requireLogin, async (req, res) => {
    const flight = await db.collection('flights').findOne({ _id: new ObjectId(req.query._id), userid: req.session.user.id });
    if (!flight) return res.render('info', { message: 'Access denied', user: req.session.user });
    res.render('edit', { flight, user: req.session.user });
});

app.put('/flights/:id', requireLogin, async (req, res) => {
    const update = { $set: req.fields };
    if (req.files?.filetoupload?.size > 0) {
        const data = await fs.readFile(req.files.filetoupload.path);
        update.$set.photo = data.toString('base64');
    }
    await db.collection('flights').updateOne({ _id: new ObjectId(req.params.id), userid: req.session.user.id }, update);
    res.redirect('/list?success=Flight updated');
});

app.delete('/flights/:flightNumber', requireLogin, async (req, res) => {
    await db.collection('flights').deleteOne({ flightNumber: req.params.flightNumber, userid: req.session.user.id });
    res.redirect('/list?success=Flight deleted');
});

// === RESTful API ===
app.post('/api/flights', requireLogin, async (req, res) => {
    const doc = { ...req.fields, userid: req.session.user.id };
    if (req.files?.filetoupload) {
        const data = await fs.readFile(req.files.filetoupload.path);
        doc.photo = data.toString('base64');
    }
    const result = await db.collection('flights').insertOne(doc);
    res.json({ success: true, id: result.insertedId });
});

app.get('/api/flights', requireLogin, async (req, res) => {
    const flights = await db.collection('flights').find({ userid: req.session.user.id }).toArray();
    res.json(flights);
});

app.get('/api/flights/:flightNumber', requireLogin, async (req, res) => {
    const flight = await db.collection('flights').findOne({ flightNumber: req.params.flightNumber, userid: req.session.user.id });
    res.json(flight || { error: 'Not found' });
});

app.put('/api/flights/:flightNumber', requireLogin, async (req, res) => {
    const update = { $set: req.fields };
    if (req.files?.filetoupload) {
        const data = await fs.readFile(req.files.filetoupload.path);
        update.$set.photo = data.toString('base64');
    }
    const result = await db.collection('flights').updateOne({ flightNumber: req.params.flightNumber, userid: req.session.user.id }, update);
    res.json({ success: result.modifiedCount > 0 });
});

app.delete('/api/flights/:flightNumber', requireLogin, async (req, res) => {
    const result = await db.collection('flights').deleteOne({ flightNumber: req.params.flightNumber, userid: req.session.user.id });
    res.json({ success: result.deletedCount > 0 });
});

// === API Test Page ===
app.get('/api-test', requireLogin, (req, res) => res.render('api-test', { user: req.session.user }));

app.get('/', requireLogin, (req, res) => res.redirect('/list'));
app.get('*', (req, res) => res.render('info', { message: 'Page not found', user: req.session.user || null }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
