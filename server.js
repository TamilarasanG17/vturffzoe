const express = require('express');
const mongoose = require('mongoose');
const City = require('./models/Cities.js'); 
const cors = require('cors'); 
const path = require('path');
const turfRoutes=require('./routes/turf.js')
const otpGenerator = require('otp-generator');
const bcrypt=require('bcryptjs')
const nodemailer=require('nodemailer')
require('dotenv').config();
const app = express();
app.use(cors())
app.use(express.json());
mongoose.connect(process.env.MONGODB_URI, {
})
.then(() => console.log('MongoDB connected'))
.catch((error) => console.error('MongoDB connection error:', error));

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/cities', async (req, res) => {
    const nameQuery = req.query.name || '';
    try {
        const cities = await City.find({ name: { $regex: nameQuery, $options: 'i' } }).select('name -_id');
        res.json(cities);
    } catch (error) {
        console.error('Error retrieving cities:', error);
        res.status(500).json({ message: 'Failed to retrieve cities' });
    }
});


app.use('/api', turfRoutes);

const bookingSchema = new mongoose.Schema({
    bookingId: { type: String, required: true, unique: true },
    turfName: { type: String, required: true },
    Name:{type:String,required:true},
    Email:{type:String,required:true},
    location: { type: String, required: true },
    date: { type: Date, required: true },
    timeSlot: { type: String, required: true },
    status: { type: String, required: true, enum: ['Confirmed', 'Completed', 'Cancelled'] },
    turfImageUrl: { type: String } 
});

const userSchema = new mongoose.Schema({
    username:{type:String},
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    otp: { type: String, default: '' },
    otpExpiry: { type: Date, default: null },
    bookings: [bookingSchema]
});



const User = mongoose.model('User', userSchema);


app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.json({ success: false, message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, specialChars: false });
    newUser.otp = otp;
    newUser.otpExpiry = Date.now() + 10 * 60000; 
    await newUser.save();

    let transporter = nodemailer.createTransport({
        service: 'gmail', 
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS
        }
    });

    let info = await transporter.sendMail({
        from: '"Turf Booking"',
        to: email,
        subject: 'OTP for Signup',
        text: `Your OTP is: ${otp}`
    });

    res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: 'User does not exist' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success: false, message: 'Incorrect password' });

    res.json({ success: true });
});

app.post('/api/forgot-password', async (req, res) => { 
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: 'User does not exist' });

    const otp = otpGenerator.generate(6, { digits: true, upperCaseAlphabets: false, specialChars: false });
    user.otp = otp;
    user.otpExpiry = Date.now() + 10 * 60000;
    await user.save();

    let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS
        }
    });

    let info = await transporter.sendMail({
        from: '"Turf Booking"',
        to: email,
        subject: 'OTP for Password Reset',
        text: `Your OTP for password reset is: ${otp}`
    });

    res.json({ success: true, message: 'OTP sent to email' });
});


app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    
    const user = await User.findOne({ email, otp });

    if (!user) {
        return res.json({ success: false, message: 'Invalid OTP' });
    }
    if (Date.now() > user.otpExpiry) {
        return res.json({ success: false, message: 'OTP expired' });
    }

    res.json({ success: true });
});

app.post('/api/reset-password', async (req, res) => { 
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.json({ success: false, message: 'User does not exist' });

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ success: true, message: 'Password reset successfully' });
});



const PORT = process.env.PORT||5000;
app.listen(PORT, () => {
    console.log(`Server is running on ${PORT}`);
});
