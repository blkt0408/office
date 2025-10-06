const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cron = require('node-cron');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve HTML/CSS/JS from 'public' folder
app.use(multer({ dest: 'uploads/' }).single('docUpload')); // For file uploads

mongoose.connect('mongodb://localhost:27017/companyhub', { useNewUrlParser: true });

// Schemas (Users, Projects, Attendance, etc.)
const userSchema = new mongoose.Schema({
    name: String, email: { type: String, unique: true }, phone: String, address: String,
    password: String, role: { type: String, enum: ['hr', 'employee', 'customer'] },
    documents: String, verified: { type: Boolean, default: false }, // Path to uploaded doc
    attendance: [{ date: Date, timeIn: Date, timeOut: Date, worksDone: Number }]
});
const User = mongoose.model('User', userSchema);

const projectSchema = new mongoose.Schema({
    name: String, progress: { type: Number, default: 0 }, // % complete
    details: String, photos: [String]
});
const Project = mongoose.model('Project', projectSchema);

// Signup (Save details, hash password, verify via email simulation)
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, phone, address, password, role } = req.body;
        const hashedPw = await bcrypt.hash(password, 10);
        const docPath = req.file ? req.file.path : null;
        const user = new User({ name, email, phone, address, password: hashedPw, role, documents: docPath });
        await user.save();
        // Simulate verification (send email in production)
        user.verified = true;
        await user.save();
        res.json({ message: 'Signup successful! Verified.' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Login (Verify ID/Password)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password) || !user.verified) {
        return res.status(401).json({ error: 'Invalid credentials or unverified.' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, 'secretkey'); // Use env var in prod
    res.json({ token, role: user.role, message: 'Logged in!' });
});

// HR-Only: Edit Interface (e.g., Company Aim)
app.post('/api/edit-aim', authenticateToken, async (req, res) => {
    if (req.user.role !== 'hr') return res.status(403).json({ error: 'HR only' });
    // Update DB (e.g., a Settings collection) and serve dynamic content
    res.json({ message: 'Updated!' });
});

// Employee Photo Post
app.post('/api/post-photo', authenticateToken, async (req, res) => {
    if (req.user.role !== 'employee') return res.status(403).json({ error: 'Employees only' });
    // Save photo to DB/Project, HR approves later
    res.json({ message: 'Photo posted!' });
});

// Daily Progress Update (Cron Job - Runs every day at midnight)
cron.schedule('0 0 * * *', async () => {
    const projects = await Project.find();
    projects.forEach(async (proj) => {
        // Simulate update: e.g., increment progress by 5-10%
        proj.progress = Math.min(100, proj.progress + Math.random() * 10);
        await proj.save();
    });
    console.log('Daily progress updated!');
});

// Attendance Tracking (On login, log timeIn; on logout, timeOut)
app.post('/api/track-attendance', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id);
    user.attendance.push({ date: new Date(), timeIn: new Date(), worksDone: 0 }); // Update worksDone via API calls
    await user.save();
    // Monthly report: Query attendance for last 