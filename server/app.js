const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();
require('./conn/conn');

const userApi = require('./routes/user');
const CatApi = require('./routes/categories');
const PodcastApi = require('./routes/podcast');
const BlogApi = require('./routes/blog');

const app = express();

// CORS configuration for local development & production
app.use(cors({
    origin: (origin, callback) => {
        // Allow all origins with credentials in development
        callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Static file serving for uploaded covers and audio
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Health route
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
});

// All API Routes
app.use("/api/v1", userApi);
app.use("/api/v1", CatApi);
app.use("/api/v1", PodcastApi);
app.use("/api/v1", BlogApi);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Podcaster Server is running on port : ${PORT}`);
});