const mongoose = require('mongoose');

const conn = async () => {
    const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/podcaster';
    try {
        await mongoose.connect(uri);
        console.log("MongoDB is connected successfully: " + uri);
    } catch (error) {
        console.warn("Primary MongoDB connection failed (" + error.message + "). Trying local fallback (127.0.0.1:27017)...");
        try {
            await mongoose.connect('mongodb://127.0.0.1:27017/podcaster');
            console.log("Connected to local fallback MongoDB.");
        } catch (fallbackError) {
            console.error("MongoDB fallback connection failed: ", fallbackError.message);
        }
    }
};

conn();

module.exports = conn;