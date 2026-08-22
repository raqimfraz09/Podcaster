const mongoose = require('mongoose');

const blogSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true,
    },
    content: {
        type: String,
        required: true,
    },
    summary: {
        type: String,
        default: '',
    },
    coverImage: {
        type: String,
        default: '',
    },
    category: {
        type: String,
        default: 'General',
    },
    tags: [{
        type: String,
    }],
    readTime: {
        type: String,
        default: '4 min read',
    },
    user: {
        type: mongoose.Types.ObjectId,
        ref: 'user',
        required: true,
    },
}, { timestamps: true });

module.exports = mongoose.model('Blog', blogSchema);
