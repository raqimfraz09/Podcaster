const router = require('express').Router();
const authMiddleware = require('../middleware/authMiddleware');
const multer = require('multer');
const Blog = require('../models/blog');

// Storage for blog cover images
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, `blog-${Date.now()}-${file.originalname}`);
    },
});

const upload = multer({ storage: storage }).single('coverImage');

// Add Blog
router.post('/add-blog', authMiddleware, (req, res, next) => {
    upload(req, res, function (err) {
        if (err) {
            return res.status(400).json({ message: "File upload error", error: err.message });
        }
        next();
    });
}, async (req, res) => {
    try {
        const { title, content, summary, category, tags, readTime } = req.body;
        const user = req.user;

        if (!title || !content) {
            return res.status(400).json({ error: "Title and content are required." });
        }

        let coverImage = '';
        if (req.file) {
            coverImage = req.file.path;
        } else if (req.body.coverImage) {
            coverImage = req.body.coverImage;
        }

        const calculatedReadTime = readTime || `${Math.max(1, Math.ceil(content.split(/\s+/).length / 180))} min read`;

        const parsedTags = Array.isArray(tags)
            ? tags
            : (typeof tags === 'string' && tags.trim().length > 0 ? tags.split(',').map(t => t.trim()) : []);

        const newBlog = new Blog({
            title,
            content,
            summary: summary || (content.length > 160 ? content.slice(0, 160) + '...' : content),
            coverImage,
            category: category || 'General',
            tags: parsedTags,
            readTime: calculatedReadTime,
            user: user._id,
        });

        await newBlog.save();
        return res.status(201).json({
            message: "Blog published successfully!",
            data: newBlog,
        });
    } catch (error) {
        console.error("Error creating blog:", error);
        return res.status(500).json({ message: "Failed to create blog", error: error.message });
    }
});

// Get All Blogs
router.get('/get-blogs', async (req, res) => {
    try {
        const blogs = await Blog.find()
            .populate('user', 'username email')
            .sort({ createdAt: -1 });
        return res.status(200).json({ data: blogs });
    } catch (error) {
        console.error("Error fetching blogs:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Get User Blogs
router.get('/get-user-blogs', authMiddleware, async (req, res) => {
    try {
        const blogs = await Blog.find({ user: req.user._id })
            .populate('user', 'username email')
            .sort({ createdAt: -1 });
        return res.status(200).json({ data: blogs });
    } catch (error) {
        console.error("Error fetching user blogs:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Get Blog by ID
router.get('/get-blogs/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const blog = await Blog.findById(id).populate('user', 'username email');
        if (!blog) {
            return res.status(404).json({ message: "Blog not found" });
        }
        return res.status(200).json({ data: blog });
    } catch (error) {
        console.error("Error fetching blog details:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

// Delete Blog
router.delete('/delete-blog/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const blog = await Blog.findById(id);
        if (!blog) {
            return res.status(404).json({ message: "Blog not found" });
        }
        if (blog.user.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: "Unauthorized to delete this blog" });
        }
        await Blog.findByIdAndDelete(id);
        return res.status(200).json({ message: "Blog deleted successfully" });
    } catch (error) {
        console.error("Error deleting blog:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

module.exports = router;
