const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
require('dotenv').config();

const User = require('./models/user');
const Category = require('./models/category');
const Podcast = require('./models/podcast');
const Blog = require('./models/blog');

// Ensure uploads dir exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Download helper
const downloadFile = (url, destPath) => {
    return new Promise((resolve, reject) => {
        if (fs.existsSync(destPath) && fs.statSync(destPath).size > 1000) {
            return resolve(destPath);
        }
        const file = fs.createWriteStream(destPath);
        const protocol = url.startsWith('https') ? https : http;
        protocol.get(url, (response) => {
            if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                return downloadFile(response.headers.location, destPath).then(resolve).catch(reject);
            }
            response.pipe(file);
            file.on('finish', () => {
                file.close(() => resolve(destPath));
            });
        }).on('error', (err) => {
            fs.unlink(destPath, () => {});
            reject(err);
        });
    });
};

const sampleAudioUrls = [
    { name: 'sample-track-1.mp3', url: 'https://cdn.freesound.org/previews/557/557194_11861866-lq.mp3' },
    { name: 'sample-track-2.mp3', url: 'https://cdn.freesound.org/previews/612/612610_11861866-lq.mp3' },
    { name: 'sample-track-3.mp3', url: 'https://cdn.freesound.org/previews/568/568600_11861866-lq.mp3' },
    { name: 'sample-track-4.mp3', url: 'https://cdn.freesound.org/previews/689/689369_11861866-lq.mp3' }
];

const seedData = async () => {
    try {
        const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/podcaster';
        await mongoose.connect(uri);
        console.log("Connected to Mongo for seeding");

        // 1. Create or get Demo User
        let demoUser = await User.findOne({ email: 'demo@podcaster.io' });
        if (!demoUser) {
            const salt = await bcrypt.genSalt(10);
            const hashedPass = await bcrypt.hash('password123', salt);
            demoUser = new User({
                username: 'alex_audio',
                email: 'demo@podcaster.io',
                password: hashedPass,
                podcasts: []
            });
            await demoUser.save();
            console.log("Created demo user: alex_audio (demo@podcaster.io / password123)");
        }

        // 2. Seed Categories
        const catNames = [
            "Tech & AI",
            "Business & Startups",
            "Comedy & Entertainment",
            "Health & Wellness",
            "Education & Science",
            "Music & Culture"
        ];
        const categoryMap = {};
        for (const name of catNames) {
            let cat = await Category.findOne({ categoryName: name });
            if (!cat) {
                cat = new Category({ categoryName: name, podcasts: [] });
                await cat.save();
            }
            categoryMap[name] = cat;
        }

        // 3. Download sample audio files
        const localAudioPaths = [];
        for (const sample of sampleAudioUrls) {
            const dest = path.join(uploadsDir, sample.name);
            try {
                await downloadFile(sample.url, dest);
                localAudioPaths.push(`uploads/${sample.name}`);
            } catch (e) {
                console.warn(`Could not download ${sample.url}: ${e.message}. Writing fallback audio placeholder.`);
                fs.writeFileSync(dest, 'AUDIO_DATA_PLACEHOLDER');
                localAudioPaths.push(`uploads/${sample.name}`);
            }
        }

        // 4. Seed sample podcasts if collection has few podcasts
        const existingCount = await Podcast.countDocuments();
        if (existingCount === 0) {
            const samplePodcasts = [
                {
                    title: "The AI Revolution: Autonomous Agents and Future Coding",
                    description: "An in-depth exploration into the breakthrough developments in reasoning models, neural architectures, and how developer workflows are fundamentally transforming across the tech landscape.",
                    category: categoryMap["Tech & AI"]._id,
                    frontImage: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=800&auto=format&fit=crop&q=80",
                    audioFile: localAudioPaths[0] || 'uploads/sample-track-1.mp3',
                    user: demoUser._id,
                },
                {
                    title: "Zero to One: Building Scalable SaaS in 2026",
                    description: "Join top venture builders and tech founders as they break down modern product market fit, organic growth loops, and architecting resilient microservices on modern cloud infrastructure.",
                    category: categoryMap["Business & Startups"]._id,
                    frontImage: "https://images.unsplash.com/photo-1557804506-669a67965ba0?w=800&auto=format&fit=crop&q=80",
                    audioFile: localAudioPaths[1] || 'uploads/sample-track-2.mp3',
                    user: demoUser._id,
                },
                {
                    title: "Midnight Comedy & Silicon Valley Confessions",
                    description: "A hilarious weekly look at the strangest pitch decks, startup fails, late night hackathons, and coffee-fueled debugging sessions with comedic guest hosts.",
                    category: categoryMap["Comedy & Entertainment"]._id,
                    frontImage: "https://images.unsplash.com/photo-1514525253161-7a46d19cd819?w=800&auto=format&fit=crop&q=80",
                    audioFile: localAudioPaths[2] || 'uploads/sample-track-3.mp3',
                    user: demoUser._id,
                },
                {
                    title: "Mind, Body & Focus: Science of High Performance",
                    description: "Neuroscientists and biohackers explore sleep optimization, circadian rhythms, active recovery, and mindfulness practices designed for busy makers and thinkers.",
                    category: categoryMap["Health & Wellness"]._id,
                    frontImage: "https://images.unsplash.com/photo-1506126613408-eca07ce68773?w=800&auto=format&fit=crop&q=80",
                    audioFile: localAudioPaths[3] || 'uploads/sample-track-4.mp3',
                    user: demoUser._id,
                }
            ];

            for (const podData of samplePodcasts) {
                const pod = new Podcast(podData);
                await pod.save();
                await User.findByIdAndUpdate(demoUser._id, { $push: { podcasts: pod._id } });
                await Category.findByIdAndUpdate(podData.category, { $push: { podcasts: pod._id } });
            }
            console.log("Seeded 4 rich sample podcasts.");
        }

        // 5. Seed sample blogs if empty
        const blogCount = await Blog.countDocuments();
        if (blogCount === 0) {
            const sampleBlogs = [
                {
                    title: "10 Audio Production Secrets Every Modern Podcaster Needs to Master",
                    summary: "From microphone acoustics and dynamic EQ to vocal compression curves, here are the production techniques that turn amateur recordings into broadcast-ready masterpieces.",
                    content: `Great audio quality is the single most important factor determining whether a first-time listener turns into a loyal subscriber.\n\n### 1. Acoustic Room Treatment Over Expensive Microphones\nMany creators make the mistake of buying a $1,000 microphone before treating their room. In reality, a $100 dynamic microphone in a treated room will dramatically outperform an expensive condenser microphone in an echoey space.\n\n### 2. The Power of Subtle Compression\nApplying multi-band compression helps tame sudden peaks while bringing up quiet vocal nuances without introducing digital distortion.\n\n### 3. Consistency in Loudness (LUFS)\nTargeting an integrated loudness of -16 to -14 LUFS ensures your episodes sound balanced across car stereos, smartphones, and high-end headphones.`,
                    category: "Tech & AI",
                    tags: ["audio", "production", "podcasting", "creator-tips"],
                    readTime: "5 min read",
                    coverImage: "https://images.unsplash.com/photo-1598488035139-bdbb2231ce04?w=800&auto=format&fit=crop&q=80",
                    user: demoUser._id,
                },
                {
                    title: "Monetizing Your Podcast in 2026: Beyond Traditional Sponsorships",
                    summary: "How modern podcasters are leveraging micro-communities, companion newsletters, premium episode tiers, and direct listener support.",
                    content: `The media landscape has permanently shifted from mass-market reach to high-engagement micro-communities.\n\nIn this article, we break down how creators are generating recurring monthly revenue by coupling podcasts with companion articles, private Q&As, and community memberships.`,
                    category: "Business & Startups",
                    tags: ["monetization", "growth", "business"],
                    readTime: "4 min read",
                    coverImage: "https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=800&auto=format&fit=crop&q=80",
                    user: demoUser._id,
                }
            ];

            for (const blogData of sampleBlogs) {
                const b = new Blog(blogData);
                await b.save();
            }
            console.log("Seeded 2 sample articles.");
        }

        console.log("Seeding finished successfully!");
        process.exit(0);
    } catch (err) {
        console.error("Seeding error:", err);
        process.exit(1);
    }
};

seedData();
