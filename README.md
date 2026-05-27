# Podcaster

A robust RESTful API backend for a podcast platform built with Node.js, Express.js, and MongoDB. This application allows users to register, authenticate, upload podcasts (audio and cover images), and organize them by categories.

## 🚀 Features

- **User Authentication:** Secure user registration and login.
  - Passwords are encrypted using `bcryptjs`.
  - Authentication is handled via JSON Web Tokens (JWT) stored securely in `HttpOnly` cookies.
- **Podcast Management:**
  - Upload audio files and cover images using `multer`.
  - Fetch all podcasts, fetch by ID, or fetch user-specific podcasts.
- **Categorization:** Create categories and organize podcasts into them.
- **Data Modeling:** Robust data models using `mongoose` for Users, Podcasts, and Categories.

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB
- **ODM:** Mongoose
- **Authentication:** jsonwebtoken (JWT), cookie-parser
- **Security:** bcryptjs (password hashing), cors
- **File Uploads:** multer
- **Environment Management:** dotenv

## 📁 Project Structure

```
Podcaster/
└── server/
    ├── conn/            # MongoDB connection configuration
    ├── middleware/      # Express middlewares (Auth, Multer for uploads)
    ├── models/          # Mongoose database schemas (User, Podcast, Category)
    ├── routes/          # API route definitions
    ├── app.js           # Application entry point
    └── package.json     # Project dependencies and scripts
```

## ⚙️ Prerequisites

Before you begin, ensure you have met the following requirements:
- **Node.js** installed on your local machine.
- A **MongoDB** database (either a local instance or MongoDB Atlas).

## 💻 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Podcaster/server
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up Environment Variables:**
   Create a `.env` file in the `server/` directory and add the following variables:
   ```env
   PORT=1000
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_secret_key_for_jwt
   NODE_ENV=development
   ```

4. **Start the server:**
   - For development (with hot-reloading via nodemon):
     ```bash
     npm run dev
     ```
   - For production:
     ```bash
     npm start
     ```

## 🔌 API Endpoints

The base URL for all API routes is `/api/v1`.

### User Routes
- `POST /sign-up` : Register a new user. (Body: `username`, `email`, `password`)
- `POST /sign-in` : Authenticate a user and set JWT cookie. (Body: `email`, `password`)
- `POST /logout` : Logout user by clearing the JWT cookie.
- `GET /check-cookie` : Verify if the user's authentication cookie is present.
- `GET /user-details` : Fetch the currently authenticated user's details. *(Requires Auth)*

### Podcast Routes
- `POST /add-podcast` : Upload a new podcast. Requires form-data with `title`, `description`, `category`, and files `frontImage`, `audioFile`. *(Requires Auth)*
- `GET /get-podcasts` : Retrieve all available podcasts.
- `GET /get-user-podcasts` : Retrieve all podcasts uploaded by the logged-in user. *(Requires Auth)*
- `GET /get-podcasts/:id` : Retrieve details of a specific podcast by its ID.
- `GET /category/:cat` : Retrieve all podcasts belonging to a specific category.

### Category Routes
- `POST /add-category` : Create a new podcast category. (Body: `categoryName`)

## 🔐 Security Considerations

- **Cookies:** JWT tokens are stored in `HttpOnly` cookies, mitigating Cross-Site Scripting (XSS) attacks. In production, ensure `secure: true` is set for cookies.
- **Password Hashing:** Plain-text passwords are never stored in the database. They are securely salted and hashed using `bcryptjs`.
