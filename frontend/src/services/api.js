import axios from 'axios';

// Create Axios client with credentials (cookies) support
const api = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Helper to resolve media URLs (images and audio files)
export const getMediaUrl = (filePath) => {
  if (!filePath) return '';
  if (filePath.startsWith('http://') || filePath.startsWith('https://') || filePath.startsWith('data:')) {
    return filePath;
  }
  // Standardize backslashes from Windows paths if any
  const normalized = filePath.replace(/\\/g, '/');
  if (normalized.startsWith('uploads/')) {
    return `/${normalized}`;
  }
  return `/${normalized}`;
};

// Auth APIs
export const registerUser = async (userData) => {
  const response = await api.post('/sign-up', userData);
  return response.data;
};

export const loginUser = async (credentials) => {
  const response = await api.post('/sign-in', credentials);
  return response.data;
};

export const logoutUser = async () => {
  const response = await api.post('/logout');
  return response.data;
};

export const checkAuthCookie = async () => {
  const response = await api.get('/check-cookie');
  return response.data;
};

export const getUserDetails = async () => {
  const response = await api.get('/user-details');
  return response.data;
};

// Podcast APIs
export const getAllPodcasts = async () => {
  const response = await api.get('/get-podcasts');
  return response.data;
};

export const getPodcastById = async (id) => {
  const response = await api.get(`/get-podcasts/${id}`);
  return response.data;
};

export const getUserPodcasts = async () => {
  const response = await api.get('/get-user-podcasts');
  return response.data;
};

export const getPodcastsByCategory = async (categoryName) => {
  const response = await api.get(`/category/${encodeURIComponent(categoryName)}`);
  return response.data;
};

export const addPodcast = async (formData, onProgress) => {
  const response = await api.post('/add-podcast', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        onProgress(percentCompleted);
      }
    },
  });
  return response.data;
};

export const deletePodcast = async (id) => {
  const response = await api.delete(`/delete-podcast/${id}`);
  return response.data;
};

// Category APIs
export const getCategories = async () => {
  const response = await api.get('/get-categories');
  return response.data;
};

export const addCategory = async (categoryName) => {
  const response = await api.post('/add-category', { categoryName });
  return response.data;
};

// Blog APIs
export const getAllBlogs = async () => {
  const response = await api.get('/get-blogs');
  return response.data;
};

export const getBlogById = async (id) => {
  const response = await api.get(`/get-blogs/${id}`);
  return response.data;
};

export const getUserBlogs = async () => {
  const response = await api.get('/get-user-blogs');
  return response.data;
};

export const addBlog = async (formData) => {
  const isFormData = formData instanceof FormData;
  const response = await api.post('/add-blog', formData, {
    headers: isFormData ? { 'Content-Type': 'multipart/form-data' } : {},
  });
  return response.data;
};

export const deleteBlog = async (id) => {
  const response = await api.delete(`/delete-blog/${id}`);
  return response.data;
};

export default api;
