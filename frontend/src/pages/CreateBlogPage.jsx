import React, { useState, useRef } from 'react';
import { Image as ImageIcon, ArrowLeft, Loader2, X } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { addBlog } from '../services/api';

export const CreateBlogPage = ({ categories, onBlogCreated, onNavigate }) => {
  const { user, openAuthModal } = useAuth();
  const { addToast } = useToast();

  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [summary, setSummary] = useState('');
  const [category, setCategory] = useState(categories[0]?.categoryName || 'Tech & AI');
  const [tags, setTags] = useState('');
  const [coverImageFile, setCoverImageFile] = useState(null);
  const [coverPreview, setCoverPreview] = useState(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);

  if (!user) {
    return (
      <div className="container" style={{ paddingTop: '4rem', paddingBottom: '4rem', textAlign: 'center' }}>
        <div style={{
          maxWidth: '420px',
          margin: '0 auto',
          backgroundColor: 'var(--bg-surface)',
          padding: '2rem',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border-light)',
          boxShadow: 'var(--shadow-xs)'
        }}>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 800, marginBottom: '0.35rem' }}>
            Publishing Studio
          </h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.25rem', fontSize: '0.875rem' }}>
            Please sign in to publish articles, show notes, and stories.
          </p>
          <button onClick={() => openAuthModal('login')} className="btn btn-primary" style={{ width: '100%' }}>
            Sign In to Publish
          </button>
        </div>
      </div>
    );
  }

  const handleImageChange = (file) => {
    if (!file) return;
    if (!file.type.startsWith('image/')) {
      setError('Please select a valid image file.');
      return;
    }
    setCoverImageFile(file);
    const reader = new FileReader();
    reader.onload = (e) => setCoverPreview(e.target.result);
    reader.readAsDataURL(file);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!title.trim()) {
      setError('Article title is required.');
      return;
    }
    if (!content.trim()) {
      setError('Article content is required.');
      return;
    }

    try {
      setLoading(true);
      const formData = new FormData();
      formData.append('title', title.trim());
      formData.append('content', content.trim());
      if (summary.trim()) formData.append('summary', summary.trim());
      formData.append('category', category);
      if (tags.trim()) formData.append('tags', tags.trim());
      if (coverImageFile) formData.append('coverImage', coverImageFile);

      await addBlog(formData);
      addToast('Article published successfully.', 'success');
      if (onBlogCreated) onBlogCreated();
      onNavigate({ page: 'blogs' });
    } catch (err) {
      console.error(err);
      const msg = err.response?.data?.error || err.response?.data?.message || 'Failed to publish article.';
      setError(msg);
      addToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container" style={{ paddingTop: '2rem', paddingBottom: '4rem', maxWidth: '740px' }}>
      <button onClick={() => onNavigate({ page: 'blogs' })} className="btn btn-ghost btn-sm" style={{ marginBottom: '1rem' }}>
        <ArrowLeft size={15} /> Back to Articles
      </button>

      <div style={{ marginBottom: '1.75rem' }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 800 }}>Write an Article</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9375rem', marginTop: '0.2rem' }}>
          Publish show notes, transcripts, or editorial essays.
        </p>
      </div>

      {error && (
        <div style={{
          backgroundColor: 'var(--danger-bg)',
          color: 'var(--danger)',
          border: '1px solid #fca5a5',
          padding: '0.75rem 1rem',
          borderRadius: 'var(--radius-xs)',
          marginBottom: '1.25rem',
          fontSize: '0.8125rem',
          fontWeight: 500
        }}>
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} style={{
        backgroundColor: 'var(--bg-surface)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-light)',
        boxShadow: 'var(--shadow-xs)',
        padding: '2rem'
      }}>
        {/* Cover Image */}
        <div className="form-group">
          <label className="form-label">Article Banner Image</label>
          {coverPreview ? (
            <div style={{ position: 'relative', width: '100%', height: '180px', borderRadius: 'var(--radius-sm)', overflow: 'hidden', border: '1px solid var(--border-light)' }}>
              <img src={coverPreview} alt="Cover preview" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
              <button
                type="button"
                onClick={() => { setCoverImageFile(null); setCoverPreview(null); }}
                style={{
                  position: 'absolute',
                  top: '8px',
                  right: '8px',
                  backgroundColor: 'rgba(15, 23, 42, 0.7)',
                  color: '#fff',
                  borderRadius: '50%',
                  width: '28px',
                  height: '28px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                <X size={14} />
              </button>
            </div>
          ) : (
            <div
              className="dropzone"
              onClick={() => fileInputRef.current?.click()}
              style={{ padding: '1.25rem' }}
            >
              <div className="dropzone-icon">
                <ImageIcon size={18} />
              </div>
              <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Select Header Banner</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>JPG, PNG, WEBP (Optional)</div>
            </div>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            style={{ display: 'none' }}
            onChange={(e) => handleImageChange(e.target.files?.[0])}
          />
        </div>

        {/* Title */}
        <div className="form-group">
          <label className="form-label">Article Title *</label>
          <input
            type="text"
            required
            placeholder="e.g. Lessons from Season 1 Production"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="form-input"
          />
        </div>

        {/* Category & Tags */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div className="form-group">
            <label className="form-label">Category</label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="form-select"
            >
              {categories.map((cat) => (
                <option key={cat._id || cat.categoryName} value={cat.categoryName}>
                  {cat.categoryName}
                </option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">Tags (comma separated)</label>
            <input
              type="text"
              placeholder="e.g. audio, recording, tips"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              className="form-input"
            />
          </div>
        </div>

        {/* Short Summary */}
        <div className="form-group">
          <label className="form-label">Summary Excerpt</label>
          <input
            type="text"
            placeholder="Brief 1-2 sentence preview for the card..."
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            className="form-input"
          />
        </div>

        {/* Body Content */}
        <div className="form-group">
          <label className="form-label">Article Body *</label>
          <textarea
            required
            rows={9}
            placeholder="Write your article or notes here..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="form-textarea"
          />
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={loading}
          className="btn btn-primary btn-lg"
          style={{ width: '100%', marginTop: '0.5rem' }}
        >
          {loading ? (
            <>
              <Loader2 size={16} className="spin" />
              <span>Publishing...</span>
            </>
          ) : (
            <span>Publish Article</span>
          )}
        </button>
      </form>
    </div>
  );
};
