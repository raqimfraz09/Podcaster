import React, { useState, useRef } from 'react';
import { 
  Upload, Image as ImageIcon, Music, ArrowLeft, Loader2, X
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { addPodcast } from '../services/api';

export const UploadPodcastPage = ({ categories, onUploadSuccess, onNavigate }) => {
  const { user, openAuthModal } = useAuth();
  const { addToast } = useToast();

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState(categories[0]?.categoryName || 'Tech & AI');
  const [customCategory, setCustomCategory] = useState('');
  const [isCustomCategory, setIsCustomCategory] = useState(false);

  const [frontImageFile, setFrontImageFile] = useState(null);
  const [frontImagePreview, setFrontImagePreview] = useState(null);

  const [audioFile, setAudioFile] = useState(null);
  const [audioFilePreview, setAudioFilePreview] = useState(null);

  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState('');

  const imageInputRef = useRef(null);
  const audioInputRef = useRef(null);

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
            Authentication Required
          </h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.25rem', fontSize: '0.875rem' }}>
            Please sign in to upload podcast episodes to your channel.
          </p>
          <button onClick={() => openAuthModal('login')} className="btn btn-primary" style={{ width: '100%' }}>
            Sign In to Continue
          </button>
        </div>
      </div>
    );
  }

  const handleImageChange = (file) => {
    if (!file) return;
    if (!file.type.startsWith('image/')) {
      setError('Please select a valid image file (PNG, JPG, WEBP).');
      return;
    }
    setFrontImageFile(file);
    const reader = new FileReader();
    reader.onload = (e) => setFrontImagePreview(e.target.result);
    reader.readAsDataURL(file);
  };

  const handleAudioChange = (file) => {
    if (!file) return;
    if (!file.type.startsWith('audio/') && !file.name.match(/\.(mp3|wav|ogg|m4a|aac)$/i)) {
      setError('Please select a valid audio file (MP3, WAV, M4A).');
      return;
    }
    setAudioFile(file);
    const objectUrl = URL.createObjectURL(file);
    setAudioFilePreview(objectUrl);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!title.trim()) {
      setError('Podcast title is required.');
      return;
    }
    if (!description.trim()) {
      setError('Please provide a 3-4 line description for your podcast.');
      return;
    }
    if (!frontImageFile) {
      setError('Please select a podcast cover image.');
      return;
    }
    if (!audioFile) {
      setError('Please select an audio file for your episode.');
      return;
    }

    const selectedCat = isCustomCategory ? customCategory.trim() : category;
    if (!selectedCat) {
      setError('Please select or specify a category.');
      return;
    }

    try {
      setIsUploading(true);
      setUploadProgress(10);

      const formData = new FormData();
      formData.append('title', title.trim());
      formData.append('description', description.trim());
      formData.append('category', selectedCat);
      formData.append('frontImage', frontImageFile);
      formData.append('audioFile', audioFile);

      await addPodcast(formData, (progress) => {
        setUploadProgress(progress);
      });

      addToast('Podcast uploaded successfully.', 'success');
      if (onUploadSuccess) onUploadSuccess();
      onNavigate({ page: 'dashboard' });
    } catch (err) {
      console.error(err);
      const msg = err.response?.data?.error || err.response?.data?.message || 'Failed to upload podcast. Please try again.';
      setError(msg);
      addToast(msg, 'error');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="container" style={{ paddingTop: '2rem', paddingBottom: '4rem', maxWidth: '740px' }}>
      <button
        onClick={() => onNavigate({ page: 'home' })}
        className="btn btn-ghost btn-sm"
        style={{ marginBottom: '1rem' }}
      >
        <ArrowLeft size={15} /> Back
      </button>

      <div style={{ marginBottom: '1.75rem' }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 800 }}>Upload Podcast Episode</h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9375rem', marginTop: '0.2rem' }}>
          Publish new audio and artwork to your channel.
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
        {/* Cover Art & Audio Dropzones */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: '1.25rem',
          marginBottom: '1.5rem'
        }}>
          {/* Cover Art */}
          <div>
            <label className="form-label">Cover Artwork *</label>
            {frontImagePreview ? (
              <div style={{ position: 'relative', width: '100%', aspectRatio: '1/1', borderRadius: 'var(--radius-sm)', overflow: 'hidden', border: '1px solid var(--border-light)' }}>
                <img src={frontImagePreview} alt="Cover preview" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                <button
                  type="button"
                  onClick={() => { setFrontImageFile(null); setFrontImagePreview(null); }}
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
                  title="Remove image"
                >
                  <X size={14} />
                </button>
              </div>
            ) : (
              <div
                className="dropzone"
                onClick={() => imageInputRef.current?.click()}
                style={{ aspectRatio: '1/1' }}
              >
                <div className="dropzone-icon">
                  <ImageIcon size={20} />
                </div>
                <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>Select Cover Image</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>JPG, PNG, WEBP (Square)</div>
              </div>
            )}
            <input
              ref={imageInputRef}
              type="file"
              accept="image/*"
              style={{ display: 'none' }}
              onChange={(e) => handleImageChange(e.target.files?.[0])}
            />
          </div>

          {/* Audio File */}
          <div>
            <label className="form-label">Audio File (MP3 / WAV) *</label>
            {audioFile ? (
              <div style={{
                backgroundColor: 'var(--bg-app)',
                border: '1px solid var(--border-light)',
                borderRadius: 'var(--radius-sm)',
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.85rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Music size={18} color="var(--accent)" />
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem', maxWidth: '170px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {audioFile.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {(audioFile.size / (1024 * 1024)).toFixed(2)} MB
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => { setAudioFile(null); setAudioFilePreview(null); }}
                    className="btn-icon"
                  >
                    <X size={15} />
                  </button>
                </div>

                {audioFilePreview && (
                  <audio controls src={audioFilePreview} style={{ width: '100%', height: '36px' }} />
                )}
              </div>
            ) : (
              <div
                className="dropzone"
                onClick={() => audioInputRef.current?.click()}
                style={{ aspectRatio: '1/1' }}
              >
                <div className="dropzone-icon">
                  <Music size={20} />
                </div>
                <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>Select Audio Track</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>MP3, WAV, AAC, M4A</div>
              </div>
            )}
            <input
              ref={audioInputRef}
              type="file"
              accept="audio/*,.mp3,.wav,.ogg,.m4a,.aac"
              style={{ display: 'none' }}
              onChange={(e) => handleAudioChange(e.target.files?.[0])}
            />
          </div>
        </div>

        {/* Title */}
        <div className="form-group">
          <label className="form-label">Episode Title *</label>
          <input
            type="text"
            required
            placeholder="e.g. Episode 42: The Future of Autonomous Agents"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="form-input"
            maxLength={120}
          />
        </div>

        {/* Category */}
        <div className="form-group">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <label className="form-label" style={{ marginBottom: 0 }}>Category *</label>
            <button
              type="button"
              onClick={() => setIsCustomCategory(!isCustomCategory)}
              style={{ fontSize: '0.75rem', color: 'var(--accent)', fontWeight: 600 }}
            >
              {isCustomCategory ? 'Choose from list' : '+ New Category'}
            </button>
          </div>

          {isCustomCategory ? (
            <input
              type="text"
              placeholder="Enter category name..."
              value={customCategory}
              onChange={(e) => setCustomCategory(e.target.value)}
              className="form-input"
              required
            />
          ) : (
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
          )}
        </div>

        {/* Description */}
        <div className="form-group">
          <label className="form-label">Episode Description (3–4 Lines) *</label>
          <textarea
            required
            rows={4}
            placeholder="Provide a concise 3-4 line summary of what listeners will learn in this episode..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="form-textarea"
          />
        </div>

        {/* Progress */}
        {isUploading && (
          <div style={{ margin: '1.25rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', fontWeight: 600, marginBottom: '0.25rem' }}>
              <span>Uploading media...</span>
              <span>{uploadProgress}%</span>
            </div>
            <div style={{ width: '100%', height: '5px', backgroundColor: 'var(--bg-subtle)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
              <div style={{ width: `${uploadProgress}%`, height: '100%', backgroundColor: 'var(--primary)', transition: 'width 0.2s' }} />
            </div>
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={isUploading}
          className="btn btn-primary btn-lg"
          style={{ width: '100%', marginTop: '0.5rem' }}
        >
          {isUploading ? (
            <>
              <Loader2 size={16} className="spin" />
              <span>Uploading Episode...</span>
            </>
          ) : (
            <span>Publish Episode</span>
          )}
        </button>
      </form>
    </div>
  );
};
