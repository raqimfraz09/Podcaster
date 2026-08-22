import React from 'react';
import { ArrowLeft, Clock, Calendar, Share2, Tag } from 'lucide-react';
import { useToast } from '../context/ToastContext';
import { getMediaUrl } from '../services/api';

export const BlogDetailsPage = ({ blog, onBack }) => {
  const { addToast } = useToast();

  if (!blog) return null;

  const coverUrl = getMediaUrl(blog.coverImage) || 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?w=1200&auto=format&fit=crop&q=80';
  const formattedDate = blog.createdAt
    ? new Date(blog.createdAt).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
    : 'Recent';

  const handleShare = () => {
    navigator.clipboard?.writeText(window.location.href);
    addToast('Article link copied.', 'success');
  };

  return (
    <div className="container" style={{ paddingTop: '1.75rem', paddingBottom: '4rem', maxWidth: '780px' }}>
      {/* Back button */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <button onClick={onBack} className="btn btn-ghost btn-sm">
          <ArrowLeft size={15} /> All Articles
        </button>

        <button onClick={handleShare} className="btn btn-secondary btn-sm">
          <Share2 size={14} /> Share
        </button>
      </div>

      <article style={{
        backgroundColor: 'var(--bg-surface)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-light)',
        boxShadow: 'var(--shadow-xs)',
        overflow: 'hidden'
      }}>
        {/* Cover banner */}
        <div style={{ width: '100%', height: '300px', overflow: 'hidden', backgroundColor: 'var(--bg-subtle)' }}>
          <img
            src={coverUrl}
            alt={blog.title}
            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
            onError={(e) => {
              e.target.src = 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?w=1200&auto=format&fit=crop&q=80';
            }}
          />
        </div>

        <div style={{ padding: '2rem' }}>
          {/* Metadata Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
            <span className="badge badge-neutral">
              {blog.category || 'Article'}
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <Clock size={12} /> {blog.readTime || '4 min read'}
            </span>
            <span style={{ color: 'var(--border-light)' }}>•</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <Calendar size={12} /> {formattedDate}
            </span>
          </div>

          {/* Title */}
          <h1 style={{
            fontSize: '2rem',
            fontWeight: 800,
            lineHeight: 1.25,
            marginBottom: '1.25rem',
            color: 'var(--text-main)'
          }}>
            {blog.title}
          </h1>

          {/* Author Card */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            padding: '0.75rem 0',
            marginBottom: '1.75rem',
            borderTop: '1px solid var(--border-light)',
            borderBottom: '1px solid var(--border-light)'
          }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              backgroundColor: 'var(--primary)',
              color: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '0.8125rem'
            }}>
              {blog.user?.username ? blog.user.username.charAt(0).toUpperCase() : 'A'}
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-main)' }}>
                @{blog.user?.username || 'Author'}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Creator & Contributor
              </div>
            </div>
          </div>

          {/* Body Content */}
          <div style={{
            fontSize: '1rem',
            lineHeight: 1.75,
            color: 'var(--text-main)',
            whiteSpace: 'pre-line'
          }}>
            {blog.content}
          </div>

          {/* Tags */}
          {blog.tags && blog.tags.length > 0 && (
            <div style={{ marginTop: '2.5rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-light)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                <Tag size={14} color="var(--text-muted)" />
                {blog.tags.map((tag, idx) => (
                  <span key={idx} className="badge badge-neutral" style={{ textTransform: 'none', fontSize: '0.75rem' }}>
                    #{tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </article>
    </div>
  );
};
