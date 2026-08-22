import React from 'react';
import { Clock, Calendar, ArrowRight } from 'lucide-react';
import { getMediaUrl } from '../services/api';

export const BlogCard = ({ blog, onClick }) => {
  const coverUrl = getMediaUrl(blog.coverImage) || 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?w=600&auto=format&fit=crop&q=80';
  const formattedDate = blog.createdAt
    ? new Date(blog.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    : 'Recent';

  return (
    <div
      className="card"
      onClick={() => onClick && onClick(blog)}
      style={{
        cursor: 'pointer',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
      }}
    >
      <div style={{
        position: 'relative',
        width: '100%',
        height: '170px',
        overflow: 'hidden',
        backgroundColor: 'var(--bg-subtle)',
        borderBottom: '1px solid var(--border-light)'
      }}>
        <img
          src={coverUrl}
          alt={blog.title}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
          }}
          loading="lazy"
          onError={(e) => {
            e.target.src = 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?w=600&auto=format&fit=crop&q=80';
          }}
        />
        <div style={{ position: 'absolute', top: '10px', left: '10px' }}>
          <span className="badge badge-neutral" style={{ backgroundColor: 'rgba(255, 255, 255, 0.92)' }}>
            {blog.category || 'Article'}
          </span>
        </div>
      </div>

      <div style={{ padding: '1.15rem', display: 'flex', flexDirection: 'column', flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', marginBottom: '0.4rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <Clock size={12} />
          <span>{blog.readTime || '4 min read'}</span>
          <span>•</span>
          <Calendar size={12} />
          <span>{formattedDate}</span>
        </div>

        <h3 style={{
          fontSize: '1.05rem',
          fontWeight: 700,
          marginBottom: '0.4rem',
          lineHeight: 1.35,
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
          color: 'var(--text-main)'
        }}>
          {blog.title}
        </h3>

        <p style={{
          fontSize: '0.8125rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
          marginBottom: '1rem',
          display: '-webkit-box',
          WebkitLineClamp: 3,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
          flex: 1
        }}>
          {blog.summary || (blog.content ? blog.content.substring(0, 130) + '...' : '')}
        </p>

        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          paddingTop: '0.65rem',
          borderTop: '1px solid var(--border-light)',
          fontSize: '0.75rem',
        }}>
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>
            @{blog.user?.username || 'Author'}
          </span>

          <span style={{ display: 'flex', alignItems: 'center', gap: '3px', color: 'var(--accent)', fontWeight: 600 }}>
            Read article <ArrowRight size={12} />
          </span>
        </div>
      </div>
    </div>
  );
};
