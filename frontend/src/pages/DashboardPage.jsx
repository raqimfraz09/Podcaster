import React, { useState, useEffect } from 'react';
import { 
  Radio, BookOpen, Trash2, Play, Pause, Plus, 
  PenSquare, Mail, Calendar, ExternalLink, Loader2 
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { usePlayer } from '../context/PlayerContext';
import { useToast } from '../context/ToastContext';
import { getUserPodcasts, getUserBlogs, deletePodcast, deleteBlog, getMediaUrl } from '../services/api';

export const DashboardPage = ({ onNavigate, onSelectPodcast, onSelectBlog }) => {
  const { user, openAuthModal } = useAuth();
  const { currentPodcast, isPlaying, playPodcast } = usePlayer();
  const { addToast } = useToast();

  const [activeTab, setActiveTab] = useState('podcasts');
  const [userPodcasts, setUserPodcasts] = useState([]);
  const [userBlogs, setUserBlogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState(null);

  const fetchDashboardData = async () => {
    if (!user) return;
    try {
      setLoading(true);
      const [podcastsRes, blogsRes] = await Promise.all([
        getUserPodcasts().catch(() => ({ data: [] })),
        getUserBlogs().catch(() => ({ data: [] })),
      ]);
      setUserPodcasts(podcastsRes.data || []);
      setUserBlogs(blogsRes.data || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user) {
      fetchDashboardData();
    }
  }, [user]);

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
            Creator Dashboard
          </h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.25rem', fontSize: '0.875rem' }}>
            Sign in to manage your uploaded episodes and articles.
          </p>
          <button onClick={() => openAuthModal('login')} className="btn btn-primary" style={{ width: '100%' }}>
            Sign In to Dashboard
          </button>
        </div>
      </div>
    );
  }

  const handleDeletePodcast = async (id, title) => {
    if (!window.confirm(`Are you sure you want to delete "${title}"?`)) {
      return;
    }
    try {
      setDeletingId(id);
      await deletePodcast(id);
      addToast('Podcast deleted.', 'success');
      setUserPodcasts(prev => prev.filter(p => p._id !== id));
    } catch (err) {
      console.error(err);
      addToast('Failed to delete podcast.', 'error');
    } finally {
      setDeletingId(null);
    }
  };

  const handleDeleteBlog = async (id, title) => {
    if (!window.confirm(`Are you sure you want to delete "${title}"?`)) {
      return;
    }
    try {
      setDeletingId(id);
      await deleteBlog(id);
      addToast('Article deleted.', 'success');
      setUserBlogs(prev => prev.filter(b => b._id !== id));
    } catch (err) {
      console.error(err);
      addToast('Failed to delete article.', 'error');
    } finally {
      setDeletingId(null);
    }
  };

  const memberDate = user.createdAt
    ? new Date(user.createdAt).toLocaleDateString('en-US', { month: 'short', year: 'numeric' })
    : '2026';

  return (
    <div className="container" style={{ paddingTop: '2rem', paddingBottom: '4rem' }}>
      {/* Header Banner */}
      <div style={{
        backgroundColor: 'var(--bg-surface)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-light)',
        boxShadow: 'var(--shadow-xs)',
        padding: '1.75rem',
        marginBottom: '1.75rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1.25rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{
            width: '52px',
            height: '52px',
            borderRadius: '50%',
            backgroundColor: 'var(--primary)',
            color: '#fff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.35rem',
            fontWeight: 800
          }}>
            {user.username?.charAt(0).toUpperCase() || 'U'}
          </div>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <h1 style={{ fontSize: '1.5rem', fontWeight: 800 }}>{user.username}</h1>
              <span className="badge badge-neutral" style={{ fontSize: '0.6875rem' }}>Creator</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.2rem', fontSize: '0.8125rem', color: 'var(--text-secondary)', flexWrap: 'wrap' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Mail size={13} /> {user.email}
              </span>
              <span>•</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Calendar size={13} /> Member since {memberDate}
              </span>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            onClick={() => onNavigate({ page: 'upload-podcast' })}
            className="btn btn-primary btn-sm"
          >
            <Plus size={14} />
            <span>Upload Podcast</span>
          </button>

          <button
            onClick={() => onNavigate({ page: 'create-blog' })}
            className="btn btn-secondary btn-sm"
          >
            <PenSquare size={14} />
            <span>Write Article</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '1rem',
        marginBottom: '1.75rem'
      }}>
        <div style={{ backgroundColor: 'var(--bg-surface)', padding: '1.15rem 1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Episodes Uploaded
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--text-main)', marginTop: '0.2rem' }}>
            {userPodcasts.length}
          </div>
        </div>

        <div style={{ backgroundColor: 'var(--bg-surface)', padding: '1.15rem 1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Articles Published
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--text-main)', marginTop: '0.2rem' }}>
            {userBlogs.length}
          </div>
        </div>

        <div style={{ backgroundColor: 'var(--bg-surface)', padding: '1.15rem 1.25rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-light)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Distribution
          </div>
          <div style={{ fontSize: '0.9375rem', fontWeight: 700, color: 'var(--success)', marginTop: '0.5rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--success)' }} /> Active & Public
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex',
        gap: '0.4rem',
        borderBottom: '1px solid var(--border-light)',
        marginBottom: '1.25rem'
      }}>
        <button
          onClick={() => setActiveTab('podcasts')}
          style={{
            padding: '0.65rem 1rem',
            fontWeight: 600,
            fontSize: '0.875rem',
            borderBottom: activeTab === 'podcasts' ? '2px solid var(--primary)' : '2px solid transparent',
            color: activeTab === 'podcasts' ? 'var(--text-main)' : 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <Radio size={16} />
          <span>My Episodes ({userPodcasts.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('blogs')}
          style={{
            padding: '0.65rem 1rem',
            fontWeight: 600,
            fontSize: '0.875rem',
            borderBottom: activeTab === 'blogs' ? '2px solid var(--primary)' : '2px solid transparent',
            color: activeTab === 'blogs' ? 'var(--text-main)' : 'var(--text-secondary)',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <BookOpen size={16} />
          <span>My Articles ({userBlogs.length})</span>
        </button>
      </div>

      {/* Tab 1: Podcasts */}
      {activeTab === 'podcasts' && (
        <div>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '2.5rem' }}>
              <Loader2 size={24} className="spin" style={{ margin: '0 auto' }} />
            </div>
          ) : userPodcasts.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {userPodcasts.map((podcast) => {
                const isCurrent = currentPodcast && currentPodcast._id === podcast._id;
                const isCurrentlyPlaying = isCurrent && isPlaying;
                const cover = getMediaUrl(podcast.frontImage) || 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=200&auto=format&fit=crop&q=80';

                return (
                  <div
                    key={podcast._id}
                    style={{
                      backgroundColor: 'var(--bg-surface)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-light)',
                      padding: '0.85rem 1rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '0.85rem'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flex: '1 1 280px' }}>
                      <img
                        src={cover}
                        alt={podcast.title}
                        style={{ width: '48px', height: '48px', borderRadius: 'var(--radius-xs)', objectFit: 'cover', border: '1px solid var(--border-light)' }}
                      />

                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '1px' }}>
                          <span className="badge badge-neutral" style={{ fontSize: '0.6875rem' }}>
                            {podcast.category?.categoryName || 'General'}
                          </span>
                        </div>
                        <h4
                          onClick={() => onSelectPodcast(podcast)}
                          style={{ fontSize: '0.9375rem', fontWeight: 700, cursor: 'pointer', color: 'var(--text-main)' }}
                        >
                          {podcast.title}
                        </h4>
                        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: '-webkit-box', WebkitLineClamp: 1, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                          {podcast.description}
                        </p>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <button
                        onClick={() => playPodcast(podcast, userPodcasts)}
                        className="btn btn-secondary btn-sm"
                      >
                        {isCurrentlyPlaying ? <Pause size={13} /> : <Play size={13} />}
                        <span>{isCurrentlyPlaying ? 'Pause' : 'Play'}</span>
                      </button>

                      <button
                        onClick={() => onSelectPodcast(podcast)}
                        className="btn btn-ghost btn-sm"
                        title="View Episode"
                      >
                        <ExternalLink size={14} />
                      </button>

                      <button
                        onClick={() => handleDeletePodcast(podcast._id, podcast.title)}
                        disabled={deletingId === podcast._id}
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--danger)' }}
                        title="Delete Episode"
                      >
                        {deletingId === podcast._id ? <Loader2 size={13} className="spin" /> : <Trash2 size={13} />}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{
              textAlign: 'center',
              padding: '3.5rem 1.5rem',
              backgroundColor: 'var(--bg-surface)',
              borderRadius: 'var(--radius-md)',
              border: '1px dashed var(--border-medium)'
            }}>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9375rem', marginBottom: '1rem' }}>
                You haven't uploaded any episodes yet.
              </p>
              <button
                onClick={() => onNavigate({ page: 'upload-podcast' })}
                className="btn btn-primary btn-sm"
              >
                <Plus size={14} /> Upload First Episode
              </button>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Articles */}
      {activeTab === 'blogs' && (
        <div>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '2.5rem' }}>
              <Loader2 size={24} className="spin" style={{ margin: '0 auto' }} />
            </div>
          ) : userBlogs.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {userBlogs.map((blog) => {
                const cover = getMediaUrl(blog.coverImage) || 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?w=200&auto=format&fit=crop&q=80';

                return (
                  <div
                    key={blog._id}
                    style={{
                      backgroundColor: 'var(--bg-surface)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-light)',
                      padding: '0.85rem 1rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '0.85rem'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flex: '1 1 280px' }}>
                      <img
                        src={cover}
                        alt={blog.title}
                        style={{ width: '48px', height: '48px', borderRadius: 'var(--radius-xs)', objectFit: 'cover', border: '1px solid var(--border-light)' }}
                      />

                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '1px' }}>
                          <span className="badge badge-neutral" style={{ fontSize: '0.6875rem' }}>
                            {blog.category || 'Article'}
                          </span>
                          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                            {blog.readTime || '4 min read'}
                          </span>
                        </div>
                        <h4
                          onClick={() => onSelectBlog(blog)}
                          style={{ fontSize: '0.9375rem', fontWeight: 700, cursor: 'pointer', color: 'var(--text-main)' }}
                        >
                          {blog.title}
                        </h4>
                        <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: '-webkit-box', WebkitLineClamp: 1, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                          {blog.summary || blog.content?.substring(0, 80)}
                        </p>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <button
                        onClick={() => onSelectBlog(blog)}
                        className="btn btn-secondary btn-sm"
                      >
                        <span>View</span>
                        <ExternalLink size={13} />
                      </button>

                      <button
                        onClick={() => handleDeleteBlog(blog._id, blog.title)}
                        disabled={deletingId === blog._id}
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--danger)' }}
                        title="Delete Article"
                      >
                        {deletingId === blog._id ? <Loader2 size={13} className="spin" /> : <Trash2 size={13} />}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{
              textAlign: 'center',
              padding: '3.5rem 1.5rem',
              backgroundColor: 'var(--bg-surface)',
              borderRadius: 'var(--radius-md)',
              border: '1px dashed var(--border-medium)'
            }}>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9375rem', marginBottom: '1rem' }}>
                You haven't written any articles yet.
              </p>
              <button
                onClick={() => onNavigate({ page: 'create-blog' })}
                className="btn btn-primary btn-sm"
              >
                <PenSquare size={14} /> Write Article
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
