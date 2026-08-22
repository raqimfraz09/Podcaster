import React, { useState } from 'react';
import { 
  Play, Pause, ArrowRight, Radio, Compass, Plus, Headphones, Sparkles, Flame, Check
} from 'lucide-react';
import { PodcastCard } from '../components/PodcastCard';
import { BlogCard } from '../components/BlogCard';
import { usePlayer } from '../context/PlayerContext';
import { useAuth } from '../context/AuthContext';
import { getMediaUrl } from '../services/api';

export const HomePage = ({ podcasts, blogs, categories, onNavigate, onSelectPodcast, onSelectBlog }) => {
  const { currentPodcast, isPlaying, playPodcast } = usePlayer();
  const { user, openAuthModal } = useAuth();
  const [selectedCategory, setSelectedCategory] = useState('All');

  const spotlightPodcast = podcasts.length > 0 ? podcasts[0] : null;
  const isSpotlightPlaying = spotlightPodcast && currentPodcast && currentPodcast._id === spotlightPodcast._id && isPlaying;

  const filteredPodcasts = selectedCategory === 'All'
    ? podcasts
    : podcasts.filter(p => (p.category?.categoryName || p.category) === selectedCategory);

  const displayPodcasts = filteredPodcasts.slice(0, 8);
  const displayBlogs = blogs.slice(0, 3);

  return (
    <div>
      {/* Modern Hero Section */}
      <section style={{
        backgroundColor: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border-light)',
        padding: '3.75rem 0 3.25rem',
        position: 'relative'
      }}>
        <div className="container">
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 1fr)',
            gap: '3rem',
            alignItems: 'center'
          }} className="hero-grid">
            {/* Left Column */}
            <div>
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.45rem',
                fontSize: '0.75rem',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
                color: 'var(--accent)',
                backgroundColor: 'var(--accent-light)',
                border: '1px solid var(--accent-border)',
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-xs)',
                marginBottom: '1.25rem'
              }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--accent)' }} />
                Open Audio Ecosystem
              </div>

              <h1 style={{ fontSize: '2.85rem', fontWeight: 800, lineHeight: 1.15, marginBottom: '1.15rem' }}>
                Where serious creators publish high-impact audio.
              </h1>

              <p style={{ fontSize: '1.05rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '2rem', maxWidth: '540px' }}>
                Discover deep conversations, insightful essays, and thought-provoking storytelling. Built for discerning listeners who value substance over noise.
              </p>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '2rem' }}>
                <button
                  onClick={() => onNavigate({ page: 'explore' })}
                  className="btn btn-primary btn-lg"
                >
                  <Compass size={16} />
                  <span>Explore Episodes</span>
                </button>

                <button
                  onClick={() => {
                    if (user) onNavigate({ page: 'upload-podcast' });
                    else openAuthModal('signup');
                  }}
                  className="btn btn-secondary btn-lg"
                >
                  <Plus size={16} />
                  <span>Publish Podcast</span>
                </button>
              </div>

              {/* Social Proof / Metrics */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '1.5rem',
                fontSize: '0.8125rem',
                color: 'var(--text-muted)',
                fontWeight: 500
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Check size={14} color="var(--success)" strokeWidth={2.5} />
                  <span>100% Free Streaming</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Check size={14} color="var(--success)" strokeWidth={2.5} />
                  <span>Studio Master Audio</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Check size={14} color="var(--success)" strokeWidth={2.5} />
                  <span>Instant RSS Export</span>
                </div>
              </div>
            </div>

            {/* Right Column: Mini Now-Playing Spotlight Box */}
            {spotlightPodcast && (
              <div style={{
                backgroundColor: 'var(--bg-app)',
                border: '1px solid var(--border-light)',
                borderRadius: 'var(--radius-md)',
                padding: '1.5rem',
                boxShadow: 'var(--shadow-card)',
                display: 'flex',
                flexDirection: 'column',
                gap: '1rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
                    Trending Episode
                  </span>
                  {isSpotlightPlaying && (
                    <div className="mini-equalizer">
                      <span /><span /><span />
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                  <img
                    src={getMediaUrl(spotlightPodcast.frontImage) || 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=200&auto=format&fit=crop&q=80'}
                    alt={spotlightPodcast.title}
                    style={{ width: '72px', height: '72px', borderRadius: 'var(--radius-xs)', objectFit: 'cover', border: '1px solid var(--border-light)' }}
                  />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent)', marginBottom: '2px' }}>
                      {spotlightPodcast.category?.categoryName || 'General'}
                    </div>
                    <div style={{ fontWeight: 700, fontSize: '0.9375rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--text-primary)' }}>
                      {spotlightPodcast.title}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      By @{spotlightPodcast.user?.username || 'Creator'}
                    </div>
                  </div>
                </div>

                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                  {spotlightPodcast.description}
                </p>

                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
                  <button
                    onClick={() => playPodcast(spotlightPodcast, podcasts)}
                    className="btn btn-primary btn-sm"
                    style={{ flex: 1 }}
                  >
                    {isSpotlightPlaying ? <Pause size={14} fill="#fff" /> : <Play size={14} fill="#fff" />}
                    <span>{isSpotlightPlaying ? 'Pause Episode' : 'Listen Now'}</span>
                  </button>

                  <button
                    onClick={() => onSelectPodcast(spotlightPodcast)}
                    className="btn btn-secondary btn-sm"
                  >
                    <span>Details</span>
                    <ArrowRight size={13} />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Featured Spotlight Card (If on page) */}
      {spotlightPodcast && (
        <section className="container">
          <div className="spotlight-card">
            <img
              src={getMediaUrl(spotlightPodcast.frontImage) || 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=500&auto=format&fit=crop&q=80'}
              alt={spotlightPodcast.title}
              className="spotlight-cover"
              onError={(e) => {
                e.target.src = 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=500&auto=format&fit=crop&q=80';
              }}
            />

            <div className="spotlight-content">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-dark">Editor's Pick</span>
                <span className="badge badge-neutral">
                  {spotlightPodcast.category?.categoryName || 'General'}
                </span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Hosted by @{spotlightPodcast.user?.username || 'Creator'}
                </span>
              </div>

              <h2 
                className="spotlight-title" 
                style={{ cursor: 'pointer' }}
                onClick={() => onSelectPodcast(spotlightPodcast)}
              >
                {spotlightPodcast.title}
              </h2>

              <p className="spotlight-desc">
                {spotlightPodcast.description}
              </p>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.5rem' }}>
                <button
                  onClick={() => playPodcast(spotlightPodcast, podcasts)}
                  className="btn btn-primary"
                >
                  {isSpotlightPlaying ? <Pause size={15} fill="#ffffff" /> : <Play size={15} fill="#ffffff" />}
                  <span>{isSpotlightPlaying ? 'Pause Episode' : 'Play Episode'}</span>
                </button>

                <button
                  onClick={() => onSelectPodcast(spotlightPodcast)}
                  className="btn btn-secondary"
                >
                  <span>Episode Details</span>
                  <ArrowRight size={14} />
                </button>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Podcast Catalog & Topic Filters */}
      <section className="container" style={{ marginTop: '2.5rem', marginBottom: '3.5rem' }}>
        <div style={{
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          marginBottom: '1.25rem',
          flexWrap: 'wrap',
          gap: '0.75rem'
        }}>
          <div>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>Explore Episodes</h2>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Curated audio discussions and interviews from independent creators
            </p>
          </div>

          <button
            onClick={() => onNavigate({ page: 'explore' })}
            className="btn btn-ghost btn-sm"
            style={{ fontWeight: 600, color: 'var(--accent)' }}
          >
            <span>View All ({podcasts.length})</span>
            <ArrowRight size={14} />
          </button>
        </div>

        {/* Filter Pills */}
        <div style={{
          display: 'flex',
          gap: '0.4rem',
          overflowX: 'auto',
          paddingBottom: '0.5rem',
          marginBottom: '1.5rem',
          scrollbarWidth: 'none'
        }}>
          <button
            onClick={() => setSelectedCategory('All')}
            className={`filter-pill ${selectedCategory === 'All' ? 'active' : ''}`}
          >
            All Episodes
          </button>
          {categories.map((cat) => (
            <button
              key={cat._id || cat.categoryName}
              onClick={() => setSelectedCategory(cat.categoryName)}
              className={`filter-pill ${selectedCategory === cat.categoryName ? 'active' : ''}`}
            >
              {cat.categoryName}
            </button>
          ))}
        </div>

        {/* Grid */}
        {displayPodcasts.length > 0 ? (
          <div className="grid-podcasts">
            {displayPodcasts.map((podcast) => (
              <PodcastCard
                key={podcast._id}
                podcast={podcast}
                playlist={podcasts}
                onClick={onSelectPodcast}
              />
            ))}
          </div>
        ) : (
          <div style={{
            textAlign: 'center',
            padding: '3rem 1.5rem',
            backgroundColor: 'var(--bg-surface)',
            borderRadius: 'var(--radius-md)',
            border: '1px dashed var(--border-medium)'
          }}>
            <p style={{ fontSize: '0.9375rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              No episodes in this category yet.
            </p>
            <button
              onClick={() => {
                if (user) onNavigate({ page: 'upload-podcast' });
                else openAuthModal('signup');
              }}
              className="btn btn-secondary btn-sm"
            >
              <Plus size={14} /> Upload First Episode
            </button>
          </div>
        )}
      </section>

      {/* Community Articles Section */}
      <section className="container" style={{ marginBottom: '3.5rem' }}>
        <div style={{
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          marginBottom: '1.25rem',
          flexWrap: 'wrap',
          gap: '0.75rem'
        }}>
          <div>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>Creator Articles & Notes</h2>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              In-depth commentary, transcripts, and behind-the-scenes thoughts
            </p>
          </div>

          <button
            onClick={() => onNavigate({ page: 'blogs' })}
            className="btn btn-ghost btn-sm"
            style={{ fontWeight: 600, color: 'var(--accent)' }}
          >
            <span>All Articles</span>
            <ArrowRight size={14} />
          </button>
        </div>

        {displayBlogs.length > 0 ? (
          <div className="grid-blogs">
            {displayBlogs.map((blog) => (
              <BlogCard
                key={blog._id}
                blog={blog}
                onClick={onSelectBlog}
              />
            ))}
          </div>
        ) : (
          <div style={{
            textAlign: 'center',
            padding: '2.5rem 1.5rem',
            backgroundColor: 'var(--bg-surface)',
            borderRadius: 'var(--radius-md)',
            border: '1px dashed var(--border-medium)'
          }}>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              No articles published yet.
            </p>
          </div>
        )}
      </section>

      {/* Bottom Creator Strip */}
      <section className="container" style={{ marginBottom: '3rem' }}>
        <div style={{
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-light)',
          borderRadius: 'var(--radius-md)',
          padding: '2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1.5rem',
          boxShadow: 'var(--shadow-card)'
        }}>
          <div style={{ maxWidth: '540px' }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 800, marginBottom: '0.35rem' }}>
              Publish your podcast to the community
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Upload episodes in seconds with custom artwork, companion articles, and clean audio delivery.
            </p>
          </div>

          <button
            onClick={() => {
              if (user) onNavigate({ page: 'upload-podcast' });
              else openAuthModal('signup');
            }}
            className="btn btn-primary"
          >
            <Plus size={15} />
            <span>Start Publishing</span>
          </button>
        </div>
      </section>
    </div>
  );
};
