import React from 'react';
import { 
  Play, Pause, ArrowLeft, Calendar, User, Share2, Download, Radio
} from 'lucide-react';
import { usePlayer } from '../context/PlayerContext';
import { useToast } from '../context/ToastContext';
import { getMediaUrl } from '../services/api';
import { PodcastCard } from '../components/PodcastCard';

export const PodcastDetailsPage = ({ podcast, allPodcasts = [], onBack, onSelectPodcast }) => {
  const { currentPodcast, isPlaying, playPodcast, togglePlayPause, currentTime, duration, seek, formatTime } = usePlayer();
  const { addToast } = useToast();

  if (!podcast) return null;

  const isCurrent = currentPodcast && currentPodcast._id === podcast._id;
  const isCurrentlyPlaying = isCurrent && isPlaying;

  const coverUrl = getMediaUrl(podcast.frontImage) || 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=800&auto=format&fit=crop&q=80';
  const audioUrl = getMediaUrl(podcast.audioFile);
  const formattedDate = podcast.createdAt
    ? new Date(podcast.createdAt).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
    : 'Recent';

  const relatedPodcasts = allPodcasts
    .filter(p => p._id !== podcast._id && (p.category?.categoryName || p.category) === (podcast.category?.categoryName || podcast.category))
    .slice(0, 3);

  const handleShare = () => {
    navigator.clipboard?.writeText(window.location.href);
    addToast('Episode link copied.', 'success');
  };

  const handlePlayHero = () => {
    if (isCurrent) {
      togglePlayPause();
    } else {
      playPodcast(podcast, allPodcasts);
    }
  };

  const progressPercent = (isCurrent && duration > 0) ? (currentTime / duration) * 100 : 0;

  return (
    <div className="container" style={{ paddingTop: '1.75rem', paddingBottom: '3.5rem' }}>
      {/* Back button */}
      <button
        onClick={onBack}
        className="btn btn-ghost btn-sm"
        style={{ marginBottom: '1.25rem' }}
      >
        <ArrowLeft size={15} /> All Episodes
      </button>

      {/* Main Details Panel */}
      <div style={{
        backgroundColor: 'var(--bg-surface)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-light)',
        boxShadow: 'var(--shadow-xs)',
        padding: '2rem',
        marginBottom: '2.5rem',
        display: 'grid',
        gridTemplateColumns: 'minmax(220px, 280px) 1fr',
        gap: '2rem',
        alignItems: 'start'
      }}>
        {/* Cover Art */}
        <div style={{ position: 'relative' }}>
          <img
            src={coverUrl}
            alt={podcast.title}
            style={{
              width: '100%',
              aspectRatio: '1 / 1',
              borderRadius: 'var(--radius-sm)',
              objectFit: 'cover',
              border: '1px solid var(--border-light)'
            }}
            onError={(e) => {
              e.target.src = 'https://images.unsplash.com/photo-1590602847861-f357a9332bbc?w=800&auto=format&fit=crop&q=80';
            }}
          />
        </div>

        {/* Content */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
            <span className="badge badge-neutral">
              {podcast.category?.categoryName || 'General'}
            </span>
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              Hosted by @{podcast.user?.username || 'Creator'}
            </span>
            <span style={{ color: 'var(--border-light)' }}>•</span>
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              {formattedDate}
            </span>
          </div>

          <h1 style={{ fontSize: '2rem', fontWeight: 800, lineHeight: 1.25, color: 'var(--text-main)' }}>
            {podcast.title}
          </h1>

          {/* Clean Player Bar */}
          <div style={{
            backgroundColor: 'var(--bg-subtle)',
            borderRadius: 'var(--radius-sm)',
            padding: '1rem 1.25rem',
            border: '1px solid var(--border-light)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.85rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <button
                onClick={handlePlayHero}
                className="btn btn-primary"
                style={{ width: '44px', height: '44px', borderRadius: '50%', padding: 0 }}
                title={isCurrentlyPlaying ? "Pause" : "Play"}
              >
                {isCurrentlyPlaying ? <Pause size={18} fill="#fff" /> : <Play size={18} fill="#fff" style={{ marginLeft: '2px' }} />}
              </button>

              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-main)' }}>
                  {isCurrentlyPlaying ? 'Now Playing' : (isCurrent ? 'Episode Paused' : 'Play Episode')}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Lossless Audio Stream
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.35rem' }}>
                <button onClick={handleShare} className="btn-icon" title="Share Episode">
                  <Share2 size={15} />
                </button>
                {audioUrl && (
                  <a href={audioUrl} download={`${podcast.title}.mp3`} className="btn-icon" title="Download Audio">
                    <Download size={15} />
                  </a>
                )}
              </div>
            </div>

            {/* Custom Scrubber */}
            {isCurrent && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <span className="time-label">{formatTime(currentTime)}</span>
                <input
                  type="range"
                  min="0"
                  max={duration || 100}
                  value={currentTime}
                  onChange={(e) => seek(parseFloat(e.target.value))}
                  className="range-slider"
                  style={{
                    background: `linear-gradient(to right, var(--primary) ${progressPercent}%, var(--border-light) ${progressPercent}%)`
                  }}
                />
                <span className="time-label" style={{ textAlign: 'right' }}>{formatTime(duration)}</span>
              </div>
            )}
          </div>

          {/* Description */}
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.35rem' }}>
              About this Episode
            </h3>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.65, fontSize: '0.9rem', whiteSpace: 'pre-line' }}>
              {podcast.description}
            </p>
          </div>
        </div>
      </div>

      {/* Related in this category */}
      {relatedPodcasts.length > 0 && (
        <section>
          <div style={{ marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>More from this Category</h2>
          </div>
          <div className="grid-podcasts">
            {relatedPodcasts.map((item) => (
              <PodcastCard
                key={item._id}
                podcast={item}
                playlist={allPodcasts}
                onClick={onSelectPodcast}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
};
