import React from 'react';
import { Play, Pause, Calendar, User as UserIcon } from 'lucide-react';
import { usePlayer } from '../context/PlayerContext';
import { getMediaUrl } from '../services/api';

export const PodcastCard = ({ podcast, playlist = [], onClick }) => {
  const { currentPodcast, isPlaying, playPodcast } = usePlayer();

  const isCurrent = currentPodcast && currentPodcast._id === podcast._id;
  const isCurrentlyPlaying = isCurrent && isPlaying;

  const handlePlayClick = (e) => {
    e.stopPropagation();
    playPodcast(podcast, playlist);
  };

  const coverUrl = getMediaUrl(podcast.frontImage) || 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=500&auto=format&fit=crop&q=80';
  const categoryName = podcast.category?.categoryName || 'General';
  const formattedDate = podcast.createdAt
    ? new Date(podcast.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    : 'Recent';

  return (
    <div 
      className={`card podcast-card ${isCurrent ? 'is-active' : ''}`}
      onClick={() => onClick && onClick(podcast)}
      style={{ cursor: 'pointer' }}
    >
      <div className="podcast-cover-wrapper">
        <img
          src={coverUrl}
          alt={podcast.title}
          className="podcast-cover"
          loading="lazy"
          onError={(e) => {
            e.target.src = 'https://images.unsplash.com/photo-1590602847861-f357a9332bbc?w=500&auto=format&fit=crop&q=80';
          }}
        />

        {/* Play Button Overlay */}
        <button
          onClick={handlePlayClick}
          className="play-card-btn"
          title={isCurrentlyPlaying ? "Pause" : "Play Episode"}
          aria-label={isCurrentlyPlaying ? "Pause" : "Play Episode"}
        >
          {isCurrentlyPlaying ? <Pause size={18} fill="#ffffff" /> : <Play size={18} fill="#ffffff" style={{ marginLeft: '2px' }} />}
        </button>

        {/* Category Badge */}
        <div style={{ position: 'absolute', top: '10px', left: '10px' }}>
          <span className="badge badge-neutral" style={{ backgroundColor: 'rgba(255, 255, 255, 0.94)' }}>
            {categoryName}
          </span>
        </div>

        {/* Active Playing Equalizer Badge */}
        {isCurrentlyPlaying && (
          <div style={{
            position: 'absolute',
            top: '10px',
            right: '10px',
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
            color: '#ffffff',
            padding: '3px 8px',
            borderRadius: 'var(--radius-xs)',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.6875rem',
            fontWeight: 700
          }}>
            <div className="mini-equalizer">
              <span /><span /><span />
            </div>
            <span>PLAYING</span>
          </div>
        )}
      </div>

      <div className="podcast-body">
        <h3 className="podcast-title" title={podcast.title}>
          {podcast.title}
        </h3>
        <p className="podcast-desc">
          {podcast.description}
        </p>

        <div className="podcast-meta">
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <UserIcon size={12} color="var(--text-muted)" />
            <span>@{podcast.user?.username || 'Creator'}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Calendar size={12} color="var(--text-muted)" />
            <span>{formattedDate}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
