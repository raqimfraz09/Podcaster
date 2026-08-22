import React from 'react';
import { 
  Play, Pause, SkipBack, SkipForward, Volume2, VolumeX, 
  RotateCcw, RotateCw
} from 'lucide-react';
import { usePlayer } from '../context/PlayerContext';
import { getMediaUrl } from '../services/api';

export const AudioPlayerBar = ({ onOpenPodcastDetails }) => {
  const {
    currentPodcast,
    isPlaying,
    currentTime,
    duration,
    volume,
    isMuted,
    playbackRate,
    togglePlayPause,
    seek,
    skipSeconds,
    setAudioVolume,
    toggleMute,
    cyclePlaybackRate,
    handleNextTrack,
    handlePrevTrack,
    formatTime,
  } = usePlayer();

  if (!currentPodcast) return null;

  const coverUrl = getMediaUrl(currentPodcast.frontImage) || 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=300&auto=format&fit=crop&q=80';
  const progressPercent = duration > 0 ? (currentTime / duration) * 100 : 0;

  return (
    <div className="player-bar" role="region" aria-label="Audio Player">
      <div className="container player-grid">
        {/* Track Details */}
        <div className="player-track-info">
          <img
            src={coverUrl}
            alt={currentPodcast.title}
            className="player-thumb"
            onError={(e) => {
              e.target.src = 'https://images.unsplash.com/photo-1478737270239-2f02b77fc618?w=300&auto=format&fit=crop&q=80';
            }}
          />
          <div className="player-meta">
            <div 
              className="player-track-title" 
              title={currentPodcast.title}
              style={{ cursor: onOpenPodcastDetails ? 'pointer' : 'default' }}
              onClick={() => onOpenPodcastDetails && onOpenPodcastDetails(currentPodcast)}
            >
              {currentPodcast.title}
            </div>
            <div className="player-track-author">
              {currentPodcast.user?.username ? `@${currentPodcast.user.username}` : (currentPodcast.category?.categoryName || 'Podcast Episode')}
            </div>
          </div>
        </div>

        {/* Center Controls */}
        <div className="player-center-controls">
          <div className="player-buttons">
            <button
              onClick={handlePrevTrack}
              className="btn-icon"
              title="Previous Episode"
            >
              <SkipBack size={16} />
            </button>

            <button
              onClick={() => skipSeconds(-10)}
              className="btn-icon"
              title="Rewind 10s"
            >
              <RotateCcw size={15} />
            </button>

            <button
              onClick={togglePlayPause}
              className="play-main-btn"
              title={isPlaying ? "Pause" : "Play"}
              aria-label={isPlaying ? "Pause" : "Play"}
            >
              {isPlaying ? <Pause size={17} fill="#ffffff" /> : <Play size={17} fill="#ffffff" style={{ marginLeft: '2px' }} />}
            </button>

            <button
              onClick={() => skipSeconds(10)}
              className="btn-icon"
              title="Forward 10s"
            >
              <RotateCw size={15} />
            </button>

            <button
              onClick={handleNextTrack}
              className="btn-icon"
              title="Next Episode"
            >
              <SkipForward size={16} />
            </button>
          </div>

          {/* Time Scrubber */}
          <div className="player-progress-row">
            <span className="time-label">{formatTime(currentTime)}</span>
            <input
              type="range"
              min="0"
              max={duration || 100}
              value={currentTime}
              onChange={(e) => seek(parseFloat(e.target.value))}
              className="range-slider"
              aria-label="Seek audio"
              style={{
                background: `linear-gradient(to right, var(--primary) ${progressPercent}%, var(--border-light) ${progressPercent}%)`
              }}
            />
            <span className="time-label" style={{ textAlign: 'right' }}>
              {formatTime(duration)}
            </span>
          </div>
        </div>

        {/* Right Controls */}
        <div className="player-extra-controls">
          <button
            onClick={cyclePlaybackRate}
            className="btn btn-secondary btn-sm"
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', fontWeight: 600 }}
            title="Playback Speed"
          >
            {playbackRate}x
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <button
              onClick={toggleMute}
              className="btn-icon"
              title={isMuted ? "Unmute" : "Mute"}
            >
              {isMuted || volume === 0 ? <VolumeX size={16} color="var(--text-muted)" /> : <Volume2 size={16} />}
            </button>

            <input
              type="range"
              min="0"
              max="1"
              step="0.02"
              value={isMuted ? 0 : volume}
              onChange={(e) => setAudioVolume(parseFloat(e.target.value))}
              className="range-slider volume-slider"
              aria-label="Volume"
            />
          </div>
        </div>
      </div>
    </div>
  );
};
