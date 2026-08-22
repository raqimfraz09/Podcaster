import React, { createContext, useContext, useState, useRef, useEffect } from 'react';
import { getMediaUrl } from '../services/api';

const PlayerContext = createContext(null);

export const PlayerProvider = ({ children }) => {
  const [currentPodcast, setCurrentPodcast] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(0.8);
  const [isMuted, setIsMuted] = useState(false);
  const [playbackRate, setPlaybackRate] = useState(1);
  const [playlist, setPlaylist] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(-1);
  const [isPlayerExpanded, setIsPlayerExpanded] = useState(false);

  const audioRef = useRef(new Audio());

  // Attach event listeners to audio element
  useEffect(() => {
    const audio = audioRef.current;

    const onTimeUpdate = () => setCurrentTime(audio.currentTime);
    const onLoadedMetadata = () => setDuration(audio.duration || 0);
    const onEnded = () => handleNextTrack();
    const onPlay = () => setIsPlaying(true);
    const onPause = () => setIsPlaying(false);

    audio.addEventListener('timeupdate', onTimeUpdate);
    audio.addEventListener('loadedmetadata', onLoadedMetadata);
    audio.addEventListener('ended', onEnded);
    audio.addEventListener('play', onPlay);
    audio.addEventListener('pause', onPause);

    return () => {
      audio.removeEventListener('timeupdate', onTimeUpdate);
      audio.removeEventListener('loadedmetadata', onLoadedMetadata);
      audio.removeEventListener('ended', onEnded);
      audio.removeEventListener('play', onPlay);
      audio.removeEventListener('pause', onPause);
      audio.pause();
    };
  }, []);

  // Update volume & mute state
  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.volume = isMuted ? 0 : volume;
    }
  }, [volume, isMuted]);

  // Update playback speed
  useEffect(() => {
    if (audioRef.current) {
      audioRef.current.playbackRate = playbackRate;
    }
  }, [playbackRate]);

  const playPodcast = (podcast, newPlaylist = null) => {
    if (!podcast || !podcast.audioFile) return;

    if (newPlaylist && Array.isArray(newPlaylist)) {
      setPlaylist(newPlaylist);
      const idx = newPlaylist.findIndex(p => p._id === podcast._id);
      setCurrentIndex(idx !== -1 ? idx : 0);
    }

    if (currentPodcast && currentPodcast._id === podcast._id) {
      togglePlayPause();
      return;
    }

    setCurrentPodcast(podcast);
    const audio = audioRef.current;
    const mediaUrl = getMediaUrl(podcast.audioFile);
    audio.src = mediaUrl;
    audio.load();
    audio.play().then(() => {
      setIsPlaying(true);
    }).catch(err => {
      console.warn("Audio autoplay blocked or failed:", err);
      setIsPlaying(false);
    });
  };

  const togglePlayPause = () => {
    if (!currentPodcast) return;
    const audio = audioRef.current;
    if (isPlaying) {
      audio.pause();
    } else {
      audio.play().catch(e => console.warn(e));
    }
  };

  const seek = (time) => {
    if (audioRef.current && Number.isFinite(time)) {
      audioRef.current.currentTime = time;
      setCurrentTime(time);
    }
  };

  const skipSeconds = (seconds) => {
    if (audioRef.current) {
      const newTime = Math.min(Math.max(0, audioRef.current.currentTime + seconds), duration || 1000);
      seek(newTime);
    }
  };

  const setAudioVolume = (val) => {
    const v = Math.max(0, Math.min(1, val));
    setVolume(v);
    if (v > 0 && isMuted) setIsMuted(false);
  };

  const toggleMute = () => {
    setIsMuted(!isMuted);
  };

  const cyclePlaybackRate = () => {
    const speeds = [1, 1.25, 1.5, 2];
    const nextIdx = (speeds.indexOf(playbackRate) + 1) % speeds.length;
    setPlaybackRate(speeds[nextIdx]);
  };

  const handleNextTrack = () => {
    if (playlist.length > 0 && currentIndex < playlist.length - 1) {
      const nextPodcast = playlist[currentIndex + 1];
      setCurrentIndex(currentIndex + 1);
      playPodcast(nextPodcast, playlist);
    }
  };

  const handlePrevTrack = () => {
    if (currentTime > 3) {
      seek(0);
      return;
    }
    if (playlist.length > 0 && currentIndex > 0) {
      const prevPodcast = playlist[currentIndex - 1];
      setCurrentIndex(currentIndex - 1);
      playPodcast(prevPodcast, playlist);
    }
  };

  const formatTime = (seconds) => {
    if (!seconds || isNaN(seconds)) return '0:00';
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  return (
    <PlayerContext.Provider
      value={{
        currentPodcast,
        isPlaying,
        currentTime,
        duration,
        volume,
        isMuted,
        playbackRate,
        playlist,
        isPlayerExpanded,
        setIsPlayerExpanded,
        playPodcast,
        togglePlayPause,
        seek,
        skipSeconds,
        setAudioVolume,
        toggleMute,
        cyclePlaybackRate,
        handleNextTrack,
        handlePrevTrack,
        formatTime,
      }}
    >
      {children}
    </PlayerContext.Provider>
  );
};

export const usePlayer = () => {
  const context = useContext(PlayerContext);
  if (!context) {
    throw new Error('usePlayer must be used within a PlayerProvider');
  }
  return context;
};
