import React, { useState, useMemo } from 'react';
import { Search, SlidersHorizontal, X } from 'lucide-react';
import { PodcastCard } from '../components/PodcastCard';

export const ExplorePage = ({ podcasts, categories, initialCategory = 'All', onSelectPodcast }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState(initialCategory);
  const [sortBy, setSortBy] = useState('newest');

  const filteredAndSortedPodcasts = useMemo(() => {
    let result = [...podcasts];

    if (selectedCategory !== 'All') {
      result = result.filter(p => {
        const catName = p.category?.categoryName || p.category;
        return catName === selectedCategory;
      });
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(p => 
        p.title.toLowerCase().includes(q) ||
        (p.description && p.description.toLowerCase().includes(q)) ||
        (p.user?.username && p.user.username.toLowerCase().includes(q)) ||
        (p.category?.categoryName && p.category.categoryName.toLowerCase().includes(q))
      );
    }

    if (sortBy === 'newest') {
      result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    } else if (sortBy === 'oldest') {
      result.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    } else if (sortBy === 'title') {
      result.sort((a, b) => a.title.localeCompare(b.title));
    }

    return result;
  }, [podcasts, selectedCategory, searchQuery, sortBy]);

  return (
    <div className="container" style={{ paddingTop: '2rem', paddingBottom: '3.5rem' }}>
      {/* Header */}
      <div style={{ marginBottom: '1.75rem' }}>
        <h1 style={{ fontSize: '2rem', fontWeight: 800, marginBottom: '0.25rem' }}>
          Explore Podcasts
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9375rem' }}>
          Search across the entire catalog or filter by category.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '0.85rem',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '1.25rem',
        backgroundColor: 'var(--bg-surface)',
        padding: '0.85rem 1rem',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-light)',
      }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: '420px' }}>
          <Search size={15} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
          <input
            type="text"
            placeholder="Search by title, description, or host..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="form-input"
            style={{ paddingLeft: '2.2rem', paddingRight: searchQuery ? '2.2rem' : '0.85rem' }}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              style={{ position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
            >
              <X size={14} />
            </button>
          )}
        </div>

        {/* Sort */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
            Sort:
          </span>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="form-select"
            style={{ width: 'auto', padding: '0.45rem 0.75rem', fontSize: '0.8125rem' }}
          >
            <option value="newest">Newest First</option>
            <option value="oldest">Oldest First</option>
            <option value="title">Title (A–Z)</option>
          </select>
        </div>
      </div>

      {/* Category Pills */}
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
          All ({podcasts.length})
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

      {/* Count */}
      <div style={{ marginBottom: '1rem', fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 500 }}>
        Showing {filteredAndSortedPodcasts.length} of {podcasts.length} episodes
      </div>

      {/* Grid */}
      {filteredAndSortedPodcasts.length > 0 ? (
        <div className="grid-podcasts">
          {filteredAndSortedPodcasts.map((podcast) => (
            <PodcastCard
              key={podcast._id}
              podcast={podcast}
              playlist={filteredAndSortedPodcasts}
              onClick={onSelectPodcast}
            />
          ))}
        </div>
      ) : (
        <div style={{
          textAlign: 'center',
          padding: '3.5rem 1.5rem',
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px dashed var(--border-medium)',
          marginTop: '0.5rem'
        }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.35rem' }}>
            No episodes found
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1.25rem' }}>
            Try adjusting your search keywords or category filter.
          </p>
          <button
            onClick={() => {
              setSearchQuery('');
              setSelectedCategory('All');
            }}
            className="btn btn-secondary btn-sm"
          >
            Reset Filters
          </button>
        </div>
      )}
    </div>
  );
};
