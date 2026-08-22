import React, { useState, useMemo } from 'react';
import { Search, PenSquare, X } from 'lucide-react';
import { BlogCard } from '../components/BlogCard';
import { useAuth } from '../context/AuthContext';

export const BlogsPage = ({ blogs, onSelectBlog, onNavigate }) => {
  const { user, openAuthModal } = useAuth();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');

  const blogCategories = useMemo(() => {
    const set = new Set();
    blogs.forEach(b => { if (b.category) set.add(b.category); });
    return Array.from(set);
  }, [blogs]);

  const filteredBlogs = useMemo(() => {
    let result = [...blogs];
    if (selectedCategory !== 'All') {
      result = result.filter(b => b.category === selectedCategory);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(b => 
        b.title.toLowerCase().includes(q) ||
        (b.content && b.content.toLowerCase().includes(q)) ||
        (b.summary && b.summary.toLowerCase().includes(q)) ||
        (b.user?.username && b.user.username.toLowerCase().includes(q))
      );
    }
    return result;
  }, [blogs, selectedCategory, searchQuery]);

  return (
    <div className="container" style={{ paddingTop: '2rem', paddingBottom: '3.5rem' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'flex-end',
        justifyContent: 'space-between',
        marginBottom: '1.75rem',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 800 }}>Creator Articles</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9375rem', marginTop: '0.2rem' }}>
            Show notes, essays, and stories from podcast hosts.
          </p>
        </div>

        <button
          onClick={() => {
            if (user) onNavigate({ page: 'create-blog' });
            else openAuthModal('signup');
          }}
          className="btn btn-primary btn-sm"
        >
          <PenSquare size={14} />
          <span>Write Article</span>
        </button>
      </div>

      {/* Filter and Search */}
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
        border: '1px solid var(--border-light)'
      }}>
        <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: '380px' }}>
          <Search size={15} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
          <input
            type="text"
            placeholder="Search articles by title or keyword..."
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

        <div style={{ display: 'flex', gap: '0.4rem', overflowX: 'auto', scrollbarWidth: 'none' }}>
          <button
            onClick={() => setSelectedCategory('All')}
            className={`filter-pill ${selectedCategory === 'All' ? 'active' : ''}`}
          >
            All ({blogs.length})
          </button>
          {blogCategories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`filter-pill ${selectedCategory === cat ? 'active' : ''}`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Grid */}
      {filteredBlogs.length > 0 ? (
        <div className="grid-blogs">
          {filteredBlogs.map((blog) => (
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
          padding: '3.5rem 1.5rem',
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-md)',
          border: '1px dashed var(--border-medium)',
          marginTop: '1rem'
        }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.35rem' }}>
            No articles found
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1rem' }}>
            Be the first creator to share show notes or an article.
          </p>
          <button
            onClick={() => {
              if (user) onNavigate({ page: 'create-blog' });
              else openAuthModal('signup');
            }}
            className="btn btn-secondary btn-sm"
          >
            <PenSquare size={14} /> Write Article
          </button>
        </div>
      )}
    </div>
  );
};
