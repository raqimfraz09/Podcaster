import React from 'react';
import { Radio } from 'lucide-react';

export const Footer = ({ onNavigate }) => {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-grid">
          {/* Brand */}
          <div className="footer-brand">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <div className="brand-icon">
                <Radio size={16} />
              </div>
              <span style={{ fontFamily: 'var(--font-display)', fontSize: '1.15rem', fontWeight: 800 }}>
                Podcaster
              </span>
            </div>
            <p>
              An independent audio streaming platform built for long-form podcasts, creator stories, and commentary.
            </p>
          </div>

          {/* Navigation */}
          <div>
            <h4 className="footer-col-title">Navigation</h4>
            <ul className="footer-links">
              <li><a href="#home" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'home' }); }}>Home</a></li>
              <li><a href="#explore" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'explore' }); }}>Explore Episodes</a></li>
              <li><a href="#blogs" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'blogs' }); }}>Creator Articles</a></li>
              <li><a href="#upload" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'upload-podcast' }); }}>Publish Episode</a></li>
            </ul>
          </div>

          {/* Topics */}
          <div>
            <h4 className="footer-col-title">Categories</h4>
            <ul className="footer-links">
              <li><a href="#tech" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'explore', category: 'Tech & AI' }); }}>Tech & AI</a></li>
              <li><a href="#business" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'explore', category: 'Business & Startups' }); }}>Business</a></li>
              <li><a href="#comedy" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'explore', category: 'Comedy & Entertainment' }); }}>Comedy</a></li>
              <li><a href="#health" onClick={(e) => { e.preventDefault(); onNavigate({ page: 'explore', category: 'Health & Wellness' }); }}>Health & Fitness</a></li>
            </ul>
          </div>

          {/* Standards */}
          <div>
            <h4 className="footer-col-title">Platform</h4>
            <ul className="footer-links">
              <li><span>High-Definition Lossless Audio</span></li>
              <li><span>Direct Creator Distribution</span></li>
              <li><span>Open Categorization</span></li>
              <li><span>Responsive Web Player</span></li>
            </ul>
          </div>
        </div>

        <div className="footer-bottom">
          <div>
            © {new Date().getFullYear()} Podcaster Platform. All rights reserved.
          </div>
          <div>
            Production Build 1.0.0
          </div>
        </div>
      </div>
    </footer>
  );
};
