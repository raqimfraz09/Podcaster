import React, { useState, useEffect } from 'react';
import { AuthProvider } from './context/AuthContext';
import { PlayerProvider } from './context/PlayerContext';
import { ToastProvider, useToast } from './context/ToastContext';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { AudioPlayerBar } from './components/AudioPlayerBar';
import { AuthModal } from './components/AuthModal';
import { HomePage } from './pages/HomePage';
import { ExplorePage } from './pages/ExplorePage';
import { PodcastDetailsPage } from './pages/PodcastDetailsPage';
import { BlogsPage } from './pages/BlogsPage';
import { BlogDetailsPage } from './pages/BlogDetailsPage';
import { UploadPodcastPage } from './pages/UploadPodcastPage';
import { CreateBlogPage } from './pages/CreateBlogPage';
import { DashboardPage } from './pages/DashboardPage';
import { getAllPodcasts, getCategories, getAllBlogs, getBlogById, getPodcastById } from './services/api';
import { Loader2 } from 'lucide-react';

const MainApp = () => {
  const [currentRoute, setCurrentRoute] = useState({ page: 'home' });
  const [searchGlobal, setSearchGlobal] = useState('');
  const [podcasts, setPodcasts] = useState([]);
  const [blogs, setBlogs] = useState([]);
  const [categories, setCategories] = useState([]);
  const [selectedPodcast, setSelectedPodcast] = useState(null);
  const [selectedBlog, setSelectedBlog] = useState(null);
  const [loading, setLoading] = useState(true);

  // Fetch initial data from backend
  const fetchData = async () => {
    try {
      setLoading(true);
      const [podcastsRes, catsRes, blogsRes] = await Promise.all([
        getAllPodcasts().catch(err => ({ data: [] })),
        getCategories().catch(err => ({ data: [] })),
        getAllBlogs().catch(err => ({ data: [] })),
      ]);

      setPodcasts(podcastsRes.data || []);
      setCategories(catsRes.data || []);
      setBlogs(blogsRes.data || []);
    } catch (error) {
      console.error("Error loading initial data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSelectPodcast = (podcast) => {
    setSelectedPodcast(podcast);
    setCurrentRoute({ page: 'podcast-details', id: podcast._id });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleSelectBlog = (blog) => {
    setSelectedBlog(blog);
    setCurrentRoute({ page: 'blog-details', id: blog._id });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Top Navigation */}
      <Navbar
        currentRoute={currentRoute}
        setCurrentRoute={setCurrentRoute}
        searchGlobal={searchGlobal}
        setSearchGlobal={(val) => {
          setSearchGlobal(val);
          if (val && currentRoute.page !== 'explore') {
            setCurrentRoute({ page: 'explore' });
          }
        }}
      />

      {/* Main Page Area */}
      <main className="main-wrapper">
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
            <Loader2 size={36} color="var(--primary)" className="spin" />
          </div>
        ) : (
          <>
            {currentRoute.page === 'home' && (
              <HomePage
                podcasts={podcasts}
                blogs={blogs}
                categories={categories}
                onNavigate={setCurrentRoute}
                onSelectPodcast={handleSelectPodcast}
                onSelectBlog={handleSelectBlog}
              />
            )}

            {currentRoute.page === 'explore' && (
              <ExplorePage
                podcasts={podcasts}
                categories={categories}
                initialCategory={currentRoute.category || 'All'}
                onSelectPodcast={handleSelectPodcast}
              />
            )}

            {currentRoute.page === 'podcast-details' && (
              <PodcastDetailsPage
                podcast={selectedPodcast || podcasts.find(p => p._id === currentRoute.id) || podcasts[0]}
                allPodcasts={podcasts}
                onBack={() => setCurrentRoute({ page: 'explore' })}
                onSelectPodcast={handleSelectPodcast}
              />
            )}

            {currentRoute.page === 'blogs' && (
              <BlogsPage
                blogs={blogs}
                onSelectBlog={handleSelectBlog}
                onNavigate={setCurrentRoute}
              />
            )}

            {currentRoute.page === 'blog-details' && (
              <BlogDetailsPage
                blog={selectedBlog || blogs.find(b => b._id === currentRoute.id) || blogs[0]}
                onBack={() => setCurrentRoute({ page: 'blogs' })}
              />
            )}

            {currentRoute.page === 'upload-podcast' && (
              <UploadPodcastPage
                categories={categories}
                onUploadSuccess={fetchData}
                onNavigate={setCurrentRoute}
              />
            )}

            {currentRoute.page === 'create-blog' && (
              <CreateBlogPage
                categories={categories}
                onBlogCreated={fetchData}
                onNavigate={setCurrentRoute}
              />
            )}

            {currentRoute.page === 'dashboard' && (
              <DashboardPage
                onNavigate={setCurrentRoute}
                onSelectPodcast={handleSelectPodcast}
                onSelectBlog={handleSelectBlog}
              />
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <Footer onNavigate={setCurrentRoute} />

      {/* Persistent Audio Player Bar */}
      <AudioPlayerBar onOpenPodcastDetails={handleSelectPodcast} />

      {/* Authentication Modal */}
      <AuthModal />
    </div>
  );
};

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <PlayerProvider>
          <MainApp />
        </PlayerProvider>
      </AuthProvider>
    </ToastProvider>
  );
}
