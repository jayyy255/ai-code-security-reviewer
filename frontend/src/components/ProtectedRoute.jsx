import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './UserContext';

export default function ProtectedRoute({ children }) {
  const { currentUser, loading, error } = useAuth();
  const location = useLocation();
  if (loading) return <p className="container" role="status">Checking your session…</p>;
  if (error && !currentUser) return <div className="container" role="alert"><p>{error}</p><button className="btn btn-secondary" onClick={() => window.location.reload()}>Retry</button></div>;
  if (!currentUser) return <Navigate to="/login" state={{ from: location }} replace />;
  return children;
}
