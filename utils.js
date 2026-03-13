export const formatTimestamp = (ts) => {
  if (!ts) return 'N/A';
  const d = new Date(typeof ts === 'number' && ts < 1e12 ? ts * 1000 : ts);
  if (isNaN(d.getTime())) return 'N/A';
  const date = d.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
  const time = d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return `${date} · ${time}`;
};

export const getRelativeTime = (ts) => {
  if (!ts) return 'N/A';
  const d = new Date(typeof ts === 'number' && ts < 1e12 ? ts * 1000 : ts);
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
};

export const getSeverityClass = (sev) => ({
  High: 'bg-red-900/50 text-red-400 border-red-500',
  Medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-500',
  Low: 'bg-blue-900/50 text-blue-400 border-blue-500',
  Allowed: 'bg-green-900/50 text-green-400 border-green-500',
  Blocked: 'bg-red-900/50 text-red-400 border-red-500',
  Quarantined: 'bg-orange-900/50 text-orange-400 border-orange-500',
}[sev] || 'bg-gray-800 text-gray-400 border-gray-600');

export const truncateHash = (hash, len = 12) =>
  hash ? `${hash.slice(0, len)}...` : 'N/A';

export const getInitials = (name) =>
  name ? name.slice(0, 2).toUpperCase() : '??';
