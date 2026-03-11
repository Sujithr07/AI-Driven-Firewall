import React, { useState, useEffect } from 'react';
import LogCLIModal from './LogCLIModal';

const FileTextIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>
);

const ChainIntegrityBanner = ({ token }) => {
    const [status, setStatus] = useState(null);
    const [verifying, setVerifying] = useState(false);

    const verify = async () => {
        setVerifying(true);
        try {
            const res = await fetch('http://localhost:5000/api/logs/verify', {
                headers: { Authorization: `Bearer ${token}` },
            });
            const data = await res.json();
            setStatus(data);
        } catch {
            setStatus({ chain_valid: false, message: 'Verification request failed' });
        } finally {
            setVerifying(false);
        }
    };

    useEffect(() => { verify(); }, []);

    if (!status) return null;

    const valid = status.chain_valid;

    return (
        <div className={`p-4 rounded-lg border mb-4 ${valid ? 'bg-green-900/20 border-green-500' : 'bg-red-900/30 border-red-500 animate-pulse'}`}>
            <div className="flex items-start justify-between">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        <span className="text-xl">{valid ? '🔒' : '⚠️'}</span>
                        <span className={`font-bold ${valid ? 'text-green-400' : 'text-red-400'}`}>
                            {valid ? 'HASH CHAIN INTACT — All logs verified' : `TAMPERING DETECTED — ${status.tampered_entries?.length || 0} entries compromised`}
                        </span>
                    </div>
                    <p className="text-gray-400 text-xs">
                        {status.total_entries} entries verified • {status.verified_at ? new Date(status.verified_at * 1000).toLocaleTimeString() : ''}
                    </p>
                    {!valid && status.first_tampered_id != null && (
                        <p className="text-red-400 text-xs mt-1">First tampered entry: ID #{status.first_tampered_id}</p>
                    )}
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={verify}
                        disabled={verifying}
                        className="px-3 py-1.5 text-xs bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded text-gray-300 disabled:opacity-50 transition"
                    >
                        {verifying ? 'Verifying...' : '🔄 Re-verify'}
                    </button>
                    <a
                        href="http://localhost:5000/api/logs/export"
                        className="px-3 py-1.5 text-xs bg-[#00ff7f]/10 hover:bg-[#00ff7f]/20 border border-[#00ff7f]/40 rounded text-[#00ff7f] transition"
                    >
                        📥 Export Audit Log
                    </a>
                </div>
            </div>
        </div>
    );
};

const ImmutableLogsView = ({ token }) => {
    const [logs, setLogs] = useState([]);
    const [page, setPage] = useState(1);
    const [selectedLog, setSelectedLog] = useState(null);
    const [paginationInfo, setPaginationInfo] = useState({ per_page: 50, total: 0, pages: 0 });
    const [loading, setLoading] = useState(true);
    const [filters, setFilters] = useState({ severity: '', decision: '' });

    useEffect(() => {
        const fetchLogs = async () => {
            setLoading(true);
            try {
                const params = new URLSearchParams({
                    page: page,
                    per_page: paginationInfo.per_page,
                    ...(filters.severity && { severity: filters.severity }),
                    ...(filters.decision && { decision: filters.decision }),
                });

                const response = await fetch(`http://localhost:5000/api/logs?${params}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                if (response.ok) {
                    const data = await response.json();
                    setLogs(data.logs);
                    setPaginationInfo({
                        per_page: data.pagination.per_page,
                        total: data.pagination.total,
                        pages: data.pagination.pages,
                    });
                }
            } catch (error) {
                console.error('Failed to fetch logs:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchLogs();
    }, [page, filters, token, paginationInfo.per_page]);

    const SEVERITY_CLASSES = {
        High: 'bg-red-900/50 text-red-400 border-red-500',
        Medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-500',
        Low: 'bg-blue-900/50 text-blue-400 border-blue-500',
        Allowed: 'bg-green-900/50 text-green-400 border-green-400',
    };

    return (
        <div className="p-8">
            <div className="flex items-center mb-6">
                <FileTextIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                <h2 className="text-3xl font-bold text-white">Immutable Security Logs</h2>
            </div>

            <div className="mb-6 bg-[#161b22] p-4 rounded-lg border border-gray-800">
                <p className="text-gray-300 text-sm mb-2">
                    <strong>Immutable Logs:</strong> Every log entry is protected by SQLite BEFORE UPDATE and BEFORE DELETE 
                    triggers at the database engine level. Each entry carries a SHA-256 hash chained to the previous 
                    entry — any modification or deletion breaks the chain and is detected instantly by the verification engine.
                </p>
                <p className="text-gray-400 text-xs">
                    Total Logs: {paginationInfo.total} | Showing page {page} of {paginationInfo.pages}
                </p>
            </div>

            <ChainIntegrityBanner token={token} />

            {/* Filters */}
            <div className="bg-[#161b22] p-4 rounded-lg border border-gray-800 mb-6">
                <div className="flex gap-4">
                    <select
                        value={filters.severity}
                        onChange={(e) => {
                            setFilters({ ...filters, severity: e.target.value });
                            setPage(1);
                        }}
                        className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white"
                    >
                        <option value="">All Severities</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                        <option value="Allowed">Allowed</option>
                    </select>
                    <select
                        value={filters.decision}
                        onChange={(e) => {
                            setFilters({ ...filters, decision: e.target.value });
                            setPage(1);
                        }}
                        className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white"
                    >
                        <option value="">All Decisions</option>
                        <option value="Blocked">Blocked</option>
                        <option value="Quarantined">Quarantined</option>
                        <option value="Allowed">Allowed</option>
                    </select>
                </div>
            </div>

            {/* Logs Table */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                {loading ? (
                    <div className="flex items-center justify-center py-12">
                        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
                    </div>
                ) : logs.length === 0 ? (
                    <p className="text-gray-500 italic text-center py-12">No logs found</p>
                ) : (
                    <>
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-700">
                                <thead>
                                    <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                        <th className="px-4 py-3">Timestamp</th>
                                        <th className="px-4 py-3">Protocol:Port</th>
                                        <th className="px-4 py-3">Source → Dest</th>
                                        <th className="px-4 py-3">User Context</th>
                                        <th className="px-4 py-3">AI Score</th>
                                        <th className="px-4 py-3">Decision</th>
                                        <th className="px-4 py-3">Severity</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800">
                                    {logs.map((log) => (
                                        <tr key={log.id} onClick={() => setSelectedLog(log)} className="text-sm text-gray-300 hover:bg-[#1f2937]/50 cursor-pointer group hover:border-l-2 hover:border-[#00ff7f]">
                                            <td className="px-4 py-3 text-xs">
                                                {new Date(log.timestamp).toLocaleString()}
                                                <span className="ml-2 text-[#00ff7f] text-xs opacity-0 group-hover:opacity-100 transition-opacity">▶ replay</span>
                                            </td>
                                            <td className="px-4 py-3 font-mono">
                                                {log.protocol}:{log.port}
                                            </td>
                                            <td className="px-4 py-3 font-mono text-xs">
                                                {log.source_ip} → {log.destination_ip}
                                            </td>
                                            <td className="px-4 py-3 text-xs">
                                                {log.user_identity} / {log.user_device} / {log.user_resource}
                                            </td>
                                            <td className="px-4 py-3 font-mono">
                                                {log.ai_score?.toFixed(2) || 'N/A'}
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className={`px-2 py-1 text-xs rounded ${
                                                    log.decision === 'Blocked' ? 'bg-red-600/30 text-red-400' :
                                                    log.decision === 'Quarantined' ? 'bg-yellow-600/30 text-yellow-400' :
                                                    'bg-green-600/30 text-green-400'
                                                }`}>
                                                    {log.decision}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className={`px-2 py-1 text-xs rounded ${SEVERITY_CLASSES[log.severity] || ''}`}>
                                                    {log.severity}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Pagination */}
                        <div className="mt-4 flex justify-between items-center">
                            <button
                                onClick={() => setPage(p => p - 1)}
                                disabled={page === 1}
                                className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                Previous
                            </button>
                            <span className="text-gray-400 text-sm">
                                Page {page} of {paginationInfo.pages}
                            </span>
                            <button
                                onClick={() => setPage(p => p + 1)}
                                disabled={page >= paginationInfo.pages}
                                className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                Next
                            </button>
                        </div>
                    </>
                )}
            </div>

            <LogCLIModal log={selectedLog} onClose={() => setSelectedLog(null)} />
        </div>
    );
};

export default ImmutableLogsView;

