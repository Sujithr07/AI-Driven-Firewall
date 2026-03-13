import React, { useState, useEffect } from 'react';
import LogCLIModal from './LogCLIModal';
import { FileTextIcon, SearchIcon, RefreshIcon, XIcon, DownloadIcon, LockIcon, CheckIcon } from './icons';
import { formatTimestamp, getSeverityClass, truncateHash } from './utils';

const ChainIntegrityBanner = ({ token }) => {
    const [status, setStatus] = useState(null);
    const [verifying, setVerifying] = useState(false);

    const verify = async () => {
        setVerifying(true);
        try {
            const res = await fetch('/api/logs/verify', {
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
        <div className={`p-4 rounded-xl border-2 mb-6 ${
            valid
                ? 'bg-green-900/10 border-green-500/50'
                : 'bg-red-900/20 border-red-500 animate-pulse'
        }`}>
            <div className="flex items-start justify-between">
                <div>
                    <div className="flex items-center gap-2 mb-1">
                        {valid
                            ? <LockIcon className="w-5 h-5 text-green-400" />
                            : <span className="text-xl">⚠️</span>}
                        <span className={`font-bold ${valid ? 'text-green-400' : 'text-red-400'}`}>
                            {valid
                                ? 'HASH CHAIN INTACT — All logs verified'
                                : `TAMPERING DETECTED — ${status.tampered_entries?.length || 0} entries compromised`}
                        </span>
                    </div>
                    <p className="text-gray-400 text-xs">
                        {status.total_entries} entries verified • {status.verified_at ? formatTimestamp(status.verified_at * 1000) : ''}
                    </p>
                    {!valid && status.first_tampered_id != null && (
                        <p className="text-red-400 text-xs mt-1">First tampered entry: ID #{status.first_tampered_id}</p>
                    )}
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={verify}
                        disabled={verifying}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-lg text-gray-300 disabled:opacity-50 transition"
                    >
                        <RefreshIcon className="w-3 h-3" />
                        {verifying ? 'Verifying...' : 'Re-verify'}
                    </button>
                    <a
                        href="/api/logs/export"
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-[#00ff7f]/10 hover:bg-[#00ff7f]/20 border border-[#00ff7f]/40 rounded-lg text-[#00ff7f] transition"
                    >
                        <DownloadIcon className="w-3 h-3" /> Export
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
    const [detailLog, setDetailLog] = useState(null);
    const [paginationInfo, setPaginationInfo] = useState({ per_page: 50, total: 0, pages: 0 });
    const [loading, setLoading] = useState(true);
    const [filters, setFilters] = useState({ severity: '', decision: '' });
    const [snapshotToast, setSnapshotToast] = useState(false);

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
                const response = await fetch(`/api/logs?${params}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
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

    const copyHash = (hash) => {
        if (hash) {
            navigator.clipboard.writeText(hash).catch(() => {});
        }
    };

    const decisionClass = (d) => ({
        Blocked: 'bg-red-600/30 text-red-400',
        Quarantined: 'bg-yellow-600/30 text-yellow-400',
        Allowed: 'bg-green-600/30 text-green-400',
    }[d] || 'bg-gray-600/30 text-gray-400');

    return (
        <div className="p-8">
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center">
                    <FileTextIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                    <div>
                        <h2 className="text-3xl font-bold text-white">Immutable Security Logs</h2>
                        <p className="text-gray-400 text-sm">SHA-256 hash chain protected • {paginationInfo.total} entries</p>
                    </div>
                </div>
                <button
                    onClick={() => { setSnapshotToast(true); setTimeout(() => setSnapshotToast(false), 3000); }}
                    className="flex items-center gap-1 px-3 py-1.5 text-sm bg-[#161b22] border border-gray-700 text-gray-400 rounded-lg hover:text-white hover:border-gray-500 transition"
                >
                    <LockIcon className="w-4 h-4" /> Lock Snapshot
                </button>
            </div>

            {snapshotToast && (
                <div className="mb-4 p-3 bg-blue-900/20 border border-blue-500 rounded-lg text-blue-400 text-sm flex items-center justify-between">
                    <span>📸 Snapshot feature coming soon — logs are already immutable via DB triggers.</span>
                    <button onClick={() => setSnapshotToast(false)} className="text-blue-300 hover:text-white"><XIcon className="w-4 h-4" /></button>
                </div>
            )}

            <ChainIntegrityBanner token={token} />

            {/* Filter Bar */}
            <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800 mb-6 flex items-center gap-4">
                <select
                    value={filters.severity}
                    onChange={(e) => { setFilters({ ...filters, severity: e.target.value }); setPage(1); }}
                    className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white text-sm"
                >
                    <option value="">All Severities</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Allowed">Allowed</option>
                </select>
                <select
                    value={filters.decision}
                    onChange={(e) => { setFilters({ ...filters, decision: e.target.value }); setPage(1); }}
                    className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white text-sm"
                >
                    <option value="">All Decisions</option>
                    <option value="Blocked">Blocked</option>
                    <option value="Quarantined">Quarantined</option>
                    <option value="Allowed">Allowed</option>
                </select>
                <span className="ml-auto text-gray-400 text-xs">Page {page} of {paginationInfo.pages}</span>
            </div>

            {/* Logs Table */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 shadow-lg overflow-hidden relative">
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
                                <thead className="sticky top-0 bg-[#161b22]">
                                    <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                        <th className="px-4 py-3">Timestamp</th>
                                        <th className="px-4 py-3">Protocol:Port</th>
                                        <th className="px-4 py-3">Source → Dest</th>
                                        <th className="px-4 py-3">AI Score</th>
                                        <th className="px-4 py-3">Decision</th>
                                        <th className="px-4 py-3">Severity</th>
                                        <th className="px-4 py-3">Hash</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800">
                                    {logs.map((log) => {
                                        const isBad = log.decision === 'Blocked';
                                        return (
                                            <tr
                                                key={log.id}
                                                onClick={() => setDetailLog(log)}
                                                className={`text-sm cursor-pointer transition group ${
                                                    isBad ? 'hover:bg-red-900/10' : 'hover:bg-[#1f2937]/50'
                                                }`}
                                            >
                                                <td className="px-4 py-3 text-xs text-gray-400">
                                                    {formatTimestamp(log.timestamp)}
                                                    <span className="ml-2 text-[#00ff7f] text-xs opacity-0 group-hover:opacity-100 transition-opacity">▶ replay</span>
                                                </td>
                                                <td className="px-4 py-3 font-mono text-gray-300">{log.protocol}:{log.port}</td>
                                                <td className="px-4 py-3 font-mono text-xs text-gray-300">{log.source_ip} → {log.destination_ip}</td>
                                                <td className="px-4 py-3 font-mono text-gray-300">{log.ai_score?.toFixed(2) || 'N/A'}</td>
                                                <td className="px-4 py-3">
                                                    <span className={`px-2 py-1 text-xs rounded ${decisionClass(log.decision)}`}>
                                                        {log.decision}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className={`px-2 py-1 text-xs rounded border ${getSeverityClass(log.severity)}`}>
                                                        {log.severity}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span
                                                        className="font-mono text-xs text-gray-500 cursor-pointer hover:text-[#00ff7f] transition"
                                                        onClick={(e) => { e.stopPropagation(); copyHash(log.entry_hash); }}
                                                        title="Click to copy full hash"
                                                    >
                                                        {truncateHash(log.entry_hash)}
                                                    </span>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>

                        {/* Pagination */}
                        <div className="p-4 flex justify-between items-center border-t border-gray-800">
                            <button
                                onClick={() => setPage(p => p - 1)}
                                disabled={page === 1}
                                className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed text-sm"
                            >
                                ← Previous
                            </button>
                            <span className="text-gray-400 text-sm">Page {page} of {paginationInfo.pages}</span>
                            <button
                                onClick={() => setPage(p => p + 1)}
                                disabled={page >= paginationInfo.pages}
                                className="px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed text-sm"
                            >
                                Next →
                            </button>
                        </div>
                    </>
                )}

                {/* Slide-in Detail Panel */}
                {detailLog && (
                    <div className="absolute top-0 right-0 bottom-0 w-96 bg-[#161b22] border-l border-[#00ff7f]/30 shadow-2xl overflow-y-auto z-10">
                        <div className="p-4 border-b border-gray-800 flex justify-between items-center sticky top-0 bg-[#161b22]">
                            <h4 className="text-white font-bold text-sm">Log Details #{detailLog.id}</h4>
                            <div className="flex items-center gap-2">
                                <button onClick={() => setSelectedLog(detailLog)} className="text-[#00ff7f] text-xs hover:text-white">▶ Replay</button>
                                <button onClick={() => setDetailLog(null)} className="text-gray-400 hover:text-white"><XIcon className="w-4 h-4" /></button>
                            </div>
                        </div>
                        <div className="p-4 space-y-3">
                            {[
                                ['Timestamp', formatTimestamp(detailLog.timestamp)],
                                ['Protocol', `${detailLog.protocol}:${detailLog.port}`],
                                ['Source IP', detailLog.source_ip],
                                ['Destination IP', detailLog.destination_ip],
                                ['AI Score', detailLog.ai_score?.toFixed(4)],
                                ['Decision', detailLog.decision],
                                ['Severity', detailLog.severity],
                                ['Reason', detailLog.reason],
                                ['Identity', detailLog.user_identity],
                                ['Device', detailLog.user_device],
                                ['Resource', detailLog.user_resource],
                            ].map(([label, value]) => (
                                <div key={label}>
                                    <span className="text-xs text-gray-500 uppercase">{label}</span>
                                    <p className="text-sm text-white font-mono break-all">{value || 'N/A'}</p>
                                </div>
                            ))}
                            <div className="border-t border-gray-800 pt-3">
                                <span className="text-xs text-gray-500 uppercase">Entry Hash</span>
                                <p className="text-xs text-gray-400 font-mono break-all cursor-pointer hover:text-[#00ff7f]"
                                    onClick={() => copyHash(detailLog.entry_hash)}>
                                    {detailLog.entry_hash || 'N/A'}
                                </p>
                            </div>
                            <div>
                                <span className="text-xs text-gray-500 uppercase">Previous Hash</span>
                                <p className="text-xs text-gray-400 font-mono break-all cursor-pointer hover:text-[#00ff7f]"
                                    onClick={() => copyHash(detailLog.prev_hash)}>
                                    {detailLog.prev_hash || 'GENESIS'}
                                </p>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            <LogCLIModal log={selectedLog} onClose={() => setSelectedLog(null)} />
        </div>
    );
};

export default ImmutableLogsView;
