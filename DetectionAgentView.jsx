import React, { useState, useEffect, useCallback } from 'react';
import { BrainIcon, PlayIcon, StopIcon, SearchIcon, ShieldIcon, ActivityIcon, EyeIcon, ChevronRightIcon, RefreshIcon } from './icons';
import { formatTimestamp, getRelativeTime, getSeverityClass } from './utils';

const SEVERITY_COLORS = {
    High: 'bg-red-900/50 text-red-400 border-red-500',
    Medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-500',
    Low: 'bg-green-900/50 text-green-400 border-green-500',
};

const RuleTypeBadge = ({ type }) => {
    const map = {
        rate_limit: 'bg-yellow-900/40 text-yellow-400 border-yellow-500',
        block: 'bg-red-900/40 text-red-400 border-red-500',
        quarantine: 'bg-orange-900/40 text-orange-400 border-orange-500',
    };
    return (
        <span className={`px-2 py-0.5 rounded-full text-xs font-bold border ${map[type] || 'bg-gray-800 text-gray-400 border-gray-600'}`}>
            {(type || 'unknown').replace('_', ' ').toUpperCase()}
        </span>
    );
};

const DetectionAgentView = ({ token, onNavigateToXAI }) => {
    const [agentStatus, setAgentStatus] = useState(null);
    const [detections, setDetections] = useState([]);
    const [qTable, setQTable] = useState([]);
    const [rlStats, setRlStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('live');
    const [starting, setStarting] = useState(false);
    const [responseStatus, setResponseStatus] = useState(null);
    const [selectedDetection, setSelectedDetection] = useState(null);
    const [qSearch, setQSearch] = useState('');
    const [liveSevFilter, setLiveSevFilter] = useState('all');
    const [healingLog, setHealingLog] = useState([]);
    const [showAllHealing, setShowAllHealing] = useState(false);

    const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

    const fetchStatus = useCallback(async () => {
        try {
            const res = await fetch('/api/agent/status', { headers });
            if (res.ok) setAgentStatus(await res.json());
        } catch (e) { console.error('Failed to fetch agent status:', e); }
    }, [token]);

    const fetchDetections = useCallback(async () => {
        try {
            const res = await fetch('/api/agent/detections?limit=100', { headers });
            if (res.ok) { const data = await res.json(); setDetections(data.detections || []); }
        } catch (e) { console.error('Failed to fetch detections:', e); }
    }, [token]);

    const fetchQTable = useCallback(async () => {
        try {
            const res = await fetch('/api/agent/qtable', { headers });
            if (res.ok) { const data = await res.json(); setQTable(data.q_table || []); setRlStats(data.stats || null); }
        } catch (e) { console.error('Failed to fetch Q-table:', e); }
    }, [token]);

    const fetchResponseStatus = useCallback(async () => {
        try {
            const res = await fetch('/api/response/status', { headers });
            if (res.ok) setResponseStatus(await res.json());
        } catch (e) { console.error('Failed to fetch response status:', e); }
    }, [token]);

    useEffect(() => {
        const init = async () => {
            await fetchStatus();
            await fetchDetections();
            await fetchQTable();
            await fetchResponseStatus();
            // Try to get healing log
            try {
                const hRes = await fetch('/api/response/healing-log', { headers });
                if (hRes.ok) { const d = await hRes.json(); setHealingLog(d.log || d.healing_log || []); }
            } catch (e) { /* no healing endpoint */ }
            setLoading(false);
        };
        init();

        const interval = setInterval(() => {
            fetchStatus();
            fetchDetections();
            fetchQTable();
            fetchResponseStatus();
        }, 5000);
        return () => clearInterval(interval);
    }, [fetchStatus, fetchDetections, fetchQTable, fetchResponseStatus]);

    const startAgent = async (mode) => {
        setStarting(true);
        try {
            await fetch(`/api/agent/${mode}`, { method: 'POST', headers });
            setTimeout(fetchStatus, 1000);
        } catch (e) { console.error('Failed to start agent:', e); }
        finally { setStarting(false); }
    };

    const stopAgent = async () => {
        try {
            await fetch('/api/agent/stop', { method: 'POST', headers });
            setTimeout(fetchStatus, 1000);
        } catch (e) { console.error('Failed to stop agent:', e); }
    };

    if (loading) {
        return (
            <div className="p-8 flex items-center justify-center min-h-[80vh]">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
            </div>
        );
    }

    const isRunning = agentStatus?.running;
    const mode = agentStatus?.mode || 'unknown';
    const totalDetections = agentStatus?.total_detections || detections.length;
    const blockedCount = detections.filter(d => d.rl_action === 'block').length;
    const allowedCount = detections.filter(d => d.rl_action === 'allow').length;

    // Filter detections
    const filteredDetections = detections.filter(d => {
        if (liveSevFilter === 'all') return true;
        return d.severity === liveSevFilter;
    });

    // Filter Q-table
    const filteredQTable = qTable.filter(q =>
        qSearch === '' || (q.state || '').toLowerCase().includes(qSearch.toLowerCase())
    );

    // Response agent stats
    const activeRules = responseStatus?.active_rules || [];
    const responseConfig = responseStatus?.config || {};

    const visibleHealing = showAllHealing ? healingLog : healingLog.slice(0, 3);

    const tabs = [
        { id: 'live', label: 'Live Feed', icon: ActivityIcon },
        { id: 'qtable', label: 'Q-Table', icon: BrainIcon },
        { id: 'response', label: 'Response Agent', icon: ShieldIcon },
        { id: 'viz', label: 'Visualizations', icon: EyeIcon },
    ];

    return (
        <div className="p-8">
            {/* HEADER */}
            <div className="flex justify-between items-center mb-6">
                <div className="flex items-center gap-4">
                    <BrainIcon className="w-9 h-9 text-[#00ff7f]" />
                    <div>
                        <h2 className="text-3xl font-bold text-white">Detection Agent</h2>
                        <div className="flex items-center gap-2 mt-1">
                            <span className={`flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold ${
                                isRunning ? 'bg-green-900/50 text-green-400 border border-green-500/30' : 'bg-gray-800 text-gray-400 border border-gray-700'
                            }`}>
                                <span className={`h-2 w-2 rounded-full ${isRunning ? 'bg-green-400 animate-pulse' : 'bg-gray-500'}`} />
                                {isRunning ? 'RUNNING' : 'STOPPED'}
                            </span>
                            {isRunning && (
                                <span className="px-2 py-0.5 rounded-full text-xs bg-blue-900/40 text-blue-300 border border-blue-500/30">
                                    {mode === 'simulation' ? 'Simulation Mode' : 'Live Capture'}
                                </span>
                            )}
                        </div>
                    </div>
                </div>
                {onNavigateToXAI && (
                    <button
                        onClick={onNavigateToXAI}
                        className="flex items-center gap-1 text-sm text-[#00ff7f] hover:text-white transition"
                    >
                        View AI Transparency <ChevronRightIcon className="w-4 h-4" />
                    </button>
                )}
            </div>

            {/* AGENT CONTROLS */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg mb-6">
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Agent Controls</h3>
                {!isRunning ? (
                    <div className="flex gap-4">
                        <div className="flex-1">
                            <button
                                onClick={() => startAgent('start')}
                                disabled={starting}
                                className="w-full flex items-center justify-center gap-2 py-3 bg-[#00ff7f] hover:bg-[#00ff7f]/80 text-black font-bold rounded-lg transition disabled:opacity-50"
                            >
                                <PlayIcon className="w-5 h-5" />
                                {starting ? 'Starting...' : 'Start Simulation'}
                            </button>
                            <p className="text-xs text-gray-500 mt-1.5 text-center">Generates synthetic traffic for analysis</p>
                        </div>
                        <div className="flex-1">
                            <button
                                onClick={() => startAgent('start-live')}
                                disabled={starting}
                                className="w-full flex items-center justify-center gap-2 py-3 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg transition disabled:opacity-50"
                            >
                                <PlayIcon className="w-5 h-5" />
                                {starting ? 'Starting...' : 'Start Live Capture'}
                            </button>
                            <p className="text-xs text-gray-500 mt-1.5 text-center">Real network interface (requires root/admin)</p>
                        </div>
                    </div>
                ) : (
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            <div className="flex items-center gap-2 bg-green-900/20 px-4 py-2 rounded-lg border border-green-500/20">
                                <span className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
                                <span className="text-green-400 text-sm font-medium">Agent Active — {totalDetections} detections</span>
                            </div>
                            <span className="text-xs text-gray-500">
                                ε = {agentStatus?.epsilon?.toFixed(4) || 'N/A'}
                            </span>
                        </div>
                        <button
                            onClick={stopAgent}
                            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-bold rounded-lg transition"
                        >
                            <StopIcon className="w-5 h-5" /> Stop Agent
                        </button>
                    </div>
                )}
            </div>

            {/* TAB BAR */}
            <div className="flex gap-2 mb-6 border-b border-gray-800 pb-2">
                {tabs.map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-sm font-medium transition ${
                            activeTab === tab.id
                                ? 'bg-[#00ff7f]/10 text-[#00ff7f] border-b-2 border-[#00ff7f]'
                                : 'text-gray-400 hover:text-white hover:bg-[#161b22]'
                        }`}
                    >
                        <tab.icon className="w-4 h-4" />
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* TAB CONTENT */}

            {/* LIVE FEED TAB */}
            {activeTab === 'live' && (
                <div className="space-y-4">
                    {/* Filter bar */}
                    <div className="flex gap-2 items-center">
                        <span className="text-sm text-gray-400">Filter:</span>
                        {['all', 'High', 'Medium', 'Low'].map(f => (
                            <button key={f} onClick={() => setLiveSevFilter(f)}
                                className={`px-3 py-1 text-xs rounded-lg transition ${
                                    liveSevFilter === f
                                        ? 'bg-[#00ff7f]/20 text-[#00ff7f] border border-[#00ff7f]/30'
                                        : 'bg-[#161b22] text-gray-400 border border-gray-700 hover:text-white'
                                }`}>
                                {f === 'all' ? 'All' : f}
                            </button>
                        ))}
                        <span className="ml-auto text-xs text-gray-500">{filteredDetections.length} detections</span>
                    </div>

                    {/* Two-panel layout */}
                    <div className="flex gap-4">
                        {/* LEFT — Detection List */}
                        <div className="flex-1 bg-[#161b22] rounded-xl border border-gray-800 overflow-hidden">
                            <div className="max-h-[65vh] overflow-y-auto">
                                <table className="min-w-full divide-y divide-gray-800">
                                    <thead className="sticky top-0 bg-[#161b22]">
                                        <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                            <th className="px-3 py-2.5">Time</th>
                                            <th className="px-3 py-2.5">Source → Dest</th>
                                            <th className="px-3 py-2.5">Protocol</th>
                                            <th className="px-3 py-2.5">Severity</th>
                                            <th className="px-3 py-2.5">Action</th>
                                            <th className="px-3 py-2.5">Score</th>
                                            <th className="px-3 py-2.5"></th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-800/50">
                                        {filteredDetections.length === 0 ? (
                                            <tr>
                                                <td colSpan={7} className="px-4 py-12 text-center text-gray-500 italic">
                                                    {isRunning ? 'Waiting for detections...' : 'Start the agent to begin detecting threats'}
                                                </td>
                                            </tr>
                                        ) : filteredDetections.slice(0, 50).map((d, idx) => {
                                            const actionClass = d.rl_action === 'block' ? 'bg-red-900/50 text-red-400' : 'bg-green-900/50 text-green-400';
                                            const isSelected = selectedDetection === idx;
                                            return (
                                                <tr key={idx}
                                                    onClick={() => setSelectedDetection(isSelected ? null : idx)}
                                                    className={`text-sm cursor-pointer transition ${isSelected ? 'bg-[#00ff7f]/5' : 'hover:bg-[#1f2937]/50'}`}
                                                >
                                                    <td className="px-3 py-2 text-xs text-gray-400 whitespace-nowrap">{getRelativeTime(d.timestamp)}</td>
                                                    <td className="px-3 py-2 font-mono text-xs text-white">
                                                        {d.src_ip} <span className="text-gray-500">→</span> {d.dst_ip}
                                                    </td>
                                                    <td className="px-3 py-2 text-xs text-gray-300">{d.protocol}:{d.dport}</td>
                                                    <td className="px-3 py-2">
                                                        <span className={`px-2 py-0.5 text-xs font-bold rounded-full ${SEVERITY_COLORS[d.severity] || 'bg-gray-800 text-gray-400'}`}>
                                                            {d.severity}
                                                        </span>
                                                    </td>
                                                    <td className="px-3 py-2">
                                                        <span className={`px-2 py-0.5 text-xs font-bold rounded-full ${actionClass}`}>
                                                            {(d.rl_action || '').toUpperCase()}
                                                        </span>
                                                    </td>
                                                    <td className="px-3 py-2 font-mono text-xs text-gray-300">
                                                        {(d.rf_confidence * 100).toFixed(0)}%
                                                    </td>
                                                    <td className="px-3 py-2">
                                                        {onNavigateToXAI && (
                                                            <button onClick={(e) => { e.stopPropagation(); onNavigateToXAI(); }}
                                                                className="text-[#00ff7f] hover:text-white text-xs transition">
                                                                Explain →
                                                            </button>
                                                        )}
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        {/* RIGHT — Summary Panel */}
                        {selectedDetection !== null && filteredDetections[selectedDetection] && (
                            <div className="w-80 bg-[#161b22] rounded-xl border border-gray-800 p-4 max-h-[65vh] overflow-y-auto">
                                <h4 className="text-sm font-bold text-white mb-3">Detection Summary</h4>
                                {(() => {
                                    const d = filteredDetections[selectedDetection];
                                    return (
                                        <div className="space-y-3 text-xs">
                                            <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                                <span className="text-gray-500 uppercase">Timestamp</span>
                                                <p className="text-white">{formatTimestamp(d.timestamp)}</p>
                                            </div>
                                            <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                                <span className="text-gray-500 uppercase">Source</span>
                                                <p className="text-white font-mono">{d.src_ip}:{d.sport}</p>
                                            </div>
                                            <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                                <span className="text-gray-500 uppercase">Destination</span>
                                                <p className="text-white font-mono">{d.dst_ip}:{d.dport}</p>
                                            </div>
                                            <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                                <span className="text-gray-500 uppercase">RF Prediction</span>
                                                <p className={`font-bold ${d.rf_prediction === 'attack' ? 'text-red-400' : 'text-green-400'}`}>
                                                    {(d.rf_prediction || '').toUpperCase()} ({(d.rf_confidence * 100).toFixed(1)}%)
                                                </p>
                                            </div>
                                            <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                                <span className="text-gray-500 uppercase">RL Action</span>
                                                <p className={`font-bold ${d.rl_action === 'block' ? 'text-red-400' : 'text-green-400'}`}>
                                                    {(d.rl_action || '').toUpperCase()}
                                                </p>
                                            </div>
                                            <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                                <span className="text-gray-500 uppercase">Reason</span>
                                                <p className="text-gray-300">{d.reason}</p>
                                            </div>
                                            <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                                <span className="text-gray-500 uppercase">Exploration</span>
                                                <p className={d.was_exploration ? 'text-yellow-400' : 'text-green-400'}>
                                                    {d.was_exploration ? '🎲 Random (ε-greedy)' : '🧠 Exploitation'}
                                                </p>
                                            </div>
                                        </div>
                                    );
                                })()}
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Q-TABLE TAB */}
            {activeTab === 'qtable' && (
                <div className="space-y-4">
                    {/* RL Stats */}
                    {rlStats && (
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                            {[
                                { label: 'Epsilon', value: rlStats.epsilon?.toFixed(4), sub: 'Exploration rate' },
                                { label: 'Total States', value: rlStats.total_states || qTable.length, sub: 'Unique states learned' },
                                { label: 'Allow Dominant', value: rlStats.allow_dominant || 'N/A', sub: 'States preferring allow' },
                                { label: 'Block Dominant', value: rlStats.block_dominant || 'N/A', sub: 'States preferring block' },
                            ].map(s => (
                                <div key={s.label} className="bg-[#161b22] p-4 rounded-xl border border-gray-800 text-center">
                                    <p className="text-2xl font-bold text-white">{s.value}</p>
                                    <p className="text-sm font-medium text-[#00ff7f]">{s.label}</p>
                                    <p className="text-xs text-gray-500 mt-1">{s.sub}</p>
                                </div>
                            ))}
                        </div>
                    )}

                    {/* Search bar */}
                    <div className="flex items-center bg-[#161b22] border border-gray-700 rounded-lg px-3 py-1">
                        <SearchIcon className="w-4 h-4 text-gray-500" />
                        <input
                            type="text"
                            value={qSearch}
                            onChange={(e) => setQSearch(e.target.value)}
                            placeholder="Search Q-table states..."
                            className="flex-1 bg-transparent text-white text-sm py-2 px-2 focus:outline-none"
                        />
                    </div>

                    {/* Q-Table cards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[60vh] overflow-y-auto">
                        {filteredQTable.length === 0 ? (
                            <div className="col-span-2 text-center py-12">
                                <BrainIcon className="w-10 h-10 text-gray-700 mx-auto mb-3" />
                                <p className="text-gray-500">No Q-table entries yet. Start the agent to begin learning.</p>
                            </div>
                        ) : filteredQTable.map((entry, idx) => {
                            const qAllow = entry.allow ?? entry.q_allow ?? 0;
                            const qBlock = entry.block ?? entry.q_block ?? 0;
                            const dominant = qBlock > qAllow ? 'BLOCK' : 'ALLOW';
                            const dominantColor = dominant === 'BLOCK' ? 'text-red-400' : 'text-green-400';
                            return (
                                <div key={idx} className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                                    <p className="text-xs text-gray-500 mb-2">State:</p>
                                    <p className="font-mono text-xs text-blue-300 mb-3 break-all">{entry.state || 'unknown'}</p>
                                    <div className="space-y-2">
                                        <div className="flex items-center gap-2">
                                            <span className="text-xs text-gray-400 w-14">Allow</span>
                                            <div className="flex-1 h-3 bg-gray-900 rounded overflow-hidden">
                                                <div
                                                    className={`h-3 rounded ${qAllow >= 0 ? 'bg-green-500' : 'bg-red-500'}`}
                                                    style={{ width: `${Math.min(Math.abs(qAllow) * 100, 100)}%` }}
                                                />
                                            </div>
                                            <span className={`text-xs font-mono w-12 text-right ${qAllow >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                                                {qAllow >= 0 ? '+' : ''}{qAllow.toFixed(2)}
                                            </span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-xs text-gray-400 w-14">Block</span>
                                            <div className="flex-1 h-3 bg-gray-900 rounded overflow-hidden">
                                                <div
                                                    className={`h-3 rounded ${qBlock >= 0 ? 'bg-green-500' : 'bg-red-500'}`}
                                                    style={{ width: `${Math.min(Math.abs(qBlock) * 100, 100)}%` }}
                                                />
                                            </div>
                                            <span className={`text-xs font-mono w-12 text-right ${qBlock >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                                                {qBlock >= 0 ? '+' : ''}{qBlock.toFixed(2)}
                                            </span>
                                        </div>
                                    </div>
                                    <p className={`text-xs font-bold mt-2 ${dominantColor}`}>→ Dominant: {dominant}</p>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* RESPONSE AGENT TAB */}
            {activeTab === 'response' && (
                <div className="space-y-4">
                    {/* Stats Row */}
                    <div className="grid grid-cols-3 gap-4">
                        <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800 text-center">
                            <p className="text-2xl font-bold text-white">{activeRules.length}</p>
                            <p className="text-sm text-gray-400">Active Rules</p>
                        </div>
                        <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800 text-center">
                            <p className="text-2xl font-bold text-white">{healingLog.length}</p>
                            <p className="text-sm text-gray-400">Auto-Healed</p>
                        </div>
                        <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800 text-center">
                            <p className="text-2xl font-bold text-white">
                                {responseConfig.block_ttl ? `${responseConfig.block_ttl}s` : 'N/A'}
                            </p>
                            <p className="text-sm text-gray-400">Block TTL</p>
                        </div>
                    </div>

                    {/* Two Column Layout */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        {/* LEFT — Active Rules Table */}
                        <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                            <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Active Rules</h3>
                            {activeRules.length === 0 ? (
                                <p className="text-gray-500 text-sm text-center py-8">No active response rules</p>
                            ) : (
                                <div className="overflow-x-auto">
                                    <table className="min-w-full divide-y divide-gray-800">
                                        <thead>
                                            <tr className="text-left text-gray-400 text-xs uppercase">
                                                <th className="px-3 py-2">IP</th>
                                                <th className="px-3 py-2">Type</th>
                                                <th className="px-3 py-2">Confidence</th>
                                                <th className="px-3 py-2">Expires</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-gray-800">
                                            {activeRules.map((rule, idx) => (
                                                <tr key={idx} className="text-sm hover:bg-[#0d1117]">
                                                    <td className="px-3 py-2 font-mono text-white">{rule.ip}</td>
                                                    <td className="px-3 py-2"><RuleTypeBadge type={rule.rule_type} /></td>
                                                    <td className="px-3 py-2 text-gray-300">
                                                        {rule.confidence != null ? `${(rule.confidence * 100).toFixed(0)}%` : 'N/A'}
                                                    </td>
                                                    <td className="px-3 py-2 text-xs text-gray-400">
                                                        {rule.expires_at ? formatTimestamp(rule.expires_at * 1000) : 'N/A'}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>

                        {/* RIGHT — Config + Healing */}
                        <div className="space-y-4">
                            <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                                <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Response Configuration</h3>
                                <div className="space-y-2 text-sm">
                                    {Object.entries(responseConfig).map(([key, val]) => (
                                        <div key={key} className="flex justify-between">
                                            <span className="text-gray-400">{key.replace(/_/g, ' ')}</span>
                                            <span className="text-white font-mono">{typeof val === 'boolean' ? (val ? 'Enabled' : 'Disabled') : String(val)}</span>
                                        </div>
                                    ))}
                                    {Object.keys(responseConfig).length === 0 && (
                                        <p className="text-gray-500 text-xs italic">No config data available</p>
                                    )}
                                </div>
                            </div>

                            {/* Self-Healing Log */}
                            <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                                <h3 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Self-Healing Log</h3>
                                {healingLog.length === 0 ? (
                                    <p className="text-gray-500 text-sm text-center py-4">No auto-unblock events yet</p>
                                ) : (
                                    <div className="space-y-2">
                                        {visibleHealing.map((entry, idx) => (
                                            <div key={idx} className="bg-[#0d1117] p-3 rounded-lg border border-gray-800 flex items-start gap-3">
                                                <span className="text-green-400 text-lg mt-0.5">🔄</span>
                                                <div className="flex-1">
                                                    <div className="flex items-center gap-2">
                                                        <span className="font-mono text-white text-sm">{entry.ip}</span>
                                                        <RuleTypeBadge type={entry.original_rule_type || entry.rule_type} />
                                                    </div>
                                                    <p className="text-xs text-gray-500 mt-1">
                                                        {entry.reversed_at ? formatTimestamp(entry.reversed_at * 1000) : entry.timestamp ? formatTimestamp(entry.timestamp * 1000) : ''}
                                                        {entry.reason && <span className="ml-2 text-gray-400">{(entry.reason || '').replace(/_/g, ' ')}</span>}
                                                    </p>
                                                </div>
                                            </div>
                                        ))}
                                        {healingLog.length > 3 && (
                                            <button
                                                onClick={() => setShowAllHealing(prev => !prev)}
                                                className="w-full py-2 text-xs text-gray-400 hover:text-white border border-gray-800 rounded-lg hover:border-gray-600 transition"
                                            >
                                                {showAllHealing ? 'Show less' : `Show ${healingLog.length - 3} more`}
                                            </button>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* VISUALIZATIONS TAB */}
            {activeTab === 'viz' && (
                <VisualizationsPanel token={token} />
            )}
        </div>
    );
};


const VisualizationsPanel = ({ token }) => {
    const [charts, setCharts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

    const fetchCharts = useCallback(async () => {
        try {
            const res = await fetch('/api/agent/visualizations', { headers });
            if (res.ok) {
                const data = await res.json();
                setCharts(data.charts || []);
                setError(null);
            } else {
                setError('Failed to load charts');
            }
        } catch (e) {
            setError('Failed to connect to backend');
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchCharts();
        const interval = setInterval(fetchCharts, 10000);
        return () => clearInterval(interval);
    }, [fetchCharts]);

    if (loading) {
        return (
            <div className="bg-[#161b22] p-8 rounded-xl border border-gray-800 text-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#00ff7f] mx-auto mb-3"></div>
                <p className="text-gray-500">Generating visualizations...</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="bg-[#161b22] p-8 rounded-xl border border-gray-800 text-center">
                <p className="text-red-400 mb-2">{error}</p>
                <button onClick={() => { setLoading(true); fetchCharts(); }}
                    className="px-4 py-2 bg-[#00ff7f]/20 border border-[#00ff7f] text-[#00ff7f] rounded-lg hover:bg-[#00ff7f]/40 transition text-sm">
                    Retry
                </button>
            </div>
        );
    }

    if (charts.length === 0) {
        return (
            <div className="bg-[#161b22] p-8 rounded-xl border border-gray-800 text-center">
                <p className="text-gray-500">No detections yet. Start the agent to generate visualizations.</p>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Live Detection Charts (matplotlib + seaborn)</h3>
                <button onClick={() => { setLoading(true); fetchCharts(); }}
                    className="flex items-center gap-1 px-3 py-1 text-xs bg-[#161b22] border border-gray-700 text-gray-400 rounded-lg hover:text-white hover:border-gray-500 transition">
                    <RefreshIcon className="w-3 h-3" /> Refresh
                </button>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {charts.map((chart, idx) => (
                    <div key={idx} className="bg-[#161b22] rounded-xl border border-gray-800 overflow-hidden">
                        <div className="px-4 py-2 border-b border-gray-800">
                            <h4 className="text-sm font-medium text-white">{chart.title}</h4>
                        </div>
                        <div className="p-2 flex justify-center">
                            <img src={`data:image/png;base64,${chart.image}`} alt={chart.title}
                                className="max-w-full h-auto rounded" />
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

const BrainIconExport = BrainIcon;
export { BrainIconExport as BrainIcon };
export default DetectionAgentView;
