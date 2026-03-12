import React, { useState, useEffect, useCallback } from 'react';

const BrainIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z"/><path d="M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z"/><path d="M15 13a4.5 4.5 0 0 1-3-4 4.5 4.5 0 0 1-3 4"/><path d="M17.599 6.5a3 3 0 0 0 .399-1.375"/><path d="M6.003 5.125A3 3 0 0 0 6.401 6.5"/><path d="M3.477 10.896a4 4 0 0 1 .585-.396"/><path d="M19.938 10.5a4 4 0 0 1 .585.396"/><path d="M6 18a4 4 0 0 1-1.967-.516"/><path d="M19.967 17.484A4 4 0 0 1 18 18"/></svg>
);

const PlayIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="6 3 20 12 6 21 6 3"/></svg>
);

const StopIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>
);

const SEVERITY_COLORS = {
    High: 'bg-red-900/50 text-red-400 border-red-500',
    Medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-500',
    Low: 'bg-green-900/50 text-green-400 border-green-500',
};

const XAI_FEATURE_LABELS = {
    proto_num: 'Protocol Type',
    sport: 'Source Port',
    dport: 'Dest Port',
    packet_size: 'Packet Size',
    src_is_private: 'Src IP Private',
    dst_is_private: 'Dst IP Private',
    has_syn: 'SYN Flag (scan)',
    has_fin: 'FIN Flag',
    has_rst: 'RST Flag',
    port_is_suspicious: 'Suspicious Port',
    port_is_well_known: 'Known Safe Port',
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
    const [xaiLatest, setXaiLatest] = useState(null);

    const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

    const fetchStatus = useCallback(async () => {
        try {
            const res = await fetch('/api/agent/status', { headers });
            if (res.ok) {
                const data = await res.json();
                setAgentStatus(data);
            }
        } catch (e) {
            console.error('Failed to fetch agent status:', e);
        }
    }, [token]);

    const fetchDetections = useCallback(async () => {
        try {
            const res = await fetch('/api/agent/detections?limit=100', { headers });
            if (res.ok) {
                const data = await res.json();
                setDetections(data.detections || []);
            }
        } catch (e) {
            console.error('Failed to fetch detections:', e);
        }
    }, [token]);

    const fetchQTable = useCallback(async () => {
        try {
            const res = await fetch('/api/agent/qtable', { headers });
            if (res.ok) {
                const data = await res.json();
                setQTable(data.q_table || []);
                setRlStats(data.stats || null);
            }
        } catch (e) {
            console.error('Failed to fetch Q-table:', e);
        }
    }, [token]);

    const fetchResponseStatus = useCallback(async () => {
        try {
            const res = await fetch('/api/response/status', { headers });
            if (res.ok) {
                const data = await res.json();
                setResponseStatus(data);
            }
        } catch (e) {
            console.error('Failed to fetch response status:', e);
        }
    }, [token]);

    const fetchXAILatest = useCallback(async () => {
        try {
            const res = await fetch('/api/xai/explain?limit=1', { headers });
            if (res.ok) {
                const data = await res.json();
                if (data.detections && data.detections.length > 0) {
                    setXaiLatest(data.detections[0]);
                }
            }
        } catch (e) {
            console.error('Failed to fetch XAI latest:', e);
        }
    }, [token]);

    useEffect(() => {
        const init = async () => {
            await fetchStatus();
            await fetchDetections();
            await fetchQTable();
            setLoading(false);
        };
        init();
        const interval = setInterval(() => {
            fetchStatus();
            fetchDetections();
            fetchXAILatest();
            if (activeTab === 'qtable') fetchQTable();
            if (activeTab === 'response') fetchResponseStatus();
        }, 3000);
        return () => clearInterval(interval);
    }, [activeTab, fetchStatus, fetchDetections, fetchQTable, fetchResponseStatus, fetchXAILatest]);

    const startAgent = async (simulation = true) => {
        setStarting(true);
        try {
            const res = await fetch('/api/agent/start', {
                method: 'POST',
                headers,
                body: JSON.stringify({ simulation }),
            });
            if (res.ok) {
                await fetchStatus();
            }
        } catch (e) {
            console.error('Failed to start agent:', e);
        } finally {
            setStarting(false);
        }
    };

    const stopAgent = async () => {
        try {
            await fetch('/api/agent/stop', { method: 'POST', headers });
            await fetchStatus();
        } catch (e) {
            console.error('Failed to stop agent:', e);
        }
    };

    if (loading) {
        return (
            <div className="p-8 flex items-center justify-center min-h-[80vh]">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
            </div>
        );
    }

    const isRunning = agentStatus?.running;

    return (
        <div className="p-8">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center">
                    <BrainIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                    <div>
                        <h2 className="text-3xl font-bold text-white">Detection Agent</h2>
                        <p className="text-gray-400 text-sm">RL-Powered Network Intrusion Detection</p>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    {isRunning ? (
                        <button
                            onClick={stopAgent}
                            className="flex items-center gap-2 px-4 py-2 bg-red-600/20 border border-red-500 text-red-400 rounded-lg hover:bg-red-600/40 transition"
                        >
                            <StopIcon className="w-4 h-4" /> Stop Agent
                        </button>
                    ) : (
                        <>
                            <button
                                onClick={() => startAgent(true)}
                                disabled={starting}
                                className="flex items-center gap-2 px-4 py-2 bg-[#00ff7f]/20 border border-[#00ff7f] text-[#00ff7f] rounded-lg hover:bg-[#00ff7f]/40 transition disabled:opacity-50"
                            >
                                <PlayIcon className="w-4 h-4" /> {starting ? 'Starting...' : 'Start (Simulation)'}
                            </button>
                            <button
                                onClick={() => startAgent(false)}
                                disabled={starting}
                                className="flex items-center gap-2 px-4 py-2 bg-blue-600/20 border border-blue-500 text-blue-400 rounded-lg hover:bg-blue-600/40 transition disabled:opacity-50"
                                title="Requires administrator privileges"
                            >
                                <PlayIcon className="w-4 h-4" /> {starting ? 'Starting...' : 'Start (Live Capture)'}
                            </button>
                        </>
                    )}
                </div>
            </div>

            {/* Status Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-4 mb-6">
                <StatusCard label="Status" value={isRunning ? 'ACTIVE' : 'STOPPED'} color={isRunning ? 'text-[#00ff7f]' : 'text-red-400'} />
                <StatusCard label="Packets Processed" value={agentStatus?.packets_processed || 0} color="text-white" />
                <StatusCard label="Attacks Detected" value={agentStatus?.attacks_detected || 0} color="text-red-400" />
                <StatusCard label="RL Accuracy" value={`${agentStatus?.rl_stats?.accuracy || 0}%`} color="text-blue-400" />
                <StatusCard label="Exploration (ε)" value={agentStatus?.rl_stats?.exploration_rate || '100%'} color="text-yellow-400" />
                <StatusCard label="Hard Blocked" value={agentStatus?.response_stats?.stats?.hard_blocks || 0} color="text-red-400" />
                <StatusCard label="Self-Healed" value={agentStatus?.response_stats?.stats?.self_healed || 0} color="text-[#00ff7f]" />
            </div>

            {/* RL Stats Detail */}
            {agentStatus?.rl_stats && (
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800 mb-6">
                    <h3 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Reinforcement Learning Agent</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                            <span className="text-gray-500">Total Decisions:</span>
                            <span className="text-white ml-2 font-mono">{agentStatus.rl_stats.total_decisions}</span>
                        </div>
                        <div>
                            <span className="text-gray-500">Correct:</span>
                            <span className="text-[#00ff7f] ml-2 font-mono">{agentStatus.rl_stats.correct_decisions}</span>
                        </div>
                        <div>
                            <span className="text-gray-500">Q-Table States:</span>
                            <span className="text-blue-400 ml-2 font-mono">{agentStatus.rl_stats.q_table_size}</span>
                        </div>
                        <div>
                            <span className="text-gray-500">Avg Reward (last 100):</span>
                            <span className={`ml-2 font-mono ${agentStatus.rl_stats.avg_reward_last_100 >= 0 ? 'text-[#00ff7f]' : 'text-red-400'}`}>
                                {agentStatus.rl_stats.avg_reward_last_100}
                            </span>
                        </div>
                    </div>
                    {/* Epsilon Progress Bar */}
                    <div className="mt-3">
                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                            <span>Exploration → Exploitation</span>
                            <span>{agentStatus.rl_stats.exploration_rate}</span>
                        </div>
                        <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-yellow-500 to-[#00ff7f] transition-all duration-500"
                                style={{ width: `${(1 - agentStatus.rl_stats.epsilon) * 100}%` }}
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* XAI Mini Insight Strip */}
            {xaiLatest && (
                <div className="bg-[#161b22] border border-[#00ff7f]/20 rounded-xl p-4 mb-4">
                    <div className="flex justify-between items-center">
                        <div>
                            <div className="flex items-center gap-2 text-sm">
                                <span>🔍</span>
                                <span className="text-gray-400">Latest Explanation:</span>
                                <span className="font-mono text-[#00ff7f]">{xaiLatest.src_ip}</span>
                                <span className="text-gray-500">—</span>
                                <span className="text-white">{XAI_FEATURE_LABELS[xaiLatest.top_feature] || xaiLatest.top_feature}</span>
                                <span className="text-gray-400">was the top signal</span>
                                <span className="text-yellow-400 font-mono">({xaiLatest.top_feature_contribution >= 0 ? '+' : ''}{xaiLatest.top_feature_contribution?.toFixed(2)})</span>
                            </div>
                            <div className="flex items-center gap-2 mt-1 text-xs">
                                <span className={`inline-block w-2 h-2 rounded-full ${xaiLatest.rf_confidence >= 0.6 ? 'bg-red-500' : xaiLatest.rf_confidence >= 0.3 ? 'bg-yellow-500' : 'bg-green-500'}`}></span>
                                <span className="text-gray-400">Confidence: {(xaiLatest.rf_confidence * 100).toFixed(0)}%</span>
                                <span className={xaiLatest.rf_confidence >= 0.6 ? 'text-red-400' : xaiLatest.rf_confidence >= 0.3 ? 'text-yellow-400' : 'text-green-400'}>
                                    {xaiLatest.rf_confidence >= 0.6 ? 'HIGH THREAT' : xaiLatest.rf_confidence >= 0.3 ? 'UNCERTAIN' : 'LOW THREAT'}
                                </span>
                            </div>
                        </div>
                        {onNavigateToXAI && (
                            <button
                                onClick={onNavigateToXAI}
                                className="px-4 py-2 bg-[#00ff7f]/20 border border-[#00ff7f] text-[#00ff7f] rounded-lg hover:bg-[#00ff7f]/40 transition text-sm whitespace-nowrap"
                            >
                                Full XAI →
                            </button>
                        )}
                    </div>
                </div>
            )}

            {/* Tab Switcher */}
            <div className="flex gap-2 mb-4">
                {[
                    { id: 'live', label: 'Live Detections' },
                    { id: 'qtable', label: 'Q-Table' },
                    { id: 'response', label: '🛡️ Response Agent' },
                    { id: 'viz', label: '📊 Visualizations' },
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => { setActiveTab(tab.id); if (tab.id === 'qtable') fetchQTable(); }}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                            activeTab === tab.id
                                ? 'bg-[#00ff7f]/20 text-[#00ff7f] border border-[#00ff7f]/30'
                                : 'bg-[#161b22] text-gray-400 border border-gray-800 hover:text-white'
                        }`}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            {activeTab === 'live' && <LiveDetectionsPanel detections={detections} />}
            {activeTab === 'qtable' && <QTablePanel qTable={qTable} rlStats={rlStats} />}
            {activeTab === 'response' && <ResponseAgentPanel token={token} />}
            {activeTab === 'viz' && <VisualizationsPanel token={token} />}
        </div>
    );
};

// --- Sub-Components ---

const StatusCard = ({ label, value, color }) => (
    <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">{label}</p>
        <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
    </div>
);

const LiveDetectionsPanel = ({ detections }) => {
    if (!detections || detections.length === 0) {
        return (
            <div className="bg-[#161b22] p-8 rounded-xl border border-gray-800 text-center">
                <BrainIcon className="w-12 h-12 text-gray-700 mx-auto mb-3" />
                <p className="text-gray-500">No detections yet. Start the agent to begin monitoring.</p>
            </div>
        );
    }

    // Show newest first
    const sorted = [...detections].reverse();

    return (
        <div className="bg-[#161b22] rounded-xl border border-gray-800 overflow-hidden">
            <div className="overflow-x-auto max-h-[60vh] overflow-y-auto">
                <table className="min-w-full divide-y divide-gray-800">
                    <thead className="sticky top-0 bg-[#161b22] z-10">
                        <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                            <th className="px-3 py-3">Time</th>
                            <th className="px-3 py-3">Source</th>
                            <th className="px-3 py-3">Destination</th>
                            <th className="px-3 py-3">Proto</th>
                            <th className="px-3 py-3">Port</th>
                            <th className="px-3 py-3">Size</th>
                            <th className="px-3 py-3">RF Pred</th>
                            <th className="px-3 py-3">RF Conf</th>
                            <th className="px-3 py-3">RL Action</th>
                            <th className="px-3 py-3">Response</th>
                            <th className="px-3 py-3">Reward</th>
                            <th className="px-3 py-3">Explore?</th>
                            <th className="px-3 py-3">Reason</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800/50">
                        {sorted.map((d, idx) => (
                            <tr key={idx} className={`text-xs hover:bg-[#1f2937]/50 ${d.is_malicious ? 'bg-red-950/20' : ''} ${d.response_action === 'hard_block' ? 'border-l-2 border-red-500 bg-red-950/20' : ''} ${d.response_action === 'rate_limit' ? 'border-l-2 border-yellow-500 bg-yellow-950/10' : ''} ${d.response_action === 'quarantine' ? 'border-l-2 border-orange-500 bg-orange-950/10' : ''}`}>
                                <td className="px-3 py-2 text-gray-300 font-mono whitespace-nowrap">
                                    {new Date(d.timestamp).toLocaleTimeString()}
                                </td>
                                <td className="px-3 py-2 text-gray-300 font-mono">{d.src_ip}</td>
                                <td className="px-3 py-2 text-gray-300 font-mono">{d.dst_ip}</td>
                                <td className="px-3 py-2">
                                    <span className="px-2 py-0.5 rounded bg-blue-900/30 text-blue-300">{d.protocol}</span>
                                </td>
                                <td className="px-3 py-2 text-gray-300 font-mono">{d.dport}</td>
                                <td className="px-3 py-2 text-gray-400">{d.size}B</td>
                                <td className="px-3 py-2">
                                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                        d.rf_prediction === 'attack' ? 'bg-red-900/40 text-red-300' : 'bg-green-900/40 text-green-300'
                                    }`}>
                                        {d.rf_prediction}
                                    </span>
                                </td>
                                <td className="px-3 py-2 text-gray-300 font-mono">{(d.rf_confidence * 100).toFixed(0)}%</td>
                                <td className="px-3 py-2">
                                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                        d.rl_action === 'block' ? 'bg-red-600/30 text-red-400' : 'bg-green-600/30 text-green-400'
                                    }`}>
                                        {d.rl_action.toUpperCase()}
                                    </span>
                                </td>
                                <td className="px-3 py-2">
                                    {d.response_action === 'hard_block' ? (
                                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-600/30 text-red-400">🔴 HARD BLOCK</span>
                                    ) : d.response_action === 'rate_limit' ? (
                                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-yellow-600/30 text-yellow-400">🟡 RATE LIMIT</span>
                                    ) : d.response_action === 'quarantine' ? (
                                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-orange-600/30 text-orange-400">🟠 QUARANTINE</span>
                                    ) : d.response_action === 'temp_block' ? (
                                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-purple-600/30 text-purple-400">⏱ TEMP BLOCK</span>
                                    ) : d.response_action === 'already_blocked' ? (
                                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-gray-600/30 text-gray-400">🔒 REPEAT</span>
                                    ) : (
                                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-green-600/30 text-green-400">✅ ALLOWED</span>
                                    )}
                                </td>
                                <td className="px-3 py-2 font-mono">
                                    <span className={d.rl_reward > 0 ? 'text-[#00ff7f]' : 'text-red-400'}>
                                        {d.rl_reward > 0 ? '+1' : '-1'}
                                    </span>
                                </td>
                                <td className="px-3 py-2">
                                    {d.was_exploration ? (
                                        <span className="text-yellow-400">🎲</span>
                                    ) : (
                                        <span className="text-[#00ff7f]">🧠</span>
                                    )}
                                </td>
                                <td className="px-3 py-2 text-gray-400 max-w-[150px] truncate" title={d.reason}>
                                    {d.reason}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

const QTablePanel = ({ qTable, rlStats }) => {
    if (!qTable || qTable.length === 0) {
        return (
            <div className="bg-[#161b22] p-8 rounded-xl border border-gray-800 text-center">
                <p className="text-gray-500">Q-Table is empty. Start the agent to build learned states.</p>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                <p className="text-gray-400 text-sm mb-2">
                    The Q-Table maps <span className="text-white font-mono">(reason, ip_type, protocol, port_type)</span> states
                    to learned Q-values for <span className="text-green-400 font-mono">allow</span> and <span className="text-red-400 font-mono">block</span> actions.
                    Higher absolute difference = higher confidence in the best action.
                </p>
            </div>
            <div className="bg-[#161b22] rounded-xl border border-gray-800 overflow-hidden">
                <div className="overflow-x-auto max-h-[55vh] overflow-y-auto">
                    <table className="min-w-full divide-y divide-gray-800">
                        <thead className="sticky top-0 bg-[#161b22] z-10">
                            <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                <th className="px-4 py-3">State (reason|ip_type|protocol|port_type)</th>
                                <th className="px-4 py-3">Q(allow)</th>
                                <th className="px-4 py-3">Q(block)</th>
                                <th className="px-4 py-3">Best Action</th>
                                <th className="px-4 py-3">Confidence</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800/50">
                            {qTable.map((entry, idx) => (
                                <tr key={idx} className="text-sm hover:bg-[#1f2937]/50">
                                    <td className="px-4 py-2 font-mono text-gray-300 text-xs">
                                        {entry.state.split('|').map((part, i) => (
                                            <span key={i}>
                                                {i > 0 && <span className="text-gray-600"> | </span>}
                                                <span className="text-blue-300">{part}</span>
                                            </span>
                                        ))}
                                    </td>
                                    <td className="px-4 py-2 font-mono text-green-400">{entry.allow_q}</td>
                                    <td className="px-4 py-2 font-mono text-red-400">{entry.block_q}</td>
                                    <td className="px-4 py-2">
                                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                            entry.best_action === 'block' ? 'bg-red-600/30 text-red-400' : 'bg-green-600/30 text-green-400'
                                        }`}>
                                            {entry.best_action.toUpperCase()}
                                        </span>
                                    </td>
                                    <td className="px-4 py-2">
                                        <div className="flex items-center gap-2">
                                            <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-[#00ff7f] rounded-full"
                                                    style={{ width: `${Math.min(entry.confidence * 100, 100)}%` }}
                                                />
                                            </div>
                                            <span className="text-gray-400 text-xs font-mono">{entry.confidence}</span>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

const RuleTypeBadge = ({ type }) => {
    const styles = {
        hard_block: 'bg-red-600/30 text-red-400 border border-red-500/30',
        temp_block: 'bg-purple-600/30 text-purple-400 border border-purple-500/30',
        rate_limit: 'bg-yellow-600/30 text-yellow-400 border border-yellow-500/30',
        quarantine: 'bg-orange-600/30 text-orange-400 border border-orange-500/30',
    };
    return (
        <span className={`px-2 py-0.5 rounded text-xs font-bold ${styles[type] || 'bg-gray-600/30 text-gray-400 border border-gray-500/30'}`}>
            {(type || '').replace(/_/g, ' ').toUpperCase()}
        </span>
    );
};

const ResponseAgentPanel = ({ token }) => {
    const [data, setData] = useState(null);
    const [loadingRollback, setLoadingRollback] = useState(null);
    const [lastUpdated, setLastUpdated] = useState(null);
    const [activeTab, setActiveTab] = useState('active');
    const [rollbackTarget, setRollbackTarget] = useState(null);
    const [showAllHealing, setShowAllHealing] = useState(false);
    const [now, setNow] = useState(Date.now());
    const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

    useEffect(() => {
        const tick = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(tick);
    }, []);

    const fetchData = useCallback(async () => {
        try {
            const res = await fetch('/api/response/status', { headers });
            if (res.ok) {
                setData(await res.json());
                setLastUpdated(new Date());
            }
        } catch (e) {
            console.error('Failed to fetch response status:', e);
        }
    }, [token]);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, [fetchData]);

    const handleRollback = async (actionId) => {
        setLoadingRollback(actionId);
        setRollbackTarget(null);
        try {
            await fetch(`/api/response/rollback/${encodeURIComponent(actionId)}`, {
                method: 'POST', headers
            });
            await fetchData();
        } catch (e) {
            console.error('Rollback failed:', e);
        } finally {
            setLoadingRollback(null);
        }
    };

    const formatAge = (seconds) => {
        if (!seconds) return '0s';
        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);
        return m > 0 ? `${m}m ${s}s` : `${s}s`;
    };

    const formatExpiry = (entry) => {
        if (!entry.expires_at) return 'Permanent';
        const remaining = Math.max(0, Math.floor(entry.expires_at - Date.now() / 1000));
        if (remaining <= 0) return 'Expired';
        const m = Math.floor(remaining / 60);
        const s = remaining % 60;
        return `${m}m ${s}s left`;
    };

    const confidenceColor = (c) => {
        if (c > 0.8) return 'bg-red-500';
        if (c > 0.5) return 'bg-yellow-500';
        return 'bg-orange-500';
    };

    if (!data) {
        return (
            <div className="bg-[#161b22] p-8 rounded-xl border border-gray-800 text-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#00ff7f] mx-auto mb-3"></div>
                <p className="text-gray-500">Loading response agent data...</p>
            </div>
        );
    }

    const statCards = [
        { label: 'Hard Blocks', key: 'hard_blocks', color: 'text-red-400', icon: '🔴' },
        { label: 'Temp Blocks', key: 'temp_blocks', color: 'text-purple-400', icon: '⏱' },
        { label: 'Rate Limits', key: 'rate_limits', color: 'text-yellow-400', icon: '🟡' },
        { label: 'Quarantines', key: 'quarantines', color: 'text-orange-400', icon: '🟠' },
        { label: 'Self-Healed', key: 'self_healed', color: 'text-green-400', icon: '💚' },
        { label: 'Rollbacks', key: 'rollbacks', color: 'text-blue-400', icon: '🔵' },
    ];

    const tabs = [
        { id: 'active', label: 'Active Rules', count: data.blocked_ips?.length || 0 },
        { id: 'history', label: 'Action History', count: data.action_history?.length || 0 },
        { id: 'healing', label: 'Self-Healing Log', count: data.self_healing_log?.length || 0 },
    ];

    const healingLog = data.self_healing_log || [];
    const visibleHealing = showAllHealing ? healingLog : healingLog.slice(0, 3);
    const hiddenCount = healingLog.length - 3;

    return (
        <div className="space-y-6">
            {/* Rollback Confirmation Modal */}
            {rollbackTarget && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
                    <div className="bg-[#161b22] border border-gray-700 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
                        <h3 className="text-lg font-semibold text-white mb-3">Confirm Rollback</h3>
                        <p className="text-gray-400 text-sm mb-4">
                            Are you sure you want to rollback the rule for{' '}
                            <span className="font-mono bg-gray-800 text-white px-2 py-0.5 rounded">{rollbackTarget.ip}</span>?
                        </p>
                        <div className="flex justify-end gap-3">
                            <button
                                onClick={() => setRollbackTarget(null)}
                                className="px-4 py-2 text-sm bg-gray-800 border border-gray-700 text-gray-300 rounded-lg hover:bg-gray-700 transition"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={() => handleRollback(rollbackTarget.action_id)}
                                disabled={loadingRollback === rollbackTarget.action_id}
                                className="px-4 py-2 text-sm bg-red-600/20 border border-red-500/30 text-red-400 rounded-lg hover:bg-red-600/40 transition disabled:opacity-50"
                            >
                                {loadingRollback === rollbackTarget.action_id ? '...' : 'Rollback'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Header */}
            <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <h3 className="text-lg font-semibold text-white">🛡️ Response Agent</h3>
                        <span className="flex items-center gap-1.5">
                            <span className="relative flex h-2.5 w-2.5">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500"></span>
                            </span>
                        </span>
                        {lastUpdated && (
                            <span className="text-xs text-gray-500">
                                Updated {lastUpdated.toLocaleTimeString()}
                            </span>
                        )}
                    </div>
                    {data.dry_run ? (
                        <span className="px-3 py-1 rounded-full text-xs font-bold bg-yellow-600/30 text-yellow-400 border border-yellow-500/30">DRY RUN</span>
                    ) : (
                        <span className="px-3 py-1 rounded-full text-xs font-bold bg-red-600/30 text-red-400 border border-red-500/30 animate-pulse">LIVE</span>
                    )}
                </div>

                {/* 6 Stat Cards */}
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                    {statCards.map(({ label, key, color, icon }) => (
                        <div key={key} className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                            <p className="text-xs text-gray-500 uppercase flex items-center gap-1">
                                <span>{icon}</span> {label}
                            </p>
                            <p className={`text-xl font-bold font-mono ${color}`}>{data.stats?.[key] || 0}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* Tab Switcher */}
            <div className="flex gap-2">
                {tabs.map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 ${
                            activeTab === tab.id
                                ? 'bg-[#00ff7f]/20 text-[#00ff7f] border border-[#00ff7f]/30'
                                : 'bg-[#161b22] text-gray-400 border border-gray-800 hover:text-white'
                        }`}
                    >
                        {tab.label}
                        <span className={`px-1.5 py-0.5 rounded-full text-xs font-mono ${
                            activeTab === tab.id ? 'bg-[#00ff7f]/30 text-[#00ff7f]' : 'bg-gray-800 text-gray-500'
                        }`}>
                            {tab.count}
                        </span>
                    </button>
                ))}
            </div>

            {/* Active Rules Tab */}
            {activeTab === 'active' && (
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                    <h3 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">
                        Active Enforcement Rules ({data.total_blocked || 0})
                    </h3>
                    {(!data.blocked_ips || data.blocked_ips.length === 0) ? (
                        <div className="text-center py-10">
                            <span className="text-4xl">✅</span>
                            <p className="text-gray-500 text-sm mt-3">No active enforcement rules</p>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-800">
                                <thead>
                                    <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                        <th className="px-3 py-2">IP Address</th>
                                        <th className="px-3 py-2">Rule Type</th>
                                        <th className="px-3 py-2">Reason</th>
                                        <th className="px-3 py-2">Confidence</th>
                                        <th className="px-3 py-2">Active For</th>
                                        <th className="px-3 py-2">Expiry</th>
                                        <th className="px-3 py-2">Action</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800/50">
                                    {data.blocked_ips.map((entry, idx) => {
                                        const conf = entry.confidence || 0;
                                        return (
                                            <tr key={idx} className="text-sm hover:bg-[#1f2937]/50">
                                                <td className="px-3 py-2 font-mono text-gray-300">{entry.ip}</td>
                                                <td className="px-3 py-2"><RuleTypeBadge type={entry.rule_type} /></td>
                                                <td className="px-3 py-2 text-gray-400 max-w-[180px] truncate" title={entry.reason}>{entry.reason}</td>
                                                <td className="px-3 py-2">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                                            <div className={`h-full rounded-full ${confidenceColor(conf)}`} style={{ width: `${Math.min(conf * 100, 100)}%` }} />
                                                        </div>
                                                        <span className="text-gray-300 font-mono text-xs">{(conf * 100).toFixed(0)}%</span>
                                                    </div>
                                                </td>
                                                <td className="px-3 py-2 text-gray-400 font-mono">{formatAge(entry.age_seconds)}</td>
                                                <td className="px-3 py-2 text-gray-400 font-mono text-xs">{formatExpiry(entry)}</td>
                                                <td className="px-3 py-2">
                                                    <button
                                                        onClick={() => setRollbackTarget(entry)}
                                                        disabled={loadingRollback === entry.action_id}
                                                        className="px-2 py-1 text-xs bg-red-600/20 border border-red-500/30 text-red-400 rounded hover:bg-red-600/40 transition disabled:opacity-50"
                                                    >
                                                        {loadingRollback === entry.action_id ? '...' : 'Rollback'}
                                                    </button>
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

            {/* Action History Tab */}
            {activeTab === 'history' && (
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                    <h3 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Action History</h3>
                    {(!data.action_history || data.action_history.length === 0) ? (
                        <p className="text-gray-500 text-sm text-center py-4">No actions recorded yet</p>
                    ) : (
                        <div className="relative pl-6">
                            <div className="absolute left-2.5 top-0 bottom-0 w-px bg-gray-700"></div>
                            {data.action_history.map((entry, idx) => (
                                <div
                                    key={idx}
                                    className={`relative mb-4 ${entry.reversed ? 'opacity-50' : ''}`}
                                >
                                    <div className="absolute -left-3.5 top-1.5 w-3 h-3 rounded-full border-2 border-gray-700 bg-[#161b22]"></div>
                                    <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span className="font-mono text-white text-sm bg-gray-800 px-2 py-0.5 rounded">{entry.ip}</span>
                                            <RuleTypeBadge type={entry.rule_type} />
                                            {entry.reversed && (
                                                <span className="text-xs italic text-gray-500">reversed</span>
                                            )}
                                        </div>
                                        <div className="mt-1 flex items-center gap-3 text-xs text-gray-500">
                                            <span className="font-mono">{entry.timestamp ? new Date(entry.timestamp * 1000).toLocaleString() : ''}</span>
                                            <span className="text-gray-400">{entry.reason}</span>
                                            {entry.confidence != null && (
                                                <span className="font-mono text-gray-400">{(entry.confidence * 100).toFixed(0)}%</span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* Self-Healing Log Tab */}
            {activeTab === 'healing' && (
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                    <h3 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Self-Healing Log</h3>
                    {healingLog.length === 0 ? (
                        <p className="text-gray-500 text-sm text-center py-4">No auto-unblock events yet</p>
                    ) : (
                        <div className="space-y-3">
                            {visibleHealing.map((entry, idx) => (
                                <div key={idx} className="bg-[#0d1117] p-3 rounded-lg border border-gray-800 flex items-start gap-3">
                                    <span className="text-green-400 text-lg mt-0.5">🔄</span>
                                    <div className="flex-1">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span className="font-mono text-white text-sm">{entry.ip}</span>
                                            <RuleTypeBadge type={entry.original_rule_type || entry.rule_type} />
                                        </div>
                                        <div className="mt-1 flex items-center gap-3 text-xs text-gray-500">
                                            <span className="font-mono">
                                                {entry.reversed_at
                                                    ? new Date(entry.reversed_at * 1000).toLocaleString()
                                                    : entry.timestamp
                                                        ? new Date(entry.timestamp * 1000).toLocaleString()
                                                        : ''}
                                            </span>
                                            <span className="text-gray-400">{(entry.reason || '').replace(/_/g, ' ')}</span>
                                        </div>
                                    </div>
                                </div>
                            ))}
                            {healingLog.length > 3 && (
                                <button
                                    onClick={() => setShowAllHealing(prev => !prev)}
                                    className="w-full py-2 text-xs text-gray-400 hover:text-white border border-gray-800 rounded-lg hover:border-gray-600 transition"
                                >
                                    {showAllHealing ? 'Show less' : `Show ${hiddenCount} more`}
                                </button>
                            )}
                        </div>
                    )}
                </div>
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
                    className="px-3 py-1 text-xs bg-[#161b22] border border-gray-700 text-gray-400 rounded-lg hover:text-white hover:border-gray-500 transition">
                    ↻ Refresh
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
