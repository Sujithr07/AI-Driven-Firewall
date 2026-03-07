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

const DetectionAgentView = ({ token }) => {
    const [agentStatus, setAgentStatus] = useState(null);
    const [detections, setDetections] = useState([]);
    const [qTable, setQTable] = useState([]);
    const [rlStats, setRlStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('live');
    const [starting, setStarting] = useState(false);

    const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

    const fetchStatus = useCallback(async () => {
        try {
            const res = await fetch('http://localhost:5000/api/agent/status', { headers });
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
            const res = await fetch('http://localhost:5000/api/agent/detections?limit=100', { headers });
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
            const res = await fetch('http://localhost:5000/api/agent/qtable', { headers });
            if (res.ok) {
                const data = await res.json();
                setQTable(data.q_table || []);
                setRlStats(data.stats || null);
            }
        } catch (e) {
            console.error('Failed to fetch Q-table:', e);
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
            if (activeTab === 'qtable') fetchQTable();
        }, 3000);
        return () => clearInterval(interval);
    }, [activeTab]);

    const startAgent = async (simulation = true) => {
        setStarting(true);
        try {
            const res = await fetch('http://localhost:5000/api/agent/start', {
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
            await fetch('http://localhost:5000/api/agent/stop', { method: 'POST', headers });
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
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
                <StatusCard label="Status" value={isRunning ? 'ACTIVE' : 'STOPPED'} color={isRunning ? 'text-[#00ff7f]' : 'text-red-400'} />
                <StatusCard label="Packets Processed" value={agentStatus?.packets_processed || 0} color="text-white" />
                <StatusCard label="Attacks Detected" value={agentStatus?.attacks_detected || 0} color="text-red-400" />
                <StatusCard label="RL Accuracy" value={`${agentStatus?.rl_stats?.accuracy || 0}%`} color="text-blue-400" />
                <StatusCard label="Exploration (ε)" value={agentStatus?.rl_stats?.exploration_rate || '100%'} color="text-yellow-400" />
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

            {/* Tab Switcher */}
            <div className="flex gap-2 mb-4">
                {[
                    { id: 'live', label: 'Live Detections' },
                    { id: 'qtable', label: 'Q-Table' },
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
                            <th className="px-3 py-3">Reward</th>
                            <th className="px-3 py-3">Explore?</th>
                            <th className="px-3 py-3">Reason</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800/50">
                        {sorted.map((d, idx) => (
                            <tr key={idx} className={`text-xs hover:bg-[#1f2937]/50 ${d.is_malicious ? 'bg-red-950/20' : ''}`}>
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

const BrainIconExport = BrainIcon;
export { BrainIconExport as BrainIcon };
export default DetectionAgentView;
