import React, { useState, useEffect, useCallback } from 'react';
import { GlobeIcon, RefreshIcon, PlayIcon } from './icons';
import { formatTimestamp } from './utils';

const FederationView = ({ token }) => {
    const [localStatus, setLocalStatus] = useState(null);
    const [serverStatus, setServerStatus] = useState(null);
    const [rounds, setRounds] = useState([]);
    const [serverReachable, setServerReachable] = useState(false);
    const [triggerMsg, setTriggerMsg] = useState(null);

    const fetchData = useCallback(async () => {
        if (!token) return;
        try {
            const [statusRes, roundsRes] = await Promise.all([
                fetch('/api/fl/status', { headers: { Authorization: `Bearer ${token}` } }),
                fetch('/api/fl/rounds', { headers: { Authorization: `Bearer ${token}` } }),
            ]);

            if (statusRes.ok) {
                const statusData = await statusRes.json();
                setLocalStatus(statusData.local);
                setServerStatus(statusData.server);
                setServerReachable(!!statusData.server);
            }

            if (roundsRes.ok) {
                const roundsData = await roundsRes.json();
                setRounds(roundsData.rounds || []);
            }
        } catch (err) {
            console.error('Failed to fetch FL data:', err);
            setServerReachable(false);
        }
    }, [token]);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, [fetchData]);

    const waitingClients = serverStatus?.waiting_clients || [];

    const triggerTraining = () => {
        setTriggerMsg('Training round trigger requires the federation server. This is a UI placeholder.');
        setTimeout(() => setTriggerMsg(null), 4000);
    };

    return (
        <div className="p-8 space-y-6">
            {/* Header */}
            <div className="flex justify-between items-center">
                <div className="flex items-center gap-3">
                    <GlobeIcon className="w-9 h-9 text-[#00ff7f]" />
                    <div>
                        <h2 className="text-3xl font-bold text-white">Federated Learning</h2>
                        <p className="text-gray-400 text-sm">Privacy-preserving distributed model training</p>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    {/* Connection badge */}
                    <span className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${
                        serverReachable
                            ? 'bg-green-900/30 border-green-500/30 text-green-400'
                            : 'bg-red-900/30 border-red-500/30 text-red-400'
                    }`}>
                        <span className={`h-2 w-2 rounded-full ${serverReachable ? 'bg-green-400 animate-pulse' : 'bg-red-500'}`} />
                        {serverReachable ? 'Server Connected' : 'Server Unreachable'}
                    </span>
                    <button
                        onClick={triggerTraining}
                        className="flex items-center gap-1 px-3 py-1.5 text-sm bg-[#00ff7f] text-black font-bold rounded-lg hover:bg-[#00ff7f]/80 transition"
                    >
                        <PlayIcon className="w-4 h-4" /> Trigger Training Round
                    </button>
                </div>
            </div>

            {triggerMsg && (
                <div className="p-3 bg-blue-900/20 border border-blue-500 rounded-lg text-blue-400 text-sm">
                    {triggerMsg}
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Federation Status Card */}
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-xl font-semibold text-gray-200 mb-4">Federation Status</h3>
                    <div className="space-y-3 text-sm">
                        {[
                            ['Client ID', localStatus?.client_id || 'N/A'],
                            ['Rounds Participated', localStatus?.rounds_participated ?? 0],
                            ['Last Round', localStatus?.last_round_time ? formatTimestamp(localStatus.last_round_time) : 'Never'],
                            ['Global Model Version', `v${localStatus?.global_model_version ?? 0}`],
                            ['Differential Privacy', localStatus?.dp_enabled ? 'Enabled (ε=1.0)' : 'Disabled'],
                            ['Local Samples', localStatus?.local_samples ?? 0],
                        ].map(([label, value]) => (
                            <div key={label} className="flex justify-between">
                                <span className="text-gray-400">{label}</span>
                                <span className={`font-mono ${
                                    label === 'Differential Privacy'
                                        ? (localStatus?.dp_enabled ? 'text-[#00ff7f]' : 'text-yellow-400')
                                        : 'text-white'
                                }`}>{value}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Federation Network Card */}
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-xl font-semibold text-gray-200 mb-4">Federation Network</h3>
                    {waitingClients.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                            {waitingClients.map((client, idx) => (
                                <div key={idx} className="flex items-center gap-2 bg-[#0d1117] px-3 py-2 rounded-full border border-gray-700">
                                    <span className="h-2 w-2 rounded-full bg-[#00ff7f]" />
                                    <span className="text-white font-mono text-sm">{client.client_id}</span>
                                    <span className="text-gray-400 text-xs">{client.n_samples} samples</span>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p className="text-gray-500 italic text-sm">No clients currently waiting for aggregation.</p>
                    )}
                    {serverStatus && (
                        <div className="mt-4 pt-4 border-t border-gray-800 text-sm space-y-1">
                            <div className="flex justify-between text-gray-400">
                                <span>Current Round</span>
                                <span className="text-white font-mono">{serverStatus.round_number}</span>
                            </div>
                            <div className="flex justify-between text-gray-400">
                                <span>Min Clients</span>
                                <span className="text-white font-mono">{serverStatus.min_clients}</span>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Privacy Guarantee Card */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                <h3 className="text-xl font-semibold text-gray-200 mb-3">Privacy Guarantee</h3>
                <p className="text-gray-300 text-sm leading-relaxed">
                    Raw packet data never leaves this machine. Only differentially private weight updates
                    (ε=1.0) are shared with the federation.
                </p>
            </div>

            {/* Recent Rounds Table */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                <h3 className="text-xl font-semibold text-gray-200 mb-4">Recent Rounds</h3>
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-700">
                        <thead>
                            <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                <th className="px-4 py-2">Round</th>
                                <th className="px-4 py-2">Timestamp</th>
                                <th className="px-4 py-2">Clients</th>
                                <th className="px-4 py-2">Total Samples</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                            {rounds.length > 0 ? (
                                [...rounds].reverse().map((r, idx) => (
                                    <tr key={idx} className="text-sm text-gray-300 hover:bg-[#1f2937]/50">
                                        <td className="px-4 py-3 font-mono text-[#00ff7f]">{r.round}</td>
                                        <td className="px-4 py-3">
                                            {r.timestamp ? formatTimestamp(r.timestamp) : 'N/A'}
                                        </td>
                                        <td className="px-4 py-3">{r.clients}</td>
                                        <td className="px-4 py-3 font-mono">{r.total_samples}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan={4} className="px-4 py-6 text-center text-gray-500 italic">
                                        No aggregation rounds completed yet.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default FederationView;
