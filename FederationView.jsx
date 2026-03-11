import React, { useState, useEffect, useCallback } from 'react';

const FederationView = ({ token }) => {
    const [localStatus, setLocalStatus] = useState(null);
    const [serverStatus, setServerStatus] = useState(null);
    const [rounds, setRounds] = useState([]);
    const [serverReachable, setServerReachable] = useState(false);

    const fetchData = useCallback(async () => {
        if (!token) return;
        try {
            const [statusRes, roundsRes] = await Promise.all([
                fetch('http://localhost:5000/api/fl/status', {
                    headers: { Authorization: `Bearer ${token}` },
                }),
                fetch('http://localhost:5000/api/fl/rounds', {
                    headers: { Authorization: `Bearer ${token}` },
                }),
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

    return (
        <div className="p-8 space-y-6">
            <h2 className="text-3xl font-bold text-white mb-6">Federated Learning</h2>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Federation Status Card */}
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-xl font-semibold text-gray-200 mb-4">Federation Status</h3>
                    <div className="space-y-3 text-sm">
                        <div className="flex justify-between">
                            <span className="text-gray-400">Client ID</span>
                            <span className="text-white font-mono">{localStatus?.client_id || 'N/A'}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-gray-400">Server Connection</span>
                            <span className="flex items-center">
                                <span className={`h-2 w-2 rounded-full mr-2 ${serverReachable ? 'bg-green-400' : 'bg-red-500'}`}></span>
                                <span className={serverReachable ? 'text-green-400' : 'text-red-400'}>
                                    {serverReachable ? 'Connected' : 'Unreachable'}
                                </span>
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-400">Rounds Participated</span>
                            <span className="text-[#00ff7f] font-mono">{localStatus?.rounds_participated ?? 0}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-400">Last Round</span>
                            <span className="text-white">
                                {localStatus?.last_round_time
                                    ? new Date(localStatus.last_round_time).toLocaleString()
                                    : 'Never'}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-400">Global Model Version</span>
                            <span className="text-white font-mono">v{localStatus?.global_model_version ?? 0}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-400">Differential Privacy</span>
                            <span className={localStatus?.dp_enabled ? 'text-[#00ff7f]' : 'text-yellow-400'}>
                                {localStatus?.dp_enabled ? 'Enabled (ε=1.0)' : 'Disabled'}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-400">Local Samples</span>
                            <span className="text-white font-mono">{localStatus?.local_samples ?? 0}</span>
                        </div>
                    </div>
                </div>

                {/* Federation Network Card */}
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-xl font-semibold text-gray-200 mb-4">Federation Network</h3>
                    {waitingClients.length > 0 ? (
                        <div className="space-y-2">
                            {waitingClients.map((client, idx) => (
                                <div
                                    key={idx}
                                    className="flex justify-between items-center bg-[#0d1117] p-3 rounded-lg border border-gray-800"
                                >
                                    <div className="flex items-center">
                                        <span className="h-2 w-2 rounded-full bg-[#00ff7f] mr-3"></span>
                                        <span className="text-white font-mono text-sm">{client.client_id}</span>
                                    </div>
                                    <span className="text-gray-400 text-sm">{client.n_samples} samples</span>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p className="text-gray-500 italic text-sm">No clients currently waiting for aggregation.</p>
                    )}
                    {serverStatus && (
                        <div className="mt-4 pt-4 border-t border-gray-800 text-sm">
                            <div className="flex justify-between text-gray-400">
                                <span>Current Round</span>
                                <span className="text-white font-mono">{serverStatus.round_number}</span>
                            </div>
                            <div className="flex justify-between text-gray-400 mt-1">
                                <span>Min Clients for Aggregation</span>
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
                                            {r.timestamp ? new Date(r.timestamp).toLocaleString() : 'N/A'}
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
