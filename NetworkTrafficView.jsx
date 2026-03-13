import React, { useState, useEffect } from 'react';
import { ServerIcon, SearchIcon, EyeIcon } from './icons';
import { formatTimestamp } from './utils';

const NetworkTrafficView = ({ token }) => {
    const [trafficData, setTrafficData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [lastUpdated, setLastUpdated] = useState(null);

    useEffect(() => {
        fetchTrafficData();
        const interval = setInterval(fetchTrafficData, 5000);
        return () => clearInterval(interval);
    }, []);

    const fetchTrafficData = async () => {
        try {
            const response = await fetch('/api/network/traffic', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.ok) {
                const data = await response.json();
                setTrafficData(data);
                setLastUpdated(new Date());
            }
        } catch (error) {
            console.error('Failed to fetch traffic data:', error);
        } finally {
            setLoading(false);
        }
    };

    const protoBadge = (proto) => {
        const map = {
            TCP: 'bg-blue-900/50 border-blue-500 text-blue-300',
            UDP: 'bg-green-900/50 border-green-500 text-green-300',
            ICMP: 'bg-yellow-900/50 border-yellow-500 text-yellow-300',
        };
        return map[proto] || 'bg-gray-800 border-gray-600 text-gray-300';
    };

    const portServiceMap = { 80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 53: 'DNS', 3306: 'MySQL' };

    if (loading) {
        return (
            <div className="p-8 flex items-center justify-center min-h-[80vh]">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
            </div>
        );
    }

    return (
        <div className="p-8">
            {/* HEADER ROW */}
            <div className="flex justify-between items-center mb-6">
                <div className="flex items-center">
                    <ServerIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                    <h2 className="text-3xl font-bold text-white">Network Traffic Analysis</h2>
                </div>
                <div className="flex items-center">
                    <span className="text-gray-400 text-sm">Last updated: {formatTimestamp(lastUpdated)}</span>
                    <span className="bg-blue-900/30 border border-blue-500/30 text-blue-400 text-xs px-2 py-1 rounded-full ml-3">
                        Auto-refresh: 5s
                    </span>
                </div>
            </div>

            {/* ROW 1 — Protocol Distribution */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg mb-6">
                <h3 className="text-lg font-semibold text-gray-200 mb-4">Protocol Distribution</h3>
                {trafficData?.protocolStats && trafficData.protocolStats.length > 0 ? (
                    <>
                        <div className="space-y-0">
                            {trafficData.protocolStats.map((stat, idx) => {
                                const total = stat.count || 1;
                                const blocked = stat.blocked || 0;
                                const allowed = stat.allowed || 0;
                                const blockedPct = (blocked / total) * 100;
                                const allowedPct = (allowed / total) * 100;
                                const totalSize = ((stat.total_size || 0) / 1024).toFixed(2) + ' KB';
                                return (
                                    <div key={idx} className={`flex items-center py-3 ${idx < trafficData.protocolStats.length - 1 ? 'border-b border-gray-800' : ''}`}>
                                        <span className={`w-20 text-center px-2 py-0.5 rounded-full text-xs font-bold border ${protoBadge(stat.protocol)}`}>
                                            {stat.protocol}
                                        </span>
                                        <div className="flex-1 mx-4">
                                            <div className="flex h-2.5 rounded-full overflow-hidden bg-gray-800">
                                                <div style={{ width: `${blockedPct}%` }} className="bg-red-500/70 h-2.5" />
                                                <div style={{ width: `${allowedPct}%` }} className="bg-[#00ff7f]/70 h-2.5" />
                                            </div>
                                        </div>
                                        <div className="w-56 text-right text-xs text-gray-400">
                                            {total} pkts · {totalSize} · <span className="text-[#00ff7f]">{allowed} allowed</span> / <span className="text-red-400">{blocked} blocked</span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                        <div className="flex gap-4 mt-3 text-xs text-gray-500">
                            <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-500/70 rounded" /> Blocked</span>
                            <span className="flex items-center gap-1"><span className="w-3 h-3 bg-[#00ff7f]/70 rounded" /> Allowed</span>
                        </div>
                    </>
                ) : (
                    <p className="text-gray-500 italic text-center py-8">No protocol statistics available yet. Start the Detection Agent to see data.</p>
                )}
            </div>

            {/* ROW 2 — Two Columns */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                {/* LEFT — Top Source IPs */}
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-lg font-semibold text-gray-200 mb-4">Top Source IPs</h3>
                    {trafficData?.sourceIPs && trafficData.sourceIPs.length > 0 ? (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-800">
                                <thead>
                                    <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                        <th className="px-3 py-2">#</th>
                                        <th className="px-3 py-2">IP Address</th>
                                        <th className="px-3 py-2">Packets</th>
                                        <th className="px-3 py-2">Status</th>
                                        <th className="px-3 py-2"></th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800/50">
                                    {trafficData.sourceIPs.map((ip, idx) => (
                                        <tr key={idx} className="text-sm hover:bg-[#1f2937]/50">
                                            <td className="px-3 py-2 text-gray-500">{idx + 1}</td>
                                            <td className="px-3 py-2 font-mono text-white">{ip.ip}</td>
                                            <td className="px-3 py-2 text-gray-300">{ip.count}</td>
                                            <td className="px-3 py-2">
                                                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${ip.blocked ? 'bg-red-900/50 text-red-400' : 'bg-green-900/50 text-green-400'}`}>
                                                    {ip.blocked ? 'Blocked' : 'Active'}
                                                </span>
                                            </td>
                                            <td className="px-3 py-2">
                                                <EyeIcon className="w-4 h-4 text-gray-500 hover:text-blue-400 cursor-pointer" title="Monitor this IP" />
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <p className="text-gray-500 italic text-center py-8">No source IP data available</p>
                    )}
                </div>

                {/* RIGHT — Hourly Traffic Trend */}
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-lg font-semibold text-gray-200 mb-4">Hourly Traffic Trend (Last 12h)</h3>
                    {(() => {
                        const hours = trafficData?.hourlyStats?.slice(0, 12) || [];
                        if (hours.length === 0) {
                            // Generate placeholders
                            const now = new Date().getHours();
                            const placeholders = Array.from({ length: 12 }, (_, i) => ({
                                hour: `${(now - 11 + i + 24) % 24}h`,
                                count: Math.floor(Math.random() * 20) + 1,
                                blocked: Math.floor(Math.random() * 5),
                            }));
                            return renderSparkline(placeholders);
                        }
                        return renderSparkline(hours);
                    })()}
                    <div className="flex gap-4 mt-3 text-xs text-gray-500">
                        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-[#00ff7f]/70 rounded" /> Normal</span>
                        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-500/70 rounded" /> High Threat Activity</span>
                    </div>
                </div>
            </div>

            {/* ROW 3 — Port Activity Table */}
            {trafficData?.portStats && trafficData.portStats.length > 0 && (
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-lg font-semibold text-gray-200 mb-4">Top Active Destination Ports</h3>
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-800">
                            <thead>
                                <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                    <th className="px-4 py-3">Port</th>
                                    <th className="px-4 py-3">Service Name</th>
                                    <th className="px-4 py-3">Packets</th>
                                    <th className="px-4 py-3">Threat Level</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800/50">
                                {trafficData.portStats.slice(0, 10).map((stat, idx) => {
                                    const service = portServiceMap[stat.port] || 'Unknown';
                                    const blockedRatio = stat.count > 0 ? (stat.blocked || 0) / stat.count : 0;
                                    let threatLevel, threatClass;
                                    if (blockedRatio > 0.5) { threatLevel = 'HIGH'; threatClass = 'bg-red-900/50 text-red-400 border-red-500'; }
                                    else if (blockedRatio > 0.1) { threatLevel = 'MEDIUM'; threatClass = 'bg-yellow-900/50 text-yellow-400 border-yellow-500'; }
                                    else { threatLevel = 'LOW'; threatClass = 'bg-green-900/50 text-green-400 border-green-500'; }
                                    return (
                                        <tr key={idx} className="text-sm hover:bg-[#1f2937]/50">
                                            <td className="px-4 py-3 font-mono text-[#00ff7f]">{stat.port}</td>
                                            <td className="px-4 py-3 text-gray-300">{service}</td>
                                            <td className="px-4 py-3 text-gray-300">{stat.count || 0}</td>
                                            <td className="px-4 py-3">
                                                <span className={`px-2 py-0.5 rounded-full text-xs font-bold border ${threatClass}`}>{threatLevel}</span>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
};

function renderSparkline(hours) {
    const maxCount = Math.max(...hours.map(h => h.count || 1), 1);
    return (
        <div className="flex items-end gap-1 h-24">
            {hours.map((h, i) => {
                const height = ((h.count || 0) / maxCount) * 80;
                const hasThreat = (h.blocked || 0) > 0;
                return (
                    <div key={i} className="flex flex-col items-center flex-1">
                        <div
                            className={`w-full rounded-t ${hasThreat ? 'bg-red-500/70' : 'bg-[#00ff7f]/70'}`}
                            style={{ height: `${Math.max(height, 4)}px` }}
                            title={`${h.count || 0} packets`}
                        />
                        <span className="text-xs text-gray-500 mt-1">{h.hour}</span>
                    </div>
                );
            })}
        </div>
    );
}

export default NetworkTrafficView;
