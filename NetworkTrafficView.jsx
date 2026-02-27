import React, { useState, useEffect } from 'react';

const ServerIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
);

const NetworkTrafficView = ({ token }) => {
    const [trafficData, setTrafficData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchTrafficData();
        const interval = setInterval(fetchTrafficData, 5000);
        return () => clearInterval(interval);
    }, []);

    const fetchTrafficData = async () => {
        try {
            const response = await fetch('http://localhost:5000/api/network/traffic', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                setTrafficData(data);
            }
        } catch (error) {
            console.error('Failed to fetch traffic data:', error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="p-8 flex items-center justify-center min-h-[80vh]">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
            </div>
        );
    }

    return (
        <div className="p-8">
            <div className="flex items-center mb-6">
                <ServerIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                <h2 className="text-3xl font-bold text-white">Network Traffic Analysis</h2>
            </div>

            <div className="mb-6 bg-[#161b22] p-4 rounded-lg border border-gray-800">
                <p className="text-gray-300 text-sm">
                    This page provides comprehensive network traffic analysis including protocol statistics, 
                    port activity, and hourly trends. Data is updated in real-time from the security logs database.
                </p>
            </div>

            {/* Protocol Statistics */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg mb-6">
                <h3 className="text-xl font-semibold text-gray-200 mb-4">Traffic by Protocol</h3>
                {trafficData?.protocolStats && trafficData.protocolStats.length > 0 ? (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-700">
                            <thead>
                                <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                    <th className="px-4 py-3">Protocol</th>
                                    <th className="px-4 py-3">Total Packets</th>
                                    <th className="px-4 py-3">Total Size</th>
                                    <th className="px-4 py-3">Allowed</th>
                                    <th className="px-4 py-3">Blocked</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                                {trafficData.protocolStats.map((stat, idx) => (
                                    <tr key={idx} className="text-sm text-gray-300 hover:bg-[#1f2937]/50">
                                        <td className="px-4 py-3 font-medium">{stat.protocol}</td>
                                        <td className="px-4 py-3">{stat.count || 0}</td>
                                        <td className="px-4 py-3">{((stat.total_size || 0) / 1024).toFixed(2)} KB</td>
                                        <td className="px-4 py-3 text-green-400">{stat.allowed || 0}</td>
                                        <td className="px-4 py-3 text-red-400">{stat.blocked || 0}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="text-gray-500 italic text-center py-8">No protocol statistics available yet. Start simulating traffic to see data.</p>
                )}
            </div>

            {/* Port Statistics */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg mb-6">
                <h3 className="text-xl font-semibold text-gray-200 mb-4">Top Active Ports</h3>
                {trafficData?.portStats && trafficData.portStats.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {trafficData.portStats.map((stat, idx) => (
                            <div key={idx} className="bg-[#0d1117] p-4 rounded-lg border border-gray-700">
                                <div className="flex justify-between items-center mb-2">
                                    <span className="text-[#00ff7f] font-mono font-bold">Port {stat.port}</span>
                                    <span className="text-gray-400 text-sm">{stat.protocol}</span>
                                </div>
                                <div className="text-2xl font-bold text-white">{stat.count || 0}</div>
                                <div className="text-xs text-gray-500 mt-1">packets</div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <p className="text-gray-500 italic text-center py-8">No port statistics available yet. Start simulating traffic to see data.</p>
                )}
            </div>

            {/* Hourly Trends */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                <h3 className="text-xl font-semibold text-gray-200 mb-4">24-Hour Traffic Trends</h3>
                {trafficData?.hourlyStats && trafficData.hourlyStats.length > 0 ? (
                    <div className="space-y-2">
                        {trafficData.hourlyStats.slice(0, 12).map((stat, idx) => (
                            <div key={idx} className="flex items-center justify-between bg-[#0d1117] p-3 rounded-lg">
                                <span className="text-gray-300 text-sm">{stat.hour}</span>
                                <div className="flex items-center gap-4">
                                    <span className="text-gray-400 text-sm">Total: {stat.count || 0}</span>
                                    <span className="text-red-400 text-sm">Blocked: {stat.blocked || 0}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <p className="text-gray-500 italic text-center py-8">No hourly trends available yet. Start simulating traffic to see data.</p>
                )}
            </div>
        </div>
    );
};

export default NetworkTrafficView;

