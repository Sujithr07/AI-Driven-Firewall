import React, { useState, useEffect } from 'react';
import { LockIcon, SearchIcon, CheckIcon, XIcon, ShieldIcon, RefreshIcon } from './icons';
import { formatTimestamp, getSeverityClass } from './utils';

const FirewallRulesView = ({ token }) => {
    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedRule, setSelectedRule] = useState(null);
    const [filter, setFilter] = useState('all');
    const [searchQuery, setSearchQuery] = useState('');

    useEffect(() => {
        fetchRules();
        const interval = setInterval(fetchRules, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchRules = async () => {
        try {
            const response = await fetch('/api/response/status', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.ok) {
                const data = await response.json();
                setRules(data.active_rules || []);
            }
        } catch (error) {
            console.error('Failed to fetch firewall rules:', error);
        } finally {
            setLoading(false);
        }
    };

    const filteredRules = rules.filter(r => {
        const matchesFilter = filter === 'all' || r.rule_type === filter || r.action === filter;
        const matchesSearch = searchQuery === '' ||
            (r.ip || '').includes(searchQuery) ||
            (r.rule_type || '').toLowerCase().includes(searchQuery.toLowerCase());
        return matchesFilter && matchesSearch;
    });

    const ruleStats = {
        total: rules.length,
        rate_limit: rules.filter(r => r.rule_type === 'rate_limit').length,
        block: rules.filter(r => r.rule_type === 'block' || r.action === 'block').length,
        quarantine: rules.filter(r => r.rule_type === 'quarantine' || r.action === 'quarantine').length,
    };

    const ruleTypeColor = (type) => {
        switch (type) {
            case 'rate_limit': return 'bg-yellow-900/50 text-yellow-400 border-yellow-500';
            case 'block': return 'bg-red-900/50 text-red-400 border-red-500';
            case 'quarantine': return 'bg-orange-900/50 text-orange-400 border-orange-500';
            default: return 'bg-blue-900/50 text-blue-400 border-blue-500';
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
            {/* Header */}
            <div className="flex justify-between items-center mb-6">
                <div className="flex items-center">
                    <LockIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                    <div>
                        <h2 className="text-3xl font-bold text-white">Firewall Rules</h2>
                        <p className="text-gray-400 text-sm">AI-generated response rules from the Detection Agent</p>
                    </div>
                </div>
                <button
                    onClick={() => { setLoading(true); fetchRules(); }}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm bg-[#161b22] border border-gray-700 text-gray-400 rounded-lg hover:text-white hover:border-gray-500 transition"
                >
                    <RefreshIcon className="w-4 h-4" /> Refresh
                </button>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-4 gap-4 mb-6">
                {[
                    { label: 'Total Active', count: ruleStats.total, cls: 'border-[#00ff7f]' },
                    { label: 'Rate Limits', count: ruleStats.rate_limit, cls: 'border-yellow-500' },
                    { label: 'Blocked', count: ruleStats.block, cls: 'border-red-500' },
                    { label: 'Quarantined', count: ruleStats.quarantine, cls: 'border-orange-500' },
                ].map(s => (
                    <div key={s.label} className={`bg-[#161b22] p-4 rounded-lg border-l-4 ${s.cls} border border-gray-800`}>
                        <p className="text-sm text-gray-400">{s.label}</p>
                        <p className="text-2xl font-bold text-white">{s.count}</p>
                    </div>
                ))}
            </div>

            {/* Filter Bar */}
            <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800 mb-6 flex items-center gap-4">
                <div className="flex items-center flex-1 bg-[#0d1117] border border-gray-700 rounded-lg px-3">
                    <SearchIcon className="w-4 h-4 text-gray-500" />
                    <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search by IP or type..."
                        className="flex-1 bg-transparent text-white text-sm py-2 px-2 focus:outline-none"
                    />
                </div>
                <div className="flex gap-2">
                    {['all', 'rate_limit', 'block', 'quarantine'].map(f => (
                        <button
                            key={f}
                            onClick={() => setFilter(f)}
                            className={`px-3 py-1.5 text-sm rounded-lg transition ${
                                filter === f
                                    ? 'bg-[#00ff7f]/20 text-[#00ff7f] border border-[#00ff7f]/30'
                                    : 'bg-[#0d1117] text-gray-400 border border-gray-700 hover:text-white'
                            }`}
                        >
                            {f === 'all' ? 'All' : f.replace('_', ' ').replace(/^\w/, c => c.toUpperCase())}
                        </button>
                    ))}
                </div>
            </div>

            {/* Rules Table */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 shadow-lg overflow-hidden">
                {filteredRules.length === 0 ? (
                    <div className="text-center py-16">
                        <ShieldIcon className="w-12 h-12 text-gray-700 mx-auto mb-3" />
                        <p className="text-gray-500">No active firewall rules</p>
                        <p className="text-gray-600 text-sm mt-1">Rules are auto-generated by the Detection Agent when threats are detected</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-800">
                            <thead className="sticky top-0 bg-[#161b22]">
                                <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                    <th className="px-4 py-3">IP Address</th>
                                    <th className="px-4 py-3">Rule Type</th>
                                    <th className="px-4 py-3">Confidence</th>
                                    <th className="px-4 py-3">Created</th>
                                    <th className="px-4 py-3">Expires</th>
                                    <th className="px-4 py-3">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                                {filteredRules.map((rule, idx) => (
                                    <tr
                                        key={idx}
                                        onClick={() => setSelectedRule(idx === selectedRule ? null : idx)}
                                        className={`text-sm cursor-pointer transition ${
                                            selectedRule === idx
                                                ? 'bg-[#00ff7f]/5 border-l-4 border-[#00ff7f]'
                                                : 'text-gray-300 hover:bg-[#1f2937]/50'
                                        }`}
                                    >
                                        <td className="px-4 py-3 font-mono text-white">{rule.ip}</td>
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-0.5 text-xs font-bold rounded-full border ${ruleTypeColor(rule.rule_type)}`}>
                                                {(rule.rule_type || rule.action || 'unknown').replace('_', ' ').toUpperCase()}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 font-mono text-gray-300">
                                            {rule.confidence != null ? `${(rule.confidence * 100).toFixed(0)}%` : 'N/A'}
                                        </td>
                                        <td className="px-4 py-3 text-xs text-gray-400">
                                            {rule.created_at ? formatTimestamp(rule.created_at * 1000) : 'N/A'}
                                        </td>
                                        <td className="px-4 py-3 text-xs text-gray-400">
                                            {rule.expires_at ? formatTimestamp(rule.expires_at * 1000) : 'N/A'}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="flex items-center text-[#00ff7f] text-xs">
                                                <CheckIcon className="w-3 h-3 mr-1" /> Active
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Selected Rule Detail Slide */}
            {selectedRule !== null && filteredRules[selectedRule] && (
                <div className="mt-4 bg-[#161b22] p-6 rounded-xl border border-[#00ff7f]/30 shadow-lg">
                    <div className="flex justify-between items-start">
                        <h4 className="text-white font-bold">Rule Details</h4>
                        <button onClick={() => setSelectedRule(null)} className="text-gray-400 hover:text-white">
                            <XIcon className="w-4 h-4" />
                        </button>
                    </div>
                    <div className="grid grid-cols-2 gap-4 mt-4 text-sm">
                        {Object.entries(filteredRules[selectedRule]).map(([key, val]) => (
                            <div key={key}>
                                <span className="text-gray-500 text-xs uppercase">{key.replace(/_/g, ' ')}</span>
                                <p className="text-white font-mono text-sm break-all">{typeof val === 'object' ? JSON.stringify(val) : String(val)}</p>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default FirewallRulesView;
