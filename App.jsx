import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Login from './Login';
import NetworkTrafficView from './NetworkTrafficView';
import ImmutableLogsView from './ImmutableLogsView';
import SettingsView from './SettingsView';
import DetectionAgentView, { BrainIcon } from './DetectionAgentView';
import XAIDashboardView from './XAIDashboardView';
import FederationView from './FederationView';

// --- Icon Components (using lucide-react equivalent SVGs) ---
const ServerIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
);
const ZapIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
);
const LockIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
);
const ShieldCheckIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>
);
const SettingsIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 0 2.73l-.15.1a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.09a2 2 0 0 1 0-2.73l.15-.1a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
);
const FileTextIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>
);
const GlobeIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
);

// --- Data Structures and Logic (Kept here for completeness, though Flask controls the core logic) ---

const SEVERITY_CLASSES = {
    High: 'bg-red-900/50 text-red-400 border-red-500',
    Medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-500',
    Low: 'bg-blue-900/50 text-blue-400 border-blue-500',
    Allowed: 'bg-green-900/50 text-green-400 border-green-500',
    Blocked: 'bg-red-900/50 text-red-400 border-red-500',
    Quarantined: 'bg-yellow-900/50 text-yellow-400 border-yellow-500',
};

// --- Sidebar Navigation Component ---
const Sidebar = ({ currentPage, setCurrentPage }) => {
    const navItems = [
        { id: 'dashboard', label: 'Dashboard', icon: ZapIcon, active: currentPage === 'dashboard' },
        { id: 'network_traffic', label: 'Network Traffic', icon: ServerIcon, active: currentPage === 'network_traffic' },
        { id: 'detection_agent', label: 'Detection Agent', icon: BrainIcon, active: currentPage === 'detection_agent' },
        { id: 'xai_dashboard', label: 'XAI Explain', icon: ShieldCheckIcon, active: currentPage === 'xai_dashboard' },
        { id: 'federation', label: 'Federation', icon: GlobeIcon, active: currentPage === 'federation' },
        { id: 'threat_detection', label: 'Threat Detection', icon: ShieldCheckIcon, active: currentPage === 'threat_detection' },
        { id: 'firewall_rules', label: 'Firewall Rules', icon: LockIcon, active: currentPage === 'firewall_rules' },
        { id: 'immutable_logs', label: 'Immutable Logs', icon: FileTextIcon, active: currentPage === 'immutable_logs' },
    ];

    return (
        <div className="w-56 bg-[#090c10] min-h-screen p-4 flex flex-col fixed top-0 left-0">
            <div className="flex items-center text-2xl font-bold text-[#00ff7f] mb-8">
                {/* UPDATED: Changed to AI Driven Firewall with ShieldCheckIcon */}
                <ShieldCheckIcon className="w-6 h-6 mr-2" /> AI Driven Firewall
            </div>
            <nav className="space-y-2">
                {navItems.map((item) => (
                    <button
                        key={item.id}
                        onClick={() => setCurrentPage(item.id)}
                        className={`w-full flex items-center p-3 rounded-lg transition duration-200 ${
                            item.active 
                                ? 'bg-[#00ff7f]/20 text-[#00ff7f] font-semibold border-l-4 border-[#00ff7f]'
                                : 'text-gray-400 hover:bg-[#161b22] hover:text-white'
                        }`}
                    >
                        <item.icon className="w-5 h-5 mr-3" />
                        {item.label}
                    </button>
                ))}
            </nav>
            <div className="mt-auto pt-4 border-t border-gray-800">
                <button 
                    onClick={() => setCurrentPage('settings')}
                    className={`w-full flex items-center p-3 rounded-lg transition duration-200 text-gray-400 hover:bg-[#161b22] hover:text-white`}
                >
                    <SettingsIcon className="w-5 h-5 mr-3" />
                    Settings
                </button>
            </div>
        </div>
    );
};

// --- Dashboard Sub-Components ---

const StatCard = ({ title, value, change, color, icon }) => (
    <div className="bg-[#161b22] p-5 rounded-xl border border-gray-800 shadow-lg flex flex-col">
        <div className="flex justify-between items-start">
            <p className="text-sm font-medium text-gray-400">{title}</p>
            {React.createElement(icon, { className: `w-6 h-6 ${color}` })}
        </div>
        <div className="mt-4">
            <p className="text-3xl font-bold text-white">{value}</p>
            {change && (
                <p className={`text-sm mt-1 ${change.includes('+') ? 'text-green-400' : 'text-red-400'}`}>
                    {change}
                </p>
            )}
        </div>
    </div>
);

const AlertItem = ({ type, source, time, severity }) => (
    <div className={`p-3 rounded-lg border-l-4 ${SEVERITY_CLASSES[severity]} flex justify-between items-start mb-2`}>
        <div>
            <p className="font-semibold text-sm">{type}</p>
            <p className="text-xs text-gray-400">{source}</p>
        </div>
        <div className="text-right">
            <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${SEVERITY_CLASSES[severity].split(' ')[0].replace('/50', '')}`}>{severity}</span>
            <p className="text-xs text-gray-500 mt-1">{time}</p>
        </div>
    </div>
);

// --- Page Views ---

const DashboardView = ({ alerts, metrics, user }) => {
    const [showWelcome, setShowWelcome] = useState(true);
    
    useEffect(() => {
        // Hide welcome message after 5 seconds
        const timer = setTimeout(() => setShowWelcome(false), 5000);
        return () => clearTimeout(timer);
    }, []);
    
    return (
    <div className="p-8">
        {showWelcome && (
            <div className="mb-6 bg-[#00ff7f]/10 border border-[#00ff7f] rounded-lg p-4 flex items-center justify-between">
                <div className="flex items-center">
                    <ShieldCheckIcon className="w-6 h-6 text-[#00ff7f] mr-3" />
                    <div>
                        <h3 className="text-[#00ff7f] font-semibold">Welcome, {user?.username}!</h3>
                        <p className="text-gray-300 text-sm">AI Firewall Detection System is now active and monitoring your network.</p>
                    </div>
                </div>
                <button 
                    onClick={() => setShowWelcome(false)}
                    className="text-gray-400 hover:text-white"
                >
                    ✕
                </button>
            </div>
        )}
        <h2 className="text-3xl font-bold text-white mb-6">Security Dashboard</h2>

        {/* Top KPI Cards (Using real metrics from Flask) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard 
                title="Active Threats" 
                value={metrics.activeThreats} 
                change="" 
                color="text-red-500" 
                icon={ZapIcon}
            />
            <StatCard 
                title="Blocked Attacks" 
                value={metrics.blockedAttacks} 
                change="" 
                color="text-green-500" 
                icon={ShieldCheckIcon}
            />
            <StatCard 
                title="Network Traffic" 
                value={metrics.networkTraffic} 
                change="Normal baseline" 
                color="text-blue-500" 
                icon={ServerIcon}
            />
            <StatCard 
                title="System Health" 
                value={metrics.systemHealth} 
                change="All systems operational" 
                color="text-[#00ff7f]" 
                icon={SettingsIcon}
            />
        </div>

        {/* Map and Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-xl font-semibold text-gray-200">Global Threat Map</h3>
                    <span className="text-xs text-[#00ff7f] flex items-center"><span className="h-2 w-2 rounded-full bg-[#00ff7f] mr-1 animate-pulse"></span>Live</span>
                </div>
                {/* Simplified Map Simulation */}
                <div className="h-64 bg-gray-900 rounded relative">
                    {/* Placeholder World Map */}
                    <div className="absolute inset-0 opacity-10 text-center text-gray-700 text-5xl pt-20">MAP VIEW </div>
                    {/* Simulated Threat Hotspots (red dots matching the screenshot) */}
                    {metrics.activeThreats > 0 && (
                        <>
                            <div className="absolute top-1/4 left-1/4 h-3 w-3 bg-red-600 rounded-full animate-ping opacity-75"></div>
                            <div className="absolute top-1/2 left-3/4 h-3 w-3 bg-red-600 rounded-full"></div>
                        </>
                    )}
                    <div className="absolute top-2/3 left-1/3 h-3 w-3 bg-red-600 rounded-full animate-ping opacity-75"></div>
                </div>
                <div className="mt-4 text-sm text-gray-400">
                    <p>Current Threat Focus: <span className="text-red-400">Russia (Malware, 15 threats)</span>, <span className="text-red-400">China (Intrusion, 23 threats)</span>, <span className="text-red-400">North Korea (Phishing, 8 threats)</span></p>
                </div>
            </div>

            {/* Recent Alerts */}
            <div className="lg:col-span-1 bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-xl font-semibold text-gray-200">Recent Alerts</h3>
                    <span className="text-xs text-[#00ff7f] flex items-center"><span className="h-2 w-2 rounded-full bg-[#00ff7f] mr-1 animate-pulse"></span>Live</span>
                </div>
                <div className="max-h-80 overflow-y-auto pr-2 space-y-3">
                    {/* Show Alerts pulled from Flask metrics.alerts */}
                    {alerts.length > 0 ? (
                        alerts.map((alert, index) => {
                            // Handle both database format (user_identity) and in-memory format (userContext.identity)
                            const userIdentity = alert.user_identity || alert.userContext?.identity || 'Unknown';
                            const alertReason = alert.reason || '';
                            const alertTimestamp = alert.timestamp || Date.now();
                            const alertSeverity = alert.severity || 'Medium';
                            
                            return (
                                <AlertItem 
                                    key={index} 
                                    type={alertReason.split('.')[0] || 'Security Alert'} 
                                    source={`User: ${userIdentity}`} 
                                    time={new Date(alertTimestamp).toLocaleTimeString()} 
                                    severity={alertSeverity} 
                                />
                            );
                        })
                    ) : (
                        <p className="text-gray-500 italic">No recent critical alerts.</p>
                    )}
                </div>
            </div>
        </div>
    </div>
    );
};

const ThreatDetectionView = ({ currentLog }) => (
    <div className="p-8">
        <h2 className="text-3xl font-bold text-white mb-6">Threat Detection & Zero Trust Logs</h2>
        <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
            <div className="flex justify-between items-center mb-4">
                <h3 className="text-xl font-semibold text-gray-200">AI Engine Decisions (Real-time Feed)</h3>
                <button onClick={() => window.location.reload()} className="text-sm text-blue-400 hover:text-blue-300">
                    <ZapIcon className="w-4 h-4 inline mr-1"/> Force New Traffic Simulation
                </button>
            </div>
            <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-2">
                {currentLog.length === 0 ? (
                    <p className="text-gray-500 italic">No traffic logs yet. Start the simulation to populate data.</p>
                ) : (
                    currentLog.map((log, index) => (
                        <div key={index} className={`p-3 rounded-lg flex flex-col md:flex-row justify-between text-sm transition duration-300 ${SEVERITY_CLASSES[log.decision]}`}>
                            <div className="flex flex-col mb-2 md:mb-0">
                                <span className="font-bold text-base md:text-lg text-white">{log.decision.toUpperCase()} @ {new Date(log.timestamp).toLocaleTimeString()}</span>
                                <span className="text-xs text-gray-400">
                                    User: {(log.userContext?.identity || log.user_identity || 'Unknown').toUpperCase()} | Device: {(log.userContext?.device || log.user_device || 'Unknown').toUpperCase()} | Resource: {(log.userContext?.resource || log.user_resource || 'Unknown').toUpperCase()}
                                </span>
                            </div>
                            <div className="flex flex-col text-right">
                                <span className="font-medium text-gray-300">
                                    {(log.traffic?.description || log.description || 'Traffic event')} (AI Score: <span className="font-mono">{(log.aiResult?.finalScore || log.ai_score || 0).toFixed(2)}</span>)
                                </span>
                                <span className="italic text-xs text-gray-400">{log.reason || 'No reason provided'}</span>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    </div>
);

const FirewallRulesView = ({ token }) => {
    const [rules, setRules] = useState([]);
    const [stats, setStats] = useState({});
    const [totalBlocked, setTotalBlocked] = useState(0);
    const [lastUpdated, setLastUpdated] = useState(null);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState('');
    const [filterType, setFilterType] = useState('all');
    const [sortBy, setSortBy] = useState('newest');
    const [expandedRow, setExpandedRow] = useState(null);
    const [confirmRollback, setConfirmRollback] = useState(null);

    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const fetchRules = useCallback(async () => {
        try {
            const res = await fetch('/api/response/status', { headers });
            if (res.ok) {
                const data = await res.json();
                setRules(data.blocked_ips || []);
                setStats(data.stats || {});
                setTotalBlocked(data.total_blocked || 0);
                setLastUpdated(new Date());
            }
        } catch (e) { /* ignore */ }
        setLoading(false);
    }, [token]);

    useEffect(() => {
        fetchRules();
        const iv = setInterval(fetchRules, 5000);
        return () => clearInterval(iv);
    }, [fetchRules]);

    const formatAge = (seconds) => {
        if (!seconds) return '0s';
        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);
        return m > 0 ? `${m}m ${s}s` : `${s}s`;
    };

    const formatExpiry = (rule) => {
        if (!rule.expires_at) return { text: 'Permanent', cls: 'text-gray-500' };
        const remaining = Math.max(0, Math.floor(rule.expires_at - Date.now() / 1000));
        if (remaining <= 0) return { text: 'Expired', cls: 'text-gray-500' };
        const m = Math.floor(remaining / 60);
        const s = remaining % 60;
        const label = `expires in ${m}m ${s}s`;
        return { text: label, cls: remaining < 60 ? 'text-red-400' : 'text-purple-400' };
    };

    const decodeProtocol = (reason) => {
        if (!reason) return 'ANY';
        const r = reason.toLowerCase();
        if (r.includes('syn')) return 'TCP';
        if (r.includes('udp')) return 'UDP';
        return 'ANY';
    };

    const decodePort = (reason) => {
        if (!reason) return '—';
        const r = reason.toLowerCase();
        if (r === 'syn_scan') return 'Port Scan';
        if (r === 'ddos') return 'All Ports';
        return '—';
    };

    const REASON_MAP = {
        syn_scan: 'SYN Port Scan',
        ddos: 'DDoS Pattern',
        brute_force: 'Brute Force',
        port_scan: 'Port Scan',
        anomaly: 'Traffic Anomaly',
    };

    const decodeReason = (reason) => {
        if (!reason) return 'Unknown';
        if (REASON_MAP[reason]) return REASON_MAP[reason];
        return reason.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    };

    const riskLevel = (confidence) => {
        if (confidence > 0.85) return { label: 'Critical', color: 'text-red-400', bg: 'bg-red-600/30', bar: 'bg-red-500' };
        if (confidence > 0.65) return { label: 'High', color: 'text-orange-400', bg: 'bg-orange-600/30', bar: 'bg-orange-500' };
        if (confidence > 0.45) return { label: 'Medium', color: 'text-yellow-400', bg: 'bg-yellow-600/30', bar: 'bg-yellow-500' };
        return { label: 'Low', color: 'text-green-400', bg: 'bg-green-600/30', bar: 'bg-green-500' };
    };

    const ruleTypeStyles = {
        hard_block: { bg: 'bg-red-600/30', text: 'text-red-400', border: 'border-red-500/30', borderSolid: 'border-red-500' },
        temp_block: { bg: 'bg-purple-600/30', text: 'text-purple-400', border: 'border-purple-500/30', borderSolid: 'border-purple-500' },
        rate_limit: { bg: 'bg-yellow-600/30', text: 'text-yellow-400', border: 'border-yellow-500/30', borderSolid: 'border-yellow-500' },
        quarantine: { bg: 'bg-orange-600/30', text: 'text-orange-400', border: 'border-orange-500/30', borderSolid: 'border-orange-500' },
    };

    const RULE_TOOLTIPS = {
        hard_block: 'Permanently drops all packets from this IP via iptables DROP',
        temp_block: 'Drops packets for a fixed duration, then auto-expires',
        rate_limit: 'Allows max 10 packets/min, drops excess — used for moderate threats',
        quarantine: 'Tags packets with mark 99 for routing to an isolated segment — used for investigation',
    };

    const getIptablesCmd = (rule) => {
        const ip = rule.ip;
        if (rule.rule_type === 'hard_block' || rule.rule_type === 'temp_block')
            return `iptables -A INPUT -s ${ip} -j DROP`;
        if (rule.rule_type === 'rate_limit')
            return `iptables -A INPUT -s ${ip} -m limit --limit 10/min -j ACCEPT`;
        if (rule.rule_type === 'quarantine')
            return `iptables -A INPUT -s ${ip} -j MARK --set-mark 99`;
        return `iptables -A INPUT -s ${ip} -j DROP`;
    };

    const getRuleExplanation = (rule) => {
        if (rule.rule_type === 'hard_block') return `All inbound traffic from ${rule.ip} is permanently dropped. No packets will reach any service.`;
        if (rule.rule_type === 'temp_block') return `All inbound traffic from ${rule.ip} is dropped temporarily until the block expires.`;
        if (rule.rule_type === 'rate_limit') return `Inbound traffic from ${rule.ip} is rate-limited to 10 packets per minute. Excess packets are dropped.`;
        if (rule.rule_type === 'quarantine') return `All inbound traffic from ${rule.ip} is marked with ID 99 and routed to an isolated network segment for investigation.`;
        return `Traffic from ${rule.ip} is being controlled by the AI response agent.`;
    };

    const handleRollback = async (actionId) => {
        try {
            await fetch(`/api/response/rollback/${encodeURIComponent(actionId)}`, { method: 'POST', headers });
            await fetchRules();
        } catch (e) {
            console.error('Rollback failed:', e);
        }
        setConfirmRollback(null);
    };

    const handleExport = () => {
        const blob = new Blob([JSON.stringify(rules, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `firewall-rules-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const filtered = useMemo(() => {
        let arr = [...rules];
        if (search) arr = arr.filter(r => r.ip && r.ip.toLowerCase().includes(search.toLowerCase()));
        if (filterType !== 'all') arr = arr.filter(r => r.rule_type === filterType);
        if (sortBy === 'newest') arr.sort((a, b) => (b.age_seconds || 0) - (a.age_seconds || 0));
        else if (sortBy === 'confidence') arr.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
        else if (sortBy === 'longest') arr.sort((a, b) => (b.age_seconds || 0) - (a.age_seconds || 0));
        return arr;
    }, [rules, search, filterType, sortBy]);

    if (loading) {
        return (
            <div className="p-8 flex items-center justify-center min-h-[80vh]">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
            </div>
        );
    }

    return (
        <div className="p-8">
            {/* Title + Export */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <LockIcon className="w-8 h-8 text-[#00ff7f]" />
                    <div>
                        <h2 className="text-3xl font-bold text-white">Active Firewall Rules</h2>
                        <p className="text-gray-400 text-sm">AI-Managed Enforcement via iptables</p>
                    </div>
                </div>
                <button
                    onClick={handleExport}
                    className="px-4 py-2 text-sm bg-[#161b22] border border-gray-700 text-gray-300 rounded-lg hover:text-white hover:border-gray-500 transition"
                >
                    📥 Export JSON
                </button>
            </div>

            {/* Stat Cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                    <div className="flex items-center justify-between">
                        <p className="text-xs text-gray-500 uppercase tracking-wider">Active Rules</p>
                        <span className="relative flex h-2.5 w-2.5">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500"></span>
                        </span>
                    </div>
                    <p className="text-2xl font-bold font-mono text-white mt-1">{totalBlocked}</p>
                    {lastUpdated && <p className="text-xs text-gray-600 mt-1">Updated {lastUpdated.toLocaleTimeString()}</p>}
                </div>
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                    <p className="text-xs text-gray-500 uppercase tracking-wider">Hard Blocks</p>
                    <p className="text-2xl font-bold font-mono text-red-400 mt-1">{stats.hard_blocks || 0}</p>
                </div>
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                    <p className="text-xs text-gray-500 uppercase tracking-wider">Temp Blocks</p>
                    <p className="text-2xl font-bold font-mono text-purple-400 mt-1">{stats.temp_blocks || 0}</p>
                </div>
                <div className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                    <p className="text-xs text-gray-500 uppercase tracking-wider">Self-Healed</p>
                    <p className="text-2xl font-bold font-mono text-green-400 mt-1">{stats.self_healed || 0}</p>
                </div>
            </div>

            {/* Search & Filter Bar */}
            <div className="flex flex-wrap gap-3 mb-4">
                <input
                    type="text"
                    placeholder="Search by IP address..."
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="px-3 py-2 bg-[#0d1117] border border-gray-800 rounded-lg text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-[#00ff7f]/50 w-64"
                />
                <select
                    value={filterType}
                    onChange={e => setFilterType(e.target.value)}
                    className="px-3 py-2 bg-[#0d1117] border border-gray-800 rounded-lg text-sm text-gray-300 focus:outline-none"
                >
                    <option value="all">All Types</option>
                    <option value="hard_block">Hard Block</option>
                    <option value="temp_block">Temp Block</option>
                    <option value="rate_limit">Rate Limit</option>
                    <option value="quarantine">Quarantine</option>
                </select>
                <select
                    value={sortBy}
                    onChange={e => setSortBy(e.target.value)}
                    className="px-3 py-2 bg-[#0d1117] border border-gray-800 rounded-lg text-sm text-gray-300 focus:outline-none"
                >
                    <option value="newest">Newest First</option>
                    <option value="confidence">Highest Confidence</option>
                    <option value="longest">Longest Active</option>
                </select>
            </div>

            {/* Rules Table or Empty State */}
            {filtered.length === 0 && !loading ? (
                <div className="bg-[#161b22] p-12 rounded-xl border border-green-900/50 text-center">
                    <div className="text-6xl mb-4">🛡️</div>
                    <h3 className="text-xl font-bold text-white mb-2">All Clear — No Active Enforcement Rules</h3>
                    <p className="text-gray-500 text-sm max-w-md mx-auto">
                        The AI Response Agent has no threats to enforce against. Start the Detection Agent to begin monitoring.
                    </p>
                </div>
            ) : (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-800">
                            <thead className="bg-[#0d1117]">
                                <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                    <th className="px-4 py-3">IP Address</th>
                                    <th className="px-4 py-3">Rule Type</th>
                                    <th className="px-4 py-3">Protocol</th>
                                    <th className="px-4 py-3">Port</th>
                                    <th className="px-4 py-3">Reason</th>
                                    <th className="px-4 py-3">Risk Level</th>
                                    <th className="px-4 py-3">
                                        <span className="flex items-center gap-1">
                                            AI Decision
                                            <span className="relative group cursor-help">
                                                <span className="text-gray-500">ⓘ</span>
                                                <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 p-2 bg-[#0d1117] border border-gray-700 rounded-lg text-xs text-gray-300 font-normal normal-case tracking-normal hidden group-hover:block z-20 shadow-xl">
                                                    Rules are generated by a two-stage AI pipeline. First, a Random Forest classifier assigns a confidence score. Then, a Reinforcement Learning agent cross-validates and issues a block action.
                                                </span>
                                            </span>
                                        </span>
                                    </th>
                                    <th className="px-4 py-3">Active For</th>
                                    <th className="px-4 py-3">Expiry</th>
                                    <th className="px-4 py-3">Rollback</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800/50">
                                {filtered.map((rule, i) => {
                                    const risk = riskLevel(rule.confidence || 0);
                                    const rts = ruleTypeStyles[rule.rule_type] || ruleTypeStyles.hard_block;
                                    const expiry = formatExpiry(rule);
                                    const isExpanded = expandedRow === (rule.action_id || i);
                                    return (
                                        <React.Fragment key={rule.action_id || i}>
                                            <tr
                                                className="text-sm text-gray-300 hover:bg-[#1f2937]/50 cursor-pointer"
                                                onClick={() => setExpandedRow(isExpanded ? null : (rule.action_id || i))}
                                            >
                                                <td className="px-4 py-3 font-mono">{rule.ip}</td>
                                                <td className="px-4 py-3">
                                                    <span className="flex items-center gap-1">
                                                        <span className={`px-2 py-0.5 text-xs rounded font-bold border ${rts.bg} ${rts.text} ${rts.border}`}>
                                                            {(rule.rule_type || '').replace(/_/g, ' ').toUpperCase()}
                                                        </span>
                                                        <span className="relative group cursor-help">
                                                            <span className="text-gray-600 text-xs">ⓘ</span>
                                                            <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-56 p-2 bg-[#0d1117] border border-gray-700 rounded-lg text-xs text-gray-300 font-normal hidden group-hover:block z-20 shadow-xl">
                                                                {RULE_TOOLTIPS[rule.rule_type] || 'AI-managed enforcement rule'}
                                                            </span>
                                                        </span>
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className="px-2 py-0.5 rounded bg-blue-900/30 text-blue-300 text-xs">{decodeProtocol(rule.reason)}</span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 text-xs">{decodePort(rule.reason)}</span>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div>
                                                        <span className="text-gray-200 text-sm">{decodeReason(rule.reason)}</span>
                                                        <span className="block text-xs text-gray-600 font-mono">{rule.reason}</span>
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <div>
                                                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${risk.bg} ${risk.color}`}>{risk.label}</span>
                                                        <div className="w-16 h-1 mt-1 bg-gray-800 rounded-full overflow-hidden">
                                                            <div className={`h-full rounded-full ${risk.bar}`} style={{ width: `${Math.min((rule.confidence || 0) * 100, 100)}%` }} />
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                                                    <div className="flex flex-col gap-0.5">
                                                        <span className="px-1.5 py-0.5 rounded bg-green-900/30 text-green-400 text-[10px] font-bold">RF: {((rule.confidence || 0) * 100).toFixed(0)}%</span>
                                                        <span className="px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400 text-[10px] font-bold">RL: BLOCK</span>
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3 font-mono text-gray-400">{formatAge(rule.age_seconds)}</td>
                                                <td className="px-4 py-3">
                                                    <span className={`font-mono text-xs ${expiry.cls}`}>{expiry.text}</span>
                                                </td>
                                                <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                                                    {confirmRollback === (rule.action_id || i) ? (
                                                        <span className="flex items-center gap-1">
                                                            <span className="text-xs text-gray-400">Confirm?</span>
                                                            <button
                                                                onClick={() => handleRollback(rule.action_id)}
                                                                className="px-2 py-0.5 text-xs bg-red-600/30 text-red-400 rounded hover:bg-red-600/50 transition"
                                                            >Yes</button>
                                                            <button
                                                                onClick={() => setConfirmRollback(null)}
                                                                className="px-2 py-0.5 text-xs bg-gray-800 text-gray-400 rounded hover:bg-gray-700 transition"
                                                            >No</button>
                                                        </span>
                                                    ) : (
                                                        <button
                                                            onClick={() => setConfirmRollback(rule.action_id || i)}
                                                            className="px-2 py-1 text-xs bg-red-600/20 border border-red-500/30 text-red-400 rounded hover:bg-red-600/40 transition"
                                                        >
                                                            ↩ Rollback
                                                        </button>
                                                    )}
                                                </td>
                                            </tr>
                                            {isExpanded && (
                                                <tr>
                                                    <td colSpan={10} className="p-0">
                                                        <div className={`bg-[#0a0f16] p-4 border-l-4 ${rts.borderSolid}`}>
                                                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                                                                <div>
                                                                    <p className="text-xs text-gray-500 uppercase mb-1">iptables Command</p>
                                                                    <code className="block bg-[#0d1117] p-2 rounded text-xs text-green-400 font-mono break-all">{getIptablesCmd(rule)}</code>
                                                                </div>
                                                                <div>
                                                                    <p className="text-xs text-gray-500 uppercase mb-1">Explanation</p>
                                                                    <p className="text-gray-400 text-xs">{getRuleExplanation(rule)}</p>
                                                                </div>
                                                                <div>
                                                                    <p className="text-xs text-gray-500 uppercase mb-1">Action ID</p>
                                                                    <p className="font-mono text-xs text-gray-500 break-all">{rule.action_id}</p>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                        </React.Fragment>
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

const EmptyView = ({ title }) => (
    <div className="p-8 flex flex-col items-center justify-center min-h-[80vh] text-center">
        <FileTextIcon className="w-16 h-16 text-gray-700 mb-4"/>
        <h2 className="text-3xl font-bold text-white mb-2">{title}</h2>
        <p className="text-gray-400 max-w-lg">
            This section is where detailed data, log archives, or configuration settings would reside in a production firewall.
        </p>
    </div>
);


// --- Main App Component ---

const App = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [currentPage, setCurrentPage] = useState('dashboard');
    const [alerts, setAlerts] = useState([]); 
    const [currentLog, setCurrentLog] = useState([]);
    const [isLoading, setIsLoading] = useState(true); 
    const [metrics, setMetrics] = useState({
        activeThreats: 'N/A',
        blockedAttacks: 'N/A',
        networkTraffic: 'N/A',
        systemHealth: 'N/A',
    });
    const [backendError, setBackendError] = useState(false);

    // Check for existing session on mount
    useEffect(() => {
        try {
            document.documentElement.classList.add('dark');
            const savedToken = localStorage.getItem('token');
            const savedUser = localStorage.getItem('user');
            if (savedToken && savedUser) {
                setToken(savedToken);
                setUser(JSON.parse(savedUser));
                setIsAuthenticated(true);
            } else {
                setIsLoading(false); // If no saved session, stop loading
            }
        } catch (error) {
            console.error('Error loading session:', error);
            setIsLoading(false);
        }
    }, []);

    const handleLogin = (userData) => {
        setUser(userData);
        const savedToken = localStorage.getItem('token');
        setToken(savedToken);
        setIsAuthenticated(true);
        setCurrentPage('dashboard'); // Ensure dashboard is shown after login
        setIsLoading(true); // Start loading firewall data immediately
        // fetchInitialData will be called automatically via useEffect
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setToken(null);
        setUser(null);
        setIsAuthenticated(false);
        setCurrentPage('dashboard');
    };

    // --- Core Data Fetching Logic (Flask API) ---
    // ALL HOOKS MUST BE CALLED BEFORE ANY CONDITIONAL RETURNS

    // Function to fetch all initial dashboard data from Flask
    const fetchInitialData = useCallback(async () => {
        if (!token) return;
        try {
            const response = await fetch('/api/dashboard', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            if (!response.ok) {
                if (response.status === 401 || response.status === 422) {
                    // 401 = expired token, 422 = malformed/invalid token
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    setToken(null);
                    setUser(null);
                    setIsAuthenticated(false);
                    setIsLoading(false);
                    return;
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            
            setCurrentLog(data.currentLog || []); 
            setMetrics({
                activeThreats: data.metrics?.activeThreats ?? 0,
                blockedAttacks: data.metrics?.blockedAttacks ?? 0,
                networkTraffic: data.metrics?.networkTraffic ?? '0.00 Gbps',
                systemHealth: data.metrics?.systemHealth ?? '100%',
            });

            // Alerts are pulled directly from the initial logs array from Flask
            setAlerts(data.metrics?.alerts || []);
            setBackendError(false);
            setIsLoading(false); // Finished loading
        } catch (error) {
            console.error("Failed to fetch initial dashboard data:", error);
            // Set default values if API fails
            setMetrics({
                activeThreats: 0,
                blockedAttacks: 0,
                networkTraffic: '0.00 Gbps',
                systemHealth: '100%',
            });
            setAlerts([]);
            setCurrentLog([]);
            setBackendError(true);
            setIsLoading(false);
        }
    }, [token]);

    // Load initial data on component mount and when token changes
    useEffect(() => {
        if (isAuthenticated && token) {
            fetchInitialData();
        }
    }, [fetchInitialData, isAuthenticated, token]);


    // --- Core Simulation Logic ---

    // Function to call the Flask API simulation endpoint
    const simulateTrafficAttempt = useCallback(async () => {
        if (!token) return;
        try {
            const response = await fetch('/api/traffic/simulate', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            const newLogEntry = data.logEntry;

            // Update log (only the latest log)
            if (newLogEntry) {
                setCurrentLog(prevLog => [newLogEntry, ...prevLog].slice(0, 50));
            }
            // Update metrics from the response
            if (data.metrics) {
                setMetrics({
                    activeThreats: data.metrics.activeThreats ?? 0,
                    blockedAttacks: data.metrics.blockedAttacks ?? 0,
                    networkTraffic: data.metrics.networkTraffic ?? '0.00 Gbps',
                    systemHealth: data.metrics.systemHealth ?? '100%',
                });
                // Update alerts from the response
                setAlerts(data.metrics.alerts || []);
            }

        } catch (error) {
            console.error("Failed to simulate traffic via Flask API:", error);
            // Don't update state on error, just log it
        }

    }, [token]); 

    // Setup Continuous Monitoring/Traffic Generation (runs every 15-25 seconds for realistic traffic)
    useEffect(() => {
        if (isLoading || backendError) return; // Wait until initial data is loaded and backend is available

        let cancelled = false;
        let currentTimeoutId = null;

        // Use a randomized interval between 15-25 seconds to simulate realistic network traffic patterns
        const getRandomInterval = () => Math.floor(Math.random() * 10000) + 15000; // 15-25 seconds
        
        const scheduleNext = () => {
            currentTimeoutId = setTimeout(() => {
                if (cancelled) return;
                simulateTrafficAttempt();
                scheduleNext();
            }, getRandomInterval());
        };

        scheduleNext();
        return () => {
            cancelled = true;
            if (currentTimeoutId) clearTimeout(currentTimeoutId);
        };
    }, [simulateTrafficAttempt, isLoading, backendError]); // Added backendError dependency

    // --- View Renderer ---
    const renderContent = useMemo(() => {
        // Show loading state if data is not ready
        if (isLoading) {
            return (
                <div className="p-8 flex flex-col items-center justify-center min-h-[80vh] text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
                    <p className="mt-4 text-white">Initializing SecureOps Engine...</p>
                </div>
            );
        }
        
        // Show backend error message if API is not available
        if (backendError) {
            return (
                <div className="p-8 flex flex-col items-center justify-center min-h-[80vh] text-center">
                    <div className="bg-red-900/20 border border-red-500 rounded-lg p-6 max-w-2xl">
                        <h2 className="text-2xl font-bold text-red-400 mb-4">Backend Connection Error</h2>
                        <p className="text-gray-300 mb-4">
                            Unable to connect to the Flask backend server. Please ensure the backend is running.
                        </p>
                        <div className="text-left bg-gray-900/50 p-4 rounded mt-4">
                            <p className="text-sm text-gray-400 mb-2">To start the backend:</p>
                            <code className="text-green-400 text-sm block">python app.py</code>
                        </div>
                        <button 
                            onClick={() => {
                                setBackendError(false);
                                setIsLoading(true);
                                fetchInitialData();
                            }}
                            className="mt-4 px-4 py-2 bg-[#00ff7f] text-black rounded-lg font-semibold hover:bg-[#00ff7f]/80 transition"
                        >
                            Retry Connection
                        </button>
                    </div>
                </div>
            );
        }

        switch (currentPage) {
            case 'dashboard':
                return <DashboardView alerts={alerts} metrics={metrics} user={user} />;
            case 'detection_agent':
                return <DetectionAgentView token={token} onNavigateToXAI={() => setCurrentPage('xai_dashboard')} />;
            case 'xai_dashboard':
                return <XAIDashboardView token={token} />;
            case 'federation':
                return <FederationView token={token} />;
            case 'threat_detection':
                return <ThreatDetectionView currentLog={currentLog} />;
            case 'firewall_rules':
                return <FirewallRulesView token={token} />;
            case 'network_traffic':
                return <NetworkTrafficView token={token} />;
            case 'immutable_logs':
                return <ImmutableLogsView token={token} />;
            case 'settings':
                return <SettingsView token={token} user={user} onLogout={handleLogout} />;
            default:
                return <DashboardView alerts={alerts} metrics={metrics} user={user} />;
        }
    }, [currentPage, alerts, currentLog, isLoading, metrics, backendError, fetchInitialData, token, user]); // Added token and user

    // Show login if not authenticated - MUST BE AFTER ALL HOOKS
    if (!isAuthenticated) {
        return <Login onLogin={handleLogin} />;
    }

    // Safety check - if user is authenticated but no user data, show loading
    if (isAuthenticated && !user) {
        return (
            <div className="min-h-screen bg-[#0d1117] flex items-center justify-center">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f] mx-auto"></div>
                    <p className="mt-4 text-white">Loading user data...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="flex bg-[#0d1117] min-h-screen font-sans">
            <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />
            <main className="ml-56 w-full"> {/* Margin matches sidebar width */}
                <header className="bg-[#161b22] p-4 border-b border-gray-800 flex justify-between items-center fixed top-0 left-56 right-0 z-10 shadow-xl">
                    <div className="flex items-center">
                        <h1 className="text-xl font-semibold text-white mr-4">
                            {currentPage.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                        </h1>
                        <div className="flex items-center text-xs bg-[#00ff7f]/10 border border-[#00ff7f]/30 rounded-full px-3 py-1">
                            <ShieldCheckIcon className="w-3 h-3 text-[#00ff7f] mr-2" />
                            <span className="text-[#00ff7f] font-medium">Firewall System Active</span>
                        </div>
                    </div>
                    <div className="flex items-center text-sm">
                        <span className="text-green-400 mr-4 flex items-center">
                            <span className="h-2 w-2 rounded-full bg-green-400 mr-1 animate-pulse"></span>
                            Real-time monitoring active
                        </span>
                        <span className="text-gray-400 mr-4">User: <span className="text-white font-mono">{user?.username || 'N/A'}</span></span>
                        <span className="text-gray-400 mr-4">Role: <span className="text-[#00ff7f] font-mono uppercase">{user?.role || 'N/A'}</span></span>
                    </div>
                </header>
                <div className="pt-20"> {/* Padding to clear the fixed header */}
                    {renderContent}
                </div>
            </main>
        </div>
    );
};

export default App;