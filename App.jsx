import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import Login from './Login';
import NetworkTrafficView from './NetworkTrafficView';
import ImmutableLogsView from './ImmutableLogsView';
import SettingsView from './SettingsView';
import DetectionAgentView from './DetectionAgentView';
import XAIDashboardView from './XAIDashboardView';
import FederationView from './FederationView';
import FirewallRulesView from './FirewallRulesView';
import {
    ShieldCheckIcon, ServerIcon, ZapIcon, LockIcon, BrainIcon, GlobeIcon,
    FileTextIcon, SettingsIcon, MicroscopeIcon, MenuIcon, BellIcon,
    ShieldIcon, WifiIcon, CpuIcon
} from './icons';
import { formatTimestamp, getRelativeTime, getSeverityClass, getInitials } from './utils';

// --- Sidebar Navigation Component ---
const Sidebar = ({ currentPage, setCurrentPage, user, collapsed, setCollapsed }) => {
    const navItems = [
        { id: 'dashboard', label: 'Dashboard', icon: ZapIcon },
        { id: 'network_traffic', label: 'Network Traffic', icon: ServerIcon },
        { id: 'detection_agent', label: 'Detection Agent', icon: BrainIcon },
        { id: 'ai_transparency', label: 'AI Transparency', icon: MicroscopeIcon },
        { id: 'federation', label: 'Federation', icon: GlobeIcon },
        { id: 'immutable_logs', label: 'Immutable Logs', icon: FileTextIcon },
        { id: 'firewall_rules', label: 'Firewall Rules', icon: LockIcon },
    ];

    return (
        <div className={`${collapsed ? 'w-16' : 'w-56'} bg-[#090c10] min-h-screen p-4 flex flex-col fixed top-0 left-0 z-20 transition-all duration-300`}>
            <div className="flex items-center justify-between mb-8">
                {!collapsed && (
                    <div className="flex items-center text-xl font-bold text-[#00ff7f]">
                        <ShieldCheckIcon className="w-6 h-6 mr-2 shrink-0" /> AI Firewall
                    </div>
                )}
                <button
                    onClick={() => setCollapsed(!collapsed)}
                    className="text-gray-400 hover:text-white p-1 rounded hover:bg-[#161b22] transition"
                    title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                >
                    <MenuIcon className="w-5 h-5" />
                </button>
            </div>
            <nav className="space-y-1 flex-1">
                {navItems.map((item) => {
                    const active = currentPage === item.id;
                    return (
                        <button
                            key={item.id}
                            onClick={() => setCurrentPage(item.id)}
                            className={`w-full flex items-center ${collapsed ? 'justify-center px-2' : 'px-3'} py-2.5 rounded-lg transition duration-200 ${
                                active
                                    ? 'bg-[#00ff7f]/10 text-[#00ff7f] font-semibold border-l-4 border-[#00ff7f]'
                                    : 'text-gray-400 hover:bg-[#161b22] hover:text-white border-l-4 border-transparent'
                            }`}
                            title={collapsed ? item.label : undefined}
                        >
                            <item.icon className={`w-5 h-5 ${collapsed ? '' : 'mr-3'} shrink-0`} />
                            {!collapsed && <span className="text-sm">{item.label}</span>}
                        </button>
                    );
                })}
            </nav>
            <div className="pt-4 border-t border-gray-800 space-y-1">
                {/* User avatar display */}
                <div className={`flex items-center ${collapsed ? 'justify-center' : 'px-3'} py-2 text-gray-400`}>
                    <div className="w-8 h-8 rounded-full bg-[#00ff7f]/20 border border-[#00ff7f] flex items-center justify-center text-[#00ff7f] text-xs font-bold shrink-0">
                        {getInitials(user?.username)}
                    </div>
                    {!collapsed && <span className="ml-3 text-sm text-gray-300 truncate">{user?.username}</span>}
                </div>
                {/* Settings */}
                <button
                    onClick={() => setCurrentPage('settings')}
                    className={`w-full flex items-center ${collapsed ? 'justify-center px-2' : 'px-3'} py-2.5 rounded-lg transition duration-200 ${
                        currentPage === 'settings'
                            ? 'bg-[#00ff7f]/10 text-[#00ff7f] font-semibold border-l-4 border-[#00ff7f]'
                            : 'text-gray-400 hover:bg-[#161b22] hover:text-white border-l-4 border-transparent'
                    }`}
                    title={collapsed ? 'Settings' : undefined}
                >
                    <SettingsIcon className={`w-5 h-5 ${collapsed ? '' : 'mr-3'} shrink-0`} />
                    {!collapsed && <span className="text-sm">Settings</span>}
                </button>
            </div>
        </div>
    );
};

// --- Header Bar Component ---
const HeaderBar = ({ currentPage, user, backendError, alerts, handleLogout, setCurrentPage, sidebarWidth }) => {
    const [showDropdown, setShowDropdown] = useState(false);
    const dropdownRef = useRef(null);

    useEffect(() => {
        const handler = (e) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
                setShowDropdown(false);
            }
        };
        document.addEventListener('mousedown', handler);
        return () => document.removeEventListener('mousedown', handler);
    }, []);

    const pageLabels = {
        dashboard: { title: 'Dashboard', breadcrumb: '› Overview' },
        network_traffic: { title: 'Network Traffic', breadcrumb: '› Analysis' },
        detection_agent: { title: 'Detection Agent', breadcrumb: '› Live Feed' },
        ai_transparency: { title: 'AI Transparency', breadcrumb: '› Pipeline Walkthrough' },
        federation: { title: 'Federation', breadcrumb: '› Status' },
        immutable_logs: { title: 'Immutable Logs', breadcrumb: '› Chain View' },
        firewall_rules: { title: 'Firewall Rules', breadcrumb: '› Active Rules' },
        settings: { title: 'Settings', breadcrumb: '› Profile' },
    };

    const { title, breadcrumb } = pageLabels[currentPage] || { title: 'Dashboard', breadcrumb: '' };

    // Count high severity alerts
    const highAlertCount = (alerts || []).filter(a => a.severity === 'High').length;

    // Status pill
    let statusPill;
    if (backendError) {
        statusPill = (
            <div className="flex items-center gap-2 bg-red-900/30 border border-red-500/30 rounded-full px-3 py-1">
                <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
                <span className="text-red-400 text-xs font-medium">Backend Offline</span>
            </div>
        );
    } else {
        statusPill = (
            <div className="flex items-center gap-2 bg-green-900/30 border border-green-500/30 rounded-full px-3 py-1">
                <span className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
                <span className="text-green-400 text-xs font-medium">System Operational</span>
            </div>
        );
    }

    const roleBadgeClass = {
        admin: 'bg-amber-900/40 border-amber-500 text-amber-400',
        analyst: 'bg-blue-900/40 border-blue-500 text-blue-400',
        viewer: 'bg-gray-800 border-gray-600 text-gray-400',
    }[user?.role] || 'bg-gray-800 border-gray-600 text-gray-400';

    return (
        <header
            className="bg-[#161b22] p-4 border-b border-gray-800 flex justify-between items-center fixed top-0 right-0 z-10 shadow-xl"
            style={{ left: `${sidebarWidth}px` }}
        >
            {/* LEFT */}
            <div className="flex items-center gap-3">
                <h1 className="text-xl font-semibold text-white">{title}</h1>
                <span className="text-gray-400 text-sm">{breadcrumb}</span>
            </div>

            {/* CENTER */}
            <div className="hidden md:flex">{statusPill}</div>

            {/* RIGHT */}
            <div className="flex items-center gap-4">
                {/* Notification bell */}
                <div className="relative">
                    <BellIcon className="w-5 h-5 text-gray-400 cursor-pointer hover:text-white transition" />
                    {highAlertCount > 0 && (
                        <span className="absolute -top-1.5 -right-1.5 bg-red-500 text-white text-[10px] font-bold rounded-full w-4 h-4 flex items-center justify-center">
                            {highAlertCount > 9 ? '9+' : highAlertCount}
                        </span>
                    )}
                </div>

                {/* User avatar dropdown */}
                <div className="relative" ref={dropdownRef}>
                    <button
                        onClick={() => setShowDropdown(!showDropdown)}
                        className="w-9 h-9 rounded-full bg-[#00ff7f]/20 border border-[#00ff7f] flex items-center justify-center text-[#00ff7f] text-sm font-bold cursor-pointer hover:bg-[#00ff7f]/30 transition"
                    >
                        {getInitials(user?.username)}
                    </button>
                    {showDropdown && (
                        <div className="absolute right-0 top-12 bg-[#161b22] border border-gray-700 rounded-xl shadow-2xl p-2 w-48 z-50">
                            <div className="px-3 py-2">
                                <p className="text-white font-bold text-sm">{user?.username}</p>
                                <span className={`inline-block mt-1 px-2 py-0.5 text-xs font-bold rounded-full border ${roleBadgeClass}`}>
                                    {(user?.role || 'viewer').toUpperCase()}
                                </span>
                            </div>
                            <div className="border-t border-gray-700 my-1" />
                            <button
                                onClick={() => { setCurrentPage('settings'); setShowDropdown(false); }}
                                className="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-[#0d1117] rounded-lg transition"
                            >
                                ⚙ Profile & Settings
                            </button>
                            <button
                                onClick={() => { handleLogout(); setShowDropdown(false); }}
                                className="w-full text-left px-3 py-2 text-sm text-red-400 hover:bg-red-900/20 rounded-lg transition"
                            >
                                ↩ Logout
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </header>
    );
};


// --- Dashboard Sub-Components ---

const StatCard = ({ title, value, color, icon, sparkHeights }) => (
    <div className="bg-[#161b22] p-5 rounded-xl border border-gray-800 shadow-lg flex flex-col">
        <div className="flex justify-between items-start">
            <p className="text-sm font-medium text-gray-400">{title}</p>
            {React.createElement(icon, { className: `w-6 h-6 ${color}` })}
        </div>
        <p className="text-3xl font-bold text-white mt-2">{value}</p>
        <div className="flex items-end gap-0.5 mt-3">
            {(sparkHeights || [2, 3, 1, 4, 3]).map((h, i) => (
                <div key={i} className={`w-4 rounded-sm ${color.replace('text-', 'bg-')}/60`} style={{ height: `${h * 4}px` }} />
            ))}
        </div>
    </div>
);


// --- DashboardView (SOC Layout) ---
const DashboardView = ({ metrics, currentLog, token }) => {
    const [agentStatus, setAgentStatus] = useState(null);
    const [flStatus, setFlStatus] = useState(null);
    const [chainValid, setChainValid] = useState(null);

    useEffect(() => {
        const headers = { Authorization: `Bearer ${token}` };
        const fetchStatuses = async () => {
            try {
                const [agentRes, flRes, chainRes] = await Promise.all([
                    fetch('/api/agent/status', { headers }).catch(() => null),
                    fetch('/api/fl/status', { headers }).catch(() => null),
                    fetch('/api/logs/verify', { headers }).catch(() => null),
                ]);
                if (agentRes?.ok) setAgentStatus(await agentRes.json());
                if (flRes?.ok) {
                    const d = await flRes.json();
                    setFlStatus(d);
                }
                if (chainRes?.ok) {
                    const d = await chainRes.json();
                    setChainValid(d.chain_valid);
                }
            } catch (e) { /* ignore */ }
        };
        fetchStatuses();
        const iv = setInterval(fetchStatuses, 30000);
        return () => clearInterval(iv);
    }, [token]);

    // Compute last blocked timestamp
    const lastBlockedEntry = currentLog.find(l => l.decision === 'Blocked');
    const lastThreat = lastBlockedEntry ? getRelativeTime(lastBlockedEntry.timestamp) : 'N/A';

    // Top blocked IPs
    const blockedIPCounts = {};
    currentLog.forEach(l => {
        if (l.decision === 'Blocked' && l.source_ip) {
            blockedIPCounts[l.source_ip] = (blockedIPCounts[l.source_ip] || 0) + 1;
        }
    });
    const topBlockedIPs = Object.entries(blockedIPCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3);

    // Protocol distribution
    const protocolStats = {};
    currentLog.forEach(l => {
        const proto = l.protocol || l.traffic?.protocol || 'OTHER';
        if (!protocolStats[proto]) protocolStats[proto] = { total: 0, blocked: 0, allowed: 0 };
        protocolStats[proto].total++;
        if (l.decision === 'Blocked') protocolStats[proto].blocked++;
        else protocolStats[proto].allowed++;
    });

    const protoBadgeColor = {
        TCP: 'bg-blue-900/50 text-blue-300 border-blue-500',
        UDP: 'bg-green-900/50 text-green-300 border-green-500',
        ICMP: 'bg-yellow-900/50 text-yellow-300 border-yellow-500',
    };

    return (
        <div className="p-8">
            {/* ROW 1 - KPI Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-6 mb-8">
                <StatCard title="Active Threats" value={metrics.activeThreats} color="text-red-400" icon={ZapIcon} sparkHeights={[2,4,1,3,4]} />
                <StatCard title="Blocked Attacks" value={metrics.blockedAttacks} color="text-orange-400" icon={ShieldIcon} sparkHeights={[1,3,2,4,2]} />
                <StatCard title="Network Traffic" value={metrics.networkTraffic} color="text-blue-400" icon={WifiIcon} sparkHeights={[3,2,4,1,3]} />
                <StatCard title="System Health" value={metrics.systemHealth} color="text-[#00ff7f]" icon={CpuIcon} sparkHeights={[4,3,4,3,4]} />
            </div>

            {/* ROW 2 - Two Column Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mb-8">
                {/* LEFT - AI Decision Timeline */}
                <div className="lg:col-span-3 bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <div className="flex justify-between items-center mb-4">
                        <h3 className="text-lg font-semibold text-white">AI Decision Timeline</h3>
                        <span className="text-xs text-[#00ff7f] flex items-center">
                            <span className="h-2 w-2 rounded-full bg-[#00ff7f] mr-1 animate-pulse" />Live
                        </span>
                    </div>
                    <div className="max-h-96 overflow-y-auto space-y-2 pr-1">
                        {currentLog.length === 0 ? (
                            <div className="text-center py-8">
                                <BrainIcon className="w-10 h-10 text-gray-700 mx-auto mb-3" />
                                <p className="text-gray-500 italic text-sm">No traffic recorded yet — start the Detection Agent to begin monitoring</p>
                            </div>
                        ) : (
                            currentLog.slice(0, 20).map((entry, idx) => {
                                const borderColor = entry.decision === 'Blocked' ? 'border-red-500' :
                                    entry.decision === 'Quarantined' ? 'border-yellow-500' : 'border-green-500';
                                const badgeClass = entry.decision === 'Blocked' ? 'bg-red-900/50 text-red-400' :
                                    entry.decision === 'Quarantined' ? 'bg-amber-900/50 text-amber-400' : 'bg-green-900/50 text-green-400';
                                const aiScore = entry.aiResult?.finalScore || entry.ai_score || 0;
                                const srcIP = entry.source_ip || entry.traffic?.src_ip || entry.userContext?.identity || 'Unknown';
                                const dest = entry.userContext?.resource || entry.user_resource || entry.destination_ip || 'Unknown';
                                const reason = entry.reason || 'No reason provided';
                                return (
                                    <div key={idx} className={`border-l-4 ${borderColor} bg-[#0d1117] rounded-r-lg p-3`}>
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-2">
                                                <span className={`px-2 py-0.5 text-xs font-bold rounded-full ${badgeClass}`}>
                                                    {(entry.decision || '').toUpperCase()}
                                                </span>
                                                <span className="font-mono text-sm text-white">{srcIP}</span>
                                                <span className="text-gray-500 text-xs">→</span>
                                                <span className="text-gray-400 text-xs">{dest}</span>
                                            </div>
                                            <div className="text-right">
                                                <span className="font-mono text-xs text-gray-400">Score: {aiScore.toFixed(2)}</span>
                                                <span className="text-gray-500 text-xs ml-2">{formatTimestamp(entry.timestamp)}</span>
                                            </div>
                                        </div>
                                        <p className="text-xs text-gray-500 mt-1 truncate" title={reason}>
                                            {reason.length > 60 ? reason.slice(0, 60) + '...' : reason}
                                        </p>
                                    </div>
                                );
                            })
                        )}
                    </div>
                </div>

                {/* RIGHT - System Status */}
                <div className="lg:col-span-2 bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h4 className="text-sm font-semibold text-gray-400 uppercase mb-3">Live System Status</h4>
                    <div className="space-y-0">
                        {[
                            { label: 'Detection Agent', ok: agentStatus?.running, onLabel: 'Running', offLabel: 'Stopped' },
                            { label: 'Federation Server', ok: flStatus?.server != null, onLabel: 'Connected', offLabel: 'Unreachable' },
                            { label: 'Log Chain Integrity', ok: chainValid, onLabel: 'Intact', offLabel: 'Tampered' },
                        ].map((s, i) => (
                            <div key={i} className="flex justify-between items-center py-2.5 border-b border-gray-800">
                                <span className="text-sm text-gray-300">{s.label}</span>
                                <span className={`flex items-center text-sm ${s.ok ? 'text-green-400' : 'text-red-400'}`}>
                                    <span className={`h-2 w-2 rounded-full mr-2 ${s.ok ? 'bg-green-400' : 'bg-red-500'}`} />
                                    {s.ok ? s.onLabel : s.offLabel}
                                </span>
                            </div>
                        ))}
                        <div className="flex justify-between items-center py-2.5 border-b border-gray-800">
                            <span className="text-sm text-gray-300">Last Threat</span>
                            <span className="text-sm text-gray-400">{lastThreat}</span>
                        </div>
                    </div>

                    <h4 className="text-sm font-semibold text-gray-400 uppercase mt-5 mb-3">Top Blocked IPs</h4>
                    {topBlockedIPs.length === 0 ? (
                        <p className="text-gray-500 text-xs italic">No blocked IPs yet</p>
                    ) : (
                        <div className="space-y-2">
                            {topBlockedIPs.map(([ip, count]) => (
                                <div key={ip} className="flex justify-between items-center">
                                    <span className="font-mono text-sm text-white">{ip}</span>
                                    <span className="bg-red-900/50 text-red-400 text-xs px-2 py-0.5 rounded-full font-bold">{count}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* ROW 3 - Attack Distribution */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-6">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-lg font-semibold text-white">Attack Distribution by Protocol</h3>
                    <span className="text-xs text-gray-400">last updated: {formatTimestamp(Date.now())}</span>
                </div>
                {currentLog.length === 0 ? (
                    <p className="text-gray-500 text-sm text-center py-8 italic">Collecting data...</p>
                ) : (
                    <div className="space-y-3">
                        {Object.entries(protocolStats).map(([proto, stats]) => {
                            const blockedPct = stats.total > 0 ? (stats.blocked / stats.total) * 100 : 0;
                            const allowedPct = stats.total > 0 ? (stats.allowed / stats.total) * 100 : 0;
                            const badgeCls = protoBadgeColor[proto] || 'bg-gray-800 text-gray-300 border-gray-600';
                            return (
                                <div key={proto} className="flex items-center gap-3">
                                    <span className={`w-16 text-center px-2 py-0.5 rounded-full text-xs font-bold border ${badgeCls}`}>{proto}</span>
                                    <div className="flex-1 flex h-3 rounded-full overflow-hidden bg-gray-800">
                                        <div style={{ width: `${blockedPct}%` }} className="bg-red-500/70 h-3" />
                                        <div style={{ width: `${allowedPct}%` }} className="bg-[#00ff7f]/70 h-3" />
                                    </div>
                                    <span className="text-xs text-gray-400 w-40 text-right">{stats.blocked} blocked / {stats.total} total</span>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>
        </div>
    );
};


// --- Main App Component ---
const App = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [currentPage, setCurrentPage] = useState('dashboard');
    const [alerts, setAlerts] = useState([]);
    const [currentLog, setCurrentLog] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
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
                setIsLoading(false);
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
        setCurrentPage('dashboard');
        setIsLoading(true);
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
    const fetchInitialData = useCallback(async () => {
        if (!token) return;
        try {
            const response = await fetch('/api/dashboard', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!response.ok) {
                if (response.status === 401 || response.status === 422) {
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
            setAlerts(data.metrics?.alerts || []);
            setBackendError(false);
            setIsLoading(false);
        } catch (error) {
            console.error("Failed to fetch initial dashboard data:", error);
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

    useEffect(() => {
        if (isAuthenticated && token) {
            fetchInitialData();
        }
    }, [fetchInitialData, isAuthenticated, token]);

    // --- Core Simulation Logic ---
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

            if (newLogEntry) {
                setCurrentLog(prevLog => [newLogEntry, ...prevLog].slice(0, 50));
            }
            if (data.metrics) {
                setMetrics({
                    activeThreats: data.metrics.activeThreats ?? 0,
                    blockedAttacks: data.metrics.blockedAttacks ?? 0,
                    networkTraffic: data.metrics.networkTraffic ?? '0.00 Gbps',
                    systemHealth: data.metrics.systemHealth ?? '100%',
                });
                setAlerts(data.metrics.alerts || []);
            }
        } catch (error) {
            console.error("Failed to simulate traffic via Flask API:", error);
        }
    }, [token]);

    useEffect(() => {
        if (isLoading || backendError) return;

        let cancelled = false;
        let currentTimeoutId = null;

        const getRandomInterval = () => Math.floor(Math.random() * 10000) + 15000;

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
    }, [simulateTrafficAttempt, isLoading, backendError]);

    // --- View Renderer ---
    const renderContent = useMemo(() => {
        if (isLoading) {
            return (
                <div className="p-8 flex flex-col items-center justify-center min-h-[80vh] text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
                    <p className="mt-4 text-white">Initializing SecureOps Engine...</p>
                </div>
            );
        }

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
                return <DashboardView metrics={metrics} currentLog={currentLog} token={token} />;
            case 'detection_agent':
                return <DetectionAgentView token={token} onNavigateToXAI={() => setCurrentPage('ai_transparency')} />;
            case 'ai_transparency':
                return <XAIDashboardView token={token} onNavigateToDetection={() => setCurrentPage('detection_agent')} />;
            case 'federation':
                return <FederationView token={token} />;
            case 'firewall_rules':
                return <FirewallRulesView token={token} />;
            case 'network_traffic':
                return <NetworkTrafficView token={token} />;
            case 'immutable_logs':
                return <ImmutableLogsView token={token} />;
            case 'settings':
                return <SettingsView token={token} user={user} onLogout={handleLogout} />;
            default:
                return <DashboardView metrics={metrics} currentLog={currentLog} token={token} />;
        }
    }, [currentPage, currentLog, isLoading, metrics, backendError, fetchInitialData, token, user]);

    // Show login if not authenticated
    if (!isAuthenticated) {
        return <Login onLogin={handleLogin} />;
    }

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

    const sidebarWidth = sidebarCollapsed ? 64 : 224;

    return (
        <div className="flex bg-[#0d1117] min-h-screen font-sans">
            <Sidebar
                currentPage={currentPage}
                setCurrentPage={setCurrentPage}
                user={user}
                collapsed={sidebarCollapsed}
                setCollapsed={setSidebarCollapsed}
            />
            <main style={{ marginLeft: `${sidebarWidth}px` }} className="w-full transition-all duration-300">
                <HeaderBar
                    currentPage={currentPage}
                    user={user}
                    backendError={backendError}
                    alerts={alerts}
                    handleLogout={handleLogout}
                    setCurrentPage={setCurrentPage}
                    sidebarWidth={sidebarWidth}
                />
                <div className="pt-20">
                    {renderContent}
                </div>
            </main>
        </div>
    );
};

export default App;