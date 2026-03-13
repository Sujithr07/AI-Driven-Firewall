import React, { useState, useEffect } from 'react';
import { SettingsIcon, UserCircleIcon, BellIcon, LockIcon, CpuIcon, ShieldCheckIcon } from './icons';
import { formatTimestamp, getInitials } from './utils';

const SettingsView = ({ token, user, onLogout }) => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('profile');
    const [passwordForm, setPasswordForm] = useState({ current: '', new_password: '', confirm: '' });
    const [passwordMsg, setPasswordMsg] = useState(null);

    // Notification preferences (UI-only state)
    const [notifPrefs, setNotifPrefs] = useState({
        highThreat: true, agentStatus: true, chainTamper: true, weekly: false,
    });

    useEffect(() => {
        if (user?.role === 'admin') {
            fetchUsers();
        } else {
            setLoading(false);
        }
    }, []);

    const fetchUsers = async () => {
        try {
            const response = await fetch('/api/users', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (response.ok) {
                const data = await response.json();
                setUsers(data.users);
            }
        } catch (error) {
            console.error('Failed to fetch users:', error);
        } finally {
            setLoading(false);
        }
    };

    const handlePasswordChange = async () => {
        if (passwordForm.new_password !== passwordForm.confirm) {
            setPasswordMsg({ type: 'error', text: 'Passwords do not match' });
            return;
        }
        setPasswordMsg({ type: 'info', text: 'Password change requires backend support.' });
    };

    const settingsTabs = [
        { id: 'profile', label: 'Profile', icon: UserCircleIcon },
        { id: 'notifications', label: 'Notifications', icon: BellIcon },
        { id: 'security', label: 'Security', icon: LockIcon },
        { id: 'system', label: 'System', icon: CpuIcon },
        ...(user?.role === 'admin' ? [{ id: 'users', label: 'User Management', icon: ShieldCheckIcon }] : []),
    ];

    return (
        <div className="p-8">
            <div className="flex items-center mb-6">
                <SettingsIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                <h2 className="text-3xl font-bold text-white">Settings</h2>
            </div>

            <div className="flex gap-6">
                {/* LEFT - Vertical Tab Nav */}
                <div className="w-48 shrink-0">
                    <div className="bg-[#161b22] rounded-xl border border-gray-800 p-2 space-y-1">
                        {settingsTabs.map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`w-full flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm transition ${
                                    activeTab === tab.id
                                        ? 'bg-[#00ff7f]/10 text-[#00ff7f] font-semibold'
                                        : 'text-gray-400 hover:bg-[#0d1117] hover:text-white'
                                }`}
                            >
                                <tab.icon className="w-4 h-4" />
                                {tab.label}
                            </button>
                        ))}
                    </div>
                </div>

                {/* RIGHT - Tab Content */}
                <div className="flex-1">
                    {/* PROFILE TAB */}
                    {activeTab === 'profile' && (
                        <div className="space-y-6">
                            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                                <div className="flex items-center gap-4 mb-6">
                                    <div className="w-16 h-16 rounded-full bg-[#00ff7f]/20 border-2 border-[#00ff7f] flex items-center justify-center text-[#00ff7f] text-2xl font-bold">
                                        {getInitials(user?.username)}
                                    </div>
                                    <div>
                                        <h3 className="text-xl font-bold text-white">{user?.username}</h3>
                                        <p className="text-gray-400 text-sm">{user?.email}</p>
                                        <span className="inline-block mt-1 px-2 py-0.5 text-xs font-bold rounded-full bg-[#00ff7f]/20 text-[#00ff7f] border border-[#00ff7f]/30 uppercase">
                                            {user?.role}
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Password Change */}
                            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                                <h3 className="text-lg font-semibold text-white mb-4">Change Password</h3>
                                {passwordMsg && (
                                    <div className={`mb-3 px-3 py-2 rounded text-sm ${
                                        passwordMsg.type === 'error' ? 'bg-red-900/20 text-red-400 border border-red-500'
                                            : 'bg-blue-900/20 text-blue-400 border border-blue-500'
                                    }`}>{passwordMsg.text}</div>
                                )}
                                <div className="space-y-3 max-w-md">
                                    <input type="password" placeholder="Current Password"
                                        value={passwordForm.current}
                                        onChange={(e) => setPasswordForm({ ...passwordForm, current: e.target.value })}
                                        className="w-full px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-[#00ff7f]" />
                                    <input type="password" placeholder="New Password"
                                        value={passwordForm.new_password}
                                        onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                                        className="w-full px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-[#00ff7f]" />
                                    <input type="password" placeholder="Confirm New Password"
                                        value={passwordForm.confirm}
                                        onChange={(e) => setPasswordForm({ ...passwordForm, confirm: e.target.value })}
                                        className="w-full px-4 py-2 bg-[#0d1117] border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-[#00ff7f]" />
                                    <button onClick={handlePasswordChange}
                                        className="px-4 py-2 bg-[#00ff7f] text-black font-semibold rounded-lg hover:bg-[#00ff7f]/80 text-sm transition">
                                        Update Password
                                    </button>
                                </div>
                            </div>

                            {/* Danger Zone */}
                            <div className="bg-[#161b22] p-6 rounded-xl border border-red-900/50">
                                <h3 className="text-lg font-semibold text-red-400 mb-2">Danger Zone</h3>
                                <p className="text-gray-400 text-sm mb-3">Sign out of your account. This will clear your session.</p>
                                <button onClick={onLogout}
                                    className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition text-sm font-semibold">
                                    Logout
                                </button>
                            </div>
                        </div>
                    )}

                    {/* NOTIFICATIONS TAB */}
                    {activeTab === 'notifications' && (
                        <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                            <h3 className="text-lg font-semibold text-white mb-4">Notification Preferences</h3>
                            <div className="space-y-4">
                                {[
                                    { key: 'highThreat', label: 'High Threat Alerts', desc: 'Notify on high-severity detections' },
                                    { key: 'agentStatus', label: 'Agent Status Changes', desc: 'Notify when agent starts/stops' },
                                    { key: 'chainTamper', label: 'Chain Tamper Detection', desc: 'Notify on hash chain integrity failure' },
                                    { key: 'weekly', label: 'Weekly Summary', desc: 'Send weekly security report' },
                                ].map(pref => (
                                    <div key={pref.key} className="flex items-center justify-between py-3 border-b border-gray-800">
                                        <div>
                                            <p className="text-white text-sm font-medium">{pref.label}</p>
                                            <p className="text-gray-500 text-xs">{pref.desc}</p>
                                        </div>
                                        <button
                                            onClick={() => setNotifPrefs({ ...notifPrefs, [pref.key]: !notifPrefs[pref.key] })}
                                            className={`w-12 h-6 rounded-full transition-colors duration-200 flex items-center px-0.5 ${
                                                notifPrefs[pref.key] ? 'bg-[#00ff7f]' : 'bg-gray-600'
                                            }`}
                                        >
                                            <div className={`w-5 h-5 rounded-full bg-white shadow-md transform transition-transform duration-200 ${
                                                notifPrefs[pref.key] ? 'translate-x-6' : ''
                                            }`} />
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* SECURITY TAB */}
                    {activeTab === 'security' && (
                        <div className="space-y-6">
                            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                                <h3 className="text-lg font-semibold text-white mb-4">Active Sessions</h3>
                                <div className="bg-[#0d1117] p-4 rounded-lg border border-gray-800 flex justify-between items-center">
                                    <div>
                                        <p className="text-white text-sm font-medium">Current Session</p>
                                        <p className="text-gray-500 text-xs">Browser · This device</p>
                                    </div>
                                    <span className="text-green-400 text-xs flex items-center">
                                        <span className="h-2 w-2 rounded-full bg-green-400 mr-1.5" /> Active
                                    </span>
                                </div>
                            </div>
                            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                                <h3 className="text-lg font-semibold text-white mb-2">Two-Factor Authentication</h3>
                                <p className="text-gray-400 text-sm mb-3">2FA is not yet available. Coming in a future update.</p>
                                <span className="px-3 py-1 text-xs bg-gray-800 text-gray-400 rounded-full border border-gray-700">Not Available</span>
                            </div>
                            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                                <h3 className="text-lg font-semibold text-white mb-2">API Access</h3>
                                <p className="text-gray-400 text-sm">Use Bearer token authentication for API requests. Token is stored in localStorage.</p>
                            </div>
                        </div>
                    )}

                    {/* SYSTEM TAB */}
                    {activeTab === 'system' && (
                        <div className="space-y-6">
                            <div className="grid grid-cols-2 gap-4">
                                {[
                                    ['Database', 'SQLite (firewall_system.db)', true],
                                    ['Authentication', 'JWT Tokens', true],
                                    ['AI Engine', 'RandomForest + Q-Learning', true],
                                    ['Zero Trust', 'Enabled', true],
                                ].map(([label, value, ok]) => (
                                    <div key={label} className="bg-[#161b22] p-4 rounded-xl border border-gray-800">
                                        <p className="text-gray-400 text-sm">{label}</p>
                                        <p className={`text-lg font-bold ${ok ? 'text-[#00ff7f]' : 'text-red-400'}`}>{value}</p>
                                    </div>
                                ))}
                            </div>
                            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                                <h3 className="text-lg font-semibold text-white mb-3">AI Models Loaded</h3>
                                <div className="space-y-2 text-sm">
                                    {['RandomForestClassifier (50 trees, max_depth=10)', 'Q-Learning Agent (ε-greedy, lr=0.1)', 'SHAP TreeExplainer'].map(m => (
                                        <div key={m} className="flex items-center gap-2 text-gray-300">
                                            <span className="h-2 w-2 rounded-full bg-[#00ff7f]" />
                                            {m}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* USER MANAGEMENT TAB (Admin only) */}
                    {activeTab === 'users' && user?.role === 'admin' && (
                        <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800">
                            <h3 className="text-lg font-semibold text-white mb-4">User Management</h3>
                            {loading ? (
                                <div className="flex items-center justify-center py-8">
                                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#00ff7f]"></div>
                                </div>
                            ) : (
                                <div className="overflow-x-auto">
                                    <table className="min-w-full divide-y divide-gray-700">
                                        <thead>
                                            <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                                <th className="px-4 py-3">User</th>
                                                <th className="px-4 py-3">Email</th>
                                                <th className="px-4 py-3">Role</th>
                                                <th className="px-4 py-3">Created</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-gray-800">
                                            {users.map((u) => (
                                                <tr key={u.id} className="text-sm text-gray-300 hover:bg-[#0d1117]">
                                                    <td className="px-4 py-3 flex items-center gap-2">
                                                        <div className="w-7 h-7 rounded-full bg-[#00ff7f]/20 border border-[#00ff7f] flex items-center justify-center text-[#00ff7f] text-xs font-bold">
                                                            {getInitials(u.username)}
                                                        </div>
                                                        {u.username}
                                                    </td>
                                                    <td className="px-4 py-3">{u.email}</td>
                                                    <td className="px-4 py-3">
                                                        <span className={`px-2 py-0.5 text-xs rounded-full font-bold ${
                                                            u.role === 'admin' ? 'bg-purple-600/30 text-purple-400' : 'bg-blue-600/30 text-blue-400'
                                                        }`}>{u.role}</span>
                                                    </td>
                                                    <td className="px-4 py-3 text-xs text-gray-500">
                                                        {formatTimestamp(u.created_at)}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default SettingsView;
