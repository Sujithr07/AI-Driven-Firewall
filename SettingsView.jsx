import React, { useState, useEffect } from 'react';

const SettingsIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 0 2.73l-.15.1a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.09a2 2 0 0 1 0-2.73l.15-.1a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
);

const SettingsView = ({ token, user, onLogout }) => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        if (user?.role === 'admin') {
            fetchUsers();
        }
    }, []);

    const fetchUsers = async () => {
        try {
            const response = await fetch('http://localhost:5000/api/users', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
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

    return (
        <div className="p-8">
            <div className="flex items-center mb-6">
                <SettingsIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                <h2 className="text-3xl font-bold text-white">System Settings</h2>
            </div>

            {/* User Profile */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg mb-6">
                <h3 className="text-xl font-semibold text-gray-200 mb-4">Your Profile</h3>
                <div className="space-y-3">
                    <div>
                        <label className="text-sm text-gray-400">Username</label>
                        <div className="text-white font-medium">{user?.username}</div>
                    </div>
                    <div>
                        <label className="text-sm text-gray-400">Email</label>
                        <div className="text-white font-medium">{user?.email}</div>
                    </div>
                    <div>
                        <label className="text-sm text-gray-400">Role</label>
                        <div className="text-[#00ff7f] font-medium uppercase">{user?.role}</div>
                    </div>
                    <button
                        onClick={onLogout}
                        className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition"
                    >
                        Logout
                    </button>
                </div>
            </div>

            {/* System Information */}
            <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg mb-6">
                <h3 className="text-xl font-semibold text-gray-200 mb-4">System Information</h3>
                <div className="space-y-2 text-sm text-gray-300">
                    <div className="flex justify-between">
                        <span>Database:</span>
                        <span className="text-[#00ff7f]">SQLite (firewall_system.db)</span>
                    </div>
                    <div className="flex justify-between">
                        <span>Authentication:</span>
                        <span className="text-[#00ff7f]">JWT Tokens</span>
                    </div>
                    <div className="flex justify-between">
                        <span>AI Engine:</span>
                        <span className="text-[#00ff7f]">Active</span>
                    </div>
                    <div className="flex justify-between">
                        <span>Zero Trust:</span>
                        <span className="text-[#00ff7f]">Enabled</span>
                    </div>
                </div>
            </div>

            {/* User Management (Admin Only) */}
            {user?.role === 'admin' && (
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-xl font-semibold text-gray-200 mb-4">User Management</h3>
                    {loading ? (
                        <div className="flex items-center justify-center py-8">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#00ff7f]"></div>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-700">
                                <thead>
                                    <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                        <th className="px-4 py-3">Username</th>
                                        <th className="px-4 py-3">Email</th>
                                        <th className="px-4 py-3">Role</th>
                                        <th className="px-4 py-3">Created</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800">
                                    {users.map((u) => (
                                        <tr key={u.id} className="text-sm text-gray-300">
                                            <td className="px-4 py-3">{u.username}</td>
                                            <td className="px-4 py-3">{u.email}</td>
                                            <td className="px-4 py-3">
                                                <span className={`px-2 py-1 text-xs rounded ${
                                                    u.role === 'admin' ? 'bg-purple-600/30 text-purple-400' : 'bg-blue-600/30 text-blue-400'
                                                }`}>
                                                    {u.role}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3 text-xs text-gray-500">
                                                {new Date(u.created_at).toLocaleDateString()}
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
    );
};

export default SettingsView;

