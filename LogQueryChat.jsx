import React, { useState } from 'react';

const MessageDotsIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
);

const SparklesIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M9 3v4"/><path d="M3 5h4"/><path d="M3 9h4"/><path d="M19 17v4"/><path d="M23 17v4"/><path d="M17 19h4"/><path d="M17 23h4"/></svg>
);

const DatabaseIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>
);

const LogQueryChat = ({ token }) => {
    const [question, setQuestion] = useState('');
    const [loading, setLoading] = useState(false);
    const [answer, setAnswer] = useState(null);
    const [sources, setSources] = useState([]);
    const [showSources, setShowSources] = useState(false);
    const [chatHistory, setChatHistory] = useState([]);
    const [seeding, setSeeding] = useState(false);
    const [seedMessage, setSeedMessage] = useState(null);

    const handleAsk = async (e) => {
        e.preventDefault();
        if (!question.trim()) return;

        setLoading(true);
        setAnswer(null);
        setSources([]);

        try {
            const res = await fetch('/api/log-query', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ question }),
            });

            if (res.ok) {
                const data = await res.json();
                setAnswer(data.answer);
                setSources(data.sources || []);

                // Add to chat history (keep last 5)
                setChatHistory(prev => [
                    { question, answer: data.answer, sources: data.sources || [] },
                    ...prev.slice(0, 4),
                ]);
            } else {
                setAnswer('Failed to get answer. Please try again.');
            }
        } catch (error) {
            console.error('Error querying logs:', error);
            setAnswer('An error occurred. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const handleSeedIndex = async () => {
        setSeeding(true);
        setSeedMessage(null);

        try {
            const res = await fetch('/api/embed-existing-logs', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
            });

            if (res.ok) {
                const data = await res.json();
                setSeedMessage({ type: 'success', text: data.message || 'Index seeded successfully' });
            } else {
                setSeedMessage({ type: 'error', text: 'Failed to seed index' });
            }
        } catch (error) {
            console.error('Error seeding index:', error);
            setSeedMessage({ type: 'error', text: 'An error occurred while seeding' });
        } finally {
            setSeeding(false);
        }
    };

    const formatTime = (timestamp) => {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        return date.toLocaleTimeString();
    };

    return (
        <div className="p-8">
            {/* Header */}
            <div className="flex items-center mb-6">
                <MessageDotsIcon className="w-8 h-8 text-[#00ff7f] mr-3" />
                <div className="flex items-center gap-3">
                    <h2 className="text-3xl font-bold text-white">Log query assistant</h2>
                    <span className="px-2 py-1 bg-[#00ff7f]/20 border border-[#00ff7f]/40 rounded text-[#00ff7f] text-xs font-semibold flex items-center gap-1">
                        <SparklesIcon className="w-3 h-3" /> AI
                    </span>
                </div>
            </div>

            {/* Seed Index Button */}
            <div className="mb-6">
                <button
                    onClick={handleSeedIndex}
                    disabled={seeding}
                    className="px-4 py-2 bg-[#161b22] border border-gray-700 text-gray-300 rounded-lg hover:text-white hover:border-gray-500 transition flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    <DatabaseIcon className="w-4 h-4" />
                    {seeding ? 'Seeding...' : 'Seed index from recent logs'}
                </button>
                {seedMessage && (
                    <p className={`mt-2 text-sm ${seedMessage.type === 'success' ? 'text-green-400' : 'text-red-400'}`}>
                        {seedMessage.text}
                    </p>
                )}
            </div>

            {/* Chat History */}
            {chatHistory.length > 0 && (
                <div className="mb-6 space-y-4 max-h-96 overflow-y-auto">
                    {chatHistory.map((item, index) => (
                        <div key={index} className="bg-[#161b22] p-4 rounded-lg border border-gray-800">
                            <div className="flex items-start gap-3 mb-2">
                                <div className="w-8 h-8 bg-[#00ff7f]/20 rounded-full flex items-center justify-center flex-shrink-0">
                                    <span className="text-[#00ff7f] text-sm">Q</span>
                                </div>
                                <div className="flex-1">
                                    <p className="text-gray-300 font-medium">{item.question}</p>
                                </div>
                            </div>
                            <div className="flex items-start gap-3">
                                <div className="w-8 h-8 bg-purple-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                                    <SparklesIcon className="w-4 h-4 text-purple-400" />
                                </div>
                                <div className="flex-1">
                                    <p className="text-gray-200">{item.answer}</p>
                                    {item.sources && item.sources.length > 0 && (
                                        <button
                                            onClick={() => {
                                                setAnswer(item.answer);
                                                setSources(item.sources);
                                                setShowSources(true);
                                            }}
                                            className="mt-2 text-xs text-[#00ff7f] hover:text-[#00ff7f]/80"
                                        >
                                            View {item.sources.length} sources →
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Input */}
            <form onSubmit={handleAsk} className="mb-6">
                <div className="flex gap-3">
                    <input
                        type="text"
                        value={question}
                        onChange={(e) => setQuestion(e.target.value)}
                        placeholder="e.g. show all SSH attacks from last hour"
                        className="flex-1 px-4 py-3 bg-[#0d1117] border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-[#00ff7f]/50"
                        disabled={loading}
                    />
                    <button
                        type="submit"
                        disabled={loading || !question.trim()}
                        className="px-6 py-3 bg-[#00ff7f] hover:bg-[#00ff7f]/80 text-black font-semibold rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                        {loading ? (
                            <>
                                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-black"></div>
                                Thinking...
                            </>
                        ) : (
                            <>
                                <SparklesIcon className="w-4 h-4" />
                                Ask
                            </>
                        )}
                    </button>
                </div>
            </form>

            {/* Answer */}
            {answer && (
                <div className="bg-[#161b22] p-6 rounded-xl border border-gray-800 shadow-lg mb-4">
                    <div className="flex items-start gap-3">
                        <div className="w-8 h-8 bg-purple-500/20 rounded-full flex items-center justify-center flex-shrink-0">
                            <SparklesIcon className="w-4 h-4 text-purple-400" />
                        </div>
                        <div className="flex-1">
                            <p className="text-gray-200 text-lg leading-relaxed">{answer}</p>
                        </div>
                    </div>
                </div>
            )}

            {/* Sources */}
            {sources.length > 0 && (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 overflow-hidden">
                    <button
                        onClick={() => setShowSources(!showSources)}
                        className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-[#1f2937]/50 transition"
                    >
                        <span className="text-gray-300 font-medium flex items-center gap-2">
                            <DatabaseIcon className="w-4 h-4" />
                            Sources ({sources.length} matching logs)
                        </span>
                        <span className="text-gray-500">{showSources ? '▼' : '▶'}</span>
                    </button>
                    {showSources && (
                        <div className="px-6 pb-6">
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-700">
                                    <thead>
                                        <tr className="text-left text-gray-400 text-xs uppercase tracking-wider">
                                            <th className="px-4 py-2">Time</th>
                                            <th className="px-4 py-2">Source IP</th>
                                            <th className="px-4 py-2">Protocol</th>
                                            <th className="px-4 py-2">Reason</th>
                                            <th className="px-4 py-2">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-800">
                                        {sources.map((log, index) => (
                                            <tr key={index} className="text-sm text-gray-300">
                                                <td className="px-4 py-2 text-xs">{formatTime(log.timestamp)}</td>
                                                <td className="px-4 py-2 font-mono">{log.src_ip || 'N/A'}</td>
                                                <td className="px-4 py-2">{log.protocol || 'N/A'}</td>
                                                <td className="px-4 py-2 text-xs">{log.reason || 'N/A'}</td>
                                                <td className="px-4 py-2">
                                                    <span className={`px-2 py-0.5 text-xs rounded ${
                                                        log.action === 'Blocked' ? 'bg-red-600/30 text-red-400' :
                                                        log.action === 'Allowed' ? 'bg-green-600/30 text-green-400' :
                                                        'bg-yellow-600/30 text-yellow-400'
                                                    }`}>
                                                        {log.action || 'N/A'}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default LogQueryChat;
