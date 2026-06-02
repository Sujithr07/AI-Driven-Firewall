import React, { useState } from 'react';

const DocumentIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="16" y1="13" x2="8" y2="13"/>
        <line x1="16" y1="17" x2="8" y2="17"/>
        <line x1="10" y1="9" x2="8" y2="9"/>
    </svg>
);

const DownloadIcon = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
);

const StatPill = ({ label, value, color }) => (
    <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
        <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
        <p className={`text-2xl font-bold font-mono mt-1 ${color}`}>{value}</p>
    </div>
);

const ReportsView = ({ token }) => {
    const [n, setN] = useState(100);
    const [loading, setLoading] = useState(false);
    const [report, setReport] = useState(null);
    const [stats, setStats] = useState(null);
    const [generatedAt, setGeneratedAt] = useState(null);
    const [error, setError] = useState(null);
    const [pdfLoading, setPdfLoading] = useState(false);

    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const handleGenerate = async () => {
        setLoading(true);
        setError(null);
        setReport(null);
        setStats(null);
        try {
            const res = await fetch('/api/reports/generate', {
                method: 'POST',
                headers,
                body: JSON.stringify({ n, format: 'markdown' }),
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || 'Report generation failed');
            }
            const data = await res.json();
            setReport(data.markdown);
            setStats(data.stats);
            setGeneratedAt(data.generated_at);
        } catch (e) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    const handleDownloadPDF = async () => {
        setPdfLoading(true);
        setError(null);
        try {
            const res = await fetch('/api/reports/generate', {
                method: 'POST',
                headers,
                body: JSON.stringify({ n, format: 'pdf' }),
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || 'PDF generation failed');
            }
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threat_report_${new Date().toISOString().slice(0, 10)}.pdf`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) {
            setError(e.message);
        } finally {
            setPdfLoading(false);
        }
    };

    const handleDownloadMD = () => {
        if (!report) return;
        const blob = new Blob([report], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `threat_report_${new Date().toISOString().slice(0, 10)}.md`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="p-8">
            {/* Header */}
            <div className="flex items-center gap-3 mb-6">
                <DocumentIcon className="w-8 h-8 text-[#00ff7f]" />
                <div>
                    <h2 className="text-3xl font-bold text-white">Threat Reports</h2>
                    <p className="text-gray-400 text-sm">AI-generated security analysis from detection data</p>
                </div>
            </div>

            {/* Config panel */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-6 mb-6">
                <h3 className="text-lg font-semibold text-gray-200 mb-4">Report Configuration</h3>
                <div className="flex flex-wrap items-end gap-8">
                    <div className="flex-1 min-w-[220px]">
                        <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">
                            Detections to Analyse
                        </label>
                        <div className="flex items-center gap-4">
                            <input
                                type="range"
                                min={10}
                                max={500}
                                step={10}
                                value={n}
                                onChange={e => setN(Number(e.target.value))}
                                className="w-48 accent-[#00ff7f]"
                            />
                            <span className="text-white font-mono w-12 text-right">{n}</span>
                        </div>
                        <p className="text-xs text-gray-600 mt-1">Last {n} detection log entries will be analysed</p>
                    </div>
                    <button
                        onClick={handleGenerate}
                        disabled={loading}
                        className="px-6 py-2.5 bg-[#00ff7f] text-black font-semibold rounded-lg hover:bg-[#00ff7f]/80 transition disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {loading ? 'Generating...' : 'Generate Report'}
                    </button>
                </div>
            </div>

            {/* Error */}
            {error && (
                <div className="bg-red-900/20 border border-red-500/50 rounded-lg p-4 mb-6 text-red-400 text-sm">
                    {error}
                </div>
            )}

            {/* Stats row */}
            {stats && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
                    <StatPill label="Total Events" value={stats.total} color="text-white" />
                    <StatPill
                        label="Malicious"
                        value={`${stats.malicious} (${stats.malicious_pct}%)`}
                        color="text-red-400"
                    />
                    <StatPill label="Blocked" value={stats.blocked} color="text-orange-400" />
                    <StatPill label="Allowed" value={stats.allowed} color="text-green-400" />
                </div>
            )}

            {/* Report output */}
            {report && (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 overflow-hidden">
                    <div className="flex items-center justify-between p-4 border-b border-gray-800">
                        <div>
                            <h3 className="text-gray-200 font-semibold">Generated Report</h3>
                            {generatedAt && (
                                <p className="text-xs text-gray-500 mt-0.5">
                                    {new Date(generatedAt).toLocaleString()}
                                </p>
                            )}
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={handleDownloadMD}
                                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#0d1117] border border-gray-700 text-gray-300 rounded-lg hover:text-white hover:border-gray-500 transition"
                            >
                                <DownloadIcon className="w-3 h-3" />
                                Markdown
                            </button>
                            <button
                                onClick={handleDownloadPDF}
                                disabled={pdfLoading}
                                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#00ff7f]/10 border border-[#00ff7f]/30 text-[#00ff7f] rounded-lg hover:bg-[#00ff7f]/20 transition disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                <DownloadIcon className="w-3 h-3" />
                                {pdfLoading ? 'Building PDF...' : 'PDF'}
                            </button>
                        </div>
                    </div>
                    <pre className="p-6 text-sm text-gray-300 font-mono whitespace-pre-wrap overflow-x-auto leading-relaxed max-h-[68vh] overflow-y-auto">
                        {report}
                    </pre>
                </div>
            )}

            {/* Empty state */}
            {!report && !loading && !error && (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 p-12 text-center">
                    <DocumentIcon className="w-16 h-16 text-gray-700 mx-auto mb-4" />
                    <h3 className="text-xl font-bold text-white mb-2">No Report Generated Yet</h3>
                    <p className="text-gray-500 text-sm max-w-md mx-auto">
                        Select how many detections to analyse and click Generate Report to get an
                        AI-powered security briefing with executive summary, threat breakdown, IP
                        analysis, and recommendations.
                    </p>
                </div>
            )}

            {/* Loading state */}
            {loading && (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 p-12 text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f] mx-auto mb-4" />
                    <p className="text-gray-400">Analysing {n} detections and generating report...</p>
                    <p className="text-gray-600 text-xs mt-2">This typically takes 10–20 seconds</p>
                </div>
            )}
        </div>
    );
};

export default ReportsView;
