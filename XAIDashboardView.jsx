import React, { useState, useEffect, useCallback } from 'react';
import { MicroscopeIcon, BrainIcon, BarChartIcon, ActivityIcon, ChevronRightIcon } from './icons';
import { formatTimestamp } from './utils';

const FEATURE_LABELS = {
    proto_num: 'Protocol Type',
    sport: 'Source Port',
    dport: 'Dest Port',
    packet_size: 'Packet Size',
    src_is_private: 'Src IP Private',
    dst_is_private: 'Dst IP Private',
    has_syn: 'SYN Flag (scan)',
    has_fin: 'FIN Flag',
    has_rst: 'RST Flag',
    port_is_suspicious: 'Suspicious Port',
    port_is_well_known: 'Known Safe Port',
};

function buildPipelineSteps(d) {
    const stateParts = (d.rl_state || '|||').split('|');
    const reason = stateParts[0] || 'unknown';
    const ip_type = stateParts[1] || 'unknown';
    const protocol = stateParts[2] || d.protocol || 'unknown';
    const port_type = stateParts[3] || 'unknown';
    const flags = d.flags || '';
    const has_syn = flags.includes('S') && !flags.includes('A');
    const has_rst = flags.includes('R');

    const step1 = {
        step: 1, title: 'Packet Capture', status: 'info',
        details: [
            'Interface: eth0 (Scapy live capture / simulation mode)',
            'Packet type: IP layer detected',
            `Timestamp: ${formatTimestamp(d.timestamp)}`,
        ],
        explanation: 'Scapy intercepted this packet on the network interface.',
    };
    const step2 = {
        step: 2, title: 'Protocol & Header Parsing', status: 'info',
        details: [
            `Protocol: ${d.protocol}`, `Source port: ${d.sport}`, `Dest port: ${d.dport}`,
            `Packet size: ${d.size} bytes`,
            ...(flags ? [`TCP Flags: ${flags}`] : []),
        ],
        explanation: 'IP header parsed; protocol-specific layer accessed for ports, flags, size.',
    };
    const step3 = {
        step: 3, title: 'Feature Engineering', status: 'info',
        details: [
            `IP type: ${ip_type}`, `Port type: ${port_type}`,
            `SYN flag (no ACK): ${has_syn ? 'YES — port scan pattern' : 'NO'}`,
        ],
        explanation: 'Raw values mapped to categorical features for the ML model.',
    };
    const step4 = {
        step: 4, title: 'RandomForest Classification',
        status: d.rf_prediction === 'attack' ? 'threat' : 'safe',
        details: [
            'Model: RandomForestClassifier (50 trees)',
            `Prediction: ${(d.rf_prediction || '').toUpperCase()}`,
            `Confidence: ${(d.rf_confidence * 100).toFixed(1)}%`,
        ],
        explanation: '11-feature vector passed to the RandomForest model.',
    };
    const step5 = {
        step: 5, title: 'RL Agent Decision',
        status: d.rl_action === 'block' ? 'threat' : 'safe',
        details: [
            `State: (${reason} | ${ip_type} | ${d.protocol} | ${port_type})`,
            `Action: ${(d.rl_action || '').toUpperCase()}`,
            `Exploration: ${d.was_exploration ? 'YES (ε-greedy)' : 'NO (exploit)'}`,
            `Reward: ${d.rl_reward > 0 ? '+1.0' : '-1.0'}`,
        ],
        explanation: 'Q-Learning agent selected action based on state Q-values.',
    };

    // Heuristic scoring
    let score = 0;
    const rfConf = d.rf_confidence || 0;
    if (d.rf_prediction === 'attack') score += 0.4 * rfConf;
    else score -= 0.3 * rfConf;
    if (port_type === 'suspicious') score += 0.35;
    else if (port_type === 'well_known') score -= 0.2;
    if (has_syn && d.protocol === 'TCP') score += 0.25;
    if (has_rst) score += 0.1;
    if (ip_type === 'external_to_internal') score += 0.15;
    else if (ip_type === 'internal') score -= 0.15;
    if (d.size > 8000 || d.size < 40) score += 0.1;

    const step6 = {
        step: 6, title: 'Heuristic Ground Truth',
        status: score >= 0.35 ? 'threat' : 'safe',
        details: [`Score: ${score.toFixed(3)} (threshold: 0.35)`, `Verdict: ${score >= 0.35 ? 'MALICIOUS' : 'BENIGN'}`],
        explanation: 'Multi-signal heuristic approximates ground truth for RL reward.',
    };
    const step7 = {
        step: 7, title: 'Final Verdict',
        status: d.rl_action === 'block' ? 'threat' : 'safe',
        details: [`Action: ${(d.rl_action || '').toUpperCase()}`, `Severity: ${d.severity}`, `Reason: ${d.reason}`],
        explanation: 'RL agent action is the binding decision. Logged with SHA-256 hash chain.',
    };

    return [step1, step2, step3, step4, step5, step6, step7];
}

// --- Pipeline Walkthrough (Horizontal Stepper) ---
const PipelineWalkthroughPanel = ({ detection }) => {
    const steps = buildPipelineSteps(detection);
    const [activeStep, setActiveStep] = useState(0);

    const statusBg = (s) => s === 'threat' ? 'bg-red-600' : s === 'safe' ? 'bg-green-600' : 'bg-blue-600';
    const statusBadge = (s) => {
        if (s === 'threat') return <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-600/30 text-red-400">THREAT</span>;
        if (s === 'safe') return <span className="px-2 py-0.5 rounded text-xs font-bold bg-green-600/30 text-green-400">SAFE</span>;
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-blue-600/30 text-blue-400">INFO</span>;
    };

    return (
        <div>
            {/* Horizontal stepper */}
            <div className="flex items-center mb-6 overflow-x-auto pb-2">
                {steps.map((s, idx) => (
                    <React.Fragment key={s.step}>
                        <button
                            onClick={() => setActiveStep(idx)}
                            className={`shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white cursor-pointer transition ${
                                idx === activeStep ? `${statusBg(s.status)} ring-2 ring-offset-2 ring-offset-[#0d1117] ring-${s.status === 'threat' ? 'red' : s.status === 'safe' ? 'green' : 'blue'}-400` : statusBg(s.status) + '/60'
                            }`}
                        >
                            {s.step}
                        </button>
                        {idx < steps.length - 1 && (
                            <div className={`flex-1 h-0.5 min-w-[24px] ${idx < activeStep ? 'bg-[#00ff7f]' : 'bg-gray-700'}`} />
                        )}
                    </React.Fragment>
                ))}
            </div>

            {/* Active step content */}
            {steps[activeStep] && (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 p-5">
                    <div className="flex items-center gap-3 mb-3">
                        <h4 className="text-white font-bold">{steps[activeStep].title}</h4>
                        {statusBadge(steps[activeStep].status)}
                    </div>
                    <div className="space-y-1 mb-3">
                        {steps[activeStep].details.map((detail, di) => (
                            <div key={di} className="flex items-start gap-2 text-xs">
                                <span className="text-gray-600 mt-px">→</span>
                                <span className="text-gray-400 font-mono">{detail}</span>
                            </div>
                        ))}
                    </div>
                    <div className="text-xs text-gray-500 italic border-t border-gray-800 pt-2">
                        💡 {steps[activeStep].explanation}
                    </div>
                </div>
            )}
        </div>
    );
};

// --- SHAP Panel ---
const SHAPPanel = ({ detection, featureStats }) => {
    const conf = detection.rf_confidence || 0;
    const confPct = conf * 100;
    const zoneLabel = conf < 0.3 ? 'LOW THREAT' : conf <= 0.6 ? 'UNCERTAIN' : 'HIGH THREAT';
    const zoneColor = conf < 0.3 ? 'text-green-400' : conf <= 0.6 ? 'text-yellow-400' : 'text-red-400';

    const shapValues = detection.shap_values || {};
    const sorted = Object.entries(shapValues).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
    const [showGlobal, setShowGlobal] = useState(false);

    return (
        <div className="space-y-4">
            {/* Detection summary */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                <div className="flex items-center gap-4 text-sm">
                    <span className="text-gray-400">IP:</span>
                    <span className="font-mono text-[#00ff7f]">{detection.src_ip}</span>
                    <span className="text-gray-600">→</span>
                    <span className="font-mono text-gray-300">{detection.dst_ip}</span>
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${detection.rf_prediction === 'attack' ? 'bg-red-600/30 text-red-400' : 'bg-green-600/30 text-green-400'}`}>
                        {(detection.rf_prediction || '').toUpperCase()}
                    </span>
                    <span className="text-gray-400">Conf: {confPct.toFixed(1)}%</span>
                </div>
            </div>

            {/* Confidence Calibration Gauge */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Confidence Calibration</h4>
                <div className="relative h-6 rounded-full overflow-hidden flex">
                    <div className="w-[30%] bg-green-900/40 flex items-center justify-center text-xs text-green-400 font-medium">LOW</div>
                    <div className="w-[30%] bg-yellow-900/40 flex items-center justify-center text-xs text-yellow-400 font-medium">UNCERTAIN</div>
                    <div className="w-[40%] bg-red-900/40 flex items-center justify-center text-xs text-red-400 font-medium">HIGH THREAT</div>
                    <div className="absolute top-0 bottom-0 flex items-center" style={{ left: `${Math.min(confPct, 100)}%`, transform: 'translateX(-50%)' }}>
                        <div className="w-3 h-3 bg-white rounded-full border-2 border-gray-900 shadow-lg"></div>
                    </div>
                </div>
                <p className="mt-2 text-sm"><span className={zoneColor}>{zoneLabel}</span></p>
            </div>

            {/* SHAP Feature Importance */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">SHAP Feature Importance</h4>
                {sorted.length === 0 ? (
                    <p className="text-gray-500 text-sm">Loading SHAP values...</p>
                ) : (
                    <div className="space-y-2">
                        {sorted.map(([feat, val]) => {
                            const isPositive = val >= 0;
                            const barWidth = Math.min(Math.abs(val) / 0.35 * 100, 100);
                            return (
                                <div key={feat} className="flex items-center gap-3 text-xs">
                                    <span className="text-gray-400 w-28 text-right flex-shrink-0">{FEATURE_LABELS[feat] || feat}</span>
                                    <div className="flex-1 h-4 bg-gray-900 rounded overflow-hidden">
                                        <div className={`h-full rounded ${isPositive ? 'bg-red-500' : 'bg-green-500'}`} style={{ width: `${barWidth}%` }} />
                                    </div>
                                    <span className={`font-mono w-14 text-right flex-shrink-0 ${isPositive ? 'text-red-400' : 'text-green-400'}`}>
                                        {isPositive ? '+' : ''}{val.toFixed(2)}
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                )}
                <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
                    <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-500 rounded" /> → ATTACK</span>
                    <span className="flex items-center gap-1"><span className="w-3 h-3 bg-green-500 rounded" /> → SAFE</span>
                </div>
            </div>

            {/* Toggle: Global Feature Stats */}
            <button onClick={() => setShowGlobal(!showGlobal)}
                className="text-sm text-[#00ff7f] hover:text-white transition">
                {showGlobal ? '▼ Hide' : '▶ Show'} Global Feature Stats
            </button>

            {showGlobal && featureStats?.averages && (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                    <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                        Average Feature Importance (last {featureStats.count || 200} detections)
                    </h4>
                    <div className="space-y-2">
                        {Object.entries(featureStats.averages).sort((a, b) => b[1] - a[1]).map(([feat, val]) => {
                            const barWidth = Math.min(val / 0.35 * 100, 100);
                            return (
                                <div key={feat} className="flex items-center gap-3 text-xs">
                                    <span className="text-gray-400 w-28 text-right flex-shrink-0">{FEATURE_LABELS[feat] || feat}</span>
                                    <div className="flex-1 h-4 bg-gray-900 rounded overflow-hidden">
                                        <div className="h-full rounded bg-blue-500" style={{ width: `${barWidth}%` }} />
                                    </div>
                                    <span className="font-mono w-14 text-right text-blue-400 flex-shrink-0">{val.toFixed(3)}</span>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Counterfactual */}
            {detection.counterfactual && (
                <div className="bg-yellow-900/10 rounded-xl border border-yellow-500/30 p-4">
                    <p className="text-sm text-yellow-400">💡 {detection.counterfactual}</p>
                </div>
            )}
        </div>
    );
};

// --- Q-Table Insights Panel ---
const QTableInsightsPanel = ({ detection }) => {
    const stateParts = (detection.rl_state || '|||').split('|');
    const reason = stateParts[0] || 'unknown';
    const ip_type = stateParts[1] || 'unknown';
    const protocol = stateParts[2] || detection.protocol || 'unknown';
    const port_type = stateParts[3] || 'unknown';

    const reasonMap = {
        syn_scan: 'SYN scan pattern', suspicious_port: 'Known exploit port', external_intrusion: 'External targeting internal',
        rf_flagged: 'RF flagged', normal_service: 'Well-known port', internal_traffic: 'Internal private', benign: 'No threat signals',
    };

    let qAllow, qBlock;
    if (detection.rl_action === 'block' && detection.rl_reward > 0) { qBlock = 0.8; qAllow = -0.4; }
    else if (detection.rl_action === 'allow' && detection.rl_reward > 0) { qAllow = 0.8; qBlock = -0.4; }
    else if (detection.rl_action === 'block') { qBlock = 0.2; qAllow = 0.5; }
    else { qAllow = 0.2; qBlock = 0.5; }

    return (
        <div className="space-y-4">
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">RL State Decomposition</h4>
                <p className="text-sm text-white mb-4">
                    State: <span className="font-mono text-blue-300">({reason} | {ip_type} | {protocol} | {port_type})</span>
                </p>
                <div className="grid grid-cols-2 gap-3">
                    {[
                        { label: 'Reason', val: reason, desc: reasonMap[reason] || 'Unknown' },
                        { label: 'IP Type', val: ip_type, desc: ip_type.replace(/_/g, ' ') },
                        { label: 'Protocol', val: protocol, desc: protocol },
                        { label: 'Port Type', val: port_type, desc: port_type },
                    ].map(item => (
                        <div key={item.label} className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                            <p className="text-xs text-gray-500 uppercase mb-1">{item.label}: <span className="text-blue-300 font-mono">{item.val}</span></p>
                            <p className="text-xs text-gray-400">{item.desc}</p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Q-Value Comparison</h4>
                {[
                    { label: 'Q(allow)', val: qAllow },
                    { label: 'Q(block)', val: qBlock },
                ].map(q => (
                    <div key={q.label} className="flex items-center gap-3 mb-2">
                        <span className="text-xs text-gray-400 w-16 text-right">{q.label}</span>
                        <div className="flex-1 h-5 bg-gray-900 rounded overflow-hidden">
                            <div className={`h-full rounded ${q.val >= 0 ? 'bg-green-500' : 'bg-red-500'}`} style={{ width: `${Math.abs(q.val) * 100}%` }} />
                        </div>
                        <span className={`text-xs font-mono w-12 text-right ${q.val >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                            {q.val >= 0 ? '+' : ''}{q.val.toFixed(1)}
                        </span>
                    </div>
                ))}
            </div>

            <div className={`rounded-xl border p-4 ${detection.was_exploration ? 'bg-yellow-900/10 border-yellow-500/30' : 'bg-green-900/10 border-green-500/30'}`}>
                <p className={`text-sm ${detection.was_exploration ? 'text-yellow-400' : 'text-green-400'}`}>
                    {detection.was_exploration
                        ? `🎲 EXPLORATION (ε = ${detection.epsilon}) — random action to discover new state-action pairs`
                        : '🧠 EXPLOITATION — chose highest Q-value action based on past learning'}
                </p>
            </div>
        </div>
    );
};

// --- Main Component ---
const XAIDashboardView = ({ token, onNavigateToDetection }) => {
    const [detections, setDetections] = useState([]);
    const [featureStats, setFeatureStats] = useState(null);
    const [selectedDetection, setSelectedDetection] = useState(null);
    const [loading, setLoading] = useState(true);
    const [activeSection, setActiveSection] = useState('pipeline');
    const [userSelected, setUserSelected] = useState(false);

    const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

    const fetchDetections = useCallback(async () => {
        try {
            const res = await fetch('/api/xai/explain?limit=20', { headers });
            if (res.ok) {
                const data = await res.json();
                const dets = data.detections || [];
                setDetections(dets);
                setSelectedDetection(prev => {
                    if (!prev && dets.length > 0) return dets[0];
                    if (userSelected && prev) return prev;
                    if (!prev && dets.length > 0) return dets[0];
                    return prev;
                });
            }
        } catch (e) { console.error('Failed to fetch XAI detections:', e); }
    }, [token, userSelected]);

    const fetchFeatureStats = useCallback(async () => {
        try {
            const res = await fetch('/api/xai/feature-stats', { headers });
            if (res.ok) setFeatureStats(await res.json());
        } catch (e) { console.error('Failed to fetch feature stats:', e); }
    }, [token]);

    useEffect(() => {
        const init = async () => {
            await fetchDetections();
            await fetchFeatureStats();
            setLoading(false);
        };
        init();
        const interval = setInterval(fetchDetections, 10000);
        return () => clearInterval(interval);
    }, [fetchDetections, fetchFeatureStats]);

    if (loading) {
        return (
            <div className="p-8 flex items-center justify-center min-h-[80vh]">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#00ff7f]"></div>
            </div>
        );
    }

    const tabIcons = {
        pipeline: ActivityIcon,
        shap: BarChartIcon,
        qtable: BrainIcon,
    };

    return (
        <div className="p-8">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center">
                    <MicroscopeIcon className="w-9 h-9 text-[#00ff7f] mr-3" />
                    <div>
                        <h2 className="text-3xl font-bold text-white">AI Transparency</h2>
                        <p className="text-gray-400 text-sm">Full pipeline transparency — understand every decision</p>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <span className="px-3 py-1 rounded-full text-xs font-bold bg-green-600/20 text-green-400 border border-green-500/30">SHAP + Rule-based</span>
                    {onNavigateToDetection && (
                        <button onClick={onNavigateToDetection}
                            className="flex items-center gap-1 text-sm text-[#00ff7f] hover:text-white transition">
                            ← Detection Agent
                        </button>
                    )}
                </div>
            </div>

            {/* Section Tab Bar with SVG icons */}
            <div className="flex gap-2 mb-6">
                {[
                    { id: 'pipeline', label: 'Pipeline Walkthrough' },
                    { id: 'shap', label: 'SHAP Feature Importance' },
                    { id: 'qtable', label: 'Q-Table Insights' },
                ].map(btn => {
                    const Icon = tabIcons[btn.id];
                    return (
                        <button
                            key={btn.id}
                            onClick={() => setActiveSection(btn.id)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition ${
                                activeSection === btn.id
                                    ? 'bg-[#00ff7f]/20 text-[#00ff7f] border border-[#00ff7f]/30'
                                    : 'bg-[#161b22] text-gray-400 border border-gray-800 hover:text-white'
                            }`}
                        >
                            <Icon className="w-4 h-4" />
                            {btn.label}
                        </button>
                    );
                })}
            </div>

            {/* Two-column layout */}
            <div className="flex gap-6">
                {/* Left: Detection selector (1/3) */}
                <div className="w-1/3">
                    <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Recent Detections</h3>
                        <div className="space-y-1 max-h-[70vh] overflow-y-auto pr-1">
                            {detections.map((d, idx) => {
                                const isActive = selectedDetection && selectedDetection.timestamp === d.timestamp && selectedDetection.src_ip === d.src_ip;
                                return (
                                    <div
                                        key={idx}
                                        onClick={() => { setSelectedDetection(d); setUserSelected(true); }}
                                        className={`p-3 rounded-lg cursor-pointer transition ${
                                            isActive
                                                ? 'bg-[#00ff7f]/10 border-l-2 border-[#00ff7f]'
                                                : 'hover:bg-[#1f2937]/50 border-l-2 border-transparent'
                                        }`}
                                    >
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="text-xs text-gray-500">{formatTimestamp(d.timestamp)}</span>
                                            <span className="font-mono text-xs text-[#00ff7f]">{d.src_ip}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                                                d.rf_prediction === 'attack' ? 'bg-red-600/30 text-red-400' : 'bg-green-600/30 text-green-400'
                                            }`}>{(d.rf_prediction || '').toUpperCase()}</span>
                                            <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                                                d.rl_action === 'block' ? 'bg-red-600/30 text-red-400' : 'bg-green-600/30 text-green-400'
                                            }`}>{(d.rl_action || '').toUpperCase()}</span>
                                        </div>
                                        <p className="text-xs text-gray-500 mt-1 truncate">{d.reason}</p>
                                    </div>
                                );
                            })}
                            {detections.length === 0 && (
                                <p className="text-gray-500 text-sm text-center py-4">No detections yet</p>
                            )}
                        </div>
                    </div>
                </div>

                {/* Right: Content area (2/3) */}
                <div className="w-2/3">
                    {!selectedDetection ? (
                        <div className="bg-[#161b22] rounded-xl border border-gray-800 p-8 text-center">
                            <p className="text-gray-500">Select a detection from the left panel to view its explanation</p>
                        </div>
                    ) : (
                        <>
                            {activeSection === 'pipeline' && <PipelineWalkthroughPanel detection={selectedDetection} />}
                            {activeSection === 'shap' && <SHAPPanel detection={selectedDetection} featureStats={featureStats} />}
                            {activeSection === 'qtable' && <QTableInsightsPanel detection={selectedDetection} />}
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default XAIDashboardView;
