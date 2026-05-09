import React, { useState, useEffect, useCallback } from 'react';

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

    // Step 1
    const step1 = {
        step: 1,
        title: 'Packet Capture',
        status: 'info',
        details: [
            'Interface: eth0 (Scapy live capture / simulation mode)',
            'Packet type: IP layer detected',
            `Timestamp: ${new Date(d.timestamp).toLocaleString()}`,
        ],
        explanation: 'Scapy intercepted this packet on the network interface. The IP layer was detected, making it eligible for analysis. Non-IP packets are silently dropped at this stage.',
    };

    // Step 2
    const step2Details = [
        `Protocol: ${d.protocol}`,
        `Source port: ${d.sport}`,
        `Destination port: ${d.dport}`,
        `Packet size: ${d.size} bytes`,
    ];
    if (flags) step2Details.push(`TCP Flags: ${flags}`);
    if (d.protocol === 'TCP') step2Details.push('TCP detected via ip_layer.proto = 6 — source/dest ports and flags read from TCP header');
    else if (d.protocol === 'UDP') step2Details.push('UDP detected via ip_layer.proto = 17 — source/dest ports read, no flags');
    else if (d.protocol === 'ICMP') step2Details.push('ICMP detected via ip_layer.proto = 1 — type/code fields used, ports set to 0');

    const step2 = {
        step: 2,
        title: 'Protocol & Header Parsing',
        status: 'info',
        details: step2Details,
        explanation: 'The IP header was parsed to extract the protocol number (proto field). Based on proto=6/17/1, the appropriate layer was accessed to read source port, destination port, packet size, and TCP flags. These raw values feed directly into the feature vector.',
    };

    // Step 3
    let ipTypeExpl = '';
    if (ip_type === 'external_to_internal') ipTypeExpl = `(src IP ${d.src_ip} is public, dst IP ${d.dst_ip} is private — highest risk category)`;
    else if (ip_type === 'internal_to_external') ipTypeExpl = '(src is private, dst is public — outbound traffic)';
    else if (ip_type === 'internal') ipTypeExpl = '(both IPs are private RFC1918 ranges — low risk)';
    else ipTypeExpl = '(both IPs are public)';

    let portTypeExpl = '';
    if (port_type === 'suspicious') portTypeExpl = `(port ${d.dport} is in known malware/exploit port list)`;
    else if (port_type === 'well_known') portTypeExpl = `(port ${d.dport} is a standard service port)`;
    else if (port_type === 'high') portTypeExpl = `(port ${d.dport} is above 1024 — ephemeral range)`;
    else portTypeExpl = `(port ${d.dport} is low and unclassified)`;

    const step3 = {
        step: 3,
        title: 'Feature Engineering',
        status: 'info',
        details: [
            `IP type classification: ${ip_type} ${ipTypeExpl}`,
            `Port type classification: ${port_type} ${portTypeExpl}`,
            `SYN flag (no ACK): ${has_syn ? 'YES — classic port scan pattern' : 'NO — normal or no TCP flags'}`,
        ],
        explanation: 'Raw packet values were mapped to categorical and binary features. IP classification determines directionality risk. Port classification uses two lookup sets: SUSPICIOUS_PORTS (known exploit ports like 4444, 1337, 31337) and WELL_KNOWN_PORTS (80, 443, 22, etc). The SYN-without-ACK pattern detects port scans.',
    };

    // Step 4
    const step4 = {
        step: 4,
        title: 'RandomForest Classification',
        status: d.rf_prediction === 'attack' ? 'threat' : 'safe',
        details: [
            'Model: RandomForestClassifier (50 trees, max_depth=10)',
            'Input: 11-feature numeric vector',
            `Prediction: ${(d.rf_prediction || '').toUpperCase()}`,
            `Confidence: ${(d.rf_confidence * 100).toFixed(1)}%`,
            'Training: Self-trains on live traffic — retrained every 50 new labeled samples',
        ],
        explanation: 'The 11-feature vector was passed to the RandomForest model which voted across 50 decision trees. Each tree independently classifies the packet. The majority vote gives the prediction (0=normal, 1=attack) and the proportion of trees voting for the majority class gives the confidence score. The model bootstrapped from synthetic training data and continuously retrains on feedback from the RL agent\'s reward signals.',
    };

    // Step 5
    const step5 = {
        step: 5,
        title: 'RL Agent Decision',
        status: d.rl_action === 'block' ? 'threat' : 'safe',
        details: [
            `State tuple: (${reason} | ${ip_type} | ${d.protocol} | ${port_type})`,
            `Action chosen: ${(d.rl_action || '').toUpperCase()}`,
            `Was exploration (random): ${d.was_exploration ? 'YES (ε-greedy random action)' : 'NO (exploiting learned Q-values)'}`,
            `Epsilon (exploration rate): ${d.epsilon}`,
            `Reward received: ${d.rl_reward > 0 ? '+1.0 (correct decision)' : '-1.0 (incorrect decision)'}`,
        ],
        explanation: 'The RL agent (Q-Learning with epsilon-greedy) built a 4-part state tuple from the reason label, IP type, protocol, and port type. It looked up Q-values for both \'allow\' and \'block\' actions for this state. If Q(block) > Q(allow) and random() > epsilon, it chose block (exploitation). Otherwise it explored randomly. The Q-table is updated after every decision: Q[s][a] = Q[s][a] + 0.1 * (reward - Q[s][a]).',
    };

    // Step 6 — Heuristic Ground Truth
    let score = 0.0;
    const scoreSteps = [];

    const rfConf = d.rf_confidence || 0;
    if (d.rf_prediction === 'attack') {
        const v = 0.4 * rfConf;
        score += v;
        scoreSteps.push(`RF contribution: +${v.toFixed(3)}`);
    } else {
        const v = 0.3 * rfConf;
        score -= v;
        scoreSteps.push(`RF contribution: -${v.toFixed(3)}`);
    }

    if (port_type === 'suspicious') { score += 0.35; scoreSteps.push('Port type signal: +0.350'); }
    else if (port_type === 'well_known') { score -= 0.2; scoreSteps.push('Port type signal: -0.200'); }
    else { scoreSteps.push('Port type signal: +0.000'); }

    if (has_syn && d.protocol === 'TCP') { score += 0.25; scoreSteps.push('SYN scan signal: +0.250'); }
    else { scoreSteps.push('SYN scan signal: +0.000'); }

    if (has_rst) { score += 0.1; scoreSteps.push('RST signal: +0.100'); }
    else { scoreSteps.push('RST signal: +0.000'); }

    if (ip_type === 'external_to_internal') { score += 0.15; scoreSteps.push('IP direction signal: +0.150'); }
    else if (ip_type === 'internal') { score -= 0.15; scoreSteps.push('IP direction signal: -0.150'); }
    else { scoreSteps.push('IP direction signal: +0.000'); }

    if (d.size > 8000 || d.size < 40) { score += 0.1; scoreSteps.push('Size anomaly: +0.100'); }
    else { scoreSteps.push('Size anomaly: +0.000'); }

    scoreSteps.push(`Final heuristic score: ${score.toFixed(3)} (threshold: 0.35)`);
    scoreSteps.push(`Ground truth verdict: ${score >= 0.35 ? 'MALICIOUS' : 'BENIGN'}`);

    const step6 = {
        step: 6,
        title: 'Heuristic Ground Truth Scoring',
        status: d.is_malicious ? 'threat' : 'safe',
        details: scoreSteps,
        explanation: 'The heuristic ground truth function combines multiple independent signals to approximate the true label. This is used to compute the RL reward. Each signal is weighted by importance: RF confidence carries the most weight (0.4x), followed by port suspiciousness (0.35). The final score above 0.35 means the system treats it as malicious for reward computation.',
    };

    // Step 7
    const step7 = {
        step: 7,
        title: 'Final Verdict',
        status: d.rl_action === 'block' ? 'threat' : 'safe',
        details: [
            `RL action: ${(d.rl_action || '').toUpperCase()}`,
            `Severity: ${d.severity}`,
            `Reason label: ${d.reason}`,
            'Packet logged to detection_logs table with SHA-256 hash chain entry',
        ],
        explanation: 'The RL agent\'s action is the binding decision. If \'block\', the Response Agent (if active) executes the appropriate iptables rule based on confidence tier. The detection is appended to the immutable log with a hash linking it to the previous entry. The Q-table and RandomForest model are both updated to improve future accuracy.',
    };

    return [step1, step2, step3, step4, step5, step6, step7];
}

// --- Sub-Components ---

const PipelineWalkthroughPanel = ({ detection }) => {
    const steps = buildPipelineSteps(detection);
    const statusColor = (s) => s === 'threat' ? 'border-red-500 bg-red-500' : s === 'safe' ? 'border-green-500 bg-green-500' : 'border-blue-500 bg-blue-500';
    const statusBadge = (s) => {
        if (s === 'threat') return <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-600/30 text-red-400">THREAT</span>;
        if (s === 'safe') return <span className="px-2 py-0.5 rounded text-xs font-bold bg-green-600/30 text-green-400">SAFE</span>;
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-blue-600/30 text-blue-400">INFO</span>;
    };

    return (
        <div className="space-y-0">
            {steps.map((s, idx) => (
                <div key={s.step}>
                    <div className="flex gap-4">
                        {/* Timeline column */}
                        <div className="flex flex-col items-center">
                            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white ${s.status === 'threat' ? 'bg-red-600' : s.status === 'safe' ? 'bg-green-600' : 'bg-blue-600'}`}>
                                {s.step}
                            </div>
                            {idx < steps.length - 1 && <div className="w-0.5 flex-1 bg-gray-800 min-h-[16px]"></div>}
                        </div>
                        {/* Card */}
                        <div className="flex-1 bg-[#161b22] rounded-xl border border-gray-800 p-4 mb-3">
                            <div className="flex items-center gap-3 mb-3">
                                <h4 className="text-white font-bold text-sm">{s.title}</h4>
                                {statusBadge(s.status)}
                            </div>
                            <div className="space-y-1 mb-3">
                                {s.details.map((detail, di) => (
                                    <div key={di} className="flex items-start gap-2 text-xs">
                                        <span className="text-gray-600 mt-px">→</span>
                                        <span className="text-gray-400 font-mono">{detail}</span>
                                    </div>
                                ))}
                            </div>
                            <div className="text-xs text-gray-500 italic border-t border-gray-800 pt-2">
                                <span className="mr-1">💡</span>{s.explanation}
                            </div>
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
};

const SHAPPanel = ({ detection, featureStats }) => {
    const conf = detection.rf_confidence || 0;
    const confPct = conf * 100;
    const zoneLabel = conf < 0.3 ? 'LOW THREAT' : conf <= 0.6 ? 'UNCERTAIN' : 'HIGH THREAT';
    const zoneColor = conf < 0.3 ? 'text-green-400' : conf <= 0.6 ? 'text-yellow-400' : 'text-red-400';
    const zoneSentence = conf < 0.3
        ? 'Low threat confidence — packet is likely safe'
        : conf <= 0.6
            ? 'Uncertain — manual review recommended'
            : 'High threat confidence — automated response triggered';

    const shapValues = detection.shap_values || {};
    const sorted = Object.entries(shapValues).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));

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
                    {/* Marker */}
                    <div className="absolute top-0 bottom-0 flex items-center" style={{ left: `${Math.min(confPct, 100)}%`, transform: 'translateX(-50%)' }}>
                        <div className="w-3 h-3 bg-white rounded-full border-2 border-gray-900 shadow-lg"></div>
                    </div>
                </div>
                <div className="mt-2 text-sm">
                    <span className={zoneColor}>{zoneLabel}</span>
                    <span className="text-gray-500 ml-2">— {zoneSentence}</span>
                </div>
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
                                    <div className="flex-1 h-4 bg-gray-900 rounded overflow-hidden relative">
                                        <div
                                            className={`h-full rounded ${isPositive ? 'bg-red-500' : 'bg-green-500'}`}
                                            style={{ width: `${barWidth}%` }}
                                        />
                                    </div>
                                    <span className={`font-mono w-14 text-right flex-shrink-0 ${isPositive ? 'text-red-400' : 'text-green-400'}`}>
                                        {isPositive ? '+' : ''}{val.toFixed(2)}
                                    </span>
                                </div>
                            );
                        })}
                    </div>
                )}
                <div className="text-xs text-gray-500 mt-3">
                    <span className="inline-block w-3 h-3 bg-red-500 rounded mr-1 align-middle"></span> → ATTACK
                    <span className="inline-block w-3 h-3 bg-green-500 rounded ml-3 mr-1 align-middle"></span> → SAFE
                </div>
            </div>

            {/* Counterfactual */}
            {detection.counterfactual && (
                <div className="bg-yellow-900/10 rounded-xl border border-yellow-500/30 p-4">
                    <p className="text-sm text-yellow-400">
                        <span className="mr-1">💡</span>{detection.counterfactual}
                    </p>
                </div>
            )}

            {/* Average Feature Importance */}
            {featureStats && featureStats.averages && (
                <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                    <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Average Feature Importance (last {featureStats.count || 200} detections)</h4>
                    <div className="space-y-2">
                        {Object.entries(featureStats.averages)
                            .sort((a, b) => b[1] - a[1])
                            .map(([feat, val]) => {
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
        </div>
    );
};

const QTableInsightsPanel = ({ detection }) => {
    const stateParts = (detection.rl_state || '|||').split('|');
    const reason = stateParts[0] || 'unknown';
    const ip_type = stateParts[1] || 'unknown';
    const protocol = stateParts[2] || detection.protocol || 'unknown';
    const port_type = stateParts[3] || 'unknown';

    const reasonMap = {
        syn_scan: 'SYN without ACK = port scan pattern',
        suspicious_port: 'Port in known exploit list',
        external_intrusion: 'External IP targeting internal network',
        rf_flagged: 'RandomForest flagged as attack but no specific pattern',
        normal_service: 'Well-known port with no threat signals',
        internal_traffic: 'Both IPs are internal private',
        benign: 'No threat signals detected',
    };

    const ipTypeMap = {
        external_to_internal: 'External → Internal (highest risk: inbound from public IP)',
        internal_to_external: 'Internal → External (outbound from private IP)',
        internal: 'Internal → Internal (both RFC1918 private, low risk)',
        external: 'External → External (both public IPs)',
    };

    const portTypeMap = {
        suspicious: 'Port in SUSPICIOUS_PORTS set (4444, 1337, 31337, etc.)',
        well_known: 'Port in WELL_KNOWN_PORTS set (80, 443, 22, etc.)',
        high: 'Ephemeral port above 1024',
        low: 'Low port not in either set',
    };

    // Approximate Q-values from reward
    let qAllow, qBlock;
    if (detection.rl_action === 'block' && detection.rl_reward > 0) {
        qBlock = 0.8; qAllow = -0.4;
    } else if (detection.rl_action === 'allow' && detection.rl_reward > 0) {
        qAllow = 0.8; qBlock = -0.4;
    } else if (detection.rl_action === 'block' && detection.rl_reward < 0) {
        qBlock = 0.2; qAllow = 0.5;
    } else {
        qAllow = 0.2; qBlock = 0.5;
    }

    return (
        <div className="space-y-4">
            {/* State explanation */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">RL State Decomposition</h4>
                <p className="text-sm text-white mb-4">
                    The RL agent saw state: <span className="font-mono text-blue-300">({reason} | {ip_type} | {protocol} | {port_type})</span>
                </p>
                <div className="space-y-3">
                    <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                        <p className="text-xs text-gray-500 uppercase mb-1">Reason: <span className="text-blue-300 font-mono">{reason}</span></p>
                        <p className="text-xs text-gray-400">{reasonMap[reason] || 'Unknown reason label'}</p>
                    </div>
                    <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                        <p className="text-xs text-gray-500 uppercase mb-1">IP Type: <span className="text-blue-300 font-mono">{ip_type}</span></p>
                        <p className="text-xs text-gray-400">{ipTypeMap[ip_type] || 'Unknown IP type'}</p>
                    </div>
                    <div className="bg-[#0d1117] p-3 rounded-lg border border-gray-800">
                        <p className="text-xs text-gray-500 uppercase mb-1">Port Type: <span className="text-blue-300 font-mono">{port_type}</span></p>
                        <p className="text-xs text-gray-400">{portTypeMap[port_type] || 'Unknown port type'}</p>
                    </div>
                </div>
            </div>

            {/* Q-value visualization */}
            <div className="bg-[#161b22] rounded-xl border border-gray-800 p-4">
                <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Q-Value Visualization</h4>
                <div className="space-y-3">
                    <div className="flex items-center gap-3">
                        <span className="text-xs text-gray-400 w-20 text-right">Q(allow)</span>
                        <div className="flex-1 h-5 bg-gray-900 rounded overflow-hidden relative">
                            <div
                                className={`h-full rounded ${qAllow >= 0 ? 'bg-green-500' : 'bg-red-500'}`}
                                style={{ width: `${Math.abs(qAllow) / 1.0 * 100}%` }}
                            />
                        </div>
                        <span className={`text-xs font-mono w-12 text-right ${qAllow >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                            {qAllow >= 0 ? '+' : ''}{qAllow.toFixed(1)}
                        </span>
                    </div>
                    <div className="flex items-center gap-3">
                        <span className="text-xs text-gray-400 w-20 text-right">Q(block)</span>
                        <div className="flex-1 h-5 bg-gray-900 rounded overflow-hidden relative">
                            <div
                                className={`h-full rounded ${qBlock >= 0 ? 'bg-green-500' : 'bg-red-500'}`}
                                style={{ width: `${Math.abs(qBlock) / 1.0 * 100}%` }}
                            />
                        </div>
                        <span className={`text-xs font-mono w-12 text-right ${qBlock >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                            {qBlock >= 0 ? '+' : ''}{qBlock.toFixed(1)}
                        </span>
                    </div>
                </div>
                <p className="text-xs text-gray-500 italic mt-3">
                    Note: Q-values shown are approximated from reward signal. View Detection Agent → Q-Table tab for exact learned values.
                </p>
            </div>

            {/* Exploration vs Exploitation */}
            <div className={`rounded-xl border p-4 ${detection.was_exploration ? 'bg-yellow-900/10 border-yellow-500/30' : 'bg-green-900/10 border-green-500/30'}`}>
                {detection.was_exploration ? (
                    <p className="text-sm text-yellow-400">
                        🎲 This was a random EXPLORATION move (ε = {detection.epsilon}). The agent chose randomly to discover new state-action pairs. This decision did NOT rely on learned Q-values.
                    </p>
                ) : (
                    <p className="text-sm text-green-400">
                        🧠 This was an EXPLOITATION move. The agent chose the action with the highest Q-value for this state, based on past learning.
                    </p>
                )}
            </div>
        </div>
    );
};

// --- Main Component ---

const XAIDashboardView = ({ token }) => {
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
        } catch (e) {
            console.error('Failed to fetch XAI detections:', e);
        }
    }, [token, userSelected]);

    const fetchFeatureStats = useCallback(async () => {
        try {
            const res = await fetch('/api/xai/feature-stats', { headers });
            if (res.ok) {
                const data = await res.json();
                setFeatureStats(data);
            }
        } catch (e) {
            console.error('Failed to fetch feature stats:', e);
        }
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

    return (
        <div className="p-8">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center">
                    <span className="text-3xl mr-3">🔍</span>
                    <div>
                        <h2 className="text-3xl font-bold text-white">XAI Explainable AI Dashboard</h2>
                        <p className="text-gray-400 text-sm">Full pipeline transparency — understand every decision</p>
                    </div>
                </div>
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-green-600/20 text-green-400 border border-green-500/30">SHAP + Rule-based</span>
            </div>

            {/* Section Switcher */}
            <div className="flex gap-2 mb-6">
                {[
                    { id: 'pipeline', label: '🔬 Pipeline Walkthrough' },
                    { id: 'shap', label: '📊 SHAP Feature Importance' },
                    { id: 'qtable', label: '🧠 Q-Table Insights' },
                ].map(btn => (
                    <button
                        key={btn.id}
                        onClick={() => setActiveSection(btn.id)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
                            activeSection === btn.id
                                ? 'bg-[#00ff7f]/20 text-[#00ff7f] border border-[#00ff7f]/30'
                                : 'bg-[#161b22] text-gray-400 border border-gray-800 hover:text-white'
                        }`}
                    >
                        {btn.label}
                    </button>
                ))}
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
                                            <span className="text-xs text-gray-500">{new Date(d.timestamp).toLocaleTimeString()}</span>
                                            <span className="font-mono text-xs text-[#00ff7f]">{d.src_ip}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                                                d.rf_prediction === 'attack' ? 'bg-red-600/30 text-red-400' : 'bg-green-600/30 text-green-400'
                                            }`}>
                                                {(d.rf_prediction || '').toUpperCase()}
                                            </span>
                                            <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                                                d.rl_action === 'block' ? 'bg-red-600/30 text-red-400' : 'bg-green-600/30 text-green-400'
                                            }`}>
                                                {(d.rl_action || '').toUpperCase()}
                                            </span>
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
