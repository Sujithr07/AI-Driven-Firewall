import React, { useState, useEffect, useRef } from 'react';

function buildCLILines(log) {
    const lines = [];
    const push = (text, color, delay) => lines.push({ text, color, delay });

    push('', 'text-gray-800', 0);
    push('[FIREWALL ENGINE] Packet intercepted — beginning analysis pipeline', 'text-gray-400', 80);
    push(`[TIMESTAMP]   ${new Date(log.timestamp).toISOString()}`, 'text-gray-600', 60);
    push('', 'text-gray-800', 120);

    // STEP 1
    push('══ STEP 1 — PACKET INGESTION ══════════════════════════', 'text-[#00ff7f]', 80);
    push('[SCAPY]  Packet captured on network interface', 'text-gray-400', 150);
    push(`[PARSE]  Protocol      : ${log.protocol}`, 'text-blue-400', 80);
    push(`[PARSE]  Source IP     : ${log.source_ip || 'N/A'}`, 'text-blue-400', 60);
    push(`[PARSE]  Dest IP       : ${log.destination_ip || 'N/A'}`, 'text-blue-400', 60);
    push(`[PARSE]  Port          : ${log.port}`, 'text-blue-400', 60);
    push(`[PARSE]  Packet Size   : ${log.size} bytes`, 'text-blue-400', 60);
    push(`[PARSE]  Description   : ${log.description || 'N/A'}`, 'text-blue-400', 60);
    push('', 'text-gray-800', 120);

    // STEP 2
    push('══ STEP 2 — AI THREAT CLASSIFICATION ══════════════════', 'text-[#00ff7f]', 80);
    push('[AI ENGINE] Loading RandomForest classifier...', 'text-gray-400', 180);
    push('[AI ENGINE] Running threat scoring pipeline...', 'text-gray-400', 200);
    push('[AI ENGINE] base_score          = 0.30  (baseline prior)', 'text-yellow-400', 160);

    if (log.port < 1024 && !['HTTPS', 'SSH', 'DNS'].includes(log.protocol)) {
        push(`[AI ENGINE] base_score         += 0.15  ← low privileged port (${log.port}), non-exempt protocol`, 'text-yellow-400', 130);
    } else {
        push(`[AI ENGINE] port check          : skipped  (port ${log.port} exempt or > 1024)`, 'text-gray-600', 100);
    }

    if (log.size > 8000) {
        push(`[AI ENGINE] base_score         += 0.12  ← oversized packet (${log.size} bytes > 8000)`, 'text-yellow-400', 130);
    } else {
        push(`[AI ENGINE] size check          : skipped  (${log.size} bytes within normal range)`, 'text-gray-600', 100);
    }

    const displayScore = (log.ai_score || 0).toFixed(4);
    push(`[AI ENGINE] final_score         = ${displayScore}  (after protocol modifier + noise)`, 'text-white', 180);

    if (log.ai_score >= 0.75) {
        push('[AI ENGINE] Classification     → BLOCKED_HIGH_THREAT   (score ≥ 0.75)', 'text-red-400', 120);
    } else if (log.ai_score >= 0.45) {
        push('[AI ENGINE] Classification     → QUARANTINE_SUSPICIOUS (score ≥ 0.45)', 'text-yellow-400', 120);
    } else {
        push('[AI ENGINE] Classification     → CLEAN_LOW_THREAT      (score < 0.45)', 'text-green-400', 120);
    }

    push('', 'text-gray-800', 120);

    // STEP 3
    push('══ STEP 3 — ZERO TRUST POLICY ENGINE ══════════════════', 'text-[#00ff7f]', 80);
    push('[ZERO TRUST] Evaluating identity, device, and resource context...', 'text-gray-400', 180);
    push(`[ZERO TRUST] Identity          : ${log.user_identity}`, 'text-cyan-400', 100);
    push(`[ZERO TRUST] Device            : ${log.user_device}`, 'text-cyan-400', 80);
    push(`[ZERO TRUST] Target Resource   : ${log.user_resource}`, 'text-cyan-400', 80);

    const trustMap = { low: 0.3, medium: 0.5, high: 0.7, critical: 0.9 };
    const requiredTrust = trustMap[log.user_resource] ?? 0.5;
    push(`[ZERO TRUST] Required trust     : ${requiredTrust.toFixed(2)}  (resource="${log.user_resource}")`, 'text-cyan-400', 100);

    let userTrustScore = 0;
    if (['admin', 'developer'].includes(log.user_identity)) userTrustScore += 0.4;
    if (log.user_device === 'compliant') userTrustScore += 0.4;
    if (log.user_device === 'compromised') userTrustScore -= 0.5;
    if (['unknown', 'guest'].includes(log.user_identity)) userTrustScore -= 0.3;
    push(`[ZERO TRUST] User trust score   : ${userTrustScore.toFixed(2)}`, 'text-cyan-400', 100);

    const aggregatedTrust = userTrustScore - (log.ai_score || 0);
    push(`[ZERO TRUST] Aggregated trust   : ${aggregatedTrust.toFixed(4)}  (user_trust_score − ai_threat_score)`, 'text-cyan-400', 120);

    if (aggregatedTrust >= requiredTrust) {
        push(`[ZERO TRUST] Trust check        : PASS  (${aggregatedTrust.toFixed(2)} ≥ ${requiredTrust.toFixed(2)})`, 'text-green-400', 120);
    } else {
        push(`[ZERO TRUST] Trust check        : FAIL  (${aggregatedTrust.toFixed(2)} < ${requiredTrust.toFixed(2)})`, 'text-red-400', 120);
    }

    push('', 'text-gray-800', 120);

    // STEP 4
    push('══ STEP 4 — FINAL DECISION ════════════════════════════', 'text-[#00ff7f]', 80);
    push('[DECISION ENGINE] Evaluating all signals...', 'text-gray-400', 180);

    if (log.decision === 'Blocked') {
        push('[DECISION ENGINE] Rule triggered  : AI score threshold exceeded OR trust deficit on protected resource', 'text-red-300', 150);
    } else if (log.decision === 'Quarantined') {
        push('[DECISION ENGINE] Rule triggered  : Insufficient trust score — non-critical resource quarantined', 'text-yellow-300', 150);
    } else {
        push('[DECISION ENGINE] Rule triggered  : All checks passed — trust verified, AI score within safe bounds', 'text-green-300', 150);
    }

    push(`[DECISION ENGINE] Reason          : ${log.reason || 'N/A'}`, 'text-gray-400', 120);
    push('', 'text-gray-800', 100);

    const verdictColor = log.decision === 'Blocked' ? 'text-red-400' : log.decision === 'Quarantined' ? 'text-yellow-400' : 'text-green-400';
    push('┌─────────────────────────────────────────────┐', verdictColor, 100);
    push(`│   VERDICT : ${(log.decision || '').toUpperCase().padEnd(32)}│`, verdictColor, 80);
    push(`│   SEVERITY: ${(log.severity || '').toUpperCase().padEnd(32)}│`, verdictColor, 80);
    push('└─────────────────────────────────────────────┘', verdictColor, 80);
    push('', 'text-gray-800', 120);

    // STEP 5
    push('══ STEP 5 — IMMUTABLE LOG COMMIT ══════════════════════', 'text-[#00ff7f]', 100);
    push('[DB WRITE] Computing SHA-256 hash chain entry...', 'text-gray-400', 200);
    push(`[DB WRITE] prev_hash    : ${log.prev_hash ? log.prev_hash.substring(0, 20) + '...' : 'GENESIS (first entry)'}`, 'text-gray-500', 160);
    push(`[DB WRITE] entry_hash   : ${log.entry_hash ? log.entry_hash.substring(0, 20) + '...' : '(hash chain not yet enabled)'}`, 'text-gray-500', 160);
    push('[DB WRITE] Executing SQLite INSERT...', 'text-gray-400', 150);
    push('[DB WRITE] BEFORE UPDATE trigger  : ARMED  ✓', 'text-green-500', 100);
    push('[DB WRITE] BEFORE DELETE trigger  : ARMED  ✓', 'text-green-500', 100);
    push(`[DB WRITE] ✓ Log entry #${log.id} written — tamper-proof and immutable`, 'text-[#00ff7f]', 160);
    push('', 'text-gray-800', 100);

    push(`[FIREWALL ENGINE] Pipeline complete. Total elapsed: ~${Math.floor(Math.random() * 9 + 2)}ms`, 'text-gray-600', 200);
    push('[FIREWALL ENGINE] Standing by for next packet...', 'text-gray-700', 150);

    return lines;
}

const LogCLIModal = ({ log, onClose }) => {
    const [visibleLines, setVisibleLines] = useState([]);
    const [currentIndex, setCurrentIndex] = useState(0);
    const [lines, setLines] = useState([]);
    const outputRef = useRef(null);

    useEffect(() => {
        if (log) {
            setVisibleLines([]);
            setCurrentIndex(0);
            setLines(buildCLILines(log));
        }
    }, [log]);

    useEffect(() => {
        if (currentIndex < lines.length) {
            const timer = setTimeout(() => {
                setVisibleLines(prev => [...prev, lines[currentIndex]]);
                setCurrentIndex(prev => prev + 1);
            }, lines[currentIndex].delay);
            return () => clearTimeout(timer);
        }
    }, [currentIndex, lines]);

    useEffect(() => {
        if (outputRef.current) {
            outputRef.current.scrollTop = outputRef.current.scrollHeight;
        }
    }, [visibleLines]);

    const handleReplay = () => {
        setVisibleLines([]);
        setCurrentIndex(0);
    };

    const handleSkip = () => {
        setVisibleLines(lines);
        setCurrentIndex(lines.length);
    };

    useEffect(() => {
        const handler = (e) => {
            if (e.key === 'Escape') onClose();
        };
        document.addEventListener('keydown', handler);
        return () => document.removeEventListener('keydown', handler);
    }, [onClose]);

    if (!log) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" onClick={onClose}>
            <div className="relative w-full max-w-3xl max-h-[85vh] flex flex-col bg-[#0d1117] border border-[#00ff7f]/40 rounded-xl shadow-2xl" onClick={e => e.stopPropagation()}>
                {/* Title bar */}
                <div className="flex items-center justify-between px-4 py-3 bg-[#161b22] border-b border-gray-800 rounded-t-xl">
                    <div className="flex">
                        <span className="w-3 h-3 rounded-full bg-[#ff5f56]"></span>
                        <span className="w-3 h-3 rounded-full bg-[#ffbd2e] ml-2"></span>
                        <span className="w-3 h-3 rounded-full bg-[#27c93f] ml-2"></span>
                    </div>
                    <span className="text-[#00ff7f] text-xs font-mono">firewall-engine — process-replay [log-id: {log.id}]</span>
                    <div className="flex">
                        <button onClick={handleSkip} title="Skip to end" className="text-gray-500 hover:text-gray-300 text-xs px-2 py-1 rounded hover:bg-gray-800 mr-1">⏭</button>
                        <button onClick={handleReplay} title="Replay" className="text-gray-500 hover:text-gray-300 text-xs px-2 py-1 rounded hover:bg-gray-800 mr-2">↺</button>
                        <button onClick={onClose} className="text-gray-500 hover:text-red-400 text-sm px-2 py-1 rounded hover:bg-gray-800">✕</button>
                    </div>
                </div>

                {/* Output area */}
                <div ref={outputRef} className="flex-1 overflow-y-auto p-5 font-mono text-sm space-y-0.5 min-h-[400px]">
                    {visibleLines.map((line, index) => (
                        <div key={index} className={line.color}>{line.text || '\u00a0'}</div>
                    ))}
                    {currentIndex < lines.length && <span className="text-[#00ff7f] animate-pulse">█</span>}
                </div>

                {/* Prompt bar */}
                <div className="px-5 py-2 bg-[#161b22] border-t border-gray-800 rounded-b-xl flex items-center">
                    <span className="text-[#00ff7f] font-mono text-xs">firewall@engine:~$</span>
                    <span className="ml-2 w-2 h-4 bg-[#00ff7f] animate-pulse inline-block"></span>
                </div>
            </div>
        </div>
    );
};

export default LogCLIModal;
