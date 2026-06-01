"""
Response Agent Module
=====================
Takes Detection Agent output and executes enforcement actions (iptables rules).
Supports hard blocks, rate limiting, quarantine, temp blocks, self-healing,
false-positive detection, and manual rollback.

When dry_run=True (default), all iptables commands are logged but not executed,
making it safe to run on Windows and in development.
"""

import subprocess
import threading
import time
import collections
import os
import logging

logger = logging.getLogger(__name__)


class ResponseAgent:

    def __init__(self, dry_run=True, db_callback=None):
        self.dry_run = dry_run
        self.db_callback = db_callback

        self.blocked_ips = {}

        self.action_history = collections.deque(maxlen=500)

        self.fp_tracker = {}

        self.stats = {
            "hard_blocks": 0,
            "rate_limits": 0,
            "quarantines": 0,
            "temp_blocks": 0,
            "self_healed": 0,
            "rollbacks": 0,
        }

        self._lock = threading.Lock()
        self._running = False
        self._heal_thread = None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(self, detection):
        src_ip = detection["src_ip"]
        rf_confidence = detection["rf_confidence"]
        reason = detection["reason"]
        is_malicious = detection["is_malicious"]
        rl_action = detection["rl_action"]

        if rl_action != "block" or not is_malicious:
            return {"response_action": "allowed", "rule_type": "none"}

        with self._lock:
            if src_ip in self.blocked_ips:
                self._update_fp_tracker(src_ip, rf_confidence)
                return {
                    "response_action": "already_blocked",
                    "rule_type": self.blocked_ips[src_ip]["rule_type"],
                }

            if reason == "syn_scan":
                self._temp_block(src_ip, 300, reason, rf_confidence)
                rule_type = "temp_block"
            elif rf_confidence > 0.8:
                self._hard_block(src_ip, reason, rf_confidence)
                rule_type = "hard_block"
            elif 0.5 <= rf_confidence <= 0.8:
                self._rate_limit(src_ip, reason, rf_confidence)
                rule_type = "rate_limit"
            elif 0.3 <= rf_confidence <= 0.5:
                self._quarantine(src_ip, reason, rf_confidence)
                rule_type = "quarantine"
            else:
                return {"response_action": "below_threshold", "rule_type": "none"}

        return {
            "response_action": rule_type,
            "rule_type": rule_type,
            "src_ip": src_ip,
            "confidence": rf_confidence,
        }

    # ------------------------------------------------------------------
    # Enforcement methods
    # ------------------------------------------------------------------

    def _hard_block(self, ip, reason, confidence):
        command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        undo_command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        self._run_iptables(command)

        action_id = str(time.time()) + ip
        now = time.time()

        self.blocked_ips[ip] = {
            "reason": reason,
            "timestamp": now,
            "rule_type": "hard_block",
            "confidence": confidence,
            "action_id": action_id,
            "expires_at": None,
        }

        record = {
            "action_id": action_id,
            "timestamp": now,
            "ip": ip,
            "rule_type": "hard_block",
            "confidence": confidence,
            "reason": reason,
            "command": command,
            "undo_command": undo_command,
            "reversed": False,
        }
        self.action_history.append(record)
        self.stats["hard_blocks"] += 1
        print(f"[ResponseAgent] HARD BLOCK: {ip} (confidence: {confidence:.2f}, reason: {reason})")

        if self.db_callback:
            try:
                self.db_callback(record)
            except Exception:
                pass

    def _rate_limit(self, ip, reason, confidence):
        cmd1 = ["iptables", "-A", "INPUT", "-s", ip, "-m", "limit", "--limit", "10/min", "--limit-burst", "5", "-j", "ACCEPT"]
        cmd2 = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        undo1 = ["iptables", "-D", "INPUT", "-s", ip, "-m", "limit", "--limit", "10/min", "--limit-burst", "5", "-j", "ACCEPT"]
        undo2 = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

        self._run_iptables(cmd1)
        self._run_iptables(cmd2)

        action_id = str(time.time()) + ip
        now = time.time()

        self.blocked_ips[ip] = {
            "reason": reason,
            "timestamp": now,
            "rule_type": "rate_limit",
            "confidence": confidence,
            "action_id": action_id,
            "expires_at": None,
        }

        record = {
            "action_id": action_id,
            "timestamp": now,
            "ip": ip,
            "rule_type": "rate_limit",
            "confidence": confidence,
            "reason": reason,
            "command": [cmd1, cmd2],
            "undo_command": [undo1, undo2],
            "reversed": False,
        }
        self.action_history.append(record)
        self.stats["rate_limits"] += 1
        print(f"[ResponseAgent] RATE LIMIT: {ip} — 10 packets/minute allowed")

        if self.db_callback:
            try:
                self.db_callback(record)
            except Exception:
                pass

    def _quarantine(self, ip, reason, confidence):
        command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "MARK", "--set-mark", "99"]
        undo_command = ["iptables", "-D", "INPUT", "-s", ip, "-j", "MARK", "--set-mark", "99"]
        self._run_iptables(command)

        action_id = str(time.time()) + ip
        now = time.time()

        self.blocked_ips[ip] = {
            "reason": reason,
            "timestamp": now,
            "rule_type": "quarantine",
            "confidence": confidence,
            "action_id": action_id,
            "expires_at": None,
        }

        record = {
            "action_id": action_id,
            "timestamp": now,
            "ip": ip,
            "rule_type": "quarantine",
            "confidence": confidence,
            "reason": reason,
            "command": command,
            "undo_command": undo_command,
            "reversed": False,
        }
        self.action_history.append(record)
        self.stats["quarantines"] += 1
        print(f"[ResponseAgent] QUARANTINE: {ip} — redirecting to isolated segment")

        if self.db_callback:
            try:
                self.db_callback(record)
            except Exception:
                pass

    def _temp_block(self, ip, duration, reason, confidence):
        self._hard_block(ip, reason, confidence)
        self.blocked_ips[ip]["expires_at"] = time.time() + duration
        self.blocked_ips[ip]["rule_type"] = "temp_block"
        self.stats["temp_blocks"] += 1

        timer = threading.Timer(duration, self._auto_unblock, args=(ip, "temp_block_expired"))
        timer.daemon = True
        timer.start()

        print(f"[ResponseAgent] TEMP BLOCK: {ip} — expires in {duration} seconds")

    # ------------------------------------------------------------------
    # Unblock / undo
    # ------------------------------------------------------------------

    def _auto_unblock(self, ip, reason_for_unblock):
        with self._lock:
            if ip not in self.blocked_ips:
                return

            # Find the most recent action record for this IP
            undo_command = None
            for entry in reversed(self.action_history):
                if entry["ip"] == ip and not entry["reversed"]:
                    undo_command = entry["undo_command"]
                    entry["reversed"] = True
                    entry["reversed_at"] = time.time()
                    break

            if undo_command is not None:
                if isinstance(undo_command[0], list):
                    for cmd in undo_command:
                        self._run_iptables(cmd)
                else:
                    self._run_iptables(undo_command)

            del self.blocked_ips[ip]
            self.fp_tracker.pop(ip, None)
            self.stats["self_healed"] += 1
            print(f"[ResponseAgent] AUTO-UNBLOCK: {ip} — reason: {reason_for_unblock}")

            if self.db_callback:
                try:
                    self.db_callback({
                        "action_id": f"unblock_{time.time()}_{ip}",
                        "timestamp": time.time(),
                        "ip": ip,
                        "rule_type": "unblock",
                        "confidence": 0,
                        "reason": reason_for_unblock,
                        "command": [],
                        "undo_command": [],
                        "reversed": True,
                    })
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # iptables execution
    # ------------------------------------------------------------------

    def _run_iptables(self, command):
        if self.dry_run:
            print(f"[DRY RUN] Would execute: {' '.join(command)}")
            return True
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True
            else:
                print(f"[ResponseAgent] iptables error: {result.stderr}")
                return False
        except Exception as e:
            print(f"[ResponseAgent] iptables exception: {e}")
            return False

    # ------------------------------------------------------------------
    # False-positive tracker
    # ------------------------------------------------------------------

    def _update_fp_tracker(self, ip, confidence):
        if ip not in self.fp_tracker:
            self.fp_tracker[ip] = []
        self.fp_tracker[ip].append(confidence)
        self.fp_tracker[ip] = self.fp_tracker[ip][-20:]

    # ------------------------------------------------------------------
    # Self-healing loop
    # ------------------------------------------------------------------

    def start_self_healing(self):
        self._running = True
        self._heal_thread = threading.Thread(target=self._self_healing_loop, daemon=True)
        self._heal_thread.start()

    def stop_self_healing(self):
        self._running = False

    def _self_healing_loop(self):
        while self._running:
            time.sleep(60)
            with self._lock:
                for ip in list(self.blocked_ips.keys()):
                    entry = self.blocked_ips.get(ip)
                    if entry is None:
                        continue

                    # Expired temp blocks
                    if entry["expires_at"] is not None and time.time() > entry["expires_at"]:
                        self._auto_unblock_unlocked(ip, "temp_block_expired")
                        continue

                    # False positive detection
                    readings = self.fp_tracker.get(ip, [])
                    if len(readings) > 10:
                        avg = sum(readings) / len(readings)
                        if avg < 0.4 and entry["confidence"] < 0.85:
                            self._auto_unblock_unlocked(ip, "false_positive_detected")

    def _auto_unblock_unlocked(self, ip, reason_for_unblock):
        """Same as _auto_unblock but expects lock to already be held."""
        if ip not in self.blocked_ips:
            return

        undo_command = None
        for entry in reversed(self.action_history):
            if entry["ip"] == ip and not entry["reversed"]:
                undo_command = entry["undo_command"]
                entry["reversed"] = True
                entry["reversed_at"] = time.time()
                break

        if undo_command is not None:
            if isinstance(undo_command[0], list):
                for cmd in undo_command:
                    self._run_iptables(cmd)
            else:
                self._run_iptables(undo_command)

        del self.blocked_ips[ip]
        self.fp_tracker.pop(ip, None)
        self.stats["self_healed"] += 1
        print(f"[ResponseAgent] AUTO-UNBLOCK: {ip} — reason: {reason_for_unblock}")

        if self.db_callback:
            try:
                self.db_callback({
                    "action_id": f"unblock_{time.time()}_{ip}",
                    "timestamp": time.time(),
                    "ip": ip,
                    "rule_type": "unblock",
                    "confidence": 0,
                    "reason": reason_for_unblock,
                    "command": [],
                    "undo_command": [],
                    "reversed": True,
                })
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self, action_id):
        with self._lock:
            for entry in self.action_history:
                if entry["action_id"] == action_id:
                    if entry["reversed"]:
                        return False
                    undo = entry["undo_command"]
                    if isinstance(undo, list) and len(undo) > 0 and isinstance(undo[0], list):
                        for cmd in undo:
                            self._run_iptables(cmd)
                    elif isinstance(undo, list) and len(undo) > 0:
                        self._run_iptables(undo)
                    entry["reversed"] = True
                    entry["reversed_at"] = time.time()
                    ip = entry["ip"]
                    if ip in self.blocked_ips:
                        del self.blocked_ips[ip]
                    self.stats["rollbacks"] += 1
                    return True
            return False

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self):
        with self._lock:
            now = time.time()
            blocked_list = []
            for ip, info in self.blocked_ips.items():
                blocked_list.append({
                    "ip": ip,
                    "rule_type": info["rule_type"],
                    "confidence": info["confidence"],
                    "reason": info["reason"],
                    "timestamp": info["timestamp"],
                    "expires_at": info["expires_at"],
                    "action_id": info["action_id"],
                    "age_seconds": round(now - info["timestamp"], 1),
                })

            history = list(self.action_history)
            recent_history = list(reversed(history))[:20]

            healing_log = [e for e in reversed(history) if e.get("reversed")][:10]

            return {
                "blocked_ips": blocked_list,
                "action_history": recent_history,
                "self_healing_log": healing_log,
                "stats": dict(self.stats),
                "dry_run": self.dry_run,
                "total_blocked": len(self.blocked_ips),
            }
