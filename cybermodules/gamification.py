# --- 8. GAMIFICATION ENGINE ---
import os
import json
import secrets
import datetime

from cyberapp.models.db import db_conn

class GamificationEngine:
	def __init__(self, scan_id, user_id):
		self.scan_id = scan_id
		self.user_id = user_id

	def calculate_score(self):
		score = 0
		achievements = []
		try:
			with db_conn() as conn:
				vulns = conn.execute("SELECT * FROM vulns WHERE scan_id=?", (self.scan_id,)).fetchall()
				techs = conn.execute("SELECT * FROM techno WHERE scan_id=?", (self.scan_id,)).fetchall()
				score += len(vulns) * 50
				score += len(techs) * 10
				if len(vulns) >= 5:
					achievements.append("Bug Collector")
				level = 1 + (score // 200)
				badges = [f"Hacker Level {level}"]
				conn.execute("""
					INSERT INTO gamification (scan_id, user_id, score, xp, level, achievements, badges)
					VALUES (?, ?, ?, ?, ?, ?, ?)
				""", (self.scan_id, self.user_id, score, score, level, json.dumps(achievements), json.dumps(badges)))
			self.update_leaderboard()
			with db_conn() as conn:
				conn.execute("INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
						   (self.scan_id, "ACHIEVEMENT", json.dumps(achievements)))
			return score, level, achievements, badges
		except Exception as e:
			return 0, 1, [], []

	def update_leaderboard(self):
		try:
			leaderboard_file = "/tmp/monolith_leaderboard.json"
			leaderboard = []
			if os.path.exists(leaderboard_file):
				with open(leaderboard_file, 'r') as f:
					leaderboard = json.load(f)
			user_entry = next((entry for entry in leaderboard if entry['user_id'] == self.user_id), None)
			with db_conn() as conn:
				user_scans = conn.execute("""
					SELECT COUNT(*), COALESCE(SUM(score), 0) 
					FROM gamification 
					WHERE user_id = ?
				""", (self.user_id,)).fetchone()
				total_vulns = conn.execute("""
					SELECT COUNT(*) FROM vulns v
					JOIN gamification g ON v.scan_id = g.scan_id
					WHERE g.user_id = ?
				""", (self.user_id,)).fetchone()[0]
			entry = {
				'user_id': self.user_id,
				'score': int(user_scans[1]),
				'level': 1 + (user_scans[1] // 200),
				'vulns_found': total_vulns,
				'scans_count': user_scans[0],
				'last_scan': datetime.datetime.now().isoformat()
			}
			if user_entry:
				index = leaderboard.index(user_entry)
				leaderboard[index] = entry
			else:
				leaderboard.append(entry)
			leaderboard = sorted(leaderboard, key=lambda x: x['score'], reverse=True)[:50]
			with open(leaderboard_file, 'w') as f:
				json.dump(leaderboard, f)
		except Exception as e:
			pass

	def generate_certificate(self):
		with db_conn() as conn:
			scan = conn.execute("SELECT target, date FROM scans WHERE id=?", (self.scan_id,)).fetchone()
		if not scan:
			return None
		cert = f"""
=== MONOLITH PENTEST CERTIFICATE ===
Scan ID: {self.scan_id}
Target: {scan[0]}
Date: {scan[1]}
User: {self.user_id}
Level: {1 + (self.calculate_score()[0] // 200)}
=====================================
"""
		return cert

	def create_ctf_challenge(self):
		challenge = {
			'name': f"Challenge_{self.scan_id}",
			'description': f'Pentest challenge for scan {self.scan_id}',
			'flag': f'MONOLITH{{{secrets.token_hex(8)}}}',
			'points': min(self.calculate_score()[0], 500)
		}
		with open(f"/tmp/challenge_{self.scan_id}.json", "w") as f:
			json.dump(challenge, f)
		return challenge

	def get_leaderboard_position(self):
		try:
			leaderboard_file = "/tmp/monolith_leaderboard.json"
			if os.path.exists(leaderboard_file):
				with open(leaderboard_file, 'r') as f:
					leaderboard = json.load(f)
				for idx, entry in enumerate(leaderboard, 1):
					if entry['user_id'] == self.user_id:
						return idx
			return None
		except:
			return None
# GamificationEngine ve ilgili fonksiyonlar buraya taşınacak
