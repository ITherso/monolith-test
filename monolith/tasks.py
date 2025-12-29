import subprocess
import os
import tempfile
import subprocess
import os
import tempfile
from monolith.celery_app import celery
import sqlite3
from typing import Any


@celery.task()
def run_nuclei(target: str, template_id: str = None, out_dir: str = None):
    """Run a nuclei scan (safely) and return path to output file.

    If Celery is not installed this will run synchronously via the stub.
    """
    nuclei = os.getenv('NUCLEI_BIN', 'nuclei')
    args = [nuclei, '-u', target]
    if template_id:
        args.extend(['-id', template_id])

    fd, out = tempfile.mkstemp(prefix='nuclei_', suffix='.txt')
    os.close(fd)

    with open(out, 'w') as f:
        try:
            subprocess.run(args, stdout=f, stderr=subprocess.STDOUT, text=True, timeout=900)
            return out
        except subprocess.TimeoutExpired:
            with open(out, 'a') as g:
                g.write('\n[ERROR] Timeout')
            return out
        except Exception as e:
            with open(out, 'a') as g:
                g.write('\n[ERROR] ' + str(e))
            return out


@celery.task()
def run_nmap(target: str, args: list = None):
    nmap = os.getenv('NMAP_BIN', 'nmap')
    cmd = [nmap]
    if args:
        cmd += args
    cmd.append(target)

    fd, out = tempfile.mkstemp(prefix='nmap_', suffix='.txt')
    os.close(fd)

    with open(out, 'w') as f:
        try:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, text=True, timeout=600)
            return out
        except subprocess.TimeoutExpired:
            with open(out, 'a') as g:
                g.write('\n[ERROR] Timeout')
            return out
        except Exception as e:
            with open(out, 'a') as g:
                g.write('\n[ERROR] ' + str(e))
            return out


@celery.task()
def run_gobuster(target: str, wordlist: str = None, out_dir: str = None):
    gobuster = os.getenv('GOBUSTER_BIN', 'gobuster')
    args = [gobuster, 'dir', '-u', target]
    if wordlist:
        args += ['-w', wordlist]
    fd, out = tempfile.mkstemp(prefix='gobuster_', suffix='.txt')
    os.close(fd)

    with open(out, 'w') as f:
        try:
            subprocess.run(args, stdout=f, stderr=subprocess.STDOUT, text=True, timeout=900)
            return out
        except subprocess.TimeoutExpired:
            with open(out, 'a') as g:
                g.write('\n[ERROR] Timeout')
            return out
        except Exception as e:
            with open(out, 'a') as g:
                g.write('\n[ERROR] ' + str(e))
            return out


@celery.task()
def run_scan(target: str, scan_id: int, run_python: bool, selected_tools: list, user_id: str = 'anonymous'):
    """Orchestrator task to run a full scan via the existing run_worker function.

    This imports `cyber.run_worker` and executes it. If Celery is not installed,
    the stub will call this synchronously.
    """
    try:
        # local import to avoid circular import at module load
        import cyber
        result = cyber.run_worker(target, scan_id, run_python, selected_tools, user_id)
        # if result is an error dict, persist
        if isinstance(result, dict) and result.get('error'):
            try:
                with sqlite3.connect('monolith_supreme.db') as conn:
                    conn.execute("INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                                 (scan_id, 'RUN_SCAN', result.get('error')))
                    conn.commit()
            except Exception:
                pass
        return result
    except Exception as e:
        try:
            with sqlite3.connect('monolith_supreme.db') as conn:
                conn.execute("INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                             (scan_id, 'RUN_SCAN', str(e)))
                conn.commit()
        except Exception:
            pass
        return {'error': str(e)}
