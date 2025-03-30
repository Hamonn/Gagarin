import psutil
import os

def find_processes_using_file(file_path):
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            if hasattr(proc, 'open_files'):
                for file in proc.open_files():
                    if os.path.abspath(file.path) == os.path.abspath(file_path):
                        processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            continue
    return processes


def close_file_processes(file_path):
    processes = find_processes_using_file(file_path)
    for proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            continue