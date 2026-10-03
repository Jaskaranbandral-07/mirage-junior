import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database.db_manager import DatabaseManager
from config.settings import BAIT_DIRECTORY
import logging

logger = logging.getLogger(__name__)

class HoneytokenHandler(FileSystemEventHandler):
    def __init__(self):
        self.db = DatabaseManager()
    
    def _log_event(self, event, action):
        if event.is_directory:
            return
        logger.warning(f"Honeytoken triggered! Action: {action} on {event.src_path}")
        # Normally we might extract IP or process, but for file system triggers, it's local
        self.db.log_honeytoken_trigger(
            token_name=os.path.basename(event.src_path),
            token_type='filesystem',
            ip_address='localhost',
            process_name='unknown',
            details=f"File {action}"
        )
        
    def on_modified(self, event):
        self._log_event(event, 'modified')

    def on_created(self, event):
        self._log_event(event, 'created')

    def on_deleted(self, event):
        self._log_event(event, 'deleted')


class HoneytokenMonitor(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.bait_dir = os.path.abspath(BAIT_DIRECTORY)
        os.makedirs(self.bait_dir, exist_ok=True)
        self.observer = Observer()
        self.handler = HoneytokenHandler()

    def run(self):
        self.observer.schedule(self.handler, self.bait_dir, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except Exception as e:
            self.observer.stop()
        self.observer.join()
