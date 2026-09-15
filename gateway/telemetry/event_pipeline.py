import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger("gateway.telemetry.pipeline")

EVENTS_DIR = os.getenv("EVENTS_DIR", "events")

class TelemetryPipeline:
    """
    Guaranteed event ingestion pipeline with local queue buffer and disk fallback.
    Prevents event loss during telemetry sink congestion (Critical Improvement #4).
    """
    def __init__(self, output_dir: str = EVENTS_DIR, max_queue_size: int = 10000):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.log_file = os.path.join(self.output_dir, "telemetry.jsonl")
        self.fallback_file = os.path.join(self.output_dir, "telemetry_fallback.jsonl")
        
        self.event_queue = queue.Queue(maxsize=max_queue_size)
        self.running = True
        self._worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self._worker_thread.start()

    def emit(self, event: Dict[str, Any]):
        """Non-blocking event dispatch from gateway middleware."""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            logger.error("Local telemetry queue full! Writing immediately to fallback storage.")
            self._write_immediate(self.fallback_file, event)

    def _process_queue(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1.0)
                self._write_immediate(self.log_file, event)
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error persisting security event: {e}")

    def _write_immediate(self, file_path: str, event: Dict[str, Any]):
        try:
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.critical(f"Disk write failure for event log {file_path}: {e}")

    def flush(self):
        """Drains the queue synchronously (used during test teardown)."""
        while not self.event_queue.empty():
            try:
                event = self.event_queue.get_nowait()
                self._write_immediate(self.log_file, event)
                self.event_queue.task_done()
            except queue.Empty:
                break

telemetry_pipeline = TelemetryPipeline()
