# Backend/utils/email_queue.py

import time
import threading
import datetime
from models.db import Database
from utils.email_providers import get_email_provider
from utils.json_logger import json_metrics_logger

# We control the polling interval depending on the environment
class EmailQueueWorker:
    def __init__(self, poll_interval=5):
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.db = Database()
        self.thread = None

    def start(self):
        """Starts the background polling thread."""
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._run, daemon=True, name="EmailQueueWorker")
            self.thread.start()
            json_metrics_logger.info("Email queue worker thread started.", extra={"metrics": {"event": "worker_start"}})

    def stop(self):
        """Signals the worker to stop cleanly."""
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                # 1. Claim pending emails (BEGIN EXCLUSIVE prevents race conditions across workers)
                batch = self.db.claim_pending_emails(batch_size=5)
                
                for email_job in batch:
                    self._process_job(email_job)

            except Exception as e:
                json_metrics_logger.error("Queue worker encountered a fatal polling error.", extra={"metrics": {"event": "worker_error", "error": str(e)}})
            
            # 2. Wait before next poll
            self._stop_event.wait(self.poll_interval)

    def _process_job(self, job):
        start_time = time.time()
        job_id = job['id']
        recipient = job['recipient']
        log_type = job['type']
        
        json_metrics_logger.info(f"Processing queued email: {job_id}", extra={"metrics": {"event": "email_process_start", "job_id": job_id, "type": log_type}})
        
        # Dynamic Provider Dispatch
        provider = get_email_provider()
        success, attempts, last_err = provider.send_email(
            recipient=recipient,
            subject=job['subject'],
            html_body=job['html_body'],
            text_body=job['text_body'],
            max_attempts=job['max_attempts']
        )
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Evaluate final status and mathematically expanding backoff delay
        final_status = "SENT" if success else "FAILED"
        next_retry = None
        
        # If it failed but hasn't reached max attempts, keep it PENDING for next retry
        current_attempt_count = job['attempts'] + attempts
        if not success and final_status == "FAILED" and current_attempt_count < job['max_attempts'] and "AuthError" not in str(last_err):
             final_status = "PENDING"
             
             # Exponential backoff algorithm: 2^attempts * 15 seconds base
             backoff_seconds = (2 ** current_attempt_count) * 15
             next_retry = (datetime.datetime.now() + datetime.timedelta(seconds=backoff_seconds)).isoformat()
             
             json_metrics_logger.warning(
                 f"Transient error: Queueing backoff for {backoff_seconds}s.", 
                 extra={"metrics": {"event": "exponential_backoff", "job_id": job_id, "retry_at": next_retry}}
             )
             
        if success:
             final_status = "SENT"
        elif current_attempt_count >= job['max_attempts'] or (last_err and "AuthError" in str(last_err)):
             final_status = "FAILED"

        # Update DB queue status
        self.db.update_email_queue_status(job_id, final_status, last_err, next_retry_at=next_retry)
        
        # Send metric to JSON logger
        metric_payload = {
            "event": "email_dispatch_metric",
            "job_id": job_id,
            "recipient_masked": f"***{recipient[recipient.find('@'):]}" if '@' in recipient else "***",
            "type": log_type,
            "status": final_status,
            "attempts": current_attempt_count,
            "duration_ms": duration_ms
        }
        
        if success:
            json_metrics_logger.info("Queued email dispatched successfully.", extra={"metrics": metric_payload})
        else:
            metric_payload["last_error"] = str(last_err)
            json_metrics_logger.error("Queued email dispatch failed.", extra={"metrics": metric_payload})

# Global singleton for the app to initialize
email_worker = EmailQueueWorker(poll_interval=3)
