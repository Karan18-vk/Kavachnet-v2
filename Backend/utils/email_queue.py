import time
import threading
from datetime import datetime, timedelta
from models.user import EmailQueue
from database import db
from utils.email_providers import get_email_provider
from utils.json_logger import json_metrics_logger
from sqlalchemy import or_

class EmailQueueWorker:
    def __init__(self, poll_interval=5):
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.thread = None
        self.app = None

    def start(self, app):
        """Starts the background polling thread with Flask app context."""
        self.app = app
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._run, daemon=True, name="EmailQueueWorker")
            self.thread.start()
            json_metrics_logger.info("Email queue worker thread started with SQLAlchemy backend.")

    def stop(self):
        """Signals the worker to stop cleanly."""
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                with self.app.app_context():
                    # 1. Claim pending emails with row locking
                    batch = self._claim_batch(batch_size=5)
                    for email_job in batch:
                        self._process_job(email_job)
            except Exception as e:
                json_metrics_logger.error(f"Queue worker error: {e}")
            
            self._stop_event.wait(self.poll_interval)

    def _claim_batch(self, batch_size):
        """Thread-safe claiming of pending emails using SQLAlchemy."""
        now = datetime.utcnow()
        five_mins_ago = now - timedelta(minutes=5)
        
        # Select jobs that are PENDING and due, or PROCESSING but stuck
        jobs = EmailQueue.query.filter(
            or_(
                (EmailQueue.status == "PENDING") & (EmailQueue.next_retry_at <= now),
                (EmailQueue.status == "PROCESSING") & (EmailQueue.updated_at < five_mins_ago)
            )
        ).order_by(EmailQueue.created_at.asc()).limit(batch_size).with_for_update().all()
        
        for job in jobs:
            job.status = "PROCESSING"
            job.updated_at = now
            
        db.session.commit()
        return jobs

    def _process_job(self, job):
        start_time = time.time()
        job_id = job.id
        recipient = job.recipient
        log_type = job.type
        
        # Provider Dispatch
        provider = get_email_provider()
        # Note: We assume max_attempts is 3 for now as it's not in the model but in logic
        max_attempts = 3
        
        success, sent_count, last_err = provider.send_email(
            recipient=recipient,
            subject=job.subject,
            html_body=job.html_body,
            text_body=job.text_body,
            max_attempts=max_attempts
        )
        
        duration_ms = int((time.time() - start_time) * 1000)
        final_status = "SENT" if success else "FAILED"
        next_retry = None
        
        current_attempt_count = job.attempts + sent_count
        job.attempts = current_attempt_count
        job.last_error = str(last_err) if last_err else None
        job.updated_at = datetime.utcnow()

        if not success and current_attempt_count < max_attempts and "AuthError" not in str(last_err):
             job.status = "PENDING"
             backoff_seconds = (2 ** current_attempt_count) * 15
             job.next_retry_at = datetime.utcnow() + timedelta(seconds=backoff_seconds)
        else:
             job.status = final_status
        
        db.session.commit()
        
        # Logging
        metric_payload = {
            "event": "email_dispatch_metric",
            "job_id": job_id,
            "status": job.status,
            "attempts": current_attempt_count,
            "duration_ms": duration_ms
        }
        if success:
            json_metrics_logger.info("Queued email dispatched successfully.", extra={"metrics": metric_payload})
        else:
            json_metrics_logger.error("Queued email dispatch failed.", extra={"metrics": metric_payload})

# Global singleton
email_worker = EmailQueueWorker(poll_interval=3)
