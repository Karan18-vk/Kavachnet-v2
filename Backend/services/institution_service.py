# Backend/services/institution_service.py

import uuid
import datetime
from models.db import Database

class InstitutionService:
    def __init__(self, db: Database):
        self.db = db

    def request_institution(self, data):
        name = data.get('name')
        email = data.get('email')
        contact_person = data.get('contact_person')
        phone = data.get('phone', '')

        if not all([name, email, contact_person]):
            return {"error": "name, email, and contact_person are required."}, 400

        ok, err = self.db.register_institution(name, email, contact_person, phone)
        if ok:
            self.db.save_audit_log("system", "INSTITUTION_REQUEST_SUBMITTED", "institution", name)
            return {"message": "Request submitted for review."}, 201
        return {"error": err}, 409

    def validate_code(self, code):
        inst = self.db.get_institution_by_code(code)
        if not inst:
            return {"valid": False, "error": "Invalid code."}, 404
        if inst['status'] != 'approved':
            return {"valid": False, "error": "Not approved."}, 403
        
        admin_count, staff_count = self.db.get_member_count(code)
        return {
            "valid": True,
            "institution_name": inst['name'],
            "admin_count": admin_count,
            "staff_count": staff_count,
            "admin_slots_available": max(0, 1 - admin_count),
            "staff_slots_available": max(0, 2 - staff_count)
        }, 200

    def get_all_institutions(self):
        return self.db.get_all_institutions()

    def approve_institution(self, institution_id):
        inst = self.db.get_institution_by_id(institution_id)
        if not inst:
            return {"error": "Institution not found"}, 404
            
        try:
            code, expiry = self.db.approve_institution(institution_id)
            self.db.save_audit_log("superadmin", "INSTITUTION_APPROVED", "institution", institution_id)
            
            from utils.email_tasks import send_institution_approval_task
            send_institution_approval_task(institution_id, code, expiry)
            
            return {"status": "success", "institution_code": code}, 200
        except Exception as e:
            from utils.logger import app_logger
            app_logger.error(f"Approval failed: {str(e)}")
            return {"error": "Failed to approve institution"}, 500

    def rotate_institution_code(self, institution_id):
        inst = self.db.get_institution_by_id(institution_id)
        if not inst:
            return {"error": "Institution not found"}, 404

        try:
            old_code, code, expiry = self.db.rotate_institution_code(institution_id)
            self.db.save_audit_log("superadmin", "INSTITUTION_CODE_ROTATED", "institution", institution_id)
            
            from utils.email_tasks import send_institution_code_update_task
            email_sent = send_institution_code_update_task(
                institution_id=institution_id,
                old_code=old_code,
                new_code=code,
                expiry=expiry
            )
            
            msg = "Code rotated successfully."
            if not email_sent:
                msg = "Code rotated successfully, but email dispatch failed. Verify SMTP settings."
                
            return {"status": "success", "message": msg, "new_code": code}, 200
        except Exception as e:
            from utils.logger import app_logger
            app_logger.error(f"Rotation failed: {str(e)}")
            return {"error": "Failed to rotate code"}, 500

    def reject_institution(self, institution_id, reason):
        try:
            self.db.reject_institution(institution_id, reason)
            return {"status": "success"}, 200
        except Exception as e:
            return {"error": "Failed to reject institution"}, 500
