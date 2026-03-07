# Backend/services/institution_service.py

import uuid
import datetime
from models.db import Database
from utils.response import api_response, api_error

class InstitutionService:
    def __init__(self, db: Database):
        self.db = db

    def request_institution(self, data):
        name = data.get('name')
        email = data.get('email')
        contact_person = data.get('contact_person')
        phone = data.get('phone', '')

        if not all([name, email, contact_person]):
            return api_error("name, email, and contact_person are required.", code=400)

        ok, err = self.db.register_institution(name, email, contact_person, phone)
        if ok:
            self.db.save_audit_log("system", "INSTITUTION_REQUEST_SUBMITTED", "institution", name)
            return api_response(message="Request submitted for review.", code=201)
        return api_error(err, code=409)

    def validate_code(self, code):
        inst = self.db.get_institution_by_code(code)
        if not inst:
            return api_error("Invalid code.", code=404)
        if inst['status'] != 'approved':
            return api_error("Not approved.", code=403)
        
        admin_count, staff_count = self.db.get_member_count(code)
        return api_response(data={
            "valid": True,
            "institution_name": inst['name'],
            "admin_count": admin_count,
            "staff_count": staff_count,
            "admin_slots_available": max(0, 1 - admin_count),
            "staff_slots_available": max(0, 2 - staff_count)
        })

    def get_all_institutions(self):
        return self.db.get_all_institutions()

    def approve_institution(self, institution_id):
        inst = self.db.get_institution_by_id(institution_id)
        if not inst:
            return api_error("Institution not found", code=404)
            
        try:
            code, expiry = self.db.approve_institution(institution_id)
            self.db.save_audit_log("superadmin", "INSTITUTION_APPROVED", "institution", institution_id)
            
            from utils.email_tasks import send_institution_approval_task
            send_institution_approval_task(institution_id, code, expiry)
            
            return api_response(message="Institution approved.", data={"institution_code": code})
        except Exception as e:
            from utils.logger import app_logger
            app_logger.error(f"Approval failed: {str(e)}")
            return api_error("Failed to approve institution", code=500)

    def rotate_institution_code(self, institution_id):
        inst = self.db.get_institution_by_id(institution_id)
        if not inst:
            return api_error("Institution not found", code=404)

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
                
            return api_response(message=msg, data={"new_code": code})
        except Exception as e:
            from utils.logger import app_logger
            app_logger.error(f"Rotation failed: {str(e)}")
            return api_error("Failed to rotate code", code=500)

    def reject_institution(self, institution_id, reason):
        try:
            self.db.reject_institution(institution_id, reason)
            return api_response(message="Institution rejected.")
        except Exception as e:
            return api_error("Failed to reject institution", code=500)
