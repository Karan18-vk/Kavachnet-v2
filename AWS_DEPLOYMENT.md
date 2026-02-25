# KavachNet — AWS Deployment Guide ☁️🛡️

This guide covers the professional deployment of KavachNet on Amazon Web Services.

## 🏗️ Architecture Overview

- **Frontend**: AWS S3 Static Website Hosting + CloudFront (CDN)
- **Backend**: AWS App Runner (Containerized)
- **Database**: SQLite (Stored in EBS or persistent volume)
- **Secrets**: AWS Secrets Manager

---

## 🛰️ 1. Backend Deployment (AWS App Runner)

AWS App Runner is the easiest way to deploy the Dockerized backend.

1. **Push to ECR**:

   ```bash
   aws ecr get-login-password --region your-region | docker login --username AWS --password-stdin your-account-id.dkr.ecr.your-region.amazonaws.com
   docker build -t kavachnet-backend ./Backend
   docker tag kavachnet-backend:latest your-account-id.dkr.ecr.your-region.amazonaws.com/kavachnet-backend:latest
   docker push your-account-id.dkr.ecr.your-region.amazonaws.com/kavachnet-backend:latest
   ```

2. **Create Service**:
   - Go to **AWS App Runner** console.
   - Select **Container registry** -> **ECR**.
   - Input the image URL from step 1.
   - In **Configuration**, add all variables from `.env` (Google API Key, SMTP credentials, etc.).
   - Note the **Service URL** (e.g., `https://abc123.us-east-1.awsapprunner.com`).

---

## 🎨 2. Frontend Deployment (S3 + CloudFront)

1. **Configure API URL**:
   Before uploading, open `Frontend/api.js` and ensure it can reach your App Runner URL. (Hint: You can inject a script tag in `landing.html` to set `window.BACKEND_URL`).

2. **S3 Upload**:
   - Create an S3 Bucket (e.g., `kavachnet-frontend`).
   - Enable "Static Website Hosting".
   - Upload all files from the `Frontend/` folder.

3. **CloudFront (Optional but Recommended)**:
   - Create a Distribution pointing to your S3 bucket for HTTPS and low-latency delivery.

---

## 🔒 3. Final Security Check

- Ensure **AWS WAF** (Web Application Firewall) is active on CloudFront.
- Verify that your `.env` secrets on App Runner are **not** committed to Git.
- Test the **Brute Force Lockout** on the live URL.

---

**Mission Accomplished.** KavachNet is now active on the global cloud grid.
