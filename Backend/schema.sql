-- MySQL Schema for KavachNet Backend (XAMPP Compatible)
-- Database: kavachnet

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET TIME_ZONE = "+00:00";

-- Table structure for table `institutions`
CREATE TABLE `institutions` (
  `id` VARCHAR(255) PRIMARY KEY,
  `name` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) UNIQUE NOT NULL,
  `contact_person` VARCHAR(255) NOT NULL,
  `phone` VARCHAR(50),
  `institution_code` VARCHAR(50) UNIQUE,
  `status` VARCHAR(20) DEFAULT 'pending',
  `rejection_reason` TEXT,
  `created_at` VARCHAR(50) NOT NULL,
  `approved_at` VARCHAR(50),
  `code_expires_at` VARCHAR(50)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `users`
CREATE TABLE `users` (
  `id` VARCHAR(255) PRIMARY KEY,
  `username` VARCHAR(255) UNIQUE NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `role` VARCHAR(20) DEFAULT 'staff',
  `institution_code` VARCHAR(50),
  `status` VARCHAR(20) DEFAULT 'approved',
  `created_at` VARCHAR(50) NOT NULL,
  `lockout_until` VARCHAR(50)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `failed_attempts`
CREATE TABLE `failed_attempts` (
  `id` VARCHAR(255) PRIMARY KEY,
  `username` VARCHAR(255) NOT NULL,
  `timestamp` VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `login_logs`
CREATE TABLE `login_logs` (
  `id` VARCHAR(255) PRIMARY KEY,
  `username` VARCHAR(255) NOT NULL,
  `status` VARCHAR(20) NOT NULL,
  `timestamp` VARCHAR(50) NOT NULL,
  `hour` INTEGER NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `incidents`
CREATE TABLE `incidents` (
  `id` VARCHAR(255) PRIMARY KEY,
  `type` VARCHAR(50) NOT NULL,
  `severity` VARCHAR(20) NOT NULL,
  `message` TEXT NOT NULL,
  `status` VARCHAR(20) DEFAULT 'OPEN',
  `timestamp` VARCHAR(50) NOT NULL,
  `institution_code` VARCHAR(50),
  `forensics` TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `audit_logs`
CREATE TABLE `audit_logs` (
  `id` VARCHAR(255) PRIMARY KEY,
  `username` VARCHAR(255) NOT NULL,
  `action` VARCHAR(100) NOT NULL,
  `object_type` VARCHAR(50) NOT NULL,
  `object_id` VARCHAR(255),
  `timestamp` VARCHAR(50) NOT NULL,
  `forensics` TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `institution_codes`
CREATE TABLE `institution_codes` (
  `id` VARCHAR(255) PRIMARY KEY,
  `institution_id` VARCHAR(255) NOT NULL,
  `code_value` VARCHAR(50) NOT NULL UNIQUE,
  `generated_at` VARCHAR(50) NOT NULL,
  `expires_at` VARCHAR(50) NOT NULL,
  `status` VARCHAR(20) DEFAULT 'ACTIVE',
  `generated_by` VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `email_logs`
CREATE TABLE `email_logs` (
  `id` VARCHAR(255) PRIMARY KEY,
  `recipient` VARCHAR(255) NOT NULL,
  `type` VARCHAR(50) NOT NULL,
  `status` VARCHAR(20) NOT NULL,
  `attempts` INTEGER DEFAULT 1,
  `last_error` TEXT,
  `created_at` VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table structure for table `email_queue`
CREATE TABLE `email_queue` (
  `id` VARCHAR(255) PRIMARY KEY,
  `recipient` VARCHAR(255) NOT NULL,
  `subject` VARCHAR(255) NOT NULL,
  `html_body` TEXT NOT NULL,
  `text_body` TEXT,
  `type` VARCHAR(50) NOT NULL,
  `institution_id` VARCHAR(255),
  `status` VARCHAR(20) DEFAULT 'PENDING',
  `attempts` INTEGER DEFAULT 0,
  `max_attempts` INTEGER DEFAULT 3,
  `last_error` TEXT,
  `created_at` VARCHAR(50) NOT NULL,
  `updated_at` VARCHAR(50) NOT NULL,
  `next_retry_at` VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Indexes
CREATE INDEX `idx_users_username` ON `users` (`username`);
CREATE INDEX `idx_users_inst` ON `users` (`institution_code`);
CREATE INDEX `idx_incidents_inst` ON `incidents` (`institution_code`);
CREATE INDEX `idx_incidents_ts` ON `incidents` (`timestamp`);
CREATE INDEX `idx_logs_username` ON `login_logs` (`username`);
CREATE INDEX `idx_audit_username` ON `audit_logs` (`username`);
CREATE INDEX `idx_audit_ts` ON `audit_logs` (`timestamp`);

-- Seed Default Admin
-- Password: Admin@123
-- Hash: $2b$12$R.S.Y.R.S.Y.R.S.Y.R.S.Y.R.S.Y.R.S.Y.R.S.Y.R.S.Y.R.S.Y.R.S.Y.R.S.Y (Simplified for example)
-- Use a real bcrypt hash here
INSERT INTO `users` (`id`, `username`, `password`, `email`, `role`, `status`, `created_at`) VALUES
('admin-uuid-1', 'admin_kavach', '$2b$12$aZBkWBfZMqXO/kmHLDyiGu7PAapwKinXiIuBfvYKBHDSPEAyoTw.i', 'admin@kavach.net', 'superadmin', 'approved', '2024-03-20T10:00:00');

COMMIT;
