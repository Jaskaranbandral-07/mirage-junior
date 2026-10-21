-- ========================================================
-- Production Database Automated Backup
-- Database: prod_enterprise_db
-- Server Version: PostgreSQL 15.4 / Ubuntu 22.04 LTS
-- Dump completed on 2026-10-10 03:00:01 UTC
-- ========================================================

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

-- --------------------------------------------------------
-- Table structure for table `admin_accounts`
-- --------------------------------------------------------

DROP TABLE IF EXISTS `admin_accounts`;
CREATE TABLE `admin_accounts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL UNIQUE,
  `email` varchar(128) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `salt` varchar(64) NOT NULL,
  `role` varchar(32) NOT NULL DEFAULT 'viewer',
  `mfa_secret` varchar(64) DEFAULT NULL,
  `api_key` varchar(128) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `last_login` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

--
-- Dumping data for table `admin_accounts`
--

LOCK TABLES `admin_accounts` WRITE;
INSERT INTO `admin_accounts` VALUES 
(1, 'superadmin', 'security-ops@corp.internal', '$2y$12$e8YxGz9z/0DkM2e8wYkEheNqGzH0A2p7JmKpUf8L1c8O6oGzG5Ere', 'f9a2b7c4d1e8', 'super_admin', 'JBSWY3DPEHPK3PXP', 'corp_sec_live_99d82f710a5b481ce', 1, '2026-10-09 14:22:18', '2025-01-15 08:00:00'),
(2, 'db_ops', 'dba@corp.internal', '$2y$12$v9XzHy0A/1ElN3f9xZlFieOrHzI1B3q8KnLqVg9M2d9P7pH0H6Fsf', 'c1e8f9a2b7d4', 'db_admin', 'HXDMVJECJJWSRZ3U', 'corp_dba_live_44a91b827e6c592da', 1, '2026-10-08 19:40:02', '2025-02-10 11:30:00'),
(3, 'billing_service', 'service-billing@corp.internal', '$2y$12$k4AbCd8E/9FgH1i2jKlMnoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsT', 'a7b8c9d0e1f2', 'api_service', NULL, 'decoy_billing_api_key_fake_2026', 1, '2026-10-10 02:55:00', '2025-06-01 00:00:00');
UNLOCK TABLES;

-- --------------------------------------------------------
-- Table structure for table `system_settings`
-- --------------------------------------------------------

DROP TABLE IF EXISTS `system_settings`;
CREATE TABLE `system_settings` (
  `key_name` varchar(128) NOT NULL,
  `key_value` text NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`key_name`)
);

LOCK TABLES `system_settings` WRITE;
INSERT INTO `system_settings` VALUES
('jwt_signing_key', 'dGhpc19pc19hX3Zlcnlfc2VjcmV0X2tleV9mb3JfcHJvZF8yMDI2', 'HMAC SHA256 Secret for session tokens'),
('stripe_webhook_secret', 'whsec_9941a87b204938d1209ef993c129', 'Stripe payment notification signing secret'),
('internal_smtp_relay', 'smtp://app_relay:P@ssw0rdRelay99!@10.0.0.25:587', 'Internal corporate mail relay');
UNLOCK TABLES;
