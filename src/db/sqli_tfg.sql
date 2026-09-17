-- Full schema for the sqli_tfg database (MySQL/MariaDB), structure only, no
-- data. This is the single source of truth for the schema - there is no
-- migration runner in this project, so all changes that used to live as
-- separate db/migrations/000N_*.sql files (error_message columns, host_web_app_nikto,
-- log columns, jobs_id indexes) are already folded in here.
-- To change the schema: apply the ALTER/CREATE by hand against the live DB,
-- then regenerate this file so it stays the source of truth:
--   mysqldump -u <user> -p --no-data --skip-comments --routines --triggers sqli_tfg > db/sqli_tfg.sql
-- To set up a fresh database from scratch:
--   mysql -u <user> -p sqli_tfg < db/sqli_tfg.sql

/*M!999999\- enable the sandbox mode */

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
DROP TABLE IF EXISTS `activity_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `activity_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `jobs_id` int(11) NOT NULL,
  `event_type` enum('host_identified','webapp_identified','vulnerable_page_found','dbs_obtained') NOT NULL,
  `reference_id` int(11) NOT NULL,
  `reference_table` varchar(30) NOT NULL,
  `details_json` longtext NOT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `jobs_id` (`jobs_id`),
  CONSTRAINT `activity_logs_ibfk_1` FOREIGN KEY (`jobs_id`) REFERENCES `jobs` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7140 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `crawl_page`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `crawl_page` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `web_app_id` int(11) NOT NULL,
  `base_url` varchar(1000) DEFAULT NULL,
  `url` varchar(1000) NOT NULL,
  `is_admin_path` tinyint(1) DEFAULT 0,
  `has_login_form` tinyint(1) DEFAULT 0,
  `has_register_form` tinyint(1) DEFAULT 0,
  `has_search_form` tinyint(1) DEFAULT 0,
  `has_upload_form` tinyint(1) DEFAULT 0,
  `has_form_without_csrf` tinyint(1) DEFAULT 0,
  `has_errors` tinyint(1) DEFAULT 0,
  `has_parametres_url` tinyint(1) DEFAULT 0,
  `is_referred_robots` tinyint(1) DEFAULT 0,
  `has_get_params` tinyint(1) DEFAULT 0,
  `has_post_params` tinyint(1) DEFAULT 0,
  `priority_score` int(11) DEFAULT NULL,
  `priority_level` enum('low','medium','high') DEFAULT NULL,
  `state` enum('pending','pending_score','running','running_score','error','done') DEFAULT 'pending',
  `error_message` text DEFAULT NULL,
  `log` longtext DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  `depth` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `host_id` (`web_app_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `crawl_page_ibfk_1` FOREIGN KEY (`web_app_id`) REFERENCES `host_web_app` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=37306 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `crawl_page_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `crawl_page_details` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `crawl_page_id` int(11) NOT NULL,
  `forms_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`forms_json`)),
  `standalone_inputs_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`standalone_inputs_json`)),
  `url_params_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`url_params_json`)),
  `error_details_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`error_details_json`)),
  `state` enum('pending','running','error','done') DEFAULT 'pending',
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `crawl_page_id` (`crawl_page_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `crawl_page_details_ibfk_1` FOREIGN KEY (`crawl_page_id`) REFERENCES `crawl_page` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=32266 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `host_nmap`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `host_nmap` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `host_id` int(11) NOT NULL,
  `port` int(11) NOT NULL,
  `nmap_state` varchar(50) DEFAULT NULL,
  `nmap_service` varchar(100) DEFAULT NULL,
  `nmap_version` varchar(255) DEFAULT NULL,
  `state` enum('pending','running','error','done') DEFAULT 'pending',
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `host_id` (`host_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `host_nmap_ibfk_1` FOREIGN KEY (`host_id`) REFERENCES `hosts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=290 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `host_web_app`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `host_web_app` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `host_id` int(11) NOT NULL,
  `target_url` varchar(1000) NOT NULL,
  `http_status` int(11) DEFAULT NULL,
  `redirect_location` varchar(1000) DEFAULT NULL,
  `technologies_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`technologies_json`)),
  `cookies_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`cookies_json`)),
  `headers_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`headers_json`)),
  `uncommon_headers_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`uncommon_headers_json`)),
  `state` enum('pending','running','error','done') DEFAULT 'pending',
  `error_message` text DEFAULT NULL,
  `log` longtext DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `host_id` (`host_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `host_web_app_ibfk_1` FOREIGN KEY (`host_id`) REFERENCES `hosts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=69 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `host_web_app_nikto`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `host_web_app_nikto` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `web_app_id` int(11) NOT NULL,
  `url` varchar(1000) NOT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `web_app_id` (`web_app_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `host_web_app_nikto_ibfk_1` FOREIGN KEY (`web_app_id`) REFERENCES `host_web_app` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `hosts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `hosts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `jobs_id` int(11) NOT NULL,
  `target_host` varchar(255) NOT NULL,
  `state` enum('pending','running','error','done') DEFAULT 'pending',
  `error_message` text DEFAULT NULL,
  `log` longtext DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `scan_id` (`jobs_id`),
  CONSTRAINT `hosts_ibfk_1` FOREIGN KEY (`jobs_id`) REFERENCES `jobs` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=75 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `jobs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `jobs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` enum('Normal','IA') DEFAULT 'Normal',
  `model` varchar(255) DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `depth` int(11) NOT NULL DEFAULT 4,
  `comment` varchar(500) DEFAULT NULL,
  `target_url` varchar(500) DEFAULT NULL,
  `state` enum('running','done','error') NOT NULL DEFAULT 'running',
  `error_message` text DEFAULT NULL,
  `finished_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=75 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `sqli_detector`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sqli_detector` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `crawl_page_id` int(11) NOT NULL,
  `target_url` varchar(1000) NOT NULL,
  `method` enum('GET','POST') NOT NULL,
  `is_vulnerable` tinyint(1) DEFAULT 0,
  `injection_points_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `injection_types_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `dbms` varchar(50) DEFAULT NULL,
  `error_message` text DEFAULT NULL,
  `state` enum('pending','running','error','done','discarded') DEFAULT 'pending',
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `crawl_page_id` (`crawl_page_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `sqli_detector_ibfk_1` FOREIGN KEY (`crawl_page_id`) REFERENCES `crawl_page` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=9355 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `sqli_exploit`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sqli_exploit` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sqli_detector_id` int(11) NOT NULL,
  `databases_json` longtext DEFAULT NULL,
  `total_databases` int(11) DEFAULT 0,
  `state` enum('pending','running','error','done') DEFAULT 'pending',
  `error_message` text DEFAULT NULL,
  `log` longtext DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sqli_detector_id` (`sqli_detector_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `sqli_exploit_ibfk_1` FOREIGN KEY (`sqli_detector_id`) REFERENCES `sqli_detector` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6448 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `sqli_exploit_columns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sqli_exploit_columns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sqli_exploit_tables_id` int(11) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `columns_json` longtext DEFAULT NULL,
  `state` enum('pending','running','error','done') DEFAULT 'pending',
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sqli_exploit_tables_id` (`sqli_exploit_tables_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `sqli_exploit_columns_ibfk_1` FOREIGN KEY (`sqli_exploit_tables_id`) REFERENCES `sqli_exploit_tables` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=65754 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `sqli_exploit_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sqli_exploit_data` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sqli_exploit_columns_id` int(11) DEFAULT NULL,
  `db_name` varchar(255) NOT NULL,
  `table_name` varchar(255) NOT NULL,
  `data_json` longtext DEFAULT NULL,
  `dump_success` tinyint(1) DEFAULT 0,
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sqli_exploit_columns_id` (`sqli_exploit_columns_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `sqli_exploit_data_ibfk_1` FOREIGN KEY (`sqli_exploit_columns_id`) REFERENCES `sqli_exploit_columns` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
DROP TABLE IF EXISTS `sqli_exploit_tables`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sqli_exploit_tables` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sqli_exploit_id` int(11) NOT NULL,
  `db_name` varchar(255) NOT NULL,
  `tables_json` longtext DEFAULT NULL,
  `state` enum('pending','running','error','done') DEFAULT 'pending',
  `timestamp` timestamp NULL DEFAULT current_timestamp(),
  `jobs_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `sqli_exploit_id` (`sqli_exploit_id`),
  KEY `idx_jobs_id` (`jobs_id`),
  CONSTRAINT `sqli_exploit_tables_ibfk_1` FOREIGN KEY (`sqli_exploit_id`) REFERENCES `sqli_exploit` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=59255 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

