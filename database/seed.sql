-- Seed data for COBOLGoat

-- Users (passwords stored in plaintext - intentional vulnerability)
INSERT OR IGNORE INTO users (id, username, password, role, email) VALUES
(1, 'admin', 'c0b0ladm1n', 'admin', 'admin@cobolgoat.internal'),
(2, 'alice', 'password123', 'user', 'alice@example.com'),
(3, 'bob', 'letmein', 'user', 'bob@example.com'),
(4, 'charlie', 'qwerty', 'user', 'charlie@example.com'),
(5, 'david', 'cobol4ever', 'user', 'david@example.com');

-- Accounts
INSERT OR IGNORE INTO accounts (id, owner, balance, ssn, account_type) VALUES
(1001, 'Alice Johnson', 15432.50, '123-45-6789', 'checking'),
(1002, 'Bob Smith', 2100.00, '987-65-4321', 'savings'),
(1003, 'Admin Account', 999999.99, '000-00-0000', 'admin'),
(1004, 'Charlie Brown', 500.00, '555-44-3333', 'checking'),
(1005, 'David Williams', 75000.00, '111-22-3333', 'investment');

-- Products
INSERT OR IGNORE INTO products (name, price, description, category, stock) VALUES
('COBOL Manual', 49.99, 'Complete COBOL programming reference', 'books', 100),
('Mainframe Guide', 89.99, 'IBM Z-series administration guide', 'books', 50),
('Legacy System Handbook', 34.99, 'Maintaining legacy COBOL systems', 'books', 75),
('VSAM Reference', 69.99, 'Virtual Storage Access Method complete reference', 'books', 30),
('JCL Cookbook', 44.99, 'Job Control Language recipes and patterns', 'books', 60),
('CICS Administration', 79.99, 'Customer Information Control System guide', 'books', 25),
('DB2 for COBOL', 94.99, 'Database 2 programming with COBOL', 'books', 40);

-- Secret data (accessible via SQL injection)
INSERT OR IGNORE INTO secret_data (key, value) VALUES
('admin_password', 'c0b0ladm1n'),
('db_encryption_key', 'AES256KEY1234567'),
('api_master_key', 'sk-master-00000-abc123def456ghi789'),
('backup_password', 'Backup$3cur3!'),
('internal_api_url', 'http://internal-api.cobolgoat.internal:8080'),
('aws_access_key', 'AKIAIOSFODNN7EXAMPLE'),
('aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
