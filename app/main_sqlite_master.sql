INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table', 'alembic_version', 'alembic_version', 2, 'CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
)');
INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('index', 'sqlite_autoindex_alembic_version_1', 'alembic_version', 3, null);
INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table', 'User', 'User', 4, 'CREATE TABLE "User" (
	id INTEGER NOT NULL, 
	full_name VARCHAR(60), 
	username VARCHAR(120), 
	email VARCHAR(120), 
	password_hash VARCHAR, account_confirmed BOOLEAN, date_of_birth DATETIME, email_confirmed BOOLEAN, phone_number VARCHAR, phone_number_confirmed BOOLEAN, 
	PRIMARY KEY (id)
)');
INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('index', 'ix_User_email', 'User', 5, 'CREATE UNIQUE INDEX "ix_User_email" ON "User" (email)');
INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('index', 'ix_User_username', 'User', 6, 'CREATE UNIQUE INDEX "ix_User_username" ON "User" (username)');