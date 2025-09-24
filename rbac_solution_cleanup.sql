-- ==============================================================================
-- CLEANUP SCRIPT FOR CUSTOM RBAC SOLUTION (Snowflake)
-- ==============================================================================
-- This script removes all objects and grants created by rbac_solution.sql
-- Prereqs: You must have sufficient privileges (e.g., SECURITYADMIN)
-- ==============================================================================

-- Match variables used in the main solution
SET app_db = 'SANDBOX_DB';
SET app_schema = 'ADMIN';
SET app_schema_full = $app_db || '.' || $app_schema;
SET app_wh = 'BASIC_ADMIN_XS';

-- Drop objects owned by the app role
USE ROLE rbac_app_role;
USE SCHEMA IDENTIFIER($app_schema_full);

-- Task
DROP TASK IF EXISTS RBAC_REVOKE_TASK;

-- Stored procedures
DROP PROCEDURE IF EXISTS SPROC_TEMP_REVOKE();
DROP PROCEDURE IF EXISTS SPROC_TEMP_GRANT(VARCHAR, TIMESTAMP_LTZ);

-- Tables
DROP TABLE IF EXISTS RBAC_LOG_EXECUTIONS;
DROP TABLE IF EXISTS RBAC_REQUEST_EXECUTIONS;

-- Clean up role assignments and drop role
USE ROLE SECURITYADMIN;

-- Remove role from current user and revoke role hierarchy
SET self_user = CURRENT_USER();
REVOKE ROLE rbac_app_role FROM USER IDENTIFIER($self_user);

-- Drop the application role (this automatically revokes all privileges)
DROP ROLE IF EXISTS rbac_app_role;

-- ==============================================================================
-- STREAMLIT APPLICATION CLEANUP
-- ==============================================================================
-- Note: The following files need to be manually removed from the filesystem:
--
-- Main Streamlit application:
--   - streamlit_app.py
--
-- Bundled Streamlit application (if exists):
--   - output/bundle/streamlit/temp_rbac_app/streamlit_app.py
--   - output/bundle/streamlit/temp_rbac_app/environment.yml
--   - output/bundle/streamlit/ (entire directory)
--
-- To remove these files, run the following commands in your terminal:
-- 
-- # Remove main Streamlit app
-- rm -f streamlit_app.py
--
-- # Remove bundled Streamlit directory (if exists)
-- rm -rf output/bundle/streamlit/
--
-- # Optional: Remove entire output directory if no longer needed
-- rm -rf output/
--
-- ==============================================================================
-- END OF CLEANUP
-- ==============================================================================


