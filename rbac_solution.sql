-- ============================================================================
-- CUSTOM RBAC SOLUTION FOR SNOWFLAKE
-- ============================================================================
-- This script creates a temporary grant/revoke system with logging capabilities
-- You need to have SECURITYADMIN access to run this script.
-- ============================================================================

-- Set app target location 
SET app_db = 'SANDBOX_DB';
SET app_schema = 'ADMIN';
SET app_schema_full = $app_db || '.' || $app_schema;
SET app_wh = 'BASIC_ADMIN_XS';

-- ============================================================================
-- ROLE CREATION AND PRIVILEGE GRANTING
-- ============================================================================

-- Set the role to SECURITYADMIN 
USE ROLE SECURITYADMIN;

-- Create a custom role that will be used for this RBAC solution
CREATE ROLE IF NOT EXISTS rbac_app_role;
GRANT ROLE SECURITYADMIN TO ROLE rbac_app_role;
SET self_user = CURRENT_USER();
GRANT ROLE rbac_app_role TO USER IDENTIFIER($self_user);

-- Grant privileges within database and schema to role rbac_app_role;
GRANT USAGE ON DATABASE IDENTIFIER($app_db) TO ROLE rbac_app_role;
GRANT USAGE ON SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;

-- Grant create stage privilege
GRANT CREATE STAGE ON SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;

-- Grant create streamlit privilege
GRANT CREATE STREAMLIT ON SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;

-- Grant table privileges
GRANT CREATE TABLE ON SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON FUTURE TABLES IN SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;

-- Grant stage privileges
GRANT CREATE STAGE ON SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;

-- Grant stored procedure privileges  
GRANT CREATE PROCEDURE ON SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;
GRANT USAGE ON ALL PROCEDURES IN SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;
GRANT USAGE ON FUTURE PROCEDURES IN SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;

-- Task and warehouse privileges for scheduled revoke processing
GRANT CREATE TASK ON SCHEMA IDENTIFIER($app_schema_full) TO ROLE rbac_app_role;
GRANT USAGE ON WAREHOUSE IDENTIFIER($app_wh) TO ROLE rbac_app_role;
GRANT EXECUTE TASK ON ACCOUNT TO ROLE rbac_app_role;

-- Select a schema to create the tables and procedures
USE SCHEMA IDENTIFIER($app_schema_full);
USE ROLE rbac_app_role;

-- ============================================================================
-- TABLE DEFINITIONS
-- ============================================================================

-- Create logging table for all RBAC executions
CREATE OR REPLACE TABLE RBAC_LOG_EXECUTIONS (
    LOG_ID NUMBER AUTOINCREMENT,
    USER_NAME VARCHAR,
    EXE_TS_UTC TIMESTAMP_NTZ,
    QUERY VARCHAR,
    QUERY_ID VARCHAR,
    STATUS VARCHAR
);

-- Create request tracking table for scheduled revocations
CREATE OR REPLACE TABLE RBAC_REQUEST_EXECUTIONS (
    REQUEST_ID NUMBER AUTOINCREMENT,
    USER_NAME VARCHAR,
    END_TS_UTC TIMESTAMP_NTZ,
    QUERY VARCHAR,
    STATUS VARCHAR
);

-- ============================================================================
-- STORED PROCEDURE: SPROC_TEMP_GRANT
-- ============================================================================
-- Executes a GRANT statement and schedules its corresponding REVOKE
-- Parameters:
--   GRANT_SQL: The GRANT statement to execute
--   END_TIMESTAMP: When the REVOKE should be executed
--   USER_NAME: The name of the user making the request
-- ============================================================================

CREATE OR REPLACE PROCEDURE SPROC_TEMP_GRANT(GRANT_SQL VARCHAR, END_TIMESTAMP TIMESTAMP_LTZ, USER_NAME VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER -- required so that the SP is executed as rbac_app_role
AS
$$
DECLARE
    -- Custom exceptions
    invalid_semicolon_exception EXCEPTION (-20001, 'GRANT SQL must end in a semicolon');
    invalid_grant_sql_exception EXCEPTION (-20002, 'GRANT SQL is invalid. Must be one of: GRANT ROLE to ROLE, GRANT ROLE to USER, or GRANT USAGE ON WAREHOUSE');
    invalid_timestamp_exception EXCEPTION (-20003, 'Revocation time must be at least 5 minutes in the future');
    invalid_grant_role_exception EXCEPTION (-20004, 'GRANT ROLE/USER is not allowed to grant ADMIN roles');
    
    -- Variables
    current_user VARCHAR := :USER_NAME;
    current_ts TIMESTAMP_NTZ := SYSDATE()::TIMESTAMP_NTZ ; -- In UTC
    revoke_query VARCHAR;
    query_id_result VARCHAR;
    return_message VARCHAR;
    cleaned_sql VARCHAR;
    is_valid_grant BOOLEAN;
    
BEGIN

    -- Normalize whitespace
    cleaned_sql := REGEXP_REPLACE(UPPER(LTRIM(:GRANT_SQL)), '\\s+', ' ');

    -- Validation 0; ensure parameters are not NULL
    IF (:GRANT_SQL IS NULL) THEN
        RETURN 'RBAC APP ERROR: GRANT_SQL parameter cannot be NULL';
    END IF;
    
    IF (:END_TIMESTAMP IS NULL) THEN
        RETURN 'RBAC APP ERROR: END_TIMESTAMP parameter cannot be NULL';
    END IF;
    
    IF (:USER_NAME IS NULL OR TRIM(:USER_NAME) = '') THEN
        RETURN 'RBAC APP ERROR: USER_NAME parameter cannot be NULL or empty';
    END IF;
    
    -- Validation 1: Check semicolon count (Must include 1 and only 1 semicolon )
    IF (LENGTH(cleaned_sql) - LENGTH(REPLACE(cleaned_sql, ';', '')) != 1) THEN
        RAISE invalid_semicolon_exception;
    END IF;

    -- Validation 2: Check if GRANT_SQL matches one of the allowed patterns
    is_valid_grant := FALSE;

    -- Pattern 1: GRANT ROLE <role_name> TO ROLE <role_name>
    IF (REGEXP_LIKE(cleaned_sql, '^GRANT ROLE [A-Z0-9_]+ TO ROLE [A-Z0-9_]+\\;', 'i')) THEN
        is_valid_grant := TRUE;
    ELSEIF (REGEXP_LIKE(cleaned_sql, '^GRANT ROLE [A-Z0-9_]+ TO USER [A-Z0-9_@\\.\\-]+\\;', 'i')) THEN
        is_valid_grant := TRUE;
    ELSEIF (REGEXP_LIKE(cleaned_sql, '^GRANT USAGE ON WAREHOUSE [A-Z0-9_]+ TO ROLE [A-Z0-9_]+\\;', 'i')) THEN
        is_valid_grant := TRUE;
    ELSEIF (REGEXP_LIKE(cleaned_sql, '^GRANT USAGE ON WAREHOUSE [A-Z0-9_]+ TO USER [A-Z0-9_@\\.\\-]+\\;', 'i')) THEN
        is_valid_grant := TRUE;
    END IF;

    IF (NOT is_valid_grant) THEN
        RAISE invalid_grant_sql_exception;
    END IF;
    
    -- Validation 3: Check if END_TIMESTAMP is at least 5 minutes in the future (using UTC)
    IF (NOT DATEDIFF(minute, SYSDATE(), :END_TIMESTAMP) > 5) THEN
        RAISE invalid_timestamp_exception;
    END IF;

    -- Validation 4: Ensure GRANT ROLE/USER is not being used to grant ACCOUNTADMIN, SYSADMIN, SECURITYADMIN or USERADMIN
    IF (REGEXP_LIKE(cleaned_sql, '^GRANT ROLE ACCOUNTADMIN TO ROLE [A-Z0-9_]+\\;', 'i') OR
        REGEXP_LIKE(cleaned_sql, '^GRANT ROLE SYSADMIN TO ROLE [A-Z0-9_]+\\;', 'i') OR
        REGEXP_LIKE(cleaned_sql, '^GRANT ROLE SECURITYADMIN TO ROLE [A-Z0-9_]+\\;', 'i') OR
        REGEXP_LIKE(cleaned_sql, '^GRANT ROLE USERADMIN TO ROLE [A-Z0-9_]+\\;', 'i')) THEN
        RAISE invalid_grant_role_exception;
    ELSEIF (REGEXP_LIKE(cleaned_sql, '^GRANT ROLE ACCOUNTADMIN TO USER [A-Z0-9_@\\.\\-]+\\;', 'i') OR
        REGEXP_LIKE(cleaned_sql, '^GRANT ROLE SYSADMIN TO USER [A-Z0-9_@\\.\\-]+\\;', 'i') OR
        REGEXP_LIKE(cleaned_sql, '^GRANT ROLE SECURITYADMIN TO USER [A-Z0-9_@\\.\\-]+\\;', 'i') OR
        REGEXP_LIKE(cleaned_sql, '^GRANT ROLE USERADMIN TO USER [A-Z0-9_@\\.\\-]+\\;', 'i')) THEN
        RAISE invalid_grant_role_exception;
    END IF;

    -- Execute the GRANT_SQL
    BEGIN
    
        -- Create REVOKE query by replacing GRANT with REVOKE
        revoke_query := REGEXP_REPLACE(cleaned_sql, '^GRANT', 'REVOKE', 1, 1, 'i');
        -- and replace TO USER with FROM USER
        revoke_query := REGEXP_REPLACE(revoke_query, 'TO USER', 'FROM USER', 1, 1, 'i');
        -- and replace TO ROLE with FROM ROLE
        revoke_query := REGEXP_REPLACE(revoke_query, 'TO ROLE', 'FROM ROLE', 1, 1, 'i');
    
        EXECUTE IMMEDIATE GRANT_SQL;
        
        -- Get the query ID from the last executed statement
        query_id_result := SQLID;
        
        -- Log successful execution
        INSERT INTO RBAC_LOG_EXECUTIONS (USER_NAME, EXE_TS_UTC, QUERY, QUERY_ID, STATUS) 
        VALUES (:current_user, :current_ts, :cleaned_sql, :query_id_result, 'COMPLETED');
        
        
        -- Insert request for future revocation
        INSERT INTO RBAC_REQUEST_EXECUTIONS (USER_NAME, END_TS_UTC, QUERY, STATUS)
        VALUES (:current_user, CONVERT_TIMEZONE('UTC', :END_TIMESTAMP)::TIMESTAMP_NTZ, :revoke_query, 'PENDING');
        
        return_message := 'RBAC APP SUCCESS: GRANT executed and REVOKE scheduled.';
        
    EXCEPTION

        WHEN STATEMENT_ERROR THEN
            -- Log failed execution for SQL statement errors
            INSERT INTO RBAC_LOG_EXECUTIONS (USER_NAME, EXE_TS_UTC, QUERY, QUERY_ID, STATUS)
            VALUES (:current_user, :current_ts, :GRANT_SQL, '', 'ERROR');
            
            ROLLBACK;
            return_message := 'RBAC APP ERROR: GRANT statement failed - SQLCODE: ' || SQLCODE || ', Message: ' || SQLERRM;
        WHEN OTHER THEN
            -- Log failed execution for other errors
            INSERT INTO RBAC_LOG_EXECUTIONS (USER_NAME, EXE_TS_UTC, QUERY, QUERY_ID, STATUS)
            VALUES (:current_user, :current_ts, :GRANT_SQL, '', 'ERROR');
            
            ROLLBACK;
            return_message := 'RBAC APP ERROR: Unexpected error - SQLCODE: ' || SQLCODE || ', Message: ' || SQLERRM;
    END;
    
    RETURN return_message;
    
EXCEPTION
    WHEN invalid_semicolon_exception THEN
        RETURN 'RBAC APP ERROR: ' || SQLERRM;
    WHEN invalid_grant_sql_exception THEN
        RETURN 'RBAC APP ERROR: ' || SQLERRM;
    WHEN invalid_timestamp_exception THEN
        RETURN 'RBAC APP ERROR: ' || SQLERRM;
    WHEN invalid_grant_role_exception THEN
        RETURN 'RBAC APP ERROR: ' || SQLERRM;
    WHEN STATEMENT_ERROR THEN
        ROLLBACK;
        RETURN 'RBAC APP ERROR: Database statement error - SQLCODE: ' || SQLCODE || ', Message: ' || SQLERRM;
    WHEN OTHER THEN
        ROLLBACK;
        RETURN 'RBAC APP ERROR: Unexpected error - SQLCODE: ' || SQLCODE || ', Message: ' || SQLERRM;
END;
$$;


-- ============================================================================
-- STORED PROCEDURE: SPROC_TEMP_REVOKE
-- ============================================================================
-- Processes pending REVOKE requests that are due for execution
-- No parameters required
-- ============================================================================

CREATE OR REPLACE PROCEDURE SPROC_TEMP_REVOKE()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER -- required so that the SP is executed as rbac_app_role

AS
$$
DECLARE
    -- Custom exceptions
    revoke_processing_exception EXCEPTION (-20004, 'Error during REVOKE processing');
    
    -- Variables
    current_ts TIMESTAMP_NTZ ;

    pending_cursor CURSOR FOR 
        SELECT REQUEST_ID, QUERY, USER_NAME 
        FROM RBAC_REQUEST_EXECUTIONS 
        WHERE STATUS = 'PENDING' 
        AND END_TS_UTC <= ?;
    
    -- Variables for the cursor loop
    req_id NUMBER;
    revoke_query VARCHAR;
    original_user VARCHAR;

    query_id_result VARCHAR := '';
    revoke_status VARCHAR;
    request_status VARCHAR;
    processed_count NUMBER := 0;
    
BEGIN

    current_ts := SYSDATE()::TIMESTAMP_NTZ; -- In UTC

    -- Process each pending request
    OPEN pending_cursor USING (:current_ts);
    FOR record IN pending_cursor DO
        req_id := record.REQUEST_ID;
        revoke_query := record.QUERY;
        original_user := record.USER_NAME;
        
        -- Execute the REVOKE query
        BEGIN
            EXECUTE IMMEDIATE revoke_query;

            -- Get the query ID from the last executed statement
            query_id_result := SQLID;
        
            revoke_status := 'COMPLETED';
            request_status := 'COMPLETED';
            
        EXCEPTION
            WHEN STATEMENT_ERROR THEN
                revoke_status := 'ERROR';
                request_status := 'CANCELED';
                query_id_result := 'N/A';
            WHEN OTHER THEN
                revoke_status := 'ERROR';
                request_status := 'CANCELED';
                query_id_result := 'N/A';
        END;
        
        -- Log the execution attempt (use original requester, not task owner)
        INSERT INTO RBAC_LOG_EXECUTIONS (USER_NAME, EXE_TS_UTC, QUERY, QUERY_ID, STATUS)
        VALUES (:original_user, :current_ts, :revoke_query, :query_id_result, :revoke_status);
        
        -- Update the request status
        UPDATE RBAC_REQUEST_EXECUTIONS 
        SET STATUS = :request_status
        WHERE REQUEST_ID = :req_id;
        
        processed_count := processed_count + 1;
        
    END FOR;
    
    RETURN 'RBAC APP SUCCESS: REVOKE processing completed. Processed ' || processed_count || ' requests.';
    
EXCEPTION
    WHEN STATEMENT_ERROR THEN
        ROLLBACK;
        RETURN 'RBAC APP ERROR: REVOKE processing failed. Database statement error - SQLCODE: ' || SQLCODE || ', Message: ' || SQLERRM;
    WHEN OTHER THEN
        ROLLBACK;
        RETURN 'RBAC APP ERROR: REVOKE processing failed. Unexpected error - SQLCODE: ' || SQLCODE || ', Message: ' || SQLERRM;
END;
$$;


-- ============================================================================
-- TASK: RBAC_REVOKE_TASK (Runs SPROC_TEMP_REVOKE hourly)
-- ============================================================================

-- Run at the 55th minute of the hour
CREATE OR REPLACE TASK RBAC_REVOKE_TASK
    WAREHOUSE = IDENTIFIER($app_wh)
    SCHEDULE = 'USING CRON 5 * * * * UTC'
AS
CALL SPROC_TEMP_REVOKE();

ALTER TASK RBAC_REVOKE_TASK RESUME;

-- ============================================================================
-- END OF RBAC SOLUTION
-- ============================================================================
