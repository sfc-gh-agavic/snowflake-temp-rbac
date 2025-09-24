-- ============================================================================
-- RBAC EXCEPTION CASES TEST SUITE
-- ============================================================================
-- This script tests all exception cases for the Custom RBAC Solution
-- Run this after setting up the main rbac_solution.sql
-- ============================================================================

-- Set the same variables as main script
SET app_db = 'SANDBOX_DB';
SET app_schema = 'ADMIN';
SET app_schema_full = $app_db || '.' || $app_schema;

USE SCHEMA IDENTIFIER($app_schema_full);
USE ROLE rbac_app_role;

-- ============================================================================
-- TEST SETUP - Clear previous test data
-- ============================================================================
DELETE FROM RBAC_LOG_EXECUTIONS WHERE USER_NAME = CURRENT_USER();
DELETE FROM RBAC_REQUEST_EXECUTIONS WHERE USER_NAME = CURRENT_USER();

-- ============================================================================
-- SECTION 1: SPROC_TEMP_GRANT VALIDATION EXCEPTION TESTS
-- ============================================================================

-- Test Case 1.1: Invalid GRANT_SQL - doesn't start with GRANT
SELECT '=== TEST 1.1: Invalid GRANT_SQL - Not starting with GRANT ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'SELECT * FROM RBAC_LOG_EXECUTIONS;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 1.2: Invalid GRANT_SQL - starts with REVOKE instead of GRANT
SELECT '=== TEST 1.2: Invalid GRANT_SQL - Starts with REVOKE ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'REVOKE ROLE test_role FROM USER test_user;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 1.3: Invalid semicolon count - no semicolon
SELECT '=== TEST 1.3: Invalid semicolon count - No semicolon ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE test_role TO USER test_user',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 1.4: Invalid semicolon count - multiple semicolons
SELECT '=== TEST 1.4: Invalid semicolon count - Multiple semicolons ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE test_role TO USER test_user; SELECT 1;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 1.5: Invalid GRANT pattern - unsupported GRANT type
SELECT '=== TEST 1.5: Invalid GRANT pattern - Unsupported GRANT type ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT SELECT ON TABLE test_table TO ROLE test_role;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 1.6: Invalid GRANT pattern - malformed ROLE grant
SELECT '=== TEST 1.6: Invalid GRANT pattern - Malformed ROLE grant ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE TO USER test_user;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 1.7: Invalid GRANT pattern - malformed WAREHOUSE grant
SELECT '=== TEST 1.7: Invalid GRANT pattern - Malformed WAREHOUSE grant ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT USAGE WAREHOUSE test_wh TO ROLE test_role;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 1.8: Invalid timestamp - past timestamp
SELECT '=== TEST 1.8: Invalid timestamp - Past timestamp ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE test_role TO USER test_user;',
    (DATEADD(MINUTE, -5, LOCALTIMESTAMP()))
);

-- Test Case 1.9: Invalid timestamp - less than 5 minutes in future
SELECT '=== TEST 1.9: Invalid timestamp - Less than 5 minutes future ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE test_role TO USER test_user;',
    DATEADD(MINUTE, 3, LOCALTIMESTAMP())
);

-- Test Case 1.10: Invalid timestamp - exactly current time
SELECT '=== TEST 1.10: Invalid timestamp - Current time ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE test_role TO USER test_user;',
    LOCALTIMESTAMP()
);

-- ============================================================================
-- SECTION 2: SPROC_TEMP_GRANT SQL EXECUTION EXCEPTION TESTS
-- ============================================================================

-- Test Case 2.1: Valid format but non-existent role
SELECT '=== TEST 2.1: SQL Execution Error - Non-existent role ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE non_existent_role_12345 TO USER test_user;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 2.2: Valid format but non-existent user
SELECT '=== TEST 2.2: SQL Execution Error - Non-existent user ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE rbac_app_role TO USER non_existent_user_12345;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 2.3: Valid format but non-existent warehouse
SELECT '=== TEST 2.3: SQL Execution Error - Non-existent warehouse ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT USAGE ON WAREHOUSE non_existent_warehouse_12345 TO ROLE rbac_app_role;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Test Case 2.4: Ensure GRANT ROLE/USER is not being used to grant ACCOUNTADMIN, SYSADMIN, SECURITYADMIN or USERADMIN

SELECT '=== TEST 2.4: SQL Execution Error - GRANT ROLE/USER is not allowed to grant ACCOUNTADMIN, SYSADMIN, SECURITYADMIN or USERADMIN ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE ACCOUNTADMIN TO ROLE rbac_app_role;',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- ============================================================================
-- SECTION 3: EDGE CASES AND BOUNDARY CONDITION TESTS
-- ============================================================================

-- Test Case 3.1: NULL grant
SELECT '=== TEST 3.1: Edge Case - NULL GRANT_SQL ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT(NULL, DATEADD(MINUTE, 10, LOCALTIMESTAMP()));

-- Test Case 3.2: NULL timestamp
SELECT '=== TEST 3.2: Edge Case - NULL timestamp ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT('GRANT ROLE test_role TO USER test_user;', NULL);

-- Test Case 3.3: Empty string parameters
SELECT '=== TEST 3.3: Edge Case - Empty GRANT_SQL ===' as TEST_CASE;
CALL SPROC_TEMP_GRANT('', DATEADD(MINUTE, 10, LOCALTIMESTAMP()));

-- ============================================================================
-- SECTION 4: FULL TEST OF SPROC GRANT AND REVOKE
-- ============================================================================

-- First, create some test data for revoke testing
-- Create valid grants that will succeed
SELECT '=== SETUP: Creating test data for REVOKE tests ===' as TEST_CASE;
CREATE ROLE IF NOT EXISTS test_revoke_role_1;
CALL SPROC_TEMP_GRANT(
    'GRANT ROLE test_revoke_role_1 TO USER ' || CURRENT_USER() || ';',
    DATEADD(MINUTE, 10, LOCALTIMESTAMP())
);

-- Verify the revokerequest is there
SELECT 'Pending requests before REVOKE call:' as INFO, * 
FROM RBAC_REQUEST_EXECUTIONS ;

-- Now run the REVOKE procedure 
SELECT '=== Running SPROC_TEMP_REVOKE  ===' as TEST_CASE;
CALL SPROC_TEMP_REVOKE();

-- Verify the request is still pending (timestamp is in future)
SELECT * FROM RBAC_REQUEST_EXECUTIONS ;

-- ============================================================================
-- SECTION 5: VERIFY ERROR LOGGING
-- ============================================================================

SELECT '=== ERROR LOGGING VERIFICATION ===' as TEST_CASE;

-- Show all logged errors from our tests
SELECT *
FROM RBAC_LOG_EXECUTIONS 
ORDER BY LOG_ID DESC;


-- ============================================================================
-- SECTION 6: CLEANUP TEST DATA
-- ============================================================================

SELECT '=== CLEANING UP TEST DATA ===' as TEST_CASE;

-- Clean up test roles
DROP ROLE IF EXISTS test_revoke_role_1;

-- Clean up test logs 
DELETE FROM RBAC_LOG_EXECUTIONS WHERE USER_NAME = CURRENT_USER();
DELETE FROM RBAC_REQUEST_EXECUTIONS WHERE USER_NAME = CURRENT_USER();

-- ============================================================================
-- END OF EXCEPTION TESTING SUITE
-- ============================================================================
