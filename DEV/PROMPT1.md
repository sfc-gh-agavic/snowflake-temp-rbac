You are a Snowflake developer and will help create a custom RBAC solution into a single .SQL file. Create a RREADME.md file to summarize the solution.

# REQUIREMENTS

## 1. Create a table RBAC_LOG_EXECUTIONS. It contains 5 fields. 
    LOG_ID (NUMBER AUTOINCREMENT), USER_NAME (VARCHAR), EXE_TS_UTC (TIMESTAMP_NTZ), QUERY (VARCHAR), QUERY_ID (VARCHAR), STATUS (VARCHAR)

## 2. Create a table RBAC_REQUEST_EXECUTIONS. It contains 5 fields
    REQUEST_ID (NUMBER AUTOINCREMENT), USER_NAME (VARCHAR), END_TS_UTC (TIMESTAMP_NTZ), QUERY (VARCHAR), STATUS (VARCHAR)

## 3. You will create stored producure SPROC_TEMP_GRANT that accepts two parameters: GRANT_SQL (VARCHAR) and a END_TIMESTAMP (TIMESTAMP_LTZ)

### 3a. The proc will execute three queries as part of a transaction.
 3a.1. Execute the user provided GRANT_SQL query.
 3a.2. INSERT a log record into RBAC_LOG_EXECUTIONS.  Must include values for all fields.
   USER_NAME is the current user
   EXE_TS_UTC is the current timestamp as UTC
   QUERY is the GRANT_SQL param
   QUERY_ID passed from the prior GRANT_SQL query (if available)
   STATUS is 'COMPLETED' or 'ERROR', depending on result of GRANT_SQL execution
 3a.3. INSERT a request record in RBAC_REQUEST_EXECUTIONS. Must include all values for all fields.
   USER_NAME is the current user
   END_TS_UTC is the END_TIMESTAMP param
   QUERY is the GRANT_SQL statement but with the initial function word "GRANT" replaced with "REVOKE"
   STATUS = 'PENDING'

### 3b. The proc will use standard Snowflake Scripting blocks, including EXCEPTION

### 3c. The proc will include error handling. 
 - GRANT_SQL string must start with "GRANT" (upper and lower case ok), else raise an exception and then exit.
 - GRANT_SQL string must contain one ";" ONLY (single semi colon), else raise an exception and then exit.
 - END_TIMESTAMP must be a valid Snowflake database timestamp 5 minutes or more in the future, else raise an exception and then exit.
 - If the execution of GRANT_SQL fails or throws its own error, log the error in RBAC_LOG_EXECUTIONS and then exit.
 - If any other error occurs, a generic handler should return the Snowflake error.

### 3d. The proc will return on of two messages depending on the result
- "RBAC SUCCESS: GRANT executed and REVOKE scheduled for: <END_TIMESTAMP>" with END_TIMESTAMP being the actual timestamp value
- "RBAC ERROR: <HANDLER_ERROR>" with the HANDLER_ERROR show the actual throw error.


## 4. You will create stored producure SPROC_TEMP_REVOKE that has no parameters
### 4a. The proc will execute four queries as part of a transaction
 4a.1 Review RBAC_REQUEST_EXECUTIONS where STATUS = 'PENDING' and END_TS_UTC is prior to CURRENT_TIMESTAMP (in UTC)
 4a.2 Loop through the log results and execute each QUERY from the request record
 4a.3 Before moving to next record in the loop, INSERT a log record into RBAC_LOG_EXECUTIONS.  Must include values for all fields.
   USER_NAME is the user who submitted the original GRANT
   EXE_TS_UTC is the current timestamp as UTC
   QUERY is the QUERY value from the request record
   QUERY_ID passed from the prior request query (if available)
   STATUS is 'COMPLETED' or 'ERROR', depending on result of QUERY execution
 4a.4 Before moving to next record in the loop, UPDATE the corresponding request record in RBAC_REQUEST_EXECUTIONS based on REQUEST_ID. Only the STATUS field is updated.
   STATUS = 'COMPLETED' or 'CANCELED', depending on result of QUERY execution

# RESOURCES
1. https://docs.snowflake.com/en/developer-guide/snowflake-scripting/blocks
2. https://docs.snowflake.com/en/developer-guide/snowflake-scripting/exceptions 
