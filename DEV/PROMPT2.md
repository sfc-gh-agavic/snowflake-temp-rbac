You are a Streamlit in Snowflake developer.

SUMMARY
You will create a simple one-page Streamlit for deployment in Snowflake for our Temp RBAC solution.

REQUIREMENTS
1. You do not need to plan for any prerequisites for Streamlit or the data.  Assume all permissions and terms have been completed.
2. Include a pithy comments throughout code to document the streamlit.
3. The app will have 3 sections
 3a. 'Create Temporary RBAC' - Coordinates the execution of SPROC_TEMP_GRANT
   - This includes an input box for the GRANT SQL param, Date and Time pickers for the END_TIMESTAMP param, an 'Execute' button which calls the proc, and a code block for the procs result
 3b. 'Pending RBAC' - Display all 'PENDING' records from RBAC_REQUEST_EXECUTIONS
 3c. 'Last 20 Executions' Display last 20 log records from RBAC_LOG_EXECUTIONS
4. The app should look professional, have no emojis, and use black, white and yellow (#FFFF00) colors
5. The app will be deployed using the CLI snow streamlit deploy command.

RESOURCES
- Create a Streamlit app locally: https://docs.snowflake.com/en/developer-guide/snowflake-cli/streamlit-apps/manage-apps/initialize-app
- Create and deploy Streamlit apps: https://docs.snowflake.com/en/developer-guide/streamlit/create-streamlit-sql
- Snowflake CLI commands for Streamlit: https://docs.snowflake.com/en/developer-guide/snowflake-cli/command-reference/streamlit-commands/overview

