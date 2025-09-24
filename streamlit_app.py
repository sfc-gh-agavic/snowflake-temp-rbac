import streamlit as st
import pandas as pd
from datetime import datetime, timedelta, time
from snowflake.snowpark.context import get_active_session
import time as time_module

# Configure page settings
st.set_page_config(
    page_title="Temporary RBAC Management",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for professional styling with black, white, and yellow theme
st.markdown("""
<style>
    /* Main app styling */
    .main {
        background-color: white;
    }
    
    /* Header styling */
    .main-header {
        background-color: black;
        color: white;
        padding: 1rem;
        margin: -1rem -1rem 2rem -1rem;
        text-align: center;
        border-bottom: 4px solid #FFFF00;
    }
    
    /* Section headers */
    .section-header {
        background-color: #FFFF00;
        color: black;
        padding: 0.5rem 1rem;
        margin: 1rem 0;
        font-weight: bold;
        border-radius: 4px;
    }
    
    /* Success message styling */
    .success-message {
        background-color: #FFFF00;
        color: black;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
        border: 2px solid black;
    }
    
    /* Error message styling */
    .error-message {
        background-color: #ffebee;
        color: #c62828;
        padding: 1rem;
        border-radius: 4px;
        margin: 1rem 0;
        border: 2px solid #c62828;
    }
    
    /* Button styling */
    .stButton > button {
        background-color: black;
        color: white;
        border: 2px solid #FFFF00;
        border-radius: 4px;
        font-weight: bold;
    }
    
    .stButton > button:hover {
        background-color: #FFFF00;
        color: black;
        border: 2px solid black;
    }
    
    /* Table styling */
    .dataframe {
        border: 2px solid black;
    }
    
    /* Input field styling */
    .stTextInput > div > div > input {
        border: 2px solid black;
    }
    
    .stTextArea > div > div > textarea {
        border: 2px solid black;
    }
</style>
""", unsafe_allow_html=True)

def get_snowflake_session():
    """Get the active Snowflake session"""
    try:
        return get_active_session()
    except Exception as e:
        st.error(f"Failed to connect to Snowflake: {str(e)}")
        return None

def get_current_user():
    """Get the current user accessing the Streamlit app"""
    try:
        # In Snowflake native Streamlit apps, use st.user to get the actual user
        if hasattr(st, 'user') and st.user:
            # Try different user attributes that might be available
            if hasattr(st.user, 'email') and st.user.email:
                return st.user.email
            elif hasattr(st.user, 'user_name') and st.user.user_name:
                return st.user.user_name
            elif hasattr(st.user, 'name') and st.user.name:
                return st.user.name
            else:
                # Fallback: convert st.user to string to see what's available
                return str(st.user)
        
        return None
    except Exception as e:
        st.error(f"Failed to get current user: {str(e)}")
        return None

def execute_temp_grant(grant_sql, end_timestamp, user_override=None):
    """Execute the SPROC_TEMP_GRANT stored procedure"""
    session = get_snowflake_session()
    if not session:
        return "ERROR: Could not establish Snowflake session"
    
    # Get the current user (use override if provided)
    current_user = user_override if user_override else get_current_user()
    if not current_user:
        return "ERROR: Could not determine current user"
    
    try:
        # Call the stored procedure with the current user
        result = session.call('SPROC_TEMP_GRANT', grant_sql, end_timestamp, current_user)
        return result
    except Exception as e:
        return f"ERROR: {str(e)}"

def get_last_revocation_requests():
    """Retrieve the last 20 revocation requests"""
    session = get_snowflake_session()
    if not session:
        return pd.DataFrame()
    
    try:
        # Query last 20 revocation requests
        query = """
        SELECT REQUEST_ID, USER_NAME, END_TS_UTC, QUERY, STATUS
        FROM RBAC_REQUEST_EXECUTIONS
        ORDER BY END_TS_UTC DESC
        LIMIT 20
        """
        result = session.sql(query).to_pandas()
        return result
    except Exception as e:
        st.error(f"Error retrieving revocation requests: {str(e)}")
        return pd.DataFrame()

def get_last_executions():
    """Retrieve the last 20 execution log records"""
    session = get_snowflake_session()
    if not session:
        return pd.DataFrame()
    
    try:
        # Query last 20 executions
        query = """
        SELECT LOG_ID, USER_NAME, EXE_TS_UTC, QUERY, QUERY_ID, STATUS
        FROM RBAC_LOG_EXECUTIONS
        ORDER BY EXE_TS_UTC DESC
        LIMIT 20
        """
        result = session.sql(query).to_pandas()
        return result
    except Exception as e:
        st.error(f"Error retrieving execution logs: {str(e)}")
        return pd.DataFrame()

def update_request_end_time(request_id):
    """Update the END_TS_UTC for a specific REQUEST_ID to current UTC time"""
    session = get_snowflake_session()
    if not session:
        return "ERROR: Could not establish Snowflake session"
    
    try:
        # Update the END_TS_UTC to current UTC time (rounded to current minute)
        current_utc = datetime.utcnow().replace(second=0, microsecond=0)
        
        query = f"""
        UPDATE RBAC_REQUEST_EXECUTIONS 
        SET END_TS_UTC = '{current_utc.strftime('%Y-%m-%d %H:%M:%S')}'::TIMESTAMP_NTZ
        WHERE REQUEST_ID = {request_id}
        """
        
        session.sql(query).collect()
        return f"SUCCESS: Request ID {request_id} end time updated to current UTC time"
    except Exception as e:
        return f"ERROR: Failed to update request end time: {str(e)}"

def execute_temp_revoke():
    """Execute the SPROC_TEMP_REVOKE stored procedure"""
    session = get_snowflake_session()
    if not session:
        return "ERROR: Could not establish Snowflake session"
    
    try:
        # Call the stored procedure
        result = session.call('SPROC_TEMP_REVOKE')
        return f"{result}"
    except Exception as e:
        return f"ERROR: Failed to execute SPROC_TEMP_REVOKE: {str(e)}"

# Get user's timezone from Streamlit context
user_timezone = st.context.timezone

# Get current user for display
current_user = get_current_user()

# Main application header
st.markdown('<div class="main-header"><h1>Temporary RBAC Management System</h1></div>', unsafe_allow_html=True)

# Display current user info and time
if current_user:
    current_time = datetime.now()
    st.markdown(
        f'<div style="display: flex; justify-content: space-between; color: #666; font-size: 0.9em; margin-bottom: 1rem;">'
        f'<span>Logged in as: <strong>{current_user}</strong></span>'
        f'<span>Current local time: <strong>{current_time.strftime("%Y-%m-%d %H:%M:%S")}</strong></span>'
        f'</div>',
        unsafe_allow_html=True
    )
else:
    st.warning("⚠️ Could not determine current user. Some features may not work correctly.")
    
    # Debug information to help troubleshoot
    with st.expander("Debug: User Context Information"):
        st.write("**st.user availability:**", hasattr(st, 'user'))
        if hasattr(st, 'user'):
            st.write("**st.user value:**", st.user)
            if st.user:
                st.write("**st.user attributes:**", dir(st.user))

# Section 1: Create Temporary RBAC
st.markdown('<div class="section-header">Create Temporary RBAC</div>', unsafe_allow_html=True)

with st.container():
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Initialize grant SQL in session state if not exists
        if 'grant_sql_value' not in st.session_state:
            st.session_state.grant_sql_value = ""
        
        # Input for GRANT SQL
        grant_sql = st.text_area(
            "GRANT SQL Statement",
            value=st.session_state.grant_sql_value,
            placeholder="Enter your GRANT statement here",
            height=75,
            help="""Enter a supported GRANT statement:
- `GRANT ROLE <role_name> TO ROLE <role_name>;`
- `GRANT ROLE <role_name> TO USER <user_name>;`
- `GRANT USAGE ON WAREHOUSE <warehouse_name> TO ROLE <role_name>;`
- `GRANT USAGE ON WAREHOUSE <warehouse_name> TO USER <user_name>;`"""
        )
        
        
        # Update session state with current value
        st.session_state.grant_sql_value = grant_sql
    
    with col2:
        # Date and time pickers for END_TIMESTAMP
        st.write("**Revocation Schedule**")
        
        # Default to 1 hour from now
        default_datetime = datetime.now() + timedelta(hours=1)
        
        end_date = st.date_input(
            "End Date",
            value=default_datetime.date(),
            min_value=datetime.now().date(),
            help="Select the date when the grant should be revoked"
        )
        
        # Create hourly time options (00:00 to 23:00)
        time_options = [f"{hour:02d}:00" for hour in range(24)]
        
        # Use the hour from default_datetime as the default index
        default_hour_index = default_datetime.hour
        
        end_time_str = st.selectbox(
            "End Time",
            options=time_options,
            index=default_hour_index,
            placeholder="Select an hour",
            help="Select the hour when the grant should be revoked"
        )
        
        # Convert selected time string to time object
        end_time = None
        if end_time_str:
            hour = int(end_time_str.split(':')[0])
            end_time = time(hour, 0)

# Combine date and time
if end_date and end_time:
    end_timestamp = datetime.combine(end_date, end_time)
    
# Execute button and result display
col1, col2 = st.columns([1, 3])

with col1:
    execute_button = st.button("Execute GRANT", type="primary")

with col2:
    if execute_button:
        if not grant_sql.strip():
            st.error("Please enter a GRANT SQL statement")
        elif not current_user:
            st.error("Could not determine current user. User detection is required for RBAC operations.")
        else:
            # Execute the stored procedure
            with st.spinner("Executing GRANT statement..."):
                result = execute_temp_grant(grant_sql, end_timestamp, current_user)
            
            # Display result
            if result and "SUCCESS" in result:
                st.markdown(f'<div class="success-message">{result}</div>', unsafe_allow_html=True)
                # Clear the grant SQL text area on success
                st.session_state.grant_sql_value = ""
                # Wait 3 seconds before rerun to let user see the success message
                time_module.sleep(3)
                st.rerun()
            else:
                st.markdown(f'<div class="error-message">{result}</div>', unsafe_allow_html=True)

# Section 2: Last 20 Revocation Requests
st.markdown('<div class="section-header">Last 20 Revocation Requests</div>', unsafe_allow_html=True)

with st.container():
    # Refresh button for revocation requests
    if st.button("Refresh Revocation Requests"):
        st.rerun()
    
    # Get and display last 20 revocation requests
    revocation_df = get_last_revocation_requests()
    
    if not revocation_df.empty:
        # Add column headers
        col1, col2, col3, col4, col5, col6 = st.columns([1, 2, 2, 3, 1, 1])
        with col1:
            st.write("**Request ID**")
        with col2:
            st.write("**User**")
        with col3:
            st.write("**Scheduled Revocation (local time)**")
        with col4:
            st.write("**Revoke Query**")
        with col5:
            st.write("**Status**")
        with col6:
            st.write("**Action**")
        st.markdown("---")
        
        # Display the dataframe with revoke buttons
        for index, row in revocation_df.iterrows():
            request_id = row['REQUEST_ID']
            user_name = row['USER_NAME']
            end_ts_utc = row['END_TS_UTC']
            query = row['QUERY']
            status = row['STATUS']
            
            # Create columns for the row data and button
            col1, col2, col3, col4, col5, col6 = st.columns([1, 2, 2, 3, 1, 1])
            
            with col1:
                st.write(f"**{request_id}**")
            
            with col2:
                st.write(user_name)
            
            with col3:
                # Format the datetime for display in local timezone
                if pd.notna(end_ts_utc):
                    # Convert UTC timestamp to local timezone
                    utc_time = pd.to_datetime(end_ts_utc, utc=True)
                    local_time = utc_time.tz_convert(user_timezone)
                    formatted_time = local_time.strftime('%Y-%m-%d %H:%M:%S')
                    st.write(formatted_time)
                else:
                    st.write("N/A")
            
            with col4:
                # Truncate long queries for display
                display_query = query[:50] + "..." if len(query) > 50 else query
                st.write(display_query)
            
            with col5:
                st.write(status)
            
            with col6:
                # Only show "Revoke Now" button for pending requests
                if status == 'PENDING':
                    # Create unique key for each button
                    button_key = f"revoke_now_{request_id}"
                    
                    if st.button("Revoke Now", key=button_key, type="secondary"):
                        # Store the request_id in session state for processing
                        st.session_state[f'revoke_request_{request_id}'] = True
                        st.rerun()
                else:
                    # Leave cell blank for completed requests
                    st.write("")
            
            # Check if this request should be processed
            if st.session_state.get(f'revoke_request_{request_id}', False):
                with st.spinner(f"Processing revocation for Request ID {request_id}..."):
                    # Step 1: Update the END_TS_UTC to current time
                    update_result = update_request_end_time(request_id)
                    
                    if "SUCCESS" in update_result:
                        # Step 2: Execute SPROC_TEMP_REVOKE
                        revoke_result = execute_temp_revoke()
                        
                        if "SUCCESS" in revoke_result:
                            # Store success message in session state
                            st.session_state[f'revoke_message_{request_id}'] = {
                                'type': 'success',
                                'message': f'✅ Request ID {request_id} successfully revoked!<br>{revoke_result}'
                            }
                        else:
                            # Store error message in session state
                            st.session_state[f'revoke_message_{request_id}'] = {
                                'type': 'error',
                                'message': f'❌ Failed to execute revocation procedure:<br>{update_result}<br>{revoke_result}'
                            }
                    else:
                        # Store error message in session state
                        st.session_state[f'revoke_message_{request_id}'] = {
                            'type': 'error',
                            'message': f'❌ Failed to update request end time:<br>{update_result}'
                        }
                
                # Clear the request flag
                del st.session_state[f'revoke_request_{request_id}']
                
                # Auto-refresh to show updated data
                st.rerun()
        
        st.markdown("---")
        # Count pending vs completed requests
        pending_count = len(revocation_df[revocation_df['STATUS'] == 'PENDING'])
        st.info(f"Showing {len(revocation_df)} revocation request(s): {pending_count} pending")
    else:
        st.info("No revocation requests found")

# Display any stored revocation messages
for key in list(st.session_state.keys()):
    if key.startswith('revoke_message_'):
        message_data = st.session_state[key]
        if message_data['type'] == 'success':
            st.markdown(f'<div class="success-message">{message_data["message"]}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="error-message">{message_data["message"]}</div>', unsafe_allow_html=True)
        
        # Add a dismiss button for the message
        request_id = key.replace('revoke_message_', '')
        if st.button(f"Dismiss", key=f"dismiss_{request_id}"):
            del st.session_state[key]
            st.rerun()

# Section 3: Last 20 Executions
st.markdown('<div class="section-header">Last 20 Executions</div>', unsafe_allow_html=True)

with st.container():
    # Refresh button for execution logs
    if st.button("Refresh Execution Logs"):
        st.rerun()
    
    # Get and display last 20 executions
    executions_df = get_last_executions()
    
    if not executions_df.empty:
        st.dataframe(
            executions_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "LOG_ID": "Log ID",
                "USER_NAME": "User",
                "EXE_TS_UTC": st.column_config.DatetimeColumn(
                    "Execution Time (local time)",
                    format="YYYY-MM-DD HH:mm:ss",
                    timezone=user_timezone
                ),
                "QUERY": "SQL Query",
                "QUERY_ID": "Query ID",
                "STATUS": st.column_config.TextColumn(
                    "Status",
                    help="COMPLETED = Success, ERROR = Failed"
                )
            }
        )
        
        st.info(f"Showing {len(executions_df)} recent execution(s)")
    else:
        st.info("No execution logs found")

# Footer
st.markdown("---")
st.markdown(
    '<div style="text-align: center; color: #666; font-size: 0.8em;">'
    'Temporary RBAC Management System | Built with Streamlit for Snowflake'
    '</div>',
    unsafe_allow_html=True
)
