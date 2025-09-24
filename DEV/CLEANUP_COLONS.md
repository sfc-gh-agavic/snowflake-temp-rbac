Review the use of colons in this script @rbac_solution.sql  for parameters and variables.
Note:
- Variables must be declared before use
- When using parameters within SQL statements in your stored procedure, prefix the parameter name with a colon (:)
- When using variables in SQL statements, prefix the variable name with a colon (:)
- When using variables in expressions or with Snowflake Scripting language elements (like RETURN), you do not need the colon prefix
- When using a variable as an object name (like a table name), use the IDENTIFIER keyword
- When using local variables directly in CURSOR definitions use the question mark placeholder with the USING clause.  For example.
LET c1 CURSOR for select ? as c1;
  open c1 USING (:val);  -- Use USING clause instead
  for record IN c1 DO
    req_id := record.REQUEST_ID;
  end for;