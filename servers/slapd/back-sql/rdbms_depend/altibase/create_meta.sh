is -f user_create.sql
isql -s 127.0.0.1 -u ldap -p ldap -f backsql_create.sql
isql -s 127.0.0.1 -u ldap -p ldap -f testdb_create.sql
isql -s 127.0.0.1 -u ldap -p ldap -f testdb_metadata.sql
isql -s 127.0.0.1 -u ldap -p ldap -f testdb_data.sql
