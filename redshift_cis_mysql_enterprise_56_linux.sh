#!/bin/bash
# Redshift Cyber Security CIS MYSQL Enterprise 5.6 LinuxAudit Script
# Use following command to run this scipt 
# chmod +x redshift_cis_mysql_enterprise_56_linux.sh
# ./redshift_cis_mysql_enterprise_56_linux.sh
#
# requires root permissions on the database and the underlying OS
# This script creates a temporary mysql additional config file with the
# MySQL credentials stored in clear text. Please ensure this file is 
# successfully deleted when the script terminates
# 

DATENOW=$(date +"%m-%d-%Y")
REPORTHOME=/tmp/redshift/$DATENOW/CIS_MYSQL_COMMUNITY_5_6/
REPORT=/tmp/redshift/$DATENOW/CIS_MYSQL_COMMUNITY_5_6/report.txt
MYSQL_DEFAULTS_EXTRA_FILE=/tmp/redshift/$DATENOW/CIS_MYSQL_COMMUNITY_5_6/mycnf.cnf


# create folder structure for report output
mkdir -p $REPORTHOME

# Echo timestamp
echo "########### Redshift CIS MYSQL Enterprise 5.6 $(date) ###########"

# comment out lines 27 to 30 if you are absolutely sure the current user has the required permissions
if (( $UID != 0 )); then
  echo "Please run as root"
  exit
fi

for OUTPUT in $(find /etc -name my.cnf); do
  cp $OUTPUT $REPORTHOME
done

echo "########### Redshift CIS MYSQL Enterprise 5.6 $(date) ###########" > $REPORT
echo "Script executed with id: $(id)" >> $REPORT

echo "Enter your username for the MySQL Admin User";
read username;
echo "Enter password (Not shown or logged)";
unset password;
while IFS= read -r -s -n1 pass; do
  if [[ -z $pass ]]; then
     echo
     break
  else
     echo -n '*'
     password+=$pass
  fi
done

echo "MySQL User used is: $username" >> $REPORT


echo "[client]" > $MYSQL_DEFAULTS_EXTRA_FILE
echo "user=$username" >> $MYSQL_DEFAULTS_EXTRA_FILE
echo "password=$password" >> $MYSQL_DEFAULTS_EXTRA_FILE

PASSWORDISOK=`mysqladmin --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE ping | grep -c "mysqld is alive"`

if [ $PASSWORDISOK = 0 ]; then
  echo "MySQL credentials appear to be incorrect"
  echo "MySQL Authentication failure" >> $REPORT
  exit
fi

echo -e "\r\n--> Section 1 OS level config" >> $REPORT
echo -e "\r\n----> 1.1 Place Databases on Non-System Partitions" >> $REPORT
echo -e "\r\n------> MySQL directories\r\n" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name LIKE "%dir"' >> $REPORT
echo -e "\r\n------> System directories\r\n" >> $REPORT
df -h >> $REPORT

echo -e "\r\n----> 1.2 Use Dedicated Least Privileged Account for MySQL Daemon/Service" >> $REPORT
ps -ef | grep mysql >> $REPORT

echo -e "\r\n----> 1.3 Disable	MySQL Command History" >> $REPORT
find /home -name ".mysql_history" -xtype l
find /root -name ".mysql_history" -xtype l

echo -e "\r\n----> 1.4 Verify That the MYSQL_PWD Environment Variables Is Not In Use" >> $REPORT
grep MYSQL_PWD /proc/*/environ >> $REPORT

echo -e "\r\n----> 1.5 Disable interactive login" >> $REPORT
getent passwd >> $REPORT

echo -e "\r\n----> 1.6	Verify That 'MYSQL_PWD' Is Not Set In Users' Profiles" >> $REPORT
grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile} 
grep MYSQL_PWD /root/.{bashrc,profile,bash_profile} 

echo -e "\r\n--> Section 2 Backup and DR" >> $REPORT
echo -e "\r\n----> 2.1 backups and backup policies" >> $REPORT
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 2.2 Dedicated MySQL host" >> $REPORT
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 2.3 MySQL passwords are not passed in the commandline" >> $REPORT
grep mysql /home/*/.{bash_history} 
grep mysql /root/.{bash_history}

echo -e "\r\n----> 2.4 Account reuse" >> $REPORT
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 2.5 Dedicated cryptographic key use" >> $REPORT
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n--> Section 3 File System Permissions" >> $REPORT
echo -e "\r\n----> 3.1 Validate datadir permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "datadir"' --batch --skip-column-names |sed 's/datadir\t//g') >> $REPORT

echo -e "\r\n----> 3.2 Validate log_bin_basename permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "log_bin_basename"' --batch --skip-column-names |sed 's/log_bin_basename\t//g') >> $REPORT

echo -e "\r\n----> 3.3 Validate log_error permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "log_error"' --batch --skip-column-names |sed 's/log_error\t//g') >> $REPORT

echo -e "\r\n----> 3.4 Validate slow_query_log permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "slow_query_log"' --batch --skip-column-names |sed 's/slow_query_log\t//g') >> $REPORT

echo -e "\r\n----> 3.5 Validate relay_log_basename permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "relay_log_basename"' --batch --skip-column-names |sed 's/relay_log_basename\t//g') >> $REPORT

echo -e "\r\n----> 3.6 Validate general_log_file permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "general_log_file"' --batch --skip-column-names |sed 's/general_log_file\t//g') >> $REPORT

echo -e "\r\n----> 3.7 Validate ssl key permissions" >> $REPORT
##########May produce an error if the default / no key is in use
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "ssl_key"' --batch --skip-column-names |sed 's/ssl_key\t//g') >> $REPORT

echo -e "\r\n----> 3.8 Validate plugin_dir permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "plugin_dir"' --batch --skip-column-names |sed 's/plugin_dir\t//g') >> $REPORT

echo -e "\r\n----> 3.9 Validate audit_log_file permissions" >> $REPORT
ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "audit_log_file"' --batch --skip-column-names |sed 's/audit_log_file\t//g') >> $REPORT

echo -e "\r\n--> Section 4 General" >> $REPORT
echo -e "\r\n----> 4.1 Validate release version" >> $REPORT
#cross reference with:
#1. http://www.oracle.com/technetwork/topics/security/alerts-086861.html
#2. http://dev.mysql.com/doc/relnotes/mysql/5.6/en/
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "version"' >> $REPORT

echo -e "\r\n----> 4.2 Ensure test database is not installed" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW DATABASES LIKE "test"' >> $REPORT;

echo -e "\r\n----> 4.3 Ensure 'allow-suspicious-udfs' is not enabled" >> $REPORT
#see my.cnf files copied by this script as well
for OUTPUT in $(find /etc -name my.cnf); do
  grep allow-suspicious-udfs $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT

echo -e "\r\n----> 4.4 Ensure local_infile is disabled" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "local_infile"' >> $REPORT

echo -e "\r\n----> 4.5 Ensure mysql is not started with skip grant tables" >> $REPORT
#see my.cnf files copied by this script as well
for OUTPUT in $(find /etc -name my.cnf); do
  grep skip-grant-tables $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT

echo -e "\r\n----> 4.6 Ensure have_symlink is disabled" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "have_symlink"' >> $REPORT

echo -e "\r\n----> 4.7 Ensure daemon_memcached plugin is disabled" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME="daemon_memcached"' >> $REPORT

echo -e "\r\n----> 4.8 Ensure secure_file_priv is not empty" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES WHERE Variable_name = "secure_file_priv" AND Value<>""' >> $REPORT


echo -e "\r\n----> 4.9 Ensure sql_mode contains STRICT_ALL_TABLES" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES LIKE "sql_mode";' >> $REPORT

echo -e "\r\n--> Section 5 MySQL Permissions" >> $REPORT
echo -e "\r\n----> 5.1 Ensure only admins have full database access" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host FROM mysql.user WHERE (Select_priv = "Y") OR (Insert_priv = "Y") OR (Update_priv = "Y") OR (Delete_priv = "Y") OR (Create_priv = "Y") OR (Drop_priv = "Y");' >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host FROM mysql.db WHERE (Select_priv = "Y") OR (Insert_priv = "Y") OR (Update_priv = "Y") OR (Delete_priv = "Y") OR (Create_priv = "Y") OR (Drop_priv = "Y");' >> $REPORT

echo -e "\r\n----> 5.2 Ensure file_priv is not enabled for non admin users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where File_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.3 Ensure process_priv is not enabled for non admin users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Process_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.4 Ensure Super_priv is not enabled for non admin users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Super_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.5 Ensure Shutdown_priv is not enabled for non admin users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Shutdown_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.6 Ensure Create_user_priv is not enabled for non admin users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Create_user_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.7 Ensure grant_priv is not enabled for non admin users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Grant_priv = "Y";' >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.db where Grant_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.8 Ensure repl_slave_priv is not enabled for non admin users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Repl_slave_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.9 Ensure DML/DDL Grants Are Limited to specific databases and users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT User,Host,Db FROM mysql.db WHERE Select_priv="Y" OR Insert_priv="Y" OR Update_priv="Y" OR Delete_priv="Y" OR Create_priv="Y" OR Drop_priv="Y" OR Alter_priv="Y";' >> $REPORT

echo -e "\r\n--> Section 6 Auditing and logging" >> $REPORT
echo -e "\r\n----> 6.1 Ensure log_error is not empty" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW variables LIKE "log_error";' >> $REPORT

echo -e "\r\n----> 6.2 Ensure log files are stored on a non system partition" >> $REPORT
#Ensure	the	value	returned	does	not	indicate	root	('/'),	/var,	or	/usr.
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT @@global.log_bin_basename;' >> $REPORT
df -h >> $REPORT

echo -e "\r\n----> 6.3 Ensure log warnings is set to 2" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "log_warnings"; ' >> $REPORT

echo -e "\r\n----> 6.4 Ensure log_raw is set to off" >> $REPORT
#see my.cnf files copied by this script as well
for OUTPUT in $(find /etc -name my.cnf); do
  grep log_raw $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT

echo -e "\r\n----> 6.5 Ensure audit_log_connection_policy is not set to none" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW variables LIKE "%audit_log_connection_policy%";' >> $REPORT

echo -e "\r\n----> 6.6 Ensure audit_log_exclude_accounts is not set to NULL" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW variables LIKE "%audit_log_exclude_accounts%";' >> $REPORT

echo -e "\r\n----> 6.7 Ensure audit_log_include_accounts is not set to NULL" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW variables LIKE "%audit_log_include_accounts%";' >> $REPORT

echo -e "\r\n----> 6.8 Ensure audit_log_policy is set to log logins" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "audit_log_policy";' >> $REPORT

echo -e "\r\n----> 6.9 Ensure audit_log_policy is set to log logins and connections" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "audit_log_policy";' >> $REPORT

echo -e "\r\n----> 6.10 Ensure audit_log_statement_policy is set to ALL" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "audit_log_statement_policy";' >> $REPORT

echo -e "\r\n----> 6.11 Ensure audit_log_strategy is set to SYNCHRONOUS OR SEMISYNCHRONOUS" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "audit_log_strategy";' >> $REPORT

echo -e "\r\n----> 6.12 Ensure audit_log plugin cannot be unloaded" >> $REPORT
#audit_log = 'FORCE_PLUS_PERMANENT' 
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT LOAD_OPTION FROM information_schema.plugins WHERE PLUGIN_NAME="audit_log"; ' >> $REPORT

echo -e "\r\n--> Section 7 Authentication" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT * FROM mysql.user; ' >> $REPORT

echo -e "\r\n----> 7.1 Ensure 'old_passwords' Is Not Set to '1' or 'ON'" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_name = "old_passwords"; ' >> $REPORT

echo -e "\r\n----> 7.2 Ensure 'secure_auth' Is Set to 'ON'" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_name = "secure_auth"; ' >> $REPORT

echo -e "\r\n----> 7.3 Ensure passwords are not stored in the global config" >> $REPORT
#see my.cnf files copied by this script as well
for OUTPUT in $(find /etc -name my.cnf); do
  grep password $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT

echo -e "\r\n----> 7.4 Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT @@global.sql_mode; ' >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT @@session.sql_mode; ' >> $REPORT

echo -e "\r\n----> 7.5 Ensure passwords are set for all user accounts" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT User,host FROM mysql.user WHERE (plugin IN("mysql_native_password", "mysql_old_password") AND (LENGTH(Password) = 0 OR Password IS NULL)) OR (plugin="sha256_password" AND LENGTH(authentication_string) = 0); ' >> $REPORT

echo -e "\r\n----> 7.6 Ensure password policies are in place" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES LIKE "validate_password%";' >> $REPORT

echo -e "\r\n----> 7.7 Ensure no users have wildcard hostnames" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host FROM mysql.user WHERE host = "%";' >> $REPORT

echo -e "\r\n----> 7.8 Ensure no anonymous accounts exist" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user,host FROM mysql.user WHERE user = ""; ' >> $REPORT

echo -e "\r\n--> Section 8 Network" >> $REPORT
echo -e "\r\n----> 8.1 Ensure 'have_ssl' is set to YES" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW variables WHERE variable_name = "have_ssl"; ' >> $REPORT

echo -e "\r\n----> 8.2 Ensure 'ssl_type' is set to ANY, X509 or SPECIFIED for all remote users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ("::1", "127.0.0.1", "localhost"); ' >> $REPORT

echo -e "\r\n--> Section 9 Replication" >> $REPORT
echo -e "\r\n----> 9.1 Ensure Replication traffic is secured" >> $REPORT
echo -e "Manual check. ensure that replication traffic is using SSL, VPN, SSH Tunnel or on a private network">> $REPORT

echo -e "\r\n----> 9.2 Ensure master_info_repository is set to TABLE" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "master_info_repository"; ' >> $REPORT

echo -e "\r\n----> 9.3 Ensure MASTER_SSL_VERIFY_SERVER_CERT is set to YES or 1" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select ssl_verify_server_cert from mysql.slave_master_info;' >> $REPORT

echo -e "\r\n----> 9.4 Ensure Super_Priv is not set to YES for repl users" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where user="repl" and Super_priv = "Y"; ' >> $REPORT

echo -e "\r\n----> 9.5 Ensure no replication users have wildcard hostnames" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host FROM mysql.user WHERE user="repl" AND host = "%"' >> $REPORT


echo "deleting mysql authentication file stored at $MYSQL_DEFAULTS_EXTRA_FILE"
rm $MYSQL_DEFAULTS_EXTRA_FILE
echo "please ensure this file is deleted. Enter Y/N to confirm you have read this message"
read CONFIRMATION;
if [ $CONFIRMATION != "Y" ]; then
  echo "You have been warned"
  echo "MySQL Authentication file deletion warning not confirmed" >> $REPORT
fi
echo "please compress the /tmp/redshift directory and send it to your consultant"
echo "########### Redshift CIS MYSQL Enterprise 5.6 end :D ###########" >> $REPORT
exit
