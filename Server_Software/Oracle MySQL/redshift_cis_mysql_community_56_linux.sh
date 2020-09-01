#!/bin/bash
# Redshift Cyber Security CIS MYSQL Community 5.6 LinuxAudit Script
# Use following command to run this scipt 
# chmod +x redshift_cis_mysql_community_56_linux.sh
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
echo "########### Redshift CIS MYSQL Community 5.6 $(date) ###########"

# comment out lines 27 to 30 if you are absolutely sure the current user has the required permissions
if (( $UID != 0 )); then
  echo "Please run as root"
  exit
fi

for OUTPUT in $(find /etc -name my.cnf); do
  cp $OUTPUT $REPORTHOME
done

echo "########### Redshift CIS MYSQL Community 5.6 $(date) ###########" > $REPORT
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
#

#Description:
#It is generally accepted that host operating systems should include different filesystem
#partitions for different purposes. One set of filesystems are typically called "system
#partitions", and are generally reserved for host system/application operation. The other
#set of filesystems are typically called "non-system partitions", and such locations are
#generally reserved for storing data.

#Rationale:
#Moving the database off the system partition will reduce the probability of denial of service
#via the exhaustion of available disk space to the operating system.

#Remediation:
#Perform the following steps to remediate this setting:
#1.Choose a non-system partition new location for the MySQL data
#2. Stop mysqld using a command like: service mysql stop
#3. Copy the data using a command like: cp -rp <datadir Value> <new location>
#4. Set the datadir location to the new location in the MySQL configuration file
#5. Start mysqld using a command like: service mysql start
#NOTE: On some Linux distributions you may need to additionally modify apparmor
#settings. For example, on a Ubuntu 14.04.1 system edit the file
#/etc/apparmor.d/usr.sbin.mysq so that the datadir access is appropriate. The
#original might look like this:

# Allow data dir access
#/var/lib/mysql/ r,
#/var/lib/mysql/** rwk,

#Alter those two paths to be the new location you chose above. For example, if that new
#location were /media/mysql , then the /etc/apparmor.d/usr.sbin.mysqld file should
#include something like this:
# Allow data dir access
#/media/mysql/ r,
#/media/mysql/** rwk,

#Impact:
#Moving the database to a non-system partition may be difficult depending on whether
#there was only a single partition when the operating system was set up and whether there
#is additional storage available.

echo -e "\r\n------> MySQL directories\r\n" >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name LIKE "%dir"' >> $REPORT
echo -e "\r\n------> System directories\r\n" >> $REPORT
df -h >> $REPORT

echo -e "\r\n----> 1.2 Use Dedicated Least Privileged Account for MySQL Daemon/Service" >> $REPORT

#Description:
#As with any service installed on a host, it can be provided with its own user
#context. Providing a dedicated user to the service provides the ability to precisely
#constrain the service within the larger host context.
#Rationale:
#Utilizing a least privilege account for MySQL to execute as may reduce the impact of a
#MySQL-born vulnerability. A restricted account will be unable to access resources
#unrelated to MySQL, such as operating system configurations.

#Rationale:
#Utilizing a least privilege account for MySQL to execute as may reduce the impact of a
#MySQL-born vulnerability. A restricted account will be unable to access resources
#unrelated to MySQL, such as operating system configurations.

#Remediation:
#Create a user which is only used for running MySQL and directly related processes. This
#user must not have administrative rights to the system.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/changing-mysql-user.html
#2. http://dev.mysql.com/doc/refman/


ps -ef | grep mysql >> $REPORT

echo -e "\r\n----> 1.3 Disable	MySQL Command History" >> $REPORT

#Description:
#On Linux/UNIX, the MySQL client logs statements executed interactively to a history
#file. By default, this file is named .mysql_history in the user's home directory. Most
#interactive commands run in the MySQL client application are saved to a history file. The
#MySQL command history should be disabled.

#Rationale:
#Disabling the MySQL command history reduces the proba

#Remediation:
#Perform the following steps to remediate this setting:
#1. Remove .mysql_history if it exists.
#2. Use either of the techniques below to prevent it from being created again:
#1. Set the MYSQL_HISTFILE environment variable to /dev/null. This
#will need to be placed in the shell's startup script.
#2. Create $HOME/.mysql_history as a symbolic to /dev/null .
#> ln -s /dev/null $HOME/.mysql_history
#Default Value:
#By default, the MySQL command history file is located in $HOME/.mysql_history .

#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/m

find /home -name ".mysql_history" -xtype l
find /root -name ".mysql_history" -xtype l

echo -e "\r\n----> 1.4 Verify That the MYSQL_PWD Environment Variables Is Not In Use" >> $REPORT

#Description:
#MySQL can read a default database password from an environment variable called
#MYSQL_PWD .

#Rationale:
#The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL
#credentials. Avoiding this may increase assurance that the confidentiality of MySQL
#credentials is preserved.

#Remediation:
#Check which users and/or scripts are setting MYSQL_PWD and change them to use a more
#secure method.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/environment-variables.html
#2. https://blogs.oracle.com/myoraclediary/entry/how_to_check_environment_variabl
#es

grep MYSQL_PWD /proc/*/environ >> $REPORT

echo -e "\r\n----> 1.5 Disable interactive login" >> $REPORT

#Description:
#When created, the MySQL user may have interactive access to the operating system, which
#means that the MySQL user could login to the host as any other user would.

#Rationale:
#Preventing the MySQL user from logging in interactively may reduce the impact of a
#compromised MySQL account. There is also more accountability as accessing the operating
#system where the MySQL server lies will require the user's own account. Interactive access
#by the MySQL user is unnecessary and should be disabled.

#Remediation:
#Perform the following steps to remediate this setting:
#Execute one of the following commands in a terminal
#usermod -s /bin/false mysql
#usermod -s /sbin/nologin mysql

#Impact:
#This setting will prevent the MySQL administrator from interactively logging into the
#operating system using the MySQL user. Instead, the administrator will need to log in using
#one's own account.



getent passwd >> $REPORT

echo -e "\r\n----> 1.6	Verify That 'MYSQL_PWD' Is Not Set In Users' Profiles" >> $REPORT

#Description:
#MySQL can read a default database password from an environment variable called
#MYSQL_PWD .

#Rationale:
#The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL
#credentials. Avoiding this may increase assurance that the confidentiality of MySQL
#credentials is preserved.

#Remediation:
#Check which users and/or scripts are setting MYSQL_PWD and change them to use a more
#secure method.
#Default Value:
#Not set.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/environment-variables.html
#2. https://blogs.oracle.com/myoraclediary/entry/how_to_check_environment_variabl
#es


grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile} 
grep MYSQL_PWD /root/.{bashrc,profile,bash_profile} 

echo -e "\r\n--> Section 2 Backup and DR" >> $REPORT
echo -e "\r\n----> 2.1 backups and backup policies" >> $REPORT

#2.1.1 Backup policy in place (Not Scored)
#Description:
#A backup policy should be in place.
#Rationale:
#Backing up MySQL databases, including ' mysql ', will help ensure the availability of data in
#the event of an incident.
#Audit:
#Check with " crontab -l " if there is a backup schedule.
#Remediation:
#Create a backup policy and backup schedule.
#Impact:
#Without backups it might be hard to recover from an incident.

#2.1.2 Verify backups are good (Not Scored)
#Description:
#Backups should be validated on a regular basis.
#Rationale:
#Verifying that backups are occurring appropriately will help ensure the availability of data
#in the event of an incident.
#Audit:
#Check reports of backup validation tests.
#Remediation:
#Implement regular backup checks and document each check.
#Impact:
#Without a well-tested backup, it might be hard to recover from an incident if the backup
#procedure contains errors or doesn't include all required data.


#2.1.3 Secure backup credentials (Not Scored)
#Description:
#The password, certificate and any other credentials should be protected.
#Rationale:
#A database user with the least amount of privileges required to perform backup is needed
#for backup. The credentials for this user should be protected.
#Audit:
#Check permissions of files containing passwords and/or ssl keys.
#Remediation:
#Change file permissions
#Impact:
#When the backup credentials are not properly secured then they might be abused to gain
#access to the server. The backup user needs an account with many privileges, so the
#attacker can gain (almost) complete access to the server.

#2.1.4 The backups should be properly secured (Not Scored)
#Description:
#The backup files will contain all data in the databases. Filesystem permissions and/or
#encryption should be used to prevent non authorized users from gaining access to the
#backups.
#Rationale:
#Backups should be considered sensitive information.
#Audit:
#Check who has access to the backup files.
#•Are the files world-readable (e.g. rw-r--r-)
# o Are they stored in a world readable directory?
#•Is the group MySQL and/or backup specific?
# o If not: the file and directory must not be group readable
#•Are the backups stored offsite?
# o Who has access to the backups?
#•Are the backups encrypted?
# o Where is the encryption key stored?
# o Does the encryption key consists of a guessable password?
#Remediation:
#Implement encryption or use filesystem permissions.
#Impact:
#If an unauthorized user can access backups then they have access to all the data that is in
#the database. This is true for unencrypted backups and for encrypted backups if the
#encryption key is stored along with the backup.

#2.1.5 Point in time recovery (Not Scored)
#Description:
#With binlogs it is possible to implement point-in-time recovery. This makes it possible to
#restore the changes between the last full backup and the point-in-time.
#Enabling binlogs is not sufficient, a restore procedure should be created and has to be
#tested.
#Rationale:
#This can reduce the amount of information lost.
#Audit:
#Check if binlogs are enabled and if there is a restore procedure.
#Remediation:
#Enable binlogs and create and test a restore procedure.
#Impact:
#Without point-in-time recovery the data which was stored between the last backup and the
#time of disaster might not be recoverable.

#2.1.6 Disaster recovery plan (Not Scored)
#Description:
#A disaster recovery plan should be created.
#A slave in a different datacenter can be used or offsite backups. There should be
#information about what time a recovery will take and if the recovery site has the same
#capacity.
#Rationale:
#A disaster recovery should be planned.
#Audit:
#Check if there is a disaster recovery plan
#Remediation:
#Create a disaster recovery plan
#Impact:
#Without a well-tested disaster recovery plan it might not be possible to recover in time.

#2.1.7 Backup of configuration and related files (Not Scored)
#Description:
#The following files should be included in the backup:
#•Configuration files ( my.cnf and included files)
#•SSL files (certificates, keys)
#•User Defined Functions (UDFs)
#•Source code for customizations
#Rationale:
#These files are required to be able to fully restore an instance.
#Audit:
#Check if these files are in used and are saved in the backup.
#Remediation:
#Add these files to the backup
#Impact:
#Without a complete backup it might not be possible to fully recover.

echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 2.2 Dedicated MySQL host" >> $REPORT

#Description:
#It is recommended that MySQL Server software be installed on a dedicated server. This
#architectural consideration affords flexibility in that the database server can be placed on a
#separate zone allowing access only from particular hosts and over particular protocols.
#Rationale:
#The attack surface is reduced on a server with only the underlying operating system,
#MySQL server software, and any security or operational tooling that may be additionally
#installed. A smaller attack surface reduces the probability of the data within MySQL being
#compromised.
#Audit:
#Verify there are no other roles enabled for the underlying operating system and that no
#additional applications or services unrelated to the proper operation of the MySQL server
#software are installed.
#Remediation:
#Remove excess applications or services and/or remove unnecessary roles from the
#underlying operating system.
#Impact:
#Care must be taken that applications or services that are required for the proper operation
#of the operating system are not removed.
#Custom applications may need to be modified to accommodate database connections over
#the network rather than on the use (e.g., using TCP/IP connections).
#Additional hardware and operating system licenses may be required to make the
#architectural change.

echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 2.3 MySQL passwords are not passed in the commandline" >> $REPORT

#Description:
#When a command is executed on the command line, for example mysql -u admin -
#ppassword , the password may be visible in the user's shell/command history or in the
#process list.
#Rationale:
#If the password is visible in the process list or user's shell/command history, an attacker
#will be able to access the MySQL database using the stolen credentials.
#Audit:
#Check the process or task list if the password is visible.
#Check the shell or command history if the password is visible.
#Remediation:
#Use -p without password and then enter the password when prompted, use a properly
#secured .my.cnf file, or store authentication information in encrypted format in
#.mylogin.cnf .
#Impact:
#Depending on the remediation chosen, additional steps may need to be undertaken like:
#•Entering a password when prompted;
#•Ensuring the file permissions on .my.cnf is restricted yet accessible by the user;
#•Using mysql_config_editor to encrypt the authentication credentials in
#.mylogin.cnf .
#Additionally, not all scripts/applications may be able to use .mylogin.cnf .
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/mysql-config-editor.html
#2. http://dev.mysql.com/doc/refman/5.6/en/password-security-user.html


grep mysql /home/*/.{bash_history} 
grep mysql /root/.{bash_history}

echo -e "\r\n----> 2.4 Account reuse" >> $REPORT

#Description:
#Database user accounts should not be reused for multiple applications or users.
#Rationale:
#Utilizing unique database accounts across applications will reduce the impact of a
#compromised MySQL account.
#Audit:
#Each user should be linked to one of these
#•system accounts
#•a person
#•an application
#Remediation:
#Add/Remove users so that each user is only used for one specific purpose.
#Impact:
#If a user is reused, then a compromise of this user will compromise multiple parts of the
#system and/or application.

echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 2.5 Dedicated cryptographic key use" >> $REPORT

#Description:
#The SSL certificate and key used by MySQL should be used only for MySQL and only for one
#instance.
#Rationale:
#Use of default certificates can allow an attacker to impersonate the MySQL server.
#Audit:
#Check if the certificate is bound to one instance of MySQL.
#Remediation:
#Generate a new certificate/key per MySQL instance.
#Impact:
#If a key is used on multiple system then a compromise of one system leads to compromise
#of the network traffic of all servers which use the same key.

echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n--> Section 3 File System Permissions" >> $REPORT
echo -e "\r\n----> 3.1 Validate datadir permissions" >> $REPORT

#Description:
#The data directory is the location of the MySQL databases.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL database. If someone other than the MySQL user is allowed to
#read files from the data directory he or she might be able to read data from the mysql.user
#table which contains passwords. Additionally, the ability to create files can lead to denial of
#service, or might otherwise allow someone to gain access to specific data by manually
#creating a file with a view definition.

#Remediation:
#Execute the following commands at a terminal prompt:
#chmod 700 <datadir>
#chown mysql:mysql <datadir>

ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "datadir"' --batch --skip-column-names |sed 's/datadir\t//g') >> $REPORT

echo -e "\r\n----> 3.2 Validate log_bin_basename permissions" >> $REPORT

#Description:
#MySQL can operate using a variety of log files, each used for different purposes. These are
#the binary log, error log, slow query log, relay log, and general log. Because these are files
#on the host operating system, they are subject to the permissions structure provided by the
#host and may be accessible by users other than the MySQL user.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL logs.
#Remediation:
#Execute the following command for each log file location requiring corrected permissions:
#chmod 660 <log file>
#chown mysql:mysql <log file>
#Impact:
#Changing the permissions of the log files might have impact on monitoring tools which use
#a log file adapter. Also the slow query log can be used for performance analysis by
#application developers.
#If the permissions on the relay logs and binary log files are accidentally changed to exclude
#the user account which is used to run the MySQL service, then this might break replication.
#The binary log file can be used for point in time recovery so this can also affect backup,
#restore and disaster recovery procedures.

ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "log_bin_basename"' --batch --skip-column-names |sed 's/log_bin_basename\t//g') >> $REPORT

echo -e "\r\n----> 3.3 Validate log_error permissions" >> $REPORT

#Description:
#MySQL can operate using a variety of log files, each used for different purposes. These are
#the binary log, error log, slow query log, relay log, audit log and general log. Because these
#are files on the host operating system, they are subject to the permissions structure
#provided by the host and may be accessible by users other than the MySQL user.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL logs.
#Remediation:
#Execute the following command for each log file location requiring corrected permissions:
#chmod 660 <log file>
#chown mysql:mysql <log file>
#Impact:
#Changing the permissions of the log files might have impact on monitoring tools which use
#a log file adapter. Also the slow query log can be used for performance analysis by
#application developers.
#If the permissions on the relay logs and binary log files are accidentally changed to exclude
#the user account which is used to run the MySQL service, then this might break replication.
#The binary log file can be used for point in time recovery so this can also affect backup,
#restore and disaster recovery procedures.

ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "log_error"' --batch --skip-column-names |sed 's/log_error\t//g') >> $REPORT

echo -e "\r\n----> 3.4 Validate slow_query_log permissions" >> $REPORT

#Description:
#MySQL can operate using a variety of log files, each used for different purposes. These are
#the binary log, error log, slow query log, relay log, audit log and general log. Because these
#are files on the host operating system, they are subject to the permissions structure
#provided by the host and may be accessible by users other than the MySQL user.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL logs.
#Remediation:
#Execute the following command for each log file location requiring corrected permissions:
#chmod 660 <log file>
#chown mysql:mysql <log file>
#Impact:
#Changing the permissions of the log files might have impact on monitoring tools which use
#a log file adapter. Also the slow query log can be used for performance analysis by
#application developers.
#If the permissions on the relay logs and binary log files are accidentally changed to exclude
#the user account which is used to run the MySQL service, then this might break replication.
#The binary log file can be used for point in time recovery so this can also affect backup,
#restore and disaster recovery procedures.

ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "slow_query_log"' --batch --skip-column-names |sed 's/slow_query_log\t//g') >> $REPORT

echo -e "\r\n----> 3.5 Validate relay_log_basename permissions" >> $REPORT

#Description:
#MySQL can operate using a variety of log files, each used for different purposes. These are
#the binary log, error log, slow query log, relay log, audit log and general log. Because these
#are files on the host operating system, they are subject to the permissions structure
#provided by the host and may be accessible by users other than the MySQL user.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL logs.
#Remediation:
#Execute the following command for each log file location requiring corrected permissions:
#chmod 660 <log file>
#chown mysql:mysql <log file>
#Impact:
#Changing the permissions of the log files might have impact on monitoring tools which use
#a log file adapter. Also the slow query log can be used for performance analysis by
#application developers.
#If the permissions on the relay logs and binary log files are accidentally changed to exclude
#the user account which is used to run the MySQL service, then this might break replication.
#The binary log file can be used for point in time recovery so this can also affect backup,
#restore and disaster recovery procedures.

ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "relay_log_basename"' --batch --skip-column-names |sed 's/relay_log_basename\t//g') >> $REPORT

echo -e "\r\n----> 3.6 Validate general_log_file permissions" >> $REPORT

#Description:
#MySQL can operate using a variety of log files, each used for different purposes. These are
#the binary log, error log, slow query log, relay log, audit log and general log. Because these
#are files on the host operating system, they are subject to the permissions structure
#provided by the host and may be accessible by users other than the MySQL user.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL logs.
#Remediation:
#Execute the following command for each log file location requiring corrected permissions:
#chmod 660 <log file>
#chown mysql:mysql <log file>
#Impact:
#Changing the permissions of the log files might have impact on monitoring tools which use
#a log file adapter. Also the slow query log can be used for performance analysis by
#application developers.
#If the permissions on the relay logs and binary log files are accidentally changed to exclude
#the user account which is used to run the MySQL service, then this might break replication.
#The binary log file can be used for point in time recovery so this can also affect backup,
#restore and disaster recovery procedures.

ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "general_log_file"' --batch --skip-column-names |sed 's/general_log_file\t//g') >> $REPORT

echo -e "\r\n----> 3.7 Validate ssl key permissions" >> $REPORT
##########May produce an error if the default / no key is in use

#Description:
#When configured to use SSL/TLS, MySQL relies on key files, which are stored on the host's
#filesystem. These key files are subject to the host's permissions structure.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL database and the communication with the client.
#If the contents of the SSL key file is known to an attacker he or she might impersonate the
#server. This can be used for a man-in-the-middle attack.
#Depending on the SSL cipher suite the key might also be used to decipher previously
#captured network traffic.
#Remediation:
#Execute the following commands at a terminal prompt to remediate this setting using the
#Value from the audit procedure:
#chown mysql:mysql <ssl_key Value>
#chmod 400 <ssl_key Value
#Impact:
#If the permissions for the key file are changed incorrectly this can cause SSL to be disabled
#when MySQL is restarted or can cause MySQL not to start at all.
#If other applications are using the same key pair, then changing the permissions of the key
#file will affect this application. If this is the case, then a new key pair must be generated for
#MySQL.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/ssl-connections.html


ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "ssl_key"' --batch --skip-column-names |sed 's/ssl_key\t//g') >> $REPORT

echo -e "\r\n----> 3.8 Validate plugin_dir permissions" >> $REPORT

#Description:
#The plugin directory is the location of the MySQL plugins. Plugins are storage engines or
#user defined functions (UDFs).
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL database. If someone can modify plugins then these plugins
#might be loaded when the server starts and the code will get executed.

#Remediation:
#To remediate this setting, execute the following commands at a terminal prompt using the
#plugin_dir Value from the audit procedure.
#chmod 775 <plugin_dir Value> (or use 755)
#chown mysql:mysql <plugin_dir Value>
#Impact:
#Users other than the mysql user will no longer be able to update and add/remove plugins
#unless they're able to switch to the mysql user;
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/install-plugin.html


ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "plugin_dir"' --batch --skip-column-names |sed 's/plugin_dir\t//g') >> $REPORT

echo -e "\r\n----> 3.9 Validate audit_log_file permissions" >> $REPORT

#Description:
#MySQL can operate using a variety of log files, each used for different purposes. These are
#the binary log, error log, slow query log, relay log, audit log and general log. Because these
#are files on the host operating system, they are subject to the permissions structure
#provided by the host and may be accessible by users other than the MySQL user.
#Rationale:
#Limiting the accessibility of these objects will protect the confidentiality, integrity, and
#availability of the MySQL logs.
#Remediation:
#Execute the following command for the audit_log_file discovered in the audit procedure:
#chmod 660 <audit_log_file>
#chown mysql:mysql <audit_log_file>
#Impact:
#Changing the permissions of the audit log file may have impact on who can access and edit
#the the audit log. Such changes can affect monitoring tools which maybe using a logfile
#adapter or scripted alternatives. Also the audit log may be used by alerting by
#infrastructure teams which can affect real-time audit capability.

ls -la $(mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "audit_log_file"' --batch --skip-column-names |sed 's/audit_log_file\t//g') >> $REPORT

echo -e "\r\n--> Section 4 General" >> $REPORT
echo -e "\r\n----> 4.1 Validate release version" >> $REPORT
#cross reference with:
#1. http://www.oracle.com/technetwork/topics/security/alerts-086861.html
#2. http://dev.mysql.com/doc/relnotes/mysql/5.6/en/

#Description:
#Periodically, updates to MySQL server are released to resolve bugs, mitigate vulnerabilities,
#and provide new features. It is recommended that MySQL installations are up to date with
#the latest security updates.
#Rationale:
#Maintaining currency with MySQL patches will help reduce risk associated with known
#vulnerabilities present in the MySQL server.
#Without the latest security patches MySQL might have known vulnerabilities which might
#be used by an attacker to gain access.
#Remediation:
#Install the latest patches for your version or upgrade to the latest version.
#Impact:
#To update the MySQL server a restart is required.
#References:
#1. http://www.oracle.com/technetwork/topics/security/alerts-086861.html
#2. http://dev.mysql.com/doc/relnotes/mysql/5.6/en/
#3. http://web.nvd.nist.gov/view/vuln/search-
#results?adv_search=true&cves=on&cpe_vendor=cpe%3a%2f%3aoracle&cpe_produ
#ct=cpe%3a%2f%3aoracle%3amysql&cpe_version=cpe%3a%2f%3aoracle%3amysq
#l%3a5.6.0

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "version"' >> $REPORT

echo -e "\r\n----> 4.2 Ensure test database is not installed" >> $REPORT

#Description:
#The default MySQL installation comes with an unused database called test . It is
#recommended that the test database be dropped.
#Rationale:
#The test database can be accessed by all users and can be used to consume system
#resources. Dropping the test database will reduce the attack surface of the MySQL server.
#Remediation:
#Execute the following SQL statement to drop the test database:
#DROP DATABASE "test";
#Note: mysql_secure_installation performs this operation as well as other security-
#related activities.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/mysql-secure-installation.html


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW DATABASES LIKE "test"' >> $REPORT;

echo -e "\r\n----> 4.3 Ensure 'allow-suspicious-udfs' is not enabled" >> $REPORT
#see my.cnf files copied by this script as well

#Description:
#This option prevents attaching arbitrary shared library functions as user-defined functions
#by checking for at least one corresponding method named _init, _deinit , _reset , _clear ,
#or _add .
#Rationale:
#Preventing shared libraries that do not contain user-defined functions from loading will
#reduce the attack surface of the server.
#Remediation:
#Perform the following to establish the recommended state:
#•Remove --allow-suspicious-udfs from the mysqld start up command line.
#•Remove allow-suspicious-udfs from the MySQL option file.
#Default Value:
#FALSE
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/udf-security.html
#2. http://dev.mysql.com/doc/refman/5.6/en/server-
#options.html#option_mysqld_allow-suspicious-udfs

for OUTPUT in $(find /etc -name my.cnf); do
  grep allow-suspicious-udfs $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT

echo -e "\r\n----> 4.4 Ensure local_infile is disabled" >> $REPORT

#Description:
#The local_infile parameter dictates whether files located on the MySQL client's
#computer can be loaded or selected via LOAD DATA INFILE or SELECT local_file .
#Rationale:
#Disabling local_infile reduces an attacker's ability to read sensitive files off the affected
#server via a SQL injection vulnerability.
#Remediation:
#Add the following line to the [mysqld] section of the MySQL configuration file and restart
#the MySQL service:
#local-infile=0
#Impact:
#Disabling local_infile will impact the functionality of solutions that rely on it.
#Default Value:
#ON
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/string-functions.html#function_load-file
#2. http://dev.mysql.com/doc/refman/5.6/en/load-data.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "local_infile"' >> $REPORT

echo -e "\r\n----> 4.5 Ensure mysql is not started with skip grant tables" >> $REPORT

#Description:
#This option causes mysqld to start without using the privilege system.
#Rationale:
#If this option is used, all clients of the affected server will have unrestricted access to all
#databases.

#Remediation:
#Perform the following to establish the recommended state:
#•Open the MySQL configuration (e.g. my.cnf ) file and set:
#skip-grant-tables = FALSE
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/server-
#options.html#option_mysqld_skip-grant-tables


#see my.cnf files copied by this script as well
for OUTPUT in $(find /etc -name my.cnf); do
  grep skip-grant-tables $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT

echo -e "\r\n----> 4.6 Ensure have_symlink is disabled" >> $REPORT

#Description:
#The symbolic-links and skip-symbolic-links options for MySQL determine whether
#symbolic link support is available. When use of symbolic links are enabled, they have
#different effects depending on the host platform. When symbolic links are disabled, then
#symbolic links stored in files or entries in tables are not used by the database.
#Rationale:
#Prevents sym links being used for data base files. This is especially important when MySQL
#is executing as root as arbitrary files may be overwritten. The symbolic-links option might
#allow someone to direct actions by to MySQL server to other files and/or directories.
#Remediation:
#Perform the following actions to remediate this setting:
#•Open the MySQL configuration file ( my.cnf )
#•Locate skip_symbolic_links in the configuration
#•Set the skip_symbolic_links to YES
#NOTE: If skip_symbolic_links does not exist, add it to the configuration file in the mysqld
#section.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/symbolic-links.html
#2. http://dev.mysql.com/doc/refman/5.6/en/server-
#options.html#option_mysqld_symbolic-links


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_Name = "have_symlink"' >> $REPORT

echo -e "\r\n----> 4.7 Ensure daemon_memcached plugin is disabled" >> $REPORT

#Description:
#The InnoDB memcached Plugin allows users to access data stored in InnoDB with the
#memcached protocol.
#Rationale:
#By default the plugin doesn't do authentication, which means that anyone with access to
#the TCP/IP port of the plugin can access and modify the data. However, not all data is
#exposed by default.
#Remediation:
#To remediate this setting, issue the following command in the MySQL command-line client:
#uninstall plugin daemon_memcached;
#This uninstalls the memcached plugin from the MySQL server.
#Default Value:
#disabled
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/innodb-memcached-security.html


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME="daemon_memcached"' >> $REPORT

echo -e "\r\n----> 4.8 Ensure secure_file_priv is not empty" >> $REPORT

#Description:
#The secure_file_priv option restricts to paths used by LOAD DATA INFILE or SELECT
#local_file . It is recommended that this option be set to a file system location that contains
#only resources expected to be loaded by MySQL.
#Rationale:
#Setting secure_file_priv reduces an attacker's ability to read sensitive files off the
#affected server via a SQL injection vulnerability.
#Remediation:
#Add the following line to the [mysqld] section of the MySQL configuration file and restart
#the MySQL service:
#secure_file_priv=<path_to_load_directory>
#Impact:
#Solutions that rely on loading data from various sub-directories may be negatively
#impacted by this change. Consider consolidating load directories under a common parent
#directory.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/server-system-
#variables.html#sysvar_secure_file_priv

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES WHERE Variable_name = "secure_file_priv" AND Value<>""' >> $REPORT


echo -e "\r\n----> 4.9 Ensure sql_mode contains STRICT_ALL_TABLES" >> $REPORT

#Description:
#When data changing statements are made (i.e. INSERT , UPDATE ), MySQL can handle invalid
#or missing values differently depending on whether strict SQL mode is enabled. When
#strict SQL mode is enabled, data may not be truncated or otherwise "adjusted" to make the
#data changing statement work.
#Rationale:
#Without strict mode the server tries to do proceed with the action when an error might
#have been a more secure choice. For example, by default MySQL will truncate data if it does
#not fit in a field, which can lead to unknown behavior, or be leveraged by an attacker to
#circumvent data validation.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Add STRICT_ALL_TABLES to the sql_mode in the server's configuration file
#Impact:
#Applications relying on the MySQL database should be aware that STRICT_ALL_TABLES is in
#use, such that error conditions are handled appropriately.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/server-sql-mode.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES LIKE "sql_mode";' >> $REPORT

echo -e "\r\n--> Section 5 MySQL Permissions" >> $REPORT
echo -e "\r\n----> 5.1 Ensure only admins have full database access" >> $REPORT

#Description:
#The mysql.user and mysql.db tables list a variety of privileges that can be granted (or
#denied) to MySQL users. Some of the privileges of concern include: Select_priv,
#Insert_priv , Update_priv , Delete_priv , Drop_priv , and so on. Typically, these privileges
#should not be available to every MySQL user and often are reserved for administrative use
#only.
#Rationale:
#Limiting the accessibility of the ' mysql ' database will protect the confidentiality, integrity,
#and availability of the data housed within MySQL. A user which has direct access to
#mysql.* might view password hashes, change permissions, or alter or destroy information
#intentionally or unintentionally.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Enumerate non-administrative users resulting from the audit procedure
#2. For each non-administrative user, use the REVOKE statement to remove privileges as
#appropriate
#Impact:
#Consideration should be made for which privileges are required by each user requiring
#interactive database access.

#

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host FROM mysql.user WHERE (Select_priv = "Y") OR (Insert_priv = "Y") OR (Update_priv = "Y") OR (Delete_priv = "Y") OR (Create_priv = "Y") OR (Drop_priv = "Y");' >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host FROM mysql.db WHERE (Select_priv = "Y") OR (Insert_priv = "Y") OR (Update_priv = "Y") OR (Delete_priv = "Y") OR (Create_priv = "Y") OR (Drop_priv = "Y");' >> $REPORT

echo -e "\r\n----> 5.2 Ensure file_priv is not enabled for non admin users" >> $REPORT

#Description:
#The File_priv privilege found in the mysql.user table is used to allow or disallow a user
#from reading and writing files on the server host. Any user with the File_priv right
#granted has the ability to:
#•Read files from the local file system that are readable by the MySQL server (this
#includes world-readable files)
#•Write files to the local file system where the MySQL server has write access
#Rationale:
#The File_priv right allows mysql users to read files from disk and to write files to disk.
#This may be leveraged by an attacker to further compromise MySQL. It should be noted
#that the MySQL server should not overwrite existing files.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the non-administrative users found in the result set of the audit
#procedure
#2. For each user, issue the following SQL statement (replace "<user>" with the non-
#administrative user:
#REVOKE FILE ON *.* FROM '<user>';
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_file

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where File_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.3 Ensure process_priv is not enabled for non admin users" >> $REPORT

#Description:
#The PROCESS privilege found in the mysql.user table determines whether a given user can
#see statement execution information for all sessions.
#Rationale:
#The PROCESS privilege allows principals to view currently executing MySQL statements
#beyond their own, including statements used to manage passwords. This may be leveraged
#by an attacker to compromise MySQL or to gain access to potentially sensitive data.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the non-administrative users found in the result set of the audit
#procedure
#2. For each user, issue the following SQL statement (replace " <user> " with the non-
#administrative user:
#REVOKE PROCESS ON *.* FROM '<user>';
#Impact:
#Users denied the PROCESS privilege may also be denied use of SHOW ENGINE .
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_process

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Process_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.4 Ensure Super_priv is not enabled for non admin users" >> $REPORT

#Description:
#The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL
#features. These features include, CHANGE MASTER TO , KILL , mysqladmin kill option, PURGE
#BINARY LOGS , SET GLOBAL , mysqladmin debug option, logging control, and more.
#Rationale:
#The SUPER privilege allows principals to perform many actions, including view and
#terminate currently executing MySQL statements (including statements used to manage
#passwords). This privilege also provides the ability to configure MySQL, such as
#enable/disable logging, alter data, disable/enable features. Limiting the accounts that have
#the SUPER privilege reduces the chances that an attacker can exploit these capabilities.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the non-administrative users found in the result set of the audit
#procedure
#2. For each user, issue the following SQL statement (replace " <user> " with the non-
#administrative user:
#REVOKE SUPER ON *.* FROM '<user>';
#Impact:
#When the SUPER privilege is denied to a given user, that user will be unable to take
#advantage of certain capabilities, such as certain mysqladmin options.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_super

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Super_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.5 Ensure Shutdown_priv is not enabled for non admin users" >> $REPORT

#Description:
#The SHUTDOWN privilege simply enables use of the shutdown option to the mysqladmin
#command, which allows a user with the SHUTDOWN privilege the ability to shut down the
#MySQL server.
#Rationale:
#The SHUTDOWN privilege allows principals to shutdown MySQL. This may be leveraged by an
#attacker to negatively impact the availability of MySQL.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the non-administrative users found in the result set of the audit
#procedure
#2. For each user, issue the following SQL statement (replace " <user> " with the non-
#administrative user):
#REVOKE SHUTDOWN ON *.* FROM '<user>';
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/privileges-
#provided.html#priv_shutdown


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Shutdown_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.6 Ensure Create_user_priv is not enabled for non admin users" >> $REPORT

#Description:
#The CREATE USER privilege governs the right of a given user to add or remove users,
#change existing users' names, or revoke existing users' privileges.
#Rationale:
#Reducing the number of users granted the CREATE USER right minimizes the number of
#users able to add/drop users, alter existing users' names, and manipulate existing users'
#privileges.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the non-administrative users found in the result set of the audit
#procedure
#2. For each user, issue the following SQL statement (replace "<user>" with the non-
#administrative user):
#REVOKE CREATE USER ON *.* FROM '<user>';
#Impact:
#Users that are denied the CREATE USER privilege will not only be unable to create a user,
#but they may be unable to drop a user, rename a user, or otherwise revoke a given user's
#privileges.


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Create_user_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.7 Ensure grant_priv is not enabled for non admin users" >> $REPORT

#Description:
#The GRANT OPTION privilege exists in different contexts ( mysql.user , mysql.db) for the
#purpose of governing the ability of a privileged user to manipulate the privileges of other
#users.
#Rationale:
#The GRANT privilege allows a principal to grant other principals additional privileges. This
#may be used by an attacker to compromise MySQL.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the non-administrative users found in the result sets of the audit
#procedure
#2. For each user, issue the following SQL statement (replace " <user> " with the non-
#administrative user:
#REVOKE GRANT OPTION ON *.* FROM <user>;
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_grant-
#option

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Grant_priv = "Y";' >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.db where Grant_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.8 Ensure repl_slave_priv is not enabled for non admin users" >> $REPORT

#Description:
#The REPLICATION SLAVE privilege governs whether a given user (in the context of the
#master server) can request updates that have been made on the master server.
#Rationale:
#The REPLICATION SLAVE privilege allows a principal to fetch binlog files containing all data
#changing statements and/or changes in table data from the master. This may be used by an
#attacker to read/fetch sensitive data from MySQL.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the non-slave users found in the result set of the audit procedure
#2. For each user, issue the following SQL statement (replace " <user> " with the non-
#slave user):
#REVOKE REPLICATION SLAVE ON *.* FROM <user>;
#Use the REVOKE statement to remove the SUPER privilege from users who shouldn't have
#it.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/privileges-
#provided.html#priv_replication-slave

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where Repl_slave_priv = "Y";' >> $REPORT

echo -e "\r\n----> 5.9 Ensure DML/DDL Grants Are Limited to specific databases and users" >> $REPORT

#Description:
#DML/DDL includes the set of privileges used to modify or create data structures. This
#includes INSERT , SELECT , UPDATE , DELETE , DROP , CREATE , and ALTER privileges.
#Rationale:
#INSERT , SELECT , UPDATE , DELETE , DROP , CREATE , and ALTER are powerful privileges in any
#database. Such privileges should be limited only to those users requiring such rights. By
#limiting the users with these rights and ensuring that they are limited to specific databases,
#the attack surface of the database is reduced.
#Remediation:
#Perform the following steps to remediate this setting:
#1. Enumerate the unauthorized users, hosts, and databases returned in the result set of
#the audit procedure
#2. For each user, issue the following SQL statement (replace " <user> " with the
#unauthorized user, " <host> " with host name, and " <database> " with the database
#name):=
#REVOKE SELECT ON <host>.<database> FROM <user>;
#REVOKE INSERT ON <host>.<database> FROM <user>;
#REVOKE UPDATE ON <host>.<database> FROM <user>;
#REVOKE DELETE ON <host>.<database> FROM <user>;
#REVOKE CREATE ON <host>.<database> FROM <user>;
#REVOKE DROP ON <host>.<database> FROM <user>;
#REVOKE ALTER ON <host>.<database> FROM <user>;


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT User,Host,Db FROM mysql.db WHERE Select_priv="Y" OR Insert_priv="Y" OR Update_priv="Y" OR Delete_priv="Y" OR Create_priv="Y" OR Drop_priv="Y" OR Alter_priv="Y";' >> $REPORT

echo -e "\r\n--> Section 6 Auditing and logging" >> $REPORT
echo -e "\r\n----> 6.1 Ensure log_error is not empty" >> $REPORT

#Description:
#The error log contains information about events such as mysqld starting and stopping,
#when a table needs to be checked or repaired, and, depending on the host operating
#system, stack traces when mysqld fails.
#Rationale:
#Enabling error logging may increase the ability to detect malicious attempts against MySQL,
#and other critical messages, such as if the error log is not enabled then connection error
#might go unnoticed.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Open the MySQL configuration file ( my.cnf or my.ini )
#2. Set the log-error option to the path for the error log
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/error-log.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW variables LIKE "log_error";' >> $REPORT

echo -e "\r\n----> 6.2 Ensure log files are stored on a non system partition" >> $REPORT
#Ensure	the	value	returned	does	not	indicate	root	('/'),	/var,	or	/usr.

#Description:
#MySQL log files can be set in the MySQL configuration to exist anywhere on the
#filesystem. It is common practice to ensure that the system filesystem is left uncluttered by
#application logs. System filesystems include the root, /var , or /usr .
#Rationale:
#Moving the MySQL logs off the system partition will reduce the probability of denial of
#service via the exhaustion of available disk space to the operating system.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Open the MySQL configuration file ( my.cnf )
#2. Locate the log-bin entry and set it to a file not on root ( '/' ), /var , or /usr
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/binary-log.html
#2. http://dev.mysql.com/doc/refman/5.6/en/replication-options-binary-log.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT @@global.log_bin_basename;' >> $REPORT
df -h >> $REPORT

echo -e "\r\n----> 6.3 Ensure log warnings is set to 2" >> $REPORT

#Description:
#The log_warnings system variable, enabled by default, provides additional information to
#the MySQL log. A value of 1 enables logging of warning messages, and higher integer values
#tend to enable more logging.
#NOTE: The variable scope for 5.6.3 and earlier is global and session, but for 5.6.4 and
#greater its scope is global.
#Rationale:
#This might help to detect malicious behavior by logging communication errors and aborted
#connections.
#Remediation:
#Perform the following actions to remediate this setting:
#•Open the MySQL configuration file ( my.cnf )
#•Ensure the following line is found in the mysqld section
#log-warnings = 2
#Default Value:
#The option is enabled (1) by default.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/server-
#options.html#option_mysqld_log-warnings

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "log_warnings"; ' >> $REPORT

echo -e "\r\n----> 6.4 Ensure Audit Logging is Enabled" >> $REPORT

#Description:
#Audit    logging    is    not    really    included    in    the    Community    Edition    of    MySQL    -­‐only    the    general    log.    Using    the    general    log    is    possible,    but    not    practical,    because    it    grows    quickly    and    has    an    adverse    impact    on    server    performance.    Nevertheless,    enabling    audit    logging    is    an    important    consideration    for    a    production    environment,    and    third-­‐party    tools    do    exist    to    help    with    this.    Enable    audit    logging    for
#•Interactive    user    sessions
#•Application    sessions    (optional)
#Rationale:Audit    logging    helps    to    identify    who    changed    what    and    when.    The    audit    log    might    be    used    as    evidence    in    investigations.    It    might    also    help    to    identify    what    an    attacker    was    able    to    accomplish.Audit:Verify    thata    third-­‐party    tool    is    installed    and    configured    to    enable    logging    for    interactive    user    sessions    and    (optionally)    applications    sessions.
#Remediation:
#Acquire    a    third-­‐party    MySQL    logging    solution    as    available    from    a    variety    of    sources    including,    but    not    necessarily    limited    to,    the    following:
#•The    General    Query    Log
#•MySQL    Enterprise    Audit•MariaDB    Audit    Plugin    for    MySQL
#•McAfee    MySQL    Audit
#References:
#1.http://dev.mysql.com/doc/refman/5.6/en/query-­‐log.html
#2.http://dev.mysql.com/doc/refman/5.6/en/mysql-­‐enterprise-­‐audit.html3.https://mariadb.com/kb/en/server_audit-­‐mariadb-­‐audit-­‐plugin/4.https://github.com/mcafee/mysql-­‐audit

echo -e "\r\nRequires manual verification" >> $REPORT


echo -e "\r\n----> 6.5 Ensure log_raw is set to off" >> $REPORT

#Description:
#The log-raw MySQL option determines whether passwords are rewritten by the server so
#as not to appear in log files as plain text. If log-raw is enabled, then passwords are written
#to the various log files (general query log, slow query log, and binary log) in plain text.
#Rationale:
#With raw logging of passwords enabled someone with access to the log files might see plain
#text passwords.
#Remediation:
#Perform the following actions to remediate this setting:
#•Open the MySQL configuration file ( my.cnf )
#•Find the log-raw entry and set it as follows
#log-raw = OFF
#Default Value:
#OFF
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/password-logging.html
#2. http://dev.mysql.com/doc/refman/5.6/en/server-
#options.html#option_mysqld_log-raw

#see my.cnf files copied by this script as well
for OUTPUT in $(find /etc -name my.cnf); do
  grep log_raw $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT


echo -e "\r\n----> 7.1 Ensure 'old_passwords' Is Not Set to '1' or 'ON'" >> $REPORT

#Description:
#This variable controls the password hashing method used by the PASSWORD() function and
#for the IDENTIFIED BY clause of the CREATE USER and GRANT statements.
#Before 5.6.6, the value can be 0 (or OFF), or 1 (or ON). As of 5.6.6, the following value can
#be one of the following:
#•0 - authenticate with the mysql_native_password plugin
#•1 - authenticate with the mysql_old_password plugin
#•2 - authenticate with the sha256_password plugin
#Rationale:
#The mysql_old_password plugin leverages an algorithm that can be quickly brute forced
#using an offline dictionary attack. See CVE-2003-1480 for additional details.
#Remediation:
#Configure mysql to leverage the mysql_native_password or sha256_password plugin. For
#more information, see:
#•http://dev.mysql.com/doc/refman/5.6/en/password-hashing.html
#•http://dev.mysql.com/doc/refman/5.6/en/sha256-authentication-plugin.html
#Impact:
#When old_passwords is set to 1 the PASSWORD() function will create password hashes
#with a very weak hashing algorithm which might be easy to break if captured by an
#attacker.
#Default Value:
#0
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/server-system-
#variables.html#sysvar_old_passwords
#2. CVE-2003-1480

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_name = "old_passwords"; ' >> $REPORT

echo -e "\r\n----> 7.2 Ensure 'secure_auth' Is Set to 'ON'" >> $REPORT

#Description:
#This option dictates whether the server will deny connections by clients that attempt to use
#accounts that have their password stored in the mysql_old_password format.
#Rationale:
#Enabling this option will prevent all use of passwords employing the old format (and hence
#insecure communication over the network).
#Remediation:
#Add the following line to [mysqld] portions of the MySQL option file to establish the
#recommended state:
#secure_auth=ON
#Impact:
#Accounts having credentials stored using the old password format will be unable to login.
#Execute the following command to identify accounts that will be impacted by implementing
#this setting:
#SELECT User,Host FROM mysql.user WHERE plugin='mysql_old_password';
#Default Value:
#Before MySQL 5.6.5, this option is disabled by default. As of MySQL 5.6.5, it is enabled by
#default; to disable it, use --skip-secure-auth .
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/server-
#options.html#option_mysqld_secure-auth

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES WHERE Variable_name = "secure_auth"; ' >> $REPORT

echo -e "\r\n----> 7.3 Ensure passwords are not stored in the global config" >> $REPORT

#Description:
#The [client] section of the MySQL configuration file allows setting a user and password to
#be used. Verify the password option is not used in the global configuration file ( my.cnf ).
#Rationale:
#The use of the password parameter may negatively impact the confidentiality of the user's
#password.
#Remediation:
#Use the mysql_config_editor to store authentication credentials in . mylogin.cnf in
#encrypted form.
#If not possible, use the user-specific options file, .my.cnf. , and restricting file access
#permissions to the user identity.
#Impact:
#The global configuration is by default readable for all users on the system. This is needed
#for global defaults (prompt, port, socket, etc). If a password is present in this file then all
#users on the system may be able to access it.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/mysql-config-editor.html

#see my.cnf files copied by this script as well
for OUTPUT in $(find /etc -name my.cnf); do
  grep password $OUTPUT >> $REPORT
done
ps aux |grep mysql >> $REPORT

echo -e "\r\n----> 7.4 Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'" >> $REPORT

#Description:
#NO_AUTO_CREATE_USER is an option for sql_mode that prevents a GRANT statement from
#automatically creating a user when authentication information is not provided.
#Rationale:
#Blank passwords negate the benefits provided by authentication mechanisms. Without this
#setting an administrative user might accidentally create a user without a password.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Open the MySQL configuration file ( my.cnf )
#2. Find the sql_mode setting in the [mysqld] area
#3. Add the NO_AUTO_CREATE_USER to the sql_mode setting

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT @@global.sql_mode; ' >> $REPORT
mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT @@session.sql_mode; ' >> $REPORT

echo -e "\r\n----> 7.5 Ensure passwords are set for all user accounts" >> $REPORT

#Description:
#Blank passwords allow a user to login without using a password.
#Rationale:
#Without a password only knowing the username and the list of allowed hosts will allow
#someone to connect to the server and assume the identity of the user. This, in effect,
#bypasses authentication mechanisms.
#Remediation:
#For each row returned from the audit procedure, set a password for the given user using
#the following statement (as an example):
#SET PASSWORD FOR <user>@'<host>' = PASSWORD('<clear password>')
#NOTE: Replace <user> , <host> , and <clear password> with appropriate values.


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT User,host FROM mysql.user WHERE (plugin IN("mysql_native_password", "mysql_old_password") AND (LENGTH(Password) = 0 OR Password IS NULL)) OR (plugin="sha256_password" AND LENGTH(authentication_string) = 0); ' >> $REPORT

echo -e "\r\n----> 7.6 Ensure password policies are in place" >> $REPORT

#Description:
#Password complexity includes password characteristics such as length, case, length, and
#character sets.
#Rationale:
#Complex passwords help mitigate dictionary, brute forcing, and other password
#attacks. This recommendation prevents users from choosing weak passwords which can
#easily be guessed.
#Remediation:
#Add to the global configuration:
#plugin-load=validate_password.so
#validate-password=FORCE_PLUS_PERMANENT
#validate_password_length=14
#validate_password_mixed_case_count=1
#validate_password_number_count=1
#validate_password_special_char_count=1
#validate_password_policy=MEDIUM
#And change passwords for users which have passwords which are identical to their
#username.
#Impact:
#Remediation for this recommendation requires a server restart.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/validate-password-plugin.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW VARIABLES LIKE "validate_password%";' >> $REPORT

echo -e "\r\n----> 7.7 Ensure no users have wildcard hostnames" >> $REPORT

#Description:
#MySQL can make use of host wildcards when granting permissions to users on specific
#databases. For example, you may grant a given privilege to '<user>'@'%' .
#Rationale:
#Avoiding the use of wildcards within hostnames helps control the specific locations from
#which a given user may connect to and interact with the database.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Enumerate all users returned after running the audit procedure
#2. Either ALTER the user's host to be specific or DROP the user

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host FROM mysql.user WHERE host = "%";' >> $REPORT

echo -e "\r\n----> 7.8 Ensure no anonymous accounts exist" >> $REPORT

#Description:
#Anonymous accounts are users with empty usernames (''). Anonymous accounts have no
#passwords, so anyone can use them to connect to the MySQL server.
#Rationale:
#Removing anonymous accounts will help ensure that only identified and trusted principals
#are capable of interacting with MySQL.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Enumerate the anonymous users returned from executing the audit procedure
#2. For each anonymous user, DROP or assign them a name
#NOTE: As an alternative, you may execute the mysql_secure_installation utility.
#Impact:
#Any applications relying on anonymous database access will be adversely affected by this
#change.
#Default Value:
#Using the standard installation script, mysql_install_db, it will create two anonymous
#accounts: one for the host 'localhost' and the other for the network interface's IP address.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/mysql-secure-installation.html
#2. https://dev.mysql.com/doc/refman/5.6/en/default-privileges.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user,host FROM mysql.user WHERE user = ""; ' >> $REPORT

echo -e "\r\n--> Section 8 Network" >> $REPORT
echo -e "\r\n----> 8.1 Ensure 'have_ssl' is set to YES" >> $REPORT

#Description:
#All network traffic must use SSL/TLS when traveling over untrusted networks.
#Rationale:
#The SSL/TLS-protected MySQL protocol helps to prevent eavesdropping and man-in-the-
#middle attacks.
#Remediation:
#Follow the procedures as documented in the MySQL 5.6 Reference Manual to setup SSL.
#Impact:
#Enabling SSL will allow clients to encrypt network traffic and verify the identity of the
#server. This could have impact on network traffic inspection.
#Default Value:
#DISABLED
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/ssl-connections.html
#2. http://dev.mysql.com/doc/refman/5.6/en/ssl-options.html


mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW variables WHERE variable_name = "have_ssl"; ' >> $REPORT

echo -e "\r\n----> 8.2 Ensure 'ssl_type' is set to ANY, X509 or SPECIFIED for all remote users" >> $REPORT

#Description:
#All network traffic must use SSL/TLS when traveling over untrusted networks.
#SSL/TLS should be enforced on a per-user basis for users which enter the system through
#the network.
#Rationale:
#The SSL/TLS-protected MySQL protocol helps to prevent eavesdropping and man-in-the-
#middle attacks.
#Remediation:
#Use the GRANT statement to require the use of SSL:
#GRANT USAGE ON *.* TO 'my_user'@'app1.example.com' REQUIRE SSL;
#Note that REQUIRE SSL only enforces SSL. There are options like REQUIRE X509, REQUIRE
#ISSUER, REQUIRE SUBJECT which can be used to further restrict connection options.
#Impact:
#When SSL/TLS is enforced then clients which do not use SSL will not be able to connect. If
#the server is not configured for SSL/TLS then accounts for which SSL/TLS is mandatory
#will not be able to connect
#Default Value:
#Not enforced ( ssl_type is empty)
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/ssl-connections.html
#2. http://dev.mysql.com/doc/refman/5.6/en/grant.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ("::1", "127.0.0.1", "localhost"); ' >> $REPORT

echo -e "\r\n--> Section 9 Replication" >> $REPORT
echo -e "\r\n----> 9.1 Ensure Replication traffic is secured" >> $REPORT

#Description:
#The replication traffic between servers should be secured.
#Rationale:
#The replication traffic should be secured as it gives access to all transferred information
#and might leak passwords.
#Remediation:
#Secure the network traffic
#Impact:
#When the replication traffic is not secured someone might be able to capture passwords
#and other sensitive information when sent to the slave.

echo -e "Manual check. ensure that replication traffic is using SSL, VPN, SSH Tunnel or on a private network">> $REPORT

echo -e "\r\n----> 9.3 Ensure MASTER_SSL_VERIFY_SERVER_CERT is set to YES or 1" >> $REPORT

#Description:
#In the MySQL slave context the setting MASTER_SSL_VERIFY_SERVER_CERT indicates whether
#the slave should verify the master's certificate. This configuration item may be set to Yes or
#No , and unless SSL has been enabled on the slave, the value will be ignored.
#Rationale:
#When SSL is in use certificate verification is important to authenticate the party to which a
#connection is being made. In this case, the slave (client) should verify the master's
#(server's) certificate to authenticate the master prior to continuing the connection.
#Remediation:
#To remediate this setting you must use the CHANGE MASTER TO command.
#STOP SLAVE; -- required if replication was already running
#CHANGE MASTER TO MASTER_SSL_VERIFY_SERVER_CERT=1;
#START SLAVE; -- required if you want to restart replication
#Impact:
#When using CHANGE MASTER TO , be aware of the following:
#•Slave processes need to be stopped prior to executing CHANGE MASTER TO
#•Use of CHANGE MASTER TO starts new relay logs without keeping the old ones unless
#explicitly told to keep them
#•When CHANGE MASTER TO is invoked, some information is dumped to the error log
#(previous values for MASTER_HOST, MASTER_PORT, MASTER_LOG_FILE, and
#MASTER_LOG_POS )
#•Invoking CHANGE MASTER TO will implicitly commit any ongoing transactions
#References:
#1. https://dev.mysql.com/doc/refman/5.6/en/change-master-to.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select ssl_verify_server_cert from mysql.slave_master_info;' >> $REPORT


echo -e "\r\n----> 9.3 Ensure master_info_repository is set to TABLE" >> $REPORT

#Description:
#The master_info_repository setting determines to where a slave logs master status and
#connection information. The options are FILE or TABLE . Note also that this setting is
#associated with the sync_master_info setting as well.
#Rationale:
#The password which the client uses is stored in the master info repository, which by
#default is a plaintext file. The TABLE master info repository is a bit safer, but with
#filesystem access it's still possible to gain access to the password the slave is using.
#Remediation:
#Perform the following actions to remediate this setting:
#1. Open the MySQL configuration file ( my.cnf )
#2. Locate master_info_repository
#3. Set the master_info_repository value to TABLE
#NOTE: If master_info_repository does not exist, add it to the configuration file.
#Default Value:
#FILE
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/replication-options-
#slave.html#sysvar_master_info_repository

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'SHOW GLOBAL VARIABLES LIKE "master_info_repository"; ' >> $REPORT


echo -e "\r\n----> 9.4 Ensure Super_Priv is not set to YES for repl users" >> $REPORT

#Description:
#The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL
#features. These features include, CHANGE MASTER TO , KILL , mysqladmin kill option, PURGE
#BINARY LOGS , SET GLOBAL , mysqladmin debug option, logging control, and more.
#Rationale:
#The SUPER privilege allows principals to perform many actions, including view and
#terminate currently executing MySQL statements (including statements used to manage
#passwords). This privilege also provides the ability to configure MySQL, such as
#enable/disable logging, alter data, disable/enable features. Limiting the accounts that have
#the SUPER privilege reduces the chances that an attacker can exploit these capabilities.
#Remediation:
#Execute the following steps to remediate this setting:
#1. Enumerate the replication users found in the result set of the audit procedure
#2. For each replication user, issue the following SQL statement (replace " repl " with
#your replication user's name):
#REVOKE SUPER ON *.* FROM 'repl';
#Impact:
#When the SUPER privilege is denied to a given user, that user will be unable to take
#advantage of certain capabilities, such as certain mysqladmin options.
#References:
#1. http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_super
#2. https://dev.mysql.com/doc/refman/5.6/en/show-slave-status.html

mysql --defaults-extra-file=$MYSQL_DEFAULTS_EXTRA_FILE information_schema -e 'select user, host from mysql.user where user="repl" and Super_priv = "Y"; ' >> $REPORT

echo -e "\r\n----> 9.5 Ensure no replication users have wildcard hostnames" >> $REPORT

#Description:
#MySQL can make use of host wildcards when granting permissions to users on specific
#databases. For example, you may grant a given privilege to '<user>'@'%' .
#Rationale:
#Avoiding the use of wildcards within hostnames helps control the spe
#Remediation:
#Perform the following actions to remediate this setting:
#1. Enumerate all users returned after running the audit procedure
#2. Either ALTER the user's host to be specific or DROP the user

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
