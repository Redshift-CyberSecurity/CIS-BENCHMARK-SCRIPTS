#!/bin/bash
# Redshift Cyber Security CIS PostgreSQL 12 CENTOS Linux Audit Script
# Use following command to run this scipt 
# chmod +x redshift_cis_postgressql_12_centos_linux.sh
# ./redshift_cis_postgressql_12_centos_linux.sh
#
# requires root permissions on the database and the underlying OS
# This script creates a temporary PostgreSQL additional config files with the
# PostgreSQL credentials stored in clear text. Please ensure these files are 
# successfully deleted when the script terminates
# 
# NOTE THIS SCRIPT WAS WRITTEN FOR CENTOS 7, some of the remediations 
# are meant for Centos 8 they can however be applied to Centos 7 with minimal changes.
#
# This script can easily be converted to other distros by changing the package manager
# used in section 1 and 2
#

DATENOW=$(date +"%m-%d-%Y")
REPORTHOME=/tmp/redshift/$DATENOW/CIS_POSTGRESQL_12/
REPORT=/tmp/redshift/$DATENOW/CIS_POSTGRESQL_12/report.txt
POSTGRESQL_DEFAULTS_EXTRA_FILE=/tmp/redshift/$DATENOW/CIS_POSTGRESQL_12/.altpgpass
POSTGRESCONFIG=/tmp/redshift/$DATENOW/CIS_POSTGRESQL_12/postgresql.conf

# create folder structure for report output
mkdir -p $REPORTHOME

# Echo timestamp
echo "########### Redshift CIS PostgreSQL 12 $(date) ###########"

# comment out lines 27 to 30 if you are absolutely sure the current user has the required permissions
if (( $UID != 0 )); then
  echo "Please run as root"
  exit
fi

for OUTPUT in $(find /etc/postgresql/12/main -name postgresql.conf); do
  cp $OUTPUT $REPORTHOME
done


echo "########### Redshift CIS CIS PostgreSQL 12 $(date) ###########" > $REPORT
echo "Script executed with id: $(id)" >> $REPORT

echo "Enter your username for the PostgreSQL Admin User (Usually postgres)";
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

echo "PostgreSQL User used is: $username" >> $REPORT
echo "localhost:5432:*:$username:$password" > $POSTGRESQL_DEFAULTS_EXTRA_FILE
chmod 0600 $POSTGRESQL_DEFAULTS_EXTRA_FILE
export PGPASSFILE=$POSTGRESQL_DEFAULTS_EXTRA_FILE

echo -e "\r\n--> Section 1 Installation and Patches" >> $REPORT
echo -e "\r\n----> 1.1 Ensure packages are obtained from authorized repositories" >> $REPORT
#

#Description:
#When obtaining and installing software packages (typically via yum ), it's imperative that
#packages are sourced only from valid and authorized repositories. For PostgreSQL, the
#canonical repositories are the official PostgreSQL YUM repository (yum.postgresql.org) and
#the official PostgreSQL APT repository (apt.postgresql.org).

#Rationale:
#Being open source, PostgreSQL packages are widely available across the internet through
#RPM aggregators and providers. However, using invalid or unauthorized sources for
#packages can lead to implementing untested, defective, or malicious software.
#
#Many organizations choose to implement a local software repository within their
#organization. Care must be taken to ensure that only valid and authorized packages are
#downloaded and installed into such local repositories.

#Remediation:
#Alter the configured repositories so they only include valid and authorized sources of
#packages.

#As an example of adding an authorized repository, we will install the PGDG repository RPM
#from 'yum.postgresql.org' (note that because of a change in the way packaging is handled in
#RHEL 8, we also need to disable the PostgreSQL module):
#(Note # indicate a bash command)
## whoami
#root
## dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
#Last metadata expiration check: 0:01:35 ago on Fri 04 Oct 2019 01:19:37 PM
#EDT.
#[snip]
#Installed:
# pgdg-redhat-repo-42.0-5.noarch
#
#Complete!
## dnf -qy module disable postgresql
#
#Verify the repository has been added and is enabled:
#
## whoami
#root
## dnf repolist all | grep enabled:
#AppStream CentOS-8 - AppStream enabled: 4,928
#BaseOS CentOS-8 - Base enabled: 2,713
#extras CentOS-8 - Extras enabled: 3
#pgdg10 PostgreSQL 10 for RHEL/CentOS 8 - x enabled: 504
#pgdg11 PostgreSQL 11 for RHEL/CentOS 8 - x enabled: 526
#pgdg12 PostgreSQL 12 for RHEL/CentOS 8 - x enabled: 377
#pgdg94 PostgreSQL 9.4 for RHEL/CentOS 8 - enabled: 184

#References:
#1. https://wiki.centos.org/PackageManagement/Yum/
#2. https://www.centos.org/docs/5/html/5.2/Deployment_Guide/s1-yum-yumconf-repository.html
#3. https://en.wikipedia.org/wiki/Yum_(software)
#4. https://www.howtoforge.com/creating_a_local_yum_repository_centos
#5. https://yum.postgresql.org
#6. https://apt.postgresql.org

whoami >> $REPORT
yum repolist all | grep enabled: 2&>1 >> $REPORT

echo -e "\r\n----> 1.2 Ensure Installation of Binary Packages" >> $REPORT

#Description:
#The PostgreSQL packages are installed on the Operating System from valid source.

#Rationale:
#Standard Linux distributions, although possessing the requisite packages, often do not have
#PostgreSQL pre-installed. The installation process includes installing the binaries and the
#means to generate a data cluster too. Package installation should include both the server
#and client packages. Contribution modules are optional depending upon one's architectural
#requirements (they are recommended though).
#
#From a security perspective, it's imperative to verify the PostgreSQL binary packages are
#sourced from a valid software repository. For a complete listing of all PostgreSQL binaries
#available via configured repositories inspect the output from dnf provides '*libpq.so' .

#Remediation:
#
#If the version of PostgreSQL installed is not 12.x, the packages may be uninstalled using this
#command:
#
#$ whoami
#root
#dnf remove $(rpm -qa|grep postgres)
#
#The next recommendation "1.3 Ensure Installation of Community Packages" describes how
#to explicitly choose which version of PostgreSQL to install, regardless of Linux distribution
#association.

#Impact:
#If the PostgreSQL version shipped as part of the default binary installation associated with
#your Linux distribution satisfies your requirements, this may be adequate for development
#and testing purposes. However, for production instances it's generally recommended to
#install the latest stable release of PostgreSQL.

#Audit

whoami >> $Report
yum info $(rpm -qa|grep postgres) | egrep '^Name|^Version|^From' 2&>1 >> $REPORT

#If the expected binary packages are not installed, are not the expected versions, or did not
#come from an appropriate repo, this is a fail.

echo -e "\r\n----> 1.3 Ensure Installation of Community Packages" >> $REPORT

#Description:
#Adding, and installing, the PostgreSQL community packages to the host's package
#repository.

#Rationale:
#It's an unfortunate reality that Linux distributions do not always have the most up-to-date
#versions of PostgreSQL. Disadvantages of older releases include: missing bug patches, no
#access to highly desirable contribution modules, no access to 3rd party projects that are
#complimentary to PostgreSQL, and no upgrade path migrating from one version of
#PostgreSQL to the next. The worst set of circumstances is to be limited to a version of the
#RDBMS that has reached its end-of-life.
#
#From a security perspective, it's imperative that Postgres Community Packages are only
#obtained from the official website https://yum.postgresql.org/. Being open source, the
#Postgres packages are widely available over the internet via myriad package aggregators
#and providers. Obtaining software from these unofficial sites risks installing defective,
#corrupt, or downright malicious versions of PostgreSQL.

#Remediation:
#The following example adds the PGDG repository RPM for PostgreSQL, configures dnf to
#prefer the PGDG packages for version 11, and installs the client-server-contributions rpms
#to the host where you want to install the RDBMS.
#
#Using a web browser, go to http://yum.postgresql.org and navigate to the repo download
#link for your OS and version. Copy the URL to the repo file, and then tell dnf to install it:
#
## whoami
#root
## dnf install -y https://download.postgresql.org/pub/repos$POSRGRESUSER/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
#Last metadata expiration check: 0:01:35 ago on Fri 04 Oct 2019 01:19:37 PM EDT.
#[snip]
#Installed:
#pgdg-redhat-repo-42.0-5.noarch
#Complete!
#dnf -qy module disable postgresqlPOSRGRESUSERNAME
#
#Now, configure dnf to prefer the PGDG packages for version 11:
#
## cd /etc/yum.repos.d
## for i in AppStream Base Extras
#do
#echo 'exclude=postgresql*' >> CentOS-$i.repo
#done
#
#Finally, install the PostgreSQL packages:
#
## whoami
#root
## dnf -y groupinstall 'PostgreSQL Database Server 12 PGDG'
#Dependencies resolved.
#[snip]
#Installed:
#postgresql12-12.0-1PGDG.rhel8.x86_64
#postgresql12-contrib-12.0-1PGDG.rhel8.x86_64
#postgresql12-libs-12.0-1PGDG.rhel8.x86_64
#postgresql12-server-12.0-1PGDG.rhel8.x86_64
#python2-2.7.15-22.module_el8.0.0+32+017b2cba.x86_64
#python2-libs-2.7.15-22.module_el8.0.0+32+017b2cba.x86_64
#python2-pip-9.0.3-13.module_el8.0.0+32+017b2cba.noarch
#python2-setuptools-39.0.1-11.module_el8.0.0+32+017b2cba.noarch
#libicu-60.2-7.el8.x86_64
#libxslt-1.1.32-3.el8.x86_64
#Complete!

#Note: The above-mentioned example is referenced as an illustration only. Package names
#and versions may differ.

#Audit
whoami >> $REPORT
yum info $(rpm -qa|grep postgres) | egrep '^Name|^Version|^$POSRGRESUSERFrom' 2>&1 >> $REPORT

echo -e "\r\n----> 1.4 Ensure systemd Service Files Are Enabled" >> $REPORT

#Description:
#Confirm, and correct if necessary, the PostgreSQL systemd service is enabled.

#Rationale:
#Enabling the systemd service on the OS ensures the database service is active when a
#change of state occurs as in the case of a system startup or reboot.

#Remediation:
#Irrespective of package source, PostgreSQL services can be identified because it typically
#includes the text string "postgresql". PGDG installs do not automatically register the service
#as a "want" of the default systemd target. Multiple instances of PostgreSQL services often
#distinguish themselves using a version number.
#
## whoami
#root
## systemctl enable postgresql-12
#Created symlink /etc/systemd/system/multi-user.target.wants/postgresql-12.service → /usr/lib/systemd/system/postgresql-12.service.
## systemctl list-dependencies multi-user.target | grep -i postgres
# ├─postgresql-12.service

#Audit
whoami >> $REPORT
systemctl get-default 2>&1 >> $REPORT
systemctl list-dependencies multi-user.target | grep -i postgres 2>&1 >> $REPORT

#If the intended PostgreSQL service is not registered as a dependency (or "wanPOSRGRESUSERNAMEt") of the
#default target (no output for the 3rd command above), this is a fail.

echo -e "\r\n----> 1.5 Ensure Data Cluster Initialized Successfully" >> $REPORT

#Description:
#First time installs of PostgreSQL requires the instantiation of the database cluster. A
#database cluster is a collection of databases that are managed by a single server instance.

#Rationale:
#For the purposes of security, PostgreSQL enforces ownershi$POSRGRESUSERp and permissions of the data-
#cluster such that:
#•An initialized data-cluster is owned by the UNIX account that created it.
#•The data-cluster cannot be accessed by other UNIX user-accounts.
#•The data-cluster cannot be created or owned by root
#•The PostgreSQL process cannot be invoked by root nor any UNIX user account
#other than the owner of the data cluster.
#
#Incorrectly instantiating the data-cluster will result in a failed installation.

#Remediation:
#Attempting to instantiate a data cluster to an existing non-empty directory will fail:
#
## whoami
#root
## PGSETUP_INITDB_OPTIONS="-k" /usr/pgsql-12/bin/postgresql-12-setup initdb
#Data directory is not empty!

#In the case of a cluster instantiation failure, one must delete/remove the entire data cluster
#directory and repeat the initdb command:

## whoami
#root
## rm -rf ~postgres/12
## PGSETUP_INITDB_OPTIONS="-k" /usr/pgsql-12/bin/postgresql-12-setup initdb
#Initializing database ... OK

#Audit
whoami >> $REPORT
ls -la ~postgres/12 2>&1 >> $REPORT
/usr/pgsql-12/bin/postgresql-12-check-db-dir ~postgres/12/data
echo $? >> $REPORT

echo -e "\r\n--> Section 2 Directory and File Permissions" >> $REPORT

echo -e "\r\n----> 2.1 Ensure Data Clustpostgreser Initialized Successfully" >> $REPORT

#Description:
#Files are always created using a default set of permissions. File permissions can be
#restricted by applying a permissions mask called the umask . The postgres user account
#should use a umask of 077 to deny file access to all user accounts except the owner.
#
#Rationale:
#The Linux OS defaults the umask to 002 , which means the owner and primary group can
#read and write the file, and other accounts are permitted to read the file. Not explicitly
#setting the umask to a value as restrictive as 077 allows other users to read, write, or even
#execute files and scripts created by the postgres user account. The alternative to using a
#umask is explicitly updating file permissions after file creation using the command line
#utility chmod (a manual and error prone process that is not advised).
#
#Remediation:
#Depending upon the postgres user's environment, the umask is typically set in the
#initialization file .bash_profile , but may also be set in .profile or .bashrc . To set the
#umask, add the following to the appropriate profile file:
#
#$ whoami
#postgresPOSRGRESUSERNAME
#$ cd ~
#$ ls -ld .{bash_profile,profile,bashrc}
#ls: cannot access .profile: No such file or directory
#
#ls: cannot access .bashrc: No such file or directory
#-rwx------. 1 postgres postgres 267 Aug 14 12:59 .bash_profile
#$ echo "umask 077" >> .bash_profile
#$ source .bash_profile
#$ umask
#0077

whoami >> $REPORT
su -c whoami postgres >> $REPORT
su -c umask postgres >> $REPORT

#The umask must be 077 or more restrictive for the postgres user, otherwise this is a fail.

echo -e "\r\n----> 2.2 Ensure the PostgreSQL pg_wheel group membership is correct" >> $REPORT

#Description:
#The group pg_wheel is explicitly created on a host where the PostgreSQL server is installed.
#Membership in this group enables an ordinary user account to gain 'superuser' access to a
#database cluster by using the sudo command (See 'Ensure sudo is configured correctly'
#later in this benchmark). Only user accounts authorized to have superuser access should be
#members of the pg_wheel group.
#POSRGRESUSERNAME
#Rationale:
#Users with unauthorized membership in the pg_wheel group can assume the privileges of
#the owner of the PostgreSQL RDBMS and administer the database, as well as accessing
#scripts, files, and other executables they should not be able to access.
#
#Remediation:
#If the pg_wheel group does not exist, use the following command to create it:
#
#$ whoami
#root
#$ groupadd pg_wheel && getent group pg_wheel
#pg_wheel:x:502:
#
#Note: that your system's group number may not be 502 . That's OK.
#
#Adding the postgres user to the newly created group is done by issuing:#
#
#$ whoami
#root
#$ gpasswd -a postgres pg_wheel
#Adding user postgres to group pg_wheel
#$ # verify membership
#$ awk -F':' '/pg_wheel/{print $4}' /etc/group
#postgres
#
#Removing a user account from the 'pg_wheel' group is achieved by executing the following
#command:
#
#$ whoami
#root
#$ gpasswd -d pg_wheel postgres
#Removing user postgres from group pg_wheel
#$ # verify the user was removed
#$ awk -F':' '/pg_wheel/{print $4}' /etc/group

#Audit:
#Execute the command getent to confirm that a pg_wheel group exists. If no such group
#exists, this is a fail:
whoami >> $REPORT
getent group pg_wheel >> $REPORT

#If such a group does exist, view its membership and confirm that each user is authorized to
#act as an administrator;
if getent group pg_wheel; then
	awk -F':' '/pg_wheel/{print $4}' /etc/group >> $REPORT
	echo "Further Manual Checks may be needed" >> $REPORT
else
	echo "FAIL" >> $REPORT
fi


echo -e "\r\n--> Section 3 Logging Monitoring And Auditing" >> $REPORT

echo -e "\r\n----> 3.1 PostgreSQL Logging" >> $REPORT

echo -e "\r\n------> 3.1.2 Ensure the log destinations are set correctly" >> $REPORT

#Description:
#PostgreSQL supports several methods for logging server messages, including stderr ,
#csvlog and syslog . On Windows, eventlog is also supported. One or more of these
#destinations should be set for server log output.
#
#Rationale:
#If log_destination is not set, then any log messages generated by the core PostgreSQL
#processes will be lost.
#
#Remediation:
#Execute the following SQL statements to remediate this setting (in this example, setting the
#log destination to csvlog ):
#
#postgres=# alter system set log_destination = 'csvlog';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)

#Audit:
export PGPASSFILE=$POSTGRESQL_DEFAULTS_EXTRA_FILE
psql -w -h localhost -U $username -c "show log_destination;" >> $REPORT

#The log destinations should comply with your organization's policies on logging. If all the
#expected log destinations are not set, this is a fail.

echo -e "\r\n------> 3.1.3 Ensure the logging collector is enabled" >> $REPORT

#Description:
#The logging collector is a background process that captures log messages sent to stderr
#and redirects them into log files. The logging_collector setting must be enabled in order
#for this process to run. It can only be set at server start.
#The logging collector approach is often more useful than logging to syslog , since some
#types of messages might not appear in syslog output. One common example is dynamic-
#linker failure message; another may be error messages produced by scripts such as
#archive_command .
#
#Note: This setting must be enabled when log_destination is either stderr or csvlog and
#for certain other logging parameters to take effect.
#
#Remediation:
#Execute the following SQL statement(s) to remediate this setting:
#postgres=# alter system set logging_collector = 'on';
#ALTER SYSTEM
#
#Unfortunately, this setting can only be changed at server (re)start. As root, restart the
#PostgreSQL service for this change to take effect:
#
## whoami
#root
## systemctl restart postgresql-12
## systemctl status postgresql-12|grep 'ago$'
#Active: active (running) since <date>; 1s ago
#
#Default Value:
#on

#Audit:
psql -w -h localhost -U $username -c "show logging_collector;" >> $REPORT

echo -e "\r\n------> 3.1.4 Ensure the log file destination directory is set correctly" >> $REPORT

#Description:
#The log_directory setting specifies the destination directory for log files when
#log_destination is stderr or csvlog . It can be specified as relative to the cluster data
#directory ( $PGDATA ) or as an absolute path. log_directory should be set according to your
#organization's logging policy.
#
#Rationale:
#If log_directory is not set, it is interpreted as the absolute path '/' and PostgreSQL will
#attempt to write its logs there (and typically fail due to a lack of permissions to that
#directory). This parameter should be set to direct the logs into the appropriate directory
#location as defined by your organization's logging policy.
#
#Remediation:
#Execute the following SQL statement(s) to remediate this setting:
#
#postgres=# alter system set log_directory='/var/log/postgres';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#postgres=# show log_directory;
#log_directory
#---------------
#/var/log/postgres
#(1 row)

#Note: The use of /var/log/postgres , above, is an example. This should be set to an
#appropriate path as defined by your organization's logging requirements. Having said that,
#it is a good idea to have the logs outside of your PGDATA directyory so that they are not
#included by things like pg_basebackup or pgBackRest .

#Default Value:
#log which is relative to the cluster's data directory (e.g.
#/var/lib/pgsql/<majorversion>/data/log )

#Audit:
psql -w -h localhost -U $username -c "show log_directory;" >> $REPORT

echo -e "\r\n------> 3.1.5 Ensure the filename pattern for log files is set correctlyy" >> $REPORT

#Description:
#The log_filename setting specifies the filename pattern for log files. The value for
#log_filename should match your organization's logging policy.
#
#The value is treated as a strftime pattern, so %-escapes can be used to specify time-
#varying filenames. The supported %-escapes are similar to those listed in the Open Group's
#strftime specification. If you specify a filename without escapes, you should plan to use a
#log rotation utility to avoid eventually filling the partition that contains log_directory . If
#there are any time-zone-dependent %-escapes , the computation is done in the zone
#specified by log_timezone . Also, the system's strftime is not used directly, so platform-
#specific (nonstandard) extensions do not work.
#
#If CSV-format output is enabled in log_destination , .csv will be appended to the log
#filename. (If log_filename ends in .log , the suffix is replaced instead.)
#
#Rationale:
#If log_filename is not set, then the value of log_directory is appended to an empty string
#and PostgreSQL will fail to start as it will try to write to a directory instead of a file.
#
#Remediation:
#Execute the following SQL statement(s) to remediate this setting:
#postgres=# alter system set log_filename='postgresql-%Y%m%d.log';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#postgres=# show log_filename;
#log_filename
#-------------------
#postgresql-%Y%m%d.log
#(1 row)
#Note: In this example, a new logfile will be created for each day (e.g. postgresql-
#20180901.log )
#
#Default Value:
#The default is postgresql-%a.log , which creates a new logfile for each day of the week (e.g.
#postgresql-Mon.log , postgresql-Tue.log ).

#Audit:
psql -w -h localhost -U $username -c "show log_filename;" >> $REPORT

echo -e "\r\n------> 3.1.6 Ensure the log file permissions are set correctly" >> $REPORT

#Description:
#The log_file_mode setting determines the file permissions for log files when
#logging_collector is enabled. The parameter value is expected to be a numeric mode
#specification in the form accepted by the chmod and umask system calls. (To use the
#customary octal format, the number must start with a 0 (zero).)
#
#The permissions should be set to allow only the necessary access to authorized personnel.
#In most cases the best setting is 0600 , so that only the server owner can read or write the
#log files. The other commonly useful setting is 0640 , allowing members of the owner's
#group to read the files, although to make use of that, you will need to alter the
#log_directory setting to store the log files outside the cluster data directory.
#
#Rationale:
#Log files often contain sensitive data. Allowing unnecessary access to log files may
#inadvertently expose sensitive data to unauthorized personnel.
#
#Remediation:
#Execute the following SQL statement(s) to remediate this setting (with the example
#assuming a desired value of 0600 ):
#
#postgres=# alter system set log_file_mode = '0600';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#postgres=# show log_file_mode;
#log_file_mode
#---------------
#0600
#(1 row)

#Default Value:
#0600

#Audit:
psql -w -h localhost -U $username -c "show log_file_mode;" >> $REPORT

echo -e "\r\n------> 3.1.7 Ensure 'log_truncate_on_rotation' is enabled" >> $REPORT

#Description:
#Enabling the log_truncate_on_rotation setting when logging_collector is enabled
#causes PostgreSQL to truncate (overwrite) existing log files with the same name during log
#rotation instead of appending to them. For example, using this setting in combination with
#a log_filename setting value like postgresql-%H.log would result in generating 24 hourly
#log files and then cyclically overwriting them:
#
#postgresql-00.log
#[...]
#postgresql-23.log
#
#Note: Truncation will occur only when a new file is being opened due to time-based
#rotation, not during server startup or size-based rotation (see later in this benchmark for
#size-based rotation details).
#
#Rationale:
#If this setting is disabled, pre-existing log files will be appended to if log_filename is
#configured in such a way that static names are generated.
#
#Enabling or disabling the truncation should only be decided when also considering the
#value of log_filename and log_rotation_age / log_rotation_size . Some examples to
#
#illustrate the interaction between these settings:
## truncation is moot, as each rotation gets a unique filename (postgresql-20180605.log)
#log_truncate_on_rotation = on
#log_filename = 'postgresql-%Y%m%d.log'
#log_rotation_age = '1d'
#log_rotation_size = 0
## truncation every hour, losing log data every hour until the date changes
#log_truncate_on_rotation = on
#log_filename = 'postgresql-%Y%m%d.log'
#log_rotation_age = '1h'
#log_rotation_size = 0
## no truncation if the date changed while generating 100M of log data,truncation otherwise
#log_truncate_on_rotation = on
#log_filename = 'postgresql-%Y%m%d.log'
#log_rotation_age = '0'
#log_rotation_size = '100M'
#
#Remediation:
#Execute the following SQL statement(s) to remediate this setting:
#postgres=# alter system set log_truncate_on_rotation = 'on';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#postgres=# show log_truncate_on_rotation;
#log_truncate_on_rotation
#--------------------------
#on
#(1 row)
#
#Default Value:
#on

#Audit:
psql -w -h localhost -U $username -c "show log_truncate_on_rotation;" >> $REPORT

echo -e "\r\n------> 3.1.8 Ensure the maximum log file lifetime is set correctly" >> $REPORT

#Description:
#When logging_collector is enabled, the log_rotation_age parameter determines the
#maximum lifetime of an individual log file (depending on the value of log_filename ). After
#this many minutes have elapsed, a new log file will be created via automatic log file
#rotation. Current best practices advise log rotation at least daily, but your organization's
#logging policy should dictate your rotation schedule.
#
#Rationale:
#Log rotation is a standard best practice for log management.
#
#Remediation:
#Execute the following SQL statement(s) to remediate this setting (in this example, setting it
#to one hour):
#
#postgres=# alter system set log_rotation_age='1h';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#
#Default Value:
#1d (one day)

#Audit:
psql -w -h localhost -U $username -c "show log_rotation_age;" >> $REPORT

echo -e "\r\n------> 3.1.9 Ensure the maximum log file size is set correctly" >> $REPORT

#The log_rotation_size setting determines the maximum size of an individual log file.
#Once the maximum size is reached, automatic log file rotation will occur.
#
#Rationale:
#If this is set to zero, size-triggered creation of new log files is disabled. This will prevent
#automatic log file rotation when files become too large, which could put log data at
#increased risk of loss (unless age-based rotation is configured).
#
#Remediation:
#
#Execute the following SQL statement(s) to remediate this setting (in this example, setting it
#to 1GB ):
#
#postgres=# alter system set log_rotation_size = '1GB';
#
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#
#Default Value:
#0

#Audit:
psql -w -h localhost -U $username -c "show log_rotation_size;" >> $REPORT

echo -e "\r\n------> 3.1.10 Ensure the correct syslog facility is selected" >> $REPORT

#Description:
#The syslog_facility setting specifies the syslog "facility" to be used when logging to
#syslog is enabled. You can choose from any of the 'local' facilities:
#LOCAL0
#LOCAL1
#LOCAL2
#LOCAL3
#LOCAL4
#LOCAL5
#LOCAL6
#LOCAL7
#Your organization's logging policy should dictate which facility to use based on the syslog
#daemon in use.
#Rationale:
#If not set to the appropriate facility, the PostgreSQL log messages may be intermingled with
#other applications' log messages, incorrectly routed, or potentially dropped (depending on
#your syslog configuration).

#Remediation:
#Execute the following SQL statement(s) to remediate this setting (in this example, setting it
#to the LOCAL1 facility):
#44 | P a g epostgres=# alter system set syslog_facility = 'LOCAL1';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#LOCAL0

#Audit:
psql -w -h localhost -U $username -c "show syslog_facility;" >> $REPORT

echo -e "\r\n------> 3.1.11 Ensure the program name for PostgreSQL syslog messages is correct" >> $REPORT

#Description:
#The syslog_ident setting specifies the program name used to identify PostgreSQL
#messages in syslog logs. An example of a possible program name is postgres .
#Rationale:
#If this is not set correctly, it may be difficult or impossible to distinguish PostgreSQL
#messages from other messages in syslog logs.

#Remediation:
#Execute the following SQL statement(s) to remediate this setting (in this example,
#assuming a program name of proddb ):
#postgres=# alter system set syslog_ident = 'proddb';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#postgres=# show syslog_ident;
#syslog_ident
#--------------
#proddb
#(1 row)
#Default Value:
#postgres

#Audit:
psql -w -h localhost -U $username -c "show syslog_ident;" >> $REPORT

echo -e "\r\n------> 3.1.12 Ensure the correct messages are written to the server log" >> $REPORT

#Description:
#The log_min_messages setting specifies the message levels that are written to the server
#log. Each level includes all the levels that follow it. The lower the level (vertically, below),
#the fewer messages are sent.
#Valid values are:
#DEBUG5 <-- exceedingly chatty
#DEBUG4
#DEBUG3
#DEBUG2
#DEBUG1
#INFO
#NOTICE
#WARNING
#ERROR
#LOG
#FATAL
#PANIC <-- practically mute
#WARNING is considered the best practice unless indicated otherwise by your organization's
#logging policy.

#Rationale:
#If this is not set to the correct value, too many messages or too few messages may be
#written to the server log.

#Remediation:
#Execute the following SQL statement(s) as superuser to remediate this setting (in this
#example, to set it to warning ):
#postgres=# alter system set log_min_messages = 'warning';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#WARNING

#Audit:
psql -w -h localhost -U $username -c "show log_min_messages;" >> $REPORT

echo -e "\r\n------> 3.1.13 Ensure the correct SQL statements generating errors are
recorded" >> $REPORT

#Description:
#The log_min_error_statement setting causes all SQL statements generating errors at or
#above the specified severity level to be recorded in the server log. Each level includes all
#the levels that follow it. The lower the level (vertically, below), the fewer messages are
#recorded. Valid values are:
#DEBUG5 <-- exceedingly chatty
#DEBUG4
#DEBUG3
#DEBUG2
#DEBUG1
#INFO
#NOTICE
#WARNING
#ERROR
#LOG
#FATAL
#PANIC <-- practically mute
#ERROR is considered the best practice setting. Changes should only be made in accordance
#with your organization's logging policy.
#Note: To effectively turn off logging of failing statements, set this parameter to PANIC .
#Rationale:
#If this is not set to the correct value, too many erring SQL statements or too few erring SQL
#statements may be written to the server log.

#Remediation:
#Execute the following SQL statement(s) as superuser to remediate this setting (in the
#example, to error ):
#postgres=# alter system set log_min_error_statement = 'error';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#ERROR

#Audit:
psql -w -h localhost -U $username -c "show log_min_error_statement;" >> $REPORT

echo -e "\r\n------> 3.1.14 Ensure 'debug_print_parse' is disabled" >> $REPORT

#Description:
#The debug_print_parse setting enables printing the resulting parse tree for each executed
#query. These messages are emitted at the LOG message level. Unless directed otherwise by
#your organization's logging policy, it is recommended this setting be disabled by setting it
#to off .
#Rationale:
#Enabling any of the DEBUG printing variables may cause the logging of sensitive information
#that would otherwise be omitted based on the configuration of the other logging settings.

#Remediation:
#Execute the following SQL statement(s) to remediate this setting:
#postgres=# alter system set debug_print_parse='off';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#off

#Audit:
psql -w -h localhost -U $username -c "show debug_print_parse;" >> $REPORT

echo -e "\r\n------> 3.1.15 Ensure 'debug_print_rewritten' is disabled" >> $REPORT

#Description:
#The debug_print_rewritten setting enables printing the query rewriter output for each
#executed query. These messages are emitted at the LOG message level. Unless directed
#otherwise by your organization's logging policy, it is recommended this setting be disabled
#by setting it to off .
#Rationale:
#Enabling any of the DEBUG printing variables may cause the logging of sensitive information
#that would otherwise be omitted based on the configuration of the other logging settings.

#Remediation:
#Execute the following SQL statement(s) to disable this setting:
#postgres=# alter system set debug_print_rewritten = 'off';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#off

#Audit:
psql -w -h localhost -U $username -c "show debug_print_rewritten;" >> $REPORT

echo -e "\r\n------> 3.1.16 Ensure 'debug_print_plan' is disabled" >> $REPORT

#Description:
#The debug_print_plan setting enables printing the execution plan for each executed query.
#These messages are emitted at the LOG message level. Unless directed otherwise by your
#organization's logging policy, it is recommended this setting be disabled by setting it to off .
#Rationale:
#Enabling any of the DEBUG printing variables may cause the logging of sensitive information
#that would otherwise be omitted based on the configuration of the other logging settings.

#Remediation:
#Execute the following SQL statement(s) to disable this setting:
#postgres=# alter system set debug_print_plan = 'off';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#off

#Audit:
psql -w -h localhost -U $username -c "show debug_print_plan;" >> $REPORT

echo -e "\r\n------> 3.1.17 Ensure 'debug_pretty_print' is enabled" >> $REPORT

#Description:
#Enabling debug_pretty_print indents the messages produced by debug_print_parse ,
#debug_print_rewritten , or debug_print_plan making them significantly easier to read.
#Rationale:
#If this setting is disabled, the "compact" format is used instead, significantly reducing
#readability of the DEBUG statement log messages.

#Remediation:
#Execute the following SQL statement(s) to enable this setting:
#postgres=# alter system set debug_pretty_print = 'on';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Impact:
#Be advised that the aforementioned DEBUG printing options are disabled, but if your
#organizational logging policy requires them to be on then this option comes into play.
#Default Value:
#on

#Audit:
psql -w -h localhost -U $username -c "show debug_pretty_print;" >> $REPORT

echo -e "\r\n------> 3.1.18 Ensure 'log_connections' is enabled" >> $REPORT

#Description:
#Enabling the log_connections setting causes each attempted connection to the server to
#be logged, as well as successful completion of client authentication. This parameter cannot
#be changed after session start.

#Rationale:
#PostgreSQL does not maintain an internal record of attempted connections to the database
#for later auditing. It is only by enabling the logging of these attempts that one can
#determine if unexpected attempts are being made.
#Note that enabling this without also enabling log_disconnections provides little value.
#Generally, you would enable/disable the pair together.


#Remediation:
#Execute the following SQL statement(s) to enable this setting:
#postgres=# alter system set log_connections = 'on';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#off

#Audit:
psql -w -h localhost -U $username -c "show log_connections;" >> $REPORT

echo -e "\r\n------> 3.1.19 Ensure 'log_disconnections' is enabled" >> $REPORT

#Description:
#Enabling the log_disconnections setting logs the end of each session, including session
#duration. This parameter cannot be changed after session start.

#Rationale:
#PostgreSQL does not maintain the beginning or ending of a connection internally for later
#review. It is only by enabling the logging of these that one can examine connections for
#failed attempts, 'over long' duration, or other anomalies.
#Note that enabling this without also enabling log_connections provides little value.
#Generally, you would enable/disable the pair together.

#Remediation:
#Execute the following SQL statement(s) to enable this setting:
#postgres=# alter system set log_disconnections = 'on';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#off

#Audit:
psql -w -h localhost -U $username -c "show log_disconnections;" >> $REPORT

echo -e "\r\n------> 3.1.20 Ensure 'log_error_verbosity' is set correctly" >> $REPORT

#Description:
#The log_error_verbosity setting specifies the verbosity (amount of detail) of logged
#messages. Valid values are:
#TERSE
#DEFAULT
#VERBOSE
#with each containing the fields of the level above it as well as additional fields.
#TERSE excludes the logging of DETAIL , HINT , QUERY , and CONTEXT error information.
#VERBOSE output includes the SQLSTATE , error code, and the source code file name, function
#name, and line number that generated the error.
#The appropriate value should be set based on your organization's logging policy.

#Rationale:
#If this is not set to the correct value, too many details or too few details may be logged.

#Remediation:
#Execute the following SQL statement(s) as superuser to remediate this setting (in this
#example, to verbose ):
#postgres=# alter system set log_error_verbosity = 'verbose';
#ALTER SYSTEM
#64 | P a g epostgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#DEFAULT

#Audit:
psql -w -h localhost -U $username -c "show log_error_verbosity;" >> $REPORT

echo -e "\r\n------> 3.1.21 Ensure 'log_hostname' is set correctly" >> $REPORT

#Description:
#Enabling the log_hostname setting causes the hostname of the connecting host to be logged
#in addition to the host's IP address for connection log messages. Disabling the setting
#causes only the connecting host's IP address to be logged, and not the hostname. Unless
#your organization's logging policy requires hostname logging, it is best to disable this
#setting so as not to incur the overhead of DNS resolution for each statement that is logged.

#Rationale:
#Depending on your hostname resolution setup, enabling this setting might impose a non-
#negligible performance penalty. Additionally, the IP addresses that are logged can be
#resolved to their DNS names when reviewing the logs (unless dynamic host names are
#being used as part of your DHCP setup).

#Remediation:
#Execute the following SQL statement(s) to remediate this setting (in this example, to off ):
#postgres=# alter system set log_hostname='off';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#off

#Audit:
psql -w -h localhost -U $username -c "show log_hostname;" >> $REPORT

echo -e "\r\n------> 3.1.22 Ensure 'log_line_prefix' is set correctly" >> $REPORT

#Description:
#The log_line_prefix setting specifies a printf -style string that is prefixed to each log line.
#If blank, no prefix is used. You should configure this as recommended by the pgBadger
#development team unless directed otherwise by your organization's logging policy.
#% characters begin "escape sequences" that are replaced with status information as
#outlined below. Unrecognized escapes are ignored. Other characters are copied straight to
#the log line. Some escapes are only recognized by session processes and will be treated as
#empty by background processes such as the main server process. Status information may
#be aligned either left or right by specifying a numeric literal after the % and before the
#option. A negative value will cause the status information to be padded on the right with
#spaces to give it a minimum width, whereas a positive value will pad on the left. Padding
#can be useful to aid human readability in log files.
#Any of the following escape sequences can be used:
#Escape	Effect							Session only
#%a	Application name
#%u 	User name						yes
#%d 	Database name						yes
#%r 	Remote host name or IP address, and remote port		yes
#%h 	Remote host name or IP address				yes
#%p 	Process ID						yes
#%t	Time stamp without milliseconds				no
#%m	Time stamp with milliseconds				no
#%i	Command tag: type of session's current command		no
#%e	SQLSTATE error code					yes
#%c	Session ID: see below					no
#%l	Number of the log line for each session			no
#	or process, starting at 1				
#%s	Process start time stamp				no
#%v	Virtual transaction ID (backendID/localXID)		no
#%x	Transaction ID (0 if none is assigned)			no
#%q	Produces no output, but tells non-session		no
#	processes to stop at this point in the string;
#	ignored by session processes
#%%	Literal %						no

#Rationale:
#Properly setting log_line_prefix allows for adding additional information to each log
#entry (such as the user, or the database). Said information may then be of use in auditing or
#security reviews.

#Remediation:
#Execute the following SQL statement(s) to remediate this setting:
#postgres=# alter system set log_line_prefix = '%m [%p]: [%l-1]
#db=%d,user=%u,app=%a,client=%h ';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#%m [%p]

#Audit:
psql -w -h localhost -U $username -c "show log_line_prefix;" >> $REPORT

echo -e "\r\n------> 3.1.23 Ensure 'log_statement' is set correctly" >> $REPORT

#Description:
#The log_statement setting specifies the types of SQL statements that are logged. Valid
#values are:
#none (off)
#ddl
#mod
#all (all statements)
#It is recommended this be set to ddl unless otherwise directed by your organization's
#logging policy.
#ddl logs all data definition statements:
#CREATE
#ALTER
#DROP
#mod logs all ddl statements, plus data-modifying statements:
#INSERT
#UPDATE
#DELETE
#TRUNCATE
#COPY FROM
#( PREPARE , EXECUTE , and EXPLAIN ANALYZE statements are also logged if their contained
#command is of an appropriate type.)
#For clients using extended query protocol, logging occurs when an Execute message is
#received, and values of the Bind parameters are included (with any embedded single-quote
#marks doubled).

#Rationale:
#Setting log_statement to align with your organization's secu

#Remediation:
#Execute the following SQL statement(s) as superuser to remediate this setting:
#postgres=# alter system set log_statement='ddl';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#t
#(1 row)
#Default Value:
#none

#Audit:
psql -w -h localhost -U $username -c "show log_statement;" >> $REPORT

echo -e "\r\n------> 3.1.24 Ensure 'log_timezone' is set correctly" >> $REPORT

#Description:
#The log_timezone setting specifies the time zone to use in timestamps within log messages.
#This value is cluster-wide, so that all sessions will report timestamps consistently. Unless
#directed otherwise by your organization's logging policy, set this to either GMT or UTC .

#Rationale:
#Log entry timestamps should be configured for an appropriate time zone as defined by
#your organization's logging policy to ensure a lack of confusion around when a logged
#event occurred.
#Note that this setting affects only the timestamps present in the logs. It does not affect the
#time zone in use by the database itself (for example, select now() ), nor does it affect the
#host's time zone.

#Remediation:
#Execute the following SQL statement(s) to remediate this setting:
#postgres=# alter system set log_timezone = 'GMT';
#ALTER SYSTEM
#postgres=# select pg_reload_conf();
#pg_reload_conf
#----------------
#(1 row)
#Default Value:
#By default, the PGDG packages will set this to match the server's timezone in the Operating
#System.

#Audit:
psql -w -h localhost -U $username -c "show log_timezone;" >> $REPORT

echo -e "\r\n----> 3.2 Ensure the PostgreSQL Audit Extension (pgAudit) is enabled" >> $REPORT

#Description:
#The PostgreSQL Audit Extension (pgAudit) provides detailed session and/or object audit
#logging via the standard PostgreSQL logging facility. The goal of pgAudit is to provide
#PostgreSQL users with the capability to produce audit logs often required to comply with
#government, financial, or ISO certifications.

#Rationale:
#Basic statement logging can be provided by the standard logging facility with
#log_statement = all . This is acceptable for monitoring and other uses but does not
#provide the level of detail generally required for an audit. It is not enough to have a list of
#all the operations performed against the database, it must also be possible to find
#particular statements that are of interest to an auditor. The standard logging facility shows
#what the user requested, while pgAudit focuses on the details of what happened while the
#database was satisfying the request.
#When logging SELECT and DML statements, pgAudit can be configured to log a separate entry
#for each relation referenced in a statement. No parsing is required to find all statements
#that touch a particular table. In fact, the goal is that the statement text is provided primarily
#for deep forensics and should not be required for an audit.
#
#Remediation:
#To install and enable pgAudit, simply install the appropriate rpm from the PGDG repo:
## whoami
#root
#[root@centos7 ~]# dnf -y install pgaudit14_12
#Last metadata expiration check: 0:09:08 ago on Mon 28 Oct 2019 11:23:30 AM
#EDT.
#Dependencies resolved.
#[snip]
#Installed:
#pgaudit14_12-1.4.0-1.rhel8.x86_64
#Complete!
#pgAudit is now installed and ready to be configured. Next, we need to alter the
#postgresql.conf configuration file to:
#enable pgAudit as an extension in the shared_preload_libraries parameter
#indicate which classes of statements we want to log via the pgaudit.log parameter
#and, finally, restart the PostgreSQL service:
#$ vi ${PGDATA}/postgresql.conf
#Find the shared_preload_libraries entry, and add 'pgaudit' to it (preserving any existing
#entries):
#shared_preload_libraries = 'pgaudit'
#OR
#shared_preload_libraries = 'pgaudit,somethingelse'
#Now, add a new pgaudit -specific entry:
# for this example we are logging the ddl and write operations
#pgaudit.log='ddl,write'
#Restart the PostgreSQL server for changes to take affect:
## whoami
#root
## systemctl restart postgresql-12
## systemctl status postgresql-12|grep 'ago$'
#Active: active (running) since [date] 10s ago
##
#Impact:
#Depending on settings, it is possible for pgAudit to generate an enormous volume of logging.
#Be careful to determine exactly what needs to be audit logged in your environment to avoid
#logging too much.

#Audit:
psql -w -h localhost -U $username -c "show shared_preload_libraries;" >> $REPORT

echo -e "\r\n-->Section 4 User Access and Authorization" >> $REPORT

echo -e "\r\n----> 4.1 Ensure sudo is configured correctly" >> $REPORT

#Description:
#It is common to have more than one authorized individual administering the PostgreSQL
#service at the Operating System level. It is also quite common to permit login privileges to
#individuals on a PostgreSQL host who otherwise are not authorized to access the server's
#data cluster and files. Administering the PostgreSQL data cluster, as opposed to its data, is
#to be accomplished via a localhost login of a regular UNIX user account. Access to the
#postgres superuser account is restricted in such a manner as to interdict unauthorized
#access. sudo satisfies the requirements by escalating ordinary user account privileges as
#the PostgreSQL RDBMS superuser.

#Rationale:
#Without sudo , there would not be capabilities to strictly control access to the superuser
#account and to securely and authoritatively audit its use.

#Remediation:
#As superuser root , execute the following commands:
## echo '%pg_wheel ALL= /bin/su - postgres' > /etc/sudoers.d/postgres
## chmod 600 /etc/sudoers.d/postgres
#This grants any Operating System user that is a member of the pg_wheel group to use sudo
#su - postgres to become the postgres user.
#Ensure that all Operating System user's that need such access are members of the group as
#detailed earlier in this benchmark.

#Audit:
whoami >> $REPORT
groups >> $REPORT
echo "Please note this test needs manual confirmation" >> $REPORT

echo -e "\r\n----> 4.2 Ensure excessive administrative privileges are revoked" >> $REPORT

#Description:
#With respect to PostgreSQL administrative SQL commands, only superusers should have
#elevated privileges. PostgreSQL regular, or application, users should not possess the ability
#to create roles, create new databases, manage replication, or perform any other action
#deemed privileged. Typically, regular users should only be granted the minimal set of
#privileges commensurate with managing the application:
#DDL ( create table , create view , create index , etc.)
#DML ( select , insert , update , delete )
#Further, it has become best practice to create separate roles for DDL and DML. Given an
#application called 'payroll', one would create the following users:
#payroll_owner
#payroll_user
#Any DDL privileges would be granted to the payroll_owner account only, while DML
#privileges would be given to the payroll_user account only. This prevents accidental
#creation/altering/dropping of database objects by application code that run as the
#payroll_user account.
#
#Rationale:
#By not restricting global administrative commands to superusers only, regular users
#granted excessive privileges may execute administrative commands with unintended and
#undesirable results.
#
#Remediation:
#If any regular or application users have been granted excessive administrative rights, those
#privileges should be removed immediately via the PostgreSQL ALTER ROLE SQL command.
#Using the same example above, the following SQL statements revoke all unnecessary
#elevated administrative privileges from the regular user appuser :
#$ whoami
#postgres
#$ psql -c "ALTER
#ALTER ROLE
#$ psql -c "ALTER
#ALTER ROLE
#$ psql -c "ALTER
#ALTER ROLE
#$ psql -c "ALTER
#ALTER ROLE
#$ psql -c "ALTER
#ALTER ROLE
#ROLE appuser NOSUPERUSER;"
#ROLE appuser NOCREATEROLE;"
#ROLE appuser NOCREATEDB;"
#ROLE appuser NOREPLICATION;"
#ROLE appuser NOBYPASSRLS;"
#$ psql -c "ALTER ROLE appuser NOINHERIT;"
#ALTER ROLE
#Verify the appuser now passes your check by having no defined Attributes:
#$ whoami
#postgres
#$ psql -c "\du appuser"
#List of roles
#Role name | Attributes | Member of
#----------+------------+-----------
#appuser
#|
#| {}

#Audit:
su -c whoami postgres >> $REPORT
psql -w -h localhost -U $username -c "\du *" >> $REPORT
psql -w -h localhost -U $username -c "select * from pg_user order by usename" >> $REPORT

echo -e "\r\n----> 4.3 Ensure excessive function privileges are revoked" >> $REPORT

#Description:
#In certain situations, to provide required functionality, PostgreSQL needs to execute
#internal logic (stored procedures, functions, triggers, etc.) and/or external code modules
#with elevated privileges. However, if the privileges required for execution are at a higher
#level than the privileges assigned to organizational users invoking the functionality
#applications/programs, those users are indirectly provided with greater privileges than
#assigned by their organization. This is known as privilege elevation. Privilege elevation
#must be utilized only where necessary. Execute privileges for application functions should
#be restricted to authorized users only.

#Rationale:
#Ideally, all application source code should be vetted to validate interactions between the
#application and the logic in the database, but this is usually not possible or feasible with
#available resources even if the source code is available. The DBA should attempt to obtain
#assurances from the development organization that this issue has been addressed and
#should document what has been discovered. The DBA should also inspect all application
#logic stored in the database (in the form of functions, rules, and triggers) for excessive
#privileges.

#Remediation:
#Where possible, revoke SECURITY DEFINER on PostgreSQL functions. To change a SECURITY
#DEFINER function to SECURITY INVOKER , run the following SQL:
#$ whoami
#root
#$ sudo su - postgres
#$ psql -c "ALTER FUNCTION [functionname] SECURITY INVOKER;"
#If it is not possible to revoke SECURITY DEFINER , ensure the function can be executed by
#only the accounts that absolutely need such functionality:
#postgres=# SELECT proname, proacl FROM pg_proc WHERE proname =
#'delete_customer';
#proname
#|
#proacl
#-----------------+--------------------------------------------------------
#delete_customer | {=X/postgres,postgres=X/postgres,appwriter=X/postgres}
#(1 row)
#postgres=# REVOKE EXECUTE ON FUNCTION delete_customer(integer,boolean) FROM
#appreader;
#REVOKE
#postgres=# SELECT proname, proacl FROM pg_proc WHERE proname =
#'delete_customer';
#proname
#|
#proacl
#-----------------+--------------------------------------------------------
#delete_customer | {=X/postgres,postgres=X/postgres}
#(1 row)
#Based on output above, appreader=X/postgres no longer exists in the proacl column
#results returned from query and confirms appreader is no longer granted execute privilege
#on the function.

#Audit:
su -c whoami postgres >> $REPORT
psql -w -h localhost -U $username -c "SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL;" >> $REPORT

#In the query results, a prosecdef value of ' t ' on a row indicates that that function uses
#privilege elevation.

#If elevation of PostgreSQL privileges is utilized but not documented, this is a fail.
#If elevation of PostgreSQL privileges is documented, but not implemented as described in
#the documentation, this is a fail.
#If the privilege-elevation logic can be invoked in ways other than intended, or in contexts
#other than intended, or by subjects/principals other than intended, this is a fail.

echo -e "\r\n----> 4.4 Ensure excessive DML privileges are revoked" >> $REPORT

#Description:
#DML (insert, update, delete) operations at the table level should be restricted to only
#authorized users. PostgreSQL manages table level DML permissions via the GRANT
#statement.

#Rationale:
#Excessive DML grants can lead to unprivileged users changing or deleting information
#without proper authorization.

#Remediation:
#If a given database user has been granted excessive DML privileges for a given database
#table, those privileges should be revoked immediately using the REVOKE SQL command.
#Continuing with the example above, remove unauthorized grants for appreader user using
#the REVOKE statement and verify the Boolean values are now false.
#postgres=# REVOKE INSERT, UPDATE, DELETE ON TABLE customer FROM appreader;
#REVOKE
#postgres=# select t.tablename, u.usename,
#has_table_privilege(u.usename, t.tablename, 'select') as select,
#has_table_privilege(u.usename, t.tablename, 'insert') as insert,
#has_table_privilege(u.usename, t.tablename, 'update') as update,
#has_table_privilege(u.usename, t.tablename, 'delete') as delete
#from pg_tables t, pg_user u
#where t.tablename = 'customer'
#and u.usename in ('appwriter','appreader');
#
#tablename | usename | select | insert | update | delete
#----------+-----------+--------+--------+--------+--------
#customer | appwriter | t     | t      | t      | t
#customer | appwriter | t     | t      | t      | t
#(2 rows)
#With the publication of CVE-2018-1058, it is also recommended that all privileges be
#revoked from the public schema for all users on all databases:
#postgres=# REVOKE CREATE ON SCHEMA public FROM PUBLIC;
#REVOKE
#Default Value:
#The table own

#Audit:
echo -e "\r\nRequires manual verification for each database" >> $REPORT
su -c whoami postgres >> $REPORT
psql -w -h localhost -U $username -c "\du+ *" >> $REPORT
psql -w -h localhost -U $username -c "\dt+ *.*" >> $REPORT
psql -w -h localhost -U $username -c "select t.schemaname, t.tablename, u.usename, has_table_privilege(u.usename, t.tablename, 'select') as select, has_table_privilege(u.usename, t.tablename, 'insert') as insert, has_table_privilege(u.usename, t.tablename, 'update') as update, has_table_privilege(u.usename, t.tablename, 'delete') as delete from pg_tables t, pg_user u where t.schemaname not in ('information_schema','pg_catalog');" >> $REPORT

echo -e "\r\n----> 4.5 Use pg_permission extension to audit object permissions" >> $REPORT

#Description:
#Using a PostgreSQL extension called pg_permissions it is possible to declare which DB
#users should have which permissions on a given object and generate a report showing
#compliance/deviation.

#Rationale:
#Auditing permissions in a PostgreSQL database can be intimidating given the default
#manner in which permissions are presented. The pg_permissions extension greatly
#simplifies this presentation and allows the user to declare what permissions should exist
#and then report on differences from that ideal.

#Remediation:
#Please refer to CIS Postgres 12 Benchmark documentation for this exact remediation.

#Audit:
psql -w -h localhost -U $username -c "select * from pg_available_extensions where name ='pg_permission'" >> $REPORT

echo -e "\r\n----> 4.6 Ensure Row Level Security (RLS) is configured correctly" >> $REPORT

#Description:
#In addition to the SQL-standard privilege system available through GRANT , tables can have
#row security policies that restrict, on a per-user basis, which individual rows can be
#returned by normal queries or inserted, updated, or deleted by data modification
#commands. This feature is also known as Row Level Security (RLS).
#By default, tables do not have any policies, so if a user has access privileges to a table
#according to the SQL privilege system, all rows within it are equally available for querying
#or updating. Row security policies can be specific to commands, to roles, or to both. A
#policy can be specified to apply to ALL commands, or to any combination of SELECT , INSERT ,
#UPDATE , or DELETE . Multiple roles can be assigned to a given policy, and normal role
#membership and inheritance rules apply.
#If you use RLS and apply restrictive policies to certain users, it is important that the Bypass
#RLS privilege not be granted to any unauthorized users. This privilege overrides RLS-
#enabled tables and associated policies. Generally, only superusers and elevated users
#should possess this privilege.

#Rationale:
#If RLS policies and privileges are not configured correctly, users could perform actions on
#tables that they are not authorized to perform, such as inserting, updating, or deleting
#rows.

#Remediation:
#Please refer to CIS Postgres 12 Benchmark documentation for this exact remediation.

#Audit:
echo -e "\r\nRequires manual verification" >> $REPORT
psql -w -h localhost -U $username -c "SELECT oid, relname, relrowsecurity FROM pg_class WHERE relrowsecurity IS TRUE;" >> $REPORT

echo -e "\r\n----> 4.7 Ensure the set_user extension is installed" >> $REPORT

#Description:
#PostgreSQL access to the superuser database role must be controlled and audited to
#prevent unauthorized access.
#
#Rationale:
#Even when reducing and limiting the access to the superuser role as described earlier in
#this benchmark, it is still difficult to determine who accessed the superuser role and what
#actions were taken using that role. As such, it is ideal to prevent anyone from logging in as
#the superuser and forcing them to escalate their role. This model is used at the OS level by
#the use of sudo and should be emulated in the database. The set_user extension allows for
#this setup.

#Remediation:
#Please refer to CIS Postgres 12 Benchmark documentation for this exact remediation.

#Audit:
psql -w -h localhost -U $username -c "select * from pg_available_extensions where name = 'set_user';" >> $REPORT

#If the extension is not listed this is a fail.

echo -e "\r\n----> 4.8 Make use of default roles" >> $REPORT

#Description:
#PostgreSQL provides a set of default roles which provide access to certain, commonly
#needed, privileged capabilities and information. Administrators can GRANT these roles to
#users and/or other roles in their environment, providing those users with access to the
#specified capabilities and information.

#Rationale:
#In keeping with the principle of least privilege, judicious use of the PostgreSQL default roles
#can greatly limit the access to privileged, or superuser, access.

#Remediation:
#If you've determined that one or more of the default roles can be used, simply GRANT it:
#postgres=# GRANT pg_monitor TO doug;
#GRANT ROLE
#And then remove superuser from the account:
#postgres=# ALTER ROLE doug NOSUPERUSER;
#ALTER ROLE
#postgres=# select rolname from pg_roles where rolsuper is true;
#rolname
#----------
#postgres
#(1 row)

#Default Value:
#The following default roles exist in PostgreSQL 12.x:
#pg_read_all_settings Read all configuration variables, even those normally visible
#only to superusers.
#pg_read_all_stats Read all pg_stat_* views and use various statistics related
#extensions, even those normally vsu -c whoami postgres >> $REPORTisible only to superusers.
#pg_stat_scan_tables Execute monitoring functions that may take ACCESS SHARE
#locks on tables, potentially for a long time.
#pg_signal_backend Send signals to other backends (eg: cancel query, terminate).
#pg_read_server_files Allow reading files from any location the database can
#access on the server with COPY and other file-access functions.
#pg_write_server_files Allow writing to files in any location the database can
#access on the server with COPY and other file-access functions.
#pg_execute_server_program Allow executing programs on the database server as
#the user the database runs as with COPY and other functions which allow executing
#a server-side program.
#pg_monitor Read/execute various monitoring views and functions. This role is a
#member of pg_read_all_settings , pg_read_all_stats and pg_stat_scan_tables .
#Administrators can grant access to these roles to users using the GRANT command.

#Audit:
su -c whoami postgres >> $REPORT
psql -w -h localhost -U $username -c "select rolname from pg_roles where rolsuper is true;" >> $REPORT

echo -e "\r\n-->Section 5 Connection and Login" >> $REPORT

echo -e "\r\n----> 5.1 Ensure login via 'local' UNIX Domain Socket is configured correctly" >> $REPORT

#Description:
#A remote host login, via ssh, is arguably the most secure means of remotely accessing and
#administering the PostgreSQL server. Connecting with the psql client, via UNIX DOMAIN
#SOCKETS, using the peer authentication method is the most secure mechanism available
#for local connections. Provided a database user account of the same name of the UNIX
#account has already been defined in the database, even ordinary user accounts can access
#the cluster in a similarly highly secure manner.

#Remediation:
#Please refer to CIS Postgres 12 Benchmark documentation for this exact remediation.

#Audit:
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 5.2 Ensure login via 'host' TCP/IP Socket is configured correctly" >> $REPORT

#Description:
#A large number of authentication METHODs are available for hosts connecting using
#TCP/IP sockets, including:
#trust
#reject
#md5
#scram-sha-256
#password
#gss
#sspi
#ident
#pam
#ldap
#radius
#cert
#METHODs trust , password , and ident are not to be used for remote logins. METHOD md5 is
#the most popular and can be used in both encrypted and unencrypted sessions,however, it
#is vulnerable to packet replay attacks. It is recommended that scram-sha-256 be used
#instead of md5 .
#Use of the gss , sspi , pam , ldap , radius , and cert METHODs, while more secure than md5 ,
#are dependent upon the availability of

#Remediation:
#Please refer to CIS Postgres 12 Benchmark documentation for this exact remediation.

#Default Value:
#The availability of the different password-based authentication methods depends on how a
#user's password on the server is encrypted (or hashed, more accurately). This is controlled
#by the configuration parameter password_encryption at the time the password is set.
#If a password was encrypted using the scram-sha-256 setting, then it can be used for the
#authentication methods scram-sha-256 and password (but password transmission will be
#in plain text in the latter case). The authentication method specification md5 will
#automatically switch to using the scram-sha-256 method in this case, as explained above,
#so it will also work.
#If a password was encrypted using the md5 setting, then it can be used only for the md5 and
#password authentication method specifications (again, with the password transmitted in
#plain text in the latter case).
#Previous PostgreSQL releases supported storing the password on the server in plain text.
#This is no longer possible.
#To check the currently stored password hashes, see the system catalog pg_authid . To
#upgrade an existing installation from md5 to scram-sha-256 , after having ensured that all
#client libraries in use are new enough to support SCRAM, set password_encryption =
#'scram-sha-256' in postgresql.conf , reload the postmaster , make all users set new
#passwords, and change the authentication method specifications in pg_hba.conf to scram-
#sha-256 .

#Audit:
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n-->Section 6 PostgreSQL Settings" >> $REPORT

echo -e "\r\n----> 6.1 Ensure 'Attack Vectors' Runtime Parameters are Configured" >> $REPORT

#Description:
#Understanding the vulnerability of PostgreSQL runtime parameters by the particular
#delivery method, or attack vector.

#Rationale:
#There are as many ways of compromising a server as there are runtime parameters. A
#combination of any one or more of them executed at the right time under the right
#conditions has the potential to compromise the RDBMS. Mitigating risk is dependent upon
#one's understanding of the attack vectors and includes:
#1. Via user session: includes those runtime parameters that can be set by a ROLE that
#persists for the life of a server-client session.
#2. Via attribute: includes those runtime parameters that can be set by a ROLE during a
#server-client session that can be assigned as an attribute for an entity such as a
#table, index, database, or role.
#3. Via server reload: includes those runtime parameters that can be set by the
#superuser using a SIGHUP or configuration file reload command and affects the
#entire cluster.
#4. Via server restart: includes those runtime parameters that can be set and effected by
#restarting the server process and affects the entire cluster.

#Audit:
#Review all configuration settings. Configure PostgreSQL logging to record all modifications
#and changes to the RDBMS.

#Remediation:
#In the case of a changed parameter, the value is returned back to its default value. In the
#case of a successful exploit of an already set runtime parameter then an analysis must be
#carried out determining the best approach mitigating the risk.
#Impact:
#It can be difficult to totally eliminate risk. Once changed, detecting a miscreant parameter
#can become problematic

#Audit:
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 6.2 Ensure 'backend' runtime parameters are configured correctly" >> $REPORT

#Description:
#In order to serve multiple clients efficiently, the PostgreSQL server launches a new
#"backend" process for each client. The runtime parameters in this benchmark section are
#controlled by the backend process. The server's performance, in the form of slow queries
#causing a denial of service, and the RDBM's auditing abilities for determining root cause
#analysis can be compromised via these parameters.

#Rationale:
#A denial of service is possible by denying the use of indexes and by slowing down client
#access to an unreasonable level. Unsanctioned behavior can be introduced by introducing
#rogue libraries which can then be called in a

#Remediation:
#Once detected, the unauthorized/undesired change can be corrected by altering the
#configuration file and executing a server restart. In the case where the parameter has been
#on the command line invocation of pg_ctl the restart invocation is insufficient and an
#explicit stop and start must instead be made.
#1. Query the view pg_settings and compare with previous query outputs for any
#changes.
#2. Review configuration files postgresql.conf and postgresql.auto.conf and
#compare them with previously archived file copies for any changes.
#3. Examine the process output and look for parameters that were used at server
#startup:
#ps aux | grep -E '[p]ost' | grep -- '-[D]'

#Impact:
#All changes made on this level will affect the overall behavior of the server. These changes
#can only be affected by a server restart after the parameters have been altered in the
#configuration files.

#Audit:
psql -w -h localhost -U $username -c "SELECT name, setting FROM pg_settings WHERE context IN ('backend','superuser-backend') ORDER BY 1;" >> $REPORT

#Note: Effecting changes to these parameters can only be made at server start. Therefore, a
#successful exploit may not be detected until after a server restart, e.g., during a maintenance
#window.

echo -e "\r\n----> 6.3 Ensure 'Postmaster' Runtime Parameters are Configured" >> $REPORT

#Description:
#PostgreSQL runtime parameters that are executed by the postmaster process.

#Rationale:
#The postmaster process is the supervisory process that assigns a backend process to an
#incoming client connection. The postmaster manages key runtime parameters that are
#either shared by all backend connections or needed by the postmaster process itself to run.

#Remediation:
#Once detected, the unauthorized/undesired change can be corrected by editing the altered
#configuration file and executing a server restart. In the case where the parameter has been
#on the command line invocation of pg_ctl the restart invocation is insufficient and an
#explicit stop and start must instead be made.
#Detecting a change is possible by one of the following methods:
#1. Query the view pg_settings and compare with previous query outputs for any
#changes
#2. Review the configuration files postgresql.conf and postgresql.auto.conf and
#compare with previously archived file copies for any changes
#3. Examine the process output and look for parameters that were used at server
#startup:
#ps aux | grep -E 'postgres' | grep -- '-[D]'
#Impact:
#All changes made on this level will affect the overall behavior of the server. These changes
#can be effected by editing the PostgreSQL configuration files and by either executing a
#server SIGHUP from the command line or, as superuser postgres , executing the SQL
#command select pg_reload_conf() . A denial of service is possible by the over-allocating
#of limited resources, such as RAM. Data can be corrupted by allowing damaged pages to
#load or by changing parameters to reinterpret values in an unexpected fashion, e.g.
#changing the time zone. Client messages can be altered in such a way as to interfere with
#the application logic. Logging can be altered and obfuscated inhibiting root cause analysis.

#Audit:
psql -w -h localhost -U $username -c "SELECT name, setting FROM pg_settings WHERE context = 'postmaster' ORDER BY 1;" >> $REPORT

echo -e "\r\n----> 6.4 Ensure 'SIGHUP' Runtime Parameters are Configured" >> $REPORT

#Description:
#PostgreSQL runtime parameters that are executed by the SIGHUP signal.
#Rationale:
#In order to define server behavior and optimize server performance, the server's superuser
#has the privilege of setting these parameters which are found in the configuration files
#postgresql.conf and pg_hba.conf . Alternatively, those parameters found in
#postgresql.conf can also be changed using a server login session and executing the SQL
#command ALTER SYSTEM which writes its changes in the configuration file
#postgresql.auto.conf .

#Remediation:
#Restore all values in the PostgreSQL configuration files and invoke the server to reload the
#configuration files.

#Impact:
#All changes made on this level will affect the overall behavior of the server. These changes
#can be effected by editing the PostgreSQL configuration files and by either executing a
#server SIGHUP from the command line or, as superuser postgres , executing the SQL
#command select pg_reload_conf() . A denial of service is possible by the over-allocating
#of limited resources, such as RAM. Data can be corrupted by allowing damaged pages to
#load or by changing parameters to reinterpret values in an unexpected fashion, e.g.
#changing the time zone. Client messages can be altered in such a way as to interfere with
#the application logic. Logging can be altered and obfuscated inhibiting root cause analysis.

#Audit:
psql -w -h localhost -U $username -c "SELECT name, setting FROM pg_settings WHERE context = 'sighup' ORDER BY 1;" >> $REPORT

echo -e "\r\n----> 6.5 Ensure 'Superuser' Runtime Parameters are Configured" >> $REPORT

#Description:
#PostgreSQL runtime parameters that can only be executed by the server's superuser, which
#is traditionally postgres .
#
#Rationale:
#In order to improve and optimize server performance, the server's superuser has the
#privilege of setting these parameters which are found in the configuration file
#postgresql.conf . Alternatively, they can be changed in a PostgreSQL login session via the
#SQL command ALTER SYSTEM which writes its changes in the configuration file
#postgresql.auto.conf .

#Remediation:
#The exploit is made in the configuration files. These changes are effected upon server
#restart. Once detected, the unauthorized/undesired change can be made by editing the
#altered configuration file and executing a server restart. In the case where the parameter
#has been set on the command line invocation of pg_ctl the restart invocation is
#insufficient and an explicit stop and start must instead be made.
#Detecting a change is possible by one of the following methods:
#1. Query the view pg_settings and compare with previous query outputs for any
#changes.
#2. Review the configuration files postgreql.conf and postgreql.auto.conf and
#compare with previously archived file copies for any changes
#3. Examine the process output and look for parameters that were used at server
#startup:
#ps aux | grep -E 'post' | grep -- '-[D]'

#Impact:
#All changes made on this level will affect the overall behavior of the server. These changes
#can only be affected by a server restart after the parameters have been altered in the
#configuration files. A denial of service is possible by the over allocating of limited resources,
#such as RAM. Data can be corrupted by allowing damaged pages to load or by changing
#parameters to reinterpret values in an unexpected fashion, e.g. changing the time zone.
#Client messages can be altered in such a way as to interfere with the application logic.
#Logging can be altered and obfuscated inhibiting root cause analysis.

#Audit:
psql -w -h localhost -U $username -c "SELECT name, setting FROM pg_settings WHERE context = 'superuser' ORDER BY 1;" >> $REPORT

echo -e "\r\n----> 6.6 Ensure 'User' Runtime Parameters are Configured" >> $REPORT

#Description:
#These PostgreSQL runtime parameters are managed at the user account (ROLE) level.

#Rationale:
#In order to improve performance and optimize features, a ROLE has the privilege of setting
#numerous parameters in a transaction, session, or as an entity attribute. Any ROLE can alter
#any of these parameters.

#Remediation:
#In the matter of a user session, the login sessions must be validated that it is not executing
#undesired parameter changes. In the matter of attributes that have been changed in
#entities, they must be manually reverted to its default value(s).

#Impact:
#A denial of service is possible by the over-allocating of limited resources, such as RAM.
#Changing VACUUM parameters can force a server shutdown which is standard procedure
#preventing data corruption from transaction ID wraparound. Data can be corrupted by
#changing parameters to reinterpret values in an unexpected fashion, e.g. changing the time
#zone. Logging can be altered and obfuscated to inhibit root cause analysis.

#Audit:
psql -w -h localhost -U $username -c "SELECT name, setting FROM pg_settings WHERE context = 'user' ORDER BY 1;" >> $REPORT

echo -e "\r\n----> 6.7 Ensure FIPS 140-2 OpenSSL Cryptography Is Used" >> $REPORT

#Description:
#Install, configure, and use OpenSSL on a platform that has a NIST certified FIPS 140-2
#installation of OpenSSL. This provides PostgreSQL instances the ability to generate and
#validate cryptographic hashes to protect unclassified information requiring confidentiality
#and cryptographic protection, in accordance with the data owner's requirements.

#Rationale:
#Federal Information Processing Standard (FIPS) Publication 140-2 is a computer security
#standard developed by a U.S. Government and industry working group for validating the
#quality of cryptographic modules. Use of weak, or untested, encryption algorithms
#undermine the purposes of utilizing encryption to protect data. PostgreSQL uses OpenSSL
#for the underlying encryption layer.
#The database and application must implement cryptographic modules adhering to the
#higher standards approved by the federal government since this provides assurance they
#have been tested and validated. It is the responsibility of the data owner to assess the
#cryptography requirements in light of applicable federal laws, Executive Orders, directives,
#policies, regulations, and standards.
#For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements for
#Cryptographic Modules. Note that the product's cryptographic modules must be validated
#and certified by NIST as FIPS-compliant. The security functions validated as part of FIPS
#140-2 for cryptographic modules are described in FIPS 140-2 Annex A. Currently only Red
#Hat Enterprise Linux is certified as a FIPS 140-2 distribution of OpenSSL. For other
#operating systems, users must obtain or build their own FIPS 140-2 OpenSSL libraries.

#Remediation:
#Configure OpenSSL to be FIPS compliant. PostgreSQL uses OpenSSL for cryptographic
#modules. To configure OpenSSL to be FIPS 140-2 compliant, see the official RHEL
#Documentation. Below is a general summary of the steps required:
#To switch the system to FIPS mode in RHEL 8:
# fips-mode-setup --enable
#Setting system policy to FIPS
#FIPS mode will be enabled.
#Please reboot the system for the setting to take effect.
#Restart your system to allow the kernel to switch to FIPS mode:
## reboot
#After the restart, you can check the current state of FIPS mode:
## fips-mode-setup --chec
#FIPS mode is enabled.

#Audit:
fips-mode-setup --check >> $REPORT
openssl version >> $REPORT

echo -e "\r\n----> 6.8 Ensure SSL is enabled and configured correctly" >> $REPORT

#Description:
#SSL on a PostgreSQL server should be enabled (set to on ) and configured to encrypt TCP
#traffic to and from the server.

#Rationale:
#If SSL is not enabled and configured correctly, this increases the risk of data being
#compromised in transit.

#Remediation:
#For this example, and ease of illustration, we will be using a self-signed certificate for the
#server generated via openssl , and the PostgreSQL defaults for file naming and location in
#the PostgreSQL $PGDATA directory.
#$ whoami
#postgres
#$ # create new certificate and enter details at prompts
#$ openssl req -new -text -out server.req
#Generating a 2048 bit RSA private key
#.....................+++
#..................................................................+++
#writing new private key to 'privkey.pem'
#Enter PEM pass phrase:
#Verifying - Enter PEM pass phrase:
#-----
#You are about to be asked to enter information that will be incorporated
#into your certificate request.
#What you are about to enter is what is called a Distinguished Name or a DN.
#There are quite a few fields but you can leave some blank
#For some fields there will be a default value,
#If you enter '.', the field will be left blank.
#-----
#Country Name (2 letter code) [XX]:US
#State or Province Name (full name) []:Ohio
#Locality Name (eg, city) [Default City]:Columbus
#Organization Name (eg, company) [Default Company Ltd]:Me Inc
#Organizational Unit Name (eg, section) []:IT
#Common Name (eg, your name or your server's hostname) []:my.me.inc
#Email Address []:me@meinc.com
#Please enter the following 'extra' attributes
#to be sent with your certificate request
#A challenge password []:
#An optional company name []:
#$ # remove passphrase (required for automatic server start up)
#$ openssl rsa -in privkey.pem -out server.key && rm privkey.pem
#Enter pass phrase for privkey.pem:
#writing RSA key
#$ # modify certificate to self signed, generate .key and .crt files
#$ openssl req -x509 -in server.req -text -key server.key -out server.crt
#$ # copy .key and .crt files to appropriate location, here default $PGDATA
#$ cp server.key server.crt $PGDATA
#$ # restrict file mode for server.key
#$ chmod og-rwx server.key
#Edit the PostgreSQL configuration file postgresql.conf to ensure the following items are
#set. Again, we are using defaults. Note that altering these parameters will require restarting
#the cluster.
## (change requires restart)
#ssl = on
## allowed SSL ciphers
#ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
## (change requires restart)
#ssl_cert_file = 'server.crt'
## (change requires restart)
#ssl_key_file = 'server.key'
#password_encryption =
#scram-sha-256
#Finally, restart PostgreSQL and confirm ssl using commands outlined in Audit Procedures:
#postgres=# show ssl;
#ssl
#-----
#on
#(1 row)

#Impact:
#A self-signed certificate can be used for testing, but a certificate signed by a certificate
#authority (CA) (either one of the global CAs or a local one) should be used in production so
#that clients can verify the server's identity. If all the database clients are local to the
#organization, using a local CA is recommended.
#To ultimately enable and enforce ssl authentication for the server, appropriate hostssl
#records must be added to the pg_hba.conf file. Be sure to reload PostgreSQL after any
#changes (restart not required).
#Note: The hostssl record matches connection attempts made using TCP/IP, but only when
#the connection is made with SSL encryption. The host record matches attempts made using
#TCP/IP, but allows both SSL and non-SSL connections. The hostnossl record matches
#attempts made using TCP/IP, but only those without SSL. Care should be taken to enforce
#SSL as appropriate.

#Audit:
psql -w -h localhost -U $username -c "SHOW ssl;" >> $REPORT


echo -e "\r\n----> 6.9 Ensure the pgcrypto extension is installed and configured correctly" >> $REPORT

#Description:
#PostgreSQL must implement cryptographic mechanisms to prevent unauthorized
#disclosure or modification of organization-defined information at rest (to include, at a
#minimum, PII and classified information) on organization-defined information system
#components.

#Rationale:
#PostgreSQL handling data that requires "data at rest" protections must employ
#cryptographic mechanisms to prevent unauthorized disclosure and modification of the
#information at rest. These cryptographic mechanisms may be native to PostgreSQL or
#implemented via additional software or operating system/file system settings, as
#appropriate to the situation. Information at rest refers to the state of information when it is
#located on a secondary storage device (e.g. disk drive, tape drive) within an organizational
#information system.
#Selection of a cryptographic mechanism is based on the need to protect the integrity of
#organizational information. The strength of the mechanism is commensurate with the
#security category and/or classification of the information. Organizations have the flexibility
#to either encrypt all information on storage devices (i.e. full disk encryption) or encrypt
#specific data structures (e.g. files, records, or fields). Organizations may also optionally
#choose to implement both to implement layered security.
#The decision whether, and what, to encrypt rests with the data owner and is also
#influenced by the physical measures taken to secure the equipment and media on which
#the information resides. Organizations may choose to employ different mechanisms to
#achieve confidentiality and integrity protections, as appropriate. If the confidentiality and
#integrity of application data is not protected, the data will be open to compromise and
#unauthorized modification.
#The PostgreSQL pgcrypto extension provides cryptographic functions for PostgreSQL and
#is intended to address the confidentiality and integrity of user and system information at
#rest in non-mobile devices.

#Remediation:
#The pgcrypto extension is included with the PostgreSQL 'contrib' package. Although
#included, it needs to be created in the database.
#As the database administrator, run the following:
#postgres=# CREATE EXTENSION pgcrypto;
#CREATE EXTENSION
#Verify pgcrypto is installed:
#postgres=# SELECT * FROM pg_available_extensions WHERE name='pgcrypto';
#name
#| default_version | installed_version |
#comment
#----------+-----------------+-------------------+-------------------------
#pgcrypto | 1.3
#| 1.3
#| cryptographic functions
#(1 row)

#Impact:
#When considering or undertaking any form of encryption, it is critical to understand the
#state of the encrypted data at all stages of the data lifecycle. The use of pgcrypto ensures
#that the data at rest in the tables (and therefore on disk) is encrypted, but for the data to be
#accessed by any users or applications, said users/applications will, by necessity, have
#access to the encrypt and decrypt keys and the data in question will be
#encrypted/decrypted in memory and then transferred to/from the user/application in that
#form.

#Audit:
psql -w -h localhost -U $username -c "SELECT * FROM pg_available_extensions WHERE name='pgcrypto';" >> $REPORT

echo -e "\r\n-->Section 7 Replication" >> $REPORT

echo -e "\r\n----> 7.1 Ensure a replication-only user is created and used for streaming
replication" >> $REPORT

#Description:
#Create a new user specifically for use by streaming replication instead of using the
#superuser account.

#Rationale:
#As it is not necessary to be a superuser to initiate a replication connection, it is proper to
#create an account specifically for replication. This allows further 'locking down' the uses of
#the superuser account and follows the general principle of using the least privileges
#necessary.

#Remediation:
#It will be necessary to create a new role for replication purposes:
#postgres=# create user replication_user REPLICATION encrypted password 'XXX';
#CREATE ROLE
#postgres=# select rolname from pg_roles where rolreplication is true;
#rolname
#------------------
#postgres
#replication_user
#(2 rows)
#When using pg_basebackup (or other replication tools) on your standby server, you would
#use the replication_user (and its password).
#Ensure you allow the new user via your pg_hba.conf file:
## note that 'replication' in the 2nd column is required and is a special
## keyword, not a real database
#hostssl replication
#replication_user
#0.0.0.0/0
#md5

#Audit:
psql -w -h localhost -U $username -c "select rolname from pg_roles where rolreplication is true;" >> $REPORT

echo -e "\r\n----> 7.2 Ensure base backups are configured and functional" >> $REPORT

#Description:
#A 'base backup' is a copy of the PRIMARY host's data cluster ($PGDATA) and is used to
#create STANDBY hosts and for Point In Time Recovery (PITR) mechanisms. Base backups
#should be copied across networks in a secure manner using an encrypted transport
#mechanism. The PostgreSQL CLI pg_basebackup can be used, however, SSL encryption
#should be enabled on the server as per section 6.8 of this benchmark. The pgBackRest tool
#detailed in section 8.3 of this benchmark can also be used to create a 'base backup'.

#Remediation:
#Executing base backups using pg_basebackup requires the following steps on the standby
#server:
#$ whoami
#postgres
#$ pg_basebackup -h name_or_IP_of_master \
#-p 5432 \
#-U replication_user \
#-D ~postgres/11/
#-P -v -R -Xs \

#Audit:
echo -e "\r\nRequires manual verification" >> $REPORT

echo -e "\r\n----> 7.3 Ensure WAL archiving is configured and functional" >> $REPORT

#Description:
#Write Ahead Log (WAL) Archiving, or Log Shipping, is the process of sending transaction
#log files from the PRIMARY host either to one or more STANDBY hosts or to be archived on
#a remote storage device for later use, e.g. PITR . There are several utilities that can copy
#WALs including, but not limited to, cp , scp , sftp , and rynsc . Basically, the server follows a
#set of runtime parameters which defines when the WAL should be copied using one of the
#aforementioned utilities.

#Rationale:
#Unless the server has been correctly configured, one runs the risk of sending WALs in an
#unsecured, unencrypted fashion.

#Remediation:
#Change parameters and restart the server as required.
#Note: SSH public keys must be generated and installed as per industry standards.

#Audit:
cat $POSTGRESCONFIG | grep "archive_mode" >> $REPORT
cat $POSTGRESCONFIG | grep "archive_command" >> $REPORT
cat $POSTGRESCONFIG | grep "postgres@remotehost" >> $REPORT
#Confirm SSH public/private keys have been generated on both the source and target hosts
#in their respective superuser home accounts.
echo -e "\r\nRequires manual verification of SSH keys on machine" >> $REPORT

echo -e "\r\n----> 7.4 Ensure streaming replication parameters are configured correctly" >> $REPORT

#Description:
#Streaming replication from a PRIMARY host transmits DDL, DML, passwords, and other
#potentially sensitive activities and data. These connections should be protected with Secure
#Sockets Layer (SSL).

#Rationale:
#Unencrypted transmissions could reveal sensitive information to unauthorized parties.
#Unauthenticated connections could enable man-in-the-middle attacks.

#Remediation:
#Review prior sections in this benchmark regarding SSL certificates, replication user, and
#WAL archiving.
#Confirm the file $PGDATA/standby.signal is present on the STANDBY host and
#$PGDATA/postgresql.auto.conf contains lines similar to the following:
#primary_conninfo = 'user=replication_user password=mypassword host=mySrcHost
#port=5432 sslmode=require sslcompression=1'

#Audit:
psql -w -h localhost -U $username -c "select rolname from pg_roles where rolreplication is true;" >> $REPORT
#On the target/STANDBY host, execute a psql invocation similar to the following, confirming
#that SSL communications are possible:
su -c whoami postgres >> $REPORT

echo -e "\r\n--> 8 Special Configuration Considerations" >> $REPORT

echo -e "\r\n----> 8.1 Ensure PostgreSQL configuration files are outside the data cluster" >> $REPORT

#Description:
#PostgreSQL configuration files within the data cluster's directory tree can be changed by
#anyone logging into the data cluster as the superuser, i.e. postgres . As a matter of default
#policy, configuration files such as postgresql.conf , pg_hba.conf , and pg_ident , are placed
#in the data cluster's directory, $PGDATA . PostgreSQL can be configured to relocate these files
#to locations outside the data cluster which cannot then be accessed by an ordinary
#superuser login session.
#Consideration should also be given to "include directives"; these are cluster subdirectories
#where one can locate files containing additional configuration parameters. Include
#directives are meant to add more flexibility for unique installs or large network
#environments while maintaining order and consistent architectural design.

#Rationale:
#Leaving PostgreSQL configuration files within the data cluster's directory tree increases the
#changes that they will be inadvertently or intentionally altered.

#Remediation:
#Follow these steps to remediate the configuration file locations and permissions:
#Determine appropriate locations for relocatable configuration files based on your
#organization's security policies. If necessary, relocate and/or rename configuration
#files outside of the data cluster.
#Ensure their file permissions are restricted as much as possible, i.e. only superuser
#read access.
#Change the settings accordingly in the postgresql.conf configuration file.
#Restart the database cluster for the changes to take effect.

#Default Value:
#The defaults for PostgreSQL configuration files are listed below.
#name
#|
#setting
#----------------------+----------------------------------------
#config_file | /var/lib/pgsql/12/data/postgresql.conf
#external_pid_file |
#hba_file | /var/lib/pgsql/12/data/pg_hba.conf
#ident_file | /var/lib/pgsql/12/data/pg_ident.conf
#promote_trigger_file |
#ssl_ca_file |
#ssl_cert_file | server.crt
#ssl_crl_file |
#ssl_dh_params_file |
#ssl_key_file | server.key
#(10 rows)

#Audit:
psql -w -h localhost -U $username -c "select name, setting from pg_settings where name ~ '.*_file$';" >> $REPORT

grep ^include $PGDATA/postgresql.{auto.,}conf >> $REPORT

echo -e "\r\n----> 8.2 Ensure PostgreSQL subdirectory locations are outside the data
cluster" >> $REPORT

#Description:
#The PostgreSQL cluster is organized to carry out specific tasks in subdirectories. For the
#purposes of performance, reliability, and security these subdirectories should be relocated
#outside the data cluster.

#Rationale:
#Some subdirectories contain information, such as logs, which can be of value to others such
#as developers. Other subdirectories can gain a performance benefit when placed on fast
#storage devices. Finally, relocating a subdirectory to a separate and distinct partition
#mitigates denial of service and involuntary server shutdown when excessive writes fill the
#data cluster's partition, e.g. pg_xlog and pg_log .

#Remediation:
#Perform the following steps to remediate the subdirectory locations and permissions:
#Determine appropriate data, log, and tablespace directories and locations based on
#your organization's security policies. If necessary, relocate all listed directories
#outside the data cluster.
#Ensure file permissions are restricted as much as possible, i.e. only superuser read
#access.
#When directories are relocated to other partitions, ensure that they are of sufficient
#size to mitigate against excessive space utilization.
#Lastly, change the settings accordingly in the postgresql.conf configuration file
#and restart the database cluster for changes to take effect.

#Default Value:
#The default for data_directory is ConfigDir and the default for log_directory is log
#(based on absolute path of data_dir

#Audit:
psql -w -h localhost -U $username -c "select name, setting from pg_settings where (name ~ '_directory$' or name ~ '_tablespace');" >> $REPORT

echo -e "\r\n----> 8.3 Ensure the backup and restore tool, 'pgBackRest', is installed and
configured" >> $REPORT

#Description:
#pgBackRest aims to be a simple, reliable backup and restore system that can seamlessly
#scale up to the largest databases and workloads. Instead of relying on traditional backup
#tools like tar and rsync , pgBackRest implements all backup features internally and uses a
#custom protocol for communicating with remote systems. Removing reliance on tar and
#rsync allows for better solutions to database-specific backup challenges. The custom
#remote protocol allows for more flexibility and limits the types of connections that are
#required to perform a backup which increases security.

#Rationale:
#The native PostgreSQL backup facility pg_dump provides adequate logical backup
#operations but does not provide for Point In Time Recovery (PITR). The PostgreSQL facility
#pg_basebackup performs physical backup of the database files and does provide for PITR,
#but it is constrained by single threading. Both of these methodologies are standard in the
#PostgreSQL ecosystem and appropriate for particular backup/recovery needs. pgBackRest
#offers another option with much more robust features and flexibility.
#pgBackRest is open source software developed to perform efficient backups on PostgreSQL
#databases that measure in tens of terabytes and greater. It supports per file checksums,
#compression, partial/failed backup resume, high-performance parallel transfer,
#asynchronous archiving, tablespaces, expiration, full/differential/incremental,
#local/remote operation via SSH, hard-linking, restore, backup encryption, and more.
#pgBackRest is written in C and Perl and does not depend on rsync or tar but instead
#performs its own deltas which gives it maximum flexibility. Finally, pgBackRest provides an
#easy to use internal repository listing backup details accessible via the pgbackrest info
#command, as illustrated below.

#Remediation:
#pgBackRest is not installed nor configured for PostgreSQL by default, but instead is
#maintained as a GitHub project. Fortunately, it is a part of the PGDG repository and can be
#easily installed:
#$ whoami
#root
#$ dnf -y install pgbackrest
#Last metadata expiration check: 0:00:19 ago on Tue 29 Oct 2019 12:30:51 PM
#EDT.
#Dependencies resolved.
#[snip]
#Installed:
#pgbackrest-2.18-1.rhel8.x86_64
#perl-DBD-Pg-3.7.4-
#2.module_el8.0.0+74+7e750437.x86_64
#perl-DBI-1.641-2.module_el8.0.0+66+fe1eca09.x86_64
#perl-Data-Dump-
#1.23-7.el8.noarch
#perl-Digest-HMAC-1.03-17.el8.noarch
#perl-File-Listing-
#6.04-17.el8.noarch
#perl-HTML-Parser-3.72-14.el8.x86_64
#p#erl-HTML-Tagset-
#3.20-33.el8.noarch
#perl-HTTP-Cookies-6.04-2.el8.noarch
#perl-HTTP-Date-
#6.02-18.el8.noarch
#perl-HTTP-Message-6.18-1.el8.noarch
#perl-HTTP-
#Negotiate-6.01-19.el8.noarch
#perl-IO-HTML-1.001-10.el8.noarch
#perl-LWP-
#MediaTypes-6.02-14.el8.noarch
#perl-NTLM-1.09-17.el8.noarch
#perl-Net-HTTP-6.17-
#2.el8.noarch
#perl-TimeDate-1:2.30-13.el8.noarch
#perl-Try-Tiny-0.30-
#2.el8.noarch
#perl-WWW-RobotRules-6.02-18.el8.noarch
#perl-XML-LibXML-
#1:2.0132-2.el8.x86_64
#perl-XML-NamespaceSupport-1.12-4.el8.noarch
#perl-XML-SAX-1.00-
#1.el8.noarch
#perl-XML-SAX-Base-1.09-4.el8.noarch
#perl-libwww-perl-
#6.34-1.el8.noarch
#Complete!
#Once installed, pgBackRest must be configured for things like stanza name, backup
#location, retention policy, logging, etc. Please consult the configuration guide.
#If employing pgBackRest for your backup/recovery solution, ensure the repository, base
#backups, and WAL archives are stored on a reliable file system separate from the database
#server. Further, the external storage system where backups resided should have limited
#access to only those system administrators as necessary. Finally, as with any
#backup/recovery solution, stringent testing must be conducted. A backup is only good if
#it can be restored successfully.

#Audit:
pgbackrest >> $REPORT

echo -e "\r\n----> 8.4 Ensure miscellaneous configuration settings are correct" >> $REPORT

#Description:
#This recommendation covers non-regular, special files, and dynamic libraries.
#PostgreSQL permits local logins via the UNIX DOMAIN SOCKET and, for the most part,
#anyone with a legitimate Unix login account can make the attempt. Limiting PostgreSQL
#login attempts can be made by relocating the UNIX DOMAIN SOCKET to a subdirectory with
#restricted permissions.
#The creation and implementation of user-defined dynamic libraries is an extraordinary
#powerful capability. In the hands of an experienced DBA/programmer, it can significantly
#enhance the power and flexibility of the RDBMS. But new and unexpected behavior can also
#be assigned to the RDBMS, resulting in a very dangerous environment in what should
#otherwise be trusted.

#Remediation:
#Follow these steps to remediate the configuration:
#Determine permissions based on your organization's security policies.
#Relocate all files and ensure their permissions are restricted as much as possible, i.e.
#only superuser read access.
#Ensure all directories where these files are located have restricted permissions such
#that the superuser can read but not write.
#Lastly, change the settings accordingly in the postgresql.conf configuration file
#and restart the database cluster for changes to take effect.

#Default Value:
#The dynamic_library_path default is $libdir and unix_socket_directories default is
#/var/run/postgresql, /tmp . The default for external_pid_file and all library
#parameters are initially null, or not set, upon cluster creation.

#Audit:
psql -w -h localhost -U $username -c "select name, setting from pg_settings where name in ('external_pid_file', 'unix_socket_directories','shared_preload_libraries','dynamic_library_path',' local_preload_libraries','session_preload_libraries');" >> $REPORT

#Inspect the file and directory permissions for all returned values. Only superusers should
#have access control rights for these files and directories. If permissions are not highly
#restricted, this is a fail.


echo "deleting Postgresql authentication file stored at $POSTGRESQL_DEFAULTS_EXTRA_FILE"
rm $POSTGRESQL_DEFAULTS_EXTRA_FILE
echo "please ensure this file is deleted. Enter Y/N to confirm you have read this message"
read CONFIRMATION;
if [ $CONFIRMATION != "Y" ]; then
  echo "You have been warned"
  echo "Postgresql Authentication file deletion warning not confirmed" >> $REPORT
fi
echo "please compress the /tmp/redshift directory and send it to your consultant"
echo "########### Redshift CIS CIS PostgreSQL 12 end :D ###########" >> $REPORT
exit

