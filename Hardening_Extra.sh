#!/bin/bash
# Archivo de hardening para debian 9 minimal con el fin de
# utilizarlo junto a ELK Stack y wazuh/ossec
#
# Basado en CIS Debian Linux 9 Benchmark v1.0.0
#
# Las configuraciones presentadas son solo aquellas que necesitan ser cambiadas
# para la correcta configuracion del SO, las que no aparezcan es porque la
# configuracion por defecto coincide con la del hardening, otras seran
# justificadas.
#
# Ejecutar el script una tan sola vez...
#

#installaciones
apt install ntp apparmor apparmor-utils libpam-pwquality sudo network-manager shorewall -y

#1.1 Filesystem configuration

#squashfs udf

echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf
rmmod freevxfs

echo "install jffs2 /bin/true" >> /etc/modprobe.d/jffs2.conf
rmmod jffs2

echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf
rmmod hfs

echo "install hfsplus /bin/true" >> /etc/modprobe.d/hfsplus.conf
rmmod hfsplus

echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
rmmod udf

echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
rmmod squashfs

#lynis desactivar firewire
printf "blacklist ohci1394\nblacklist sbp2\nblacklist dv1394\nblacklist raw1394\nblacklist video1394\nblacklist firewire-ohci\nblacklist firewire-sbp2\n" >> /etc/modprobe.d/firewire.conf

#
# Esta parte (1.1.[2-20]) deberia de ser con respecto al punto de montaje
# AJUSTAR EN UN FUTURO
#
sed -e "/\/tmp/ s/^#*/#/" -i /etc/fstab
echo "tmpfs   /tmp   tmpfs   defaults,rw,nosuid,nodev,noexec,relatime  0 0" >> /etc/fstab
echo "tmpfs   /var/tmp   tmpfs   defaults,rw,nosuid,nodev,noexec,relatime  0 0" >> /etc/fstab
echo "tmpfs   /dev/shm   tmpfs   defaults,rw,nosuid,nodev,noexec,relatime  0 0" >> /etc/fstab
echo "proc   /proc   proc   defaults,rw,nosuid,nodev,noexec,relatime,hidepid=2  0 0" >> /etc/fstab

# 1.1.22 Deshabilitar Automontado
systemctl disable autofs


# 1.3 sera manejado con ossec
#

# 1.4 Secure Boot Settings
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

# 1.5 Additional Process Hardening
echo "* hard core 0" >> /etc/security/limits.d/00-CIS.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/00-CIS.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/00-CIS.conf
sysctl -w kernel.randomize_va_space=2
sysctl -w fs.suid_dumpable=0

# 1.6 Mandatory Access Control con AppArmor
# En la siguiente linea se desactiva el uso de ipv6 (3.7)
sed -i "s/^GRUB_CMDLINE_LINUX.*/GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor ipv6.disable=1\"/g" /etc/default/grub
update-grub

# 1.7 Warning Banners
echo "ALERT! You are entering into a secured area! 
Your IP, Login Time, Username has been noted and has been sent to the server administrator!" > /etc/motd
echo "This service is restricted to authorized users only. All activities on this system are logged." >> /etc/motd
echo "Unauthorized access will be fully investigated and reported to the appropriate law enforcement agencies" >> /etc/motd
echo "********************************************************************
*                                                                  *
* This system is for the use of authorized users only.  Usage of   *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************" > /etc/issue
echo "********************************************************************
*                                                                  *
* This system is for the use of authorized users only.  Usage of   *
* this system may be monitored and recorded by system personnel.   *
*                                                                  *
* Anyone using this system expressly consents to such monitoring   *
* and is advised that if such monitoring reveals possible          *
* evidence of criminal activity, system personnel may provide the  *
* evidence from such monitoring to law enforcement officials.      *
*                                                                  *
********************************************************************." > /etc/issue.net
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
#
# Al instalar ntp al inicio  y al desinstalar Telnet
# se cumple con todo en la parte de Servicios (2)
apt remove telnet -y

# 3 Network Configuration
#echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/00-CIS.conf

#echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/00-CIS.conf


#Lynis

echo "kernel.core_uses_pid = 1" >> /etc/sysctl.d/00-CIS.conf
echo "kernel.kptr_restrict = 2" >> /etc/sysctl.d/00-CIS.conf
echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/00-CIS.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/00-CIS.conf
echo "kernel.sysrq = 0" >> /etc/sysctl.d/00-CIS.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/00-CIS.conf
echo "net.ipv4.conf.default.accept_source_route  = 0" >> /etc/sysctl.d/00-CIS.conf


sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0

#lynis
sysctl -w kernel.core_uses_pid=1
sysctl -w kernel.kptr_restrict=2
sysctl -w kernel.yama.ptrace_scope=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w kernel.sysrq=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_source_route=0

sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

# la parte 3.3 'TCP Wrappers' sera manejada con shorewall

# 3.4 Uncommon Network Protocols
touch /etc/modprobe.d/dccp.conf
echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf

touch /etc/modprobe.d/sctp.conf
echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf

touch /etc/modprobe.d/rds.conf
echo "install rds /bin/true" > /etc/modprobe.d/rds.conf

echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf


########################
#
# El punto 3.4 'Firewall Confiuration' será manejada con Shorewall 
# Con respecto al punto 4 'Logging and Auditing' sera manejado 
# por wazuh/ossec y ELK stack, si bien funciona con rsyslog 
# al iniciar el sistema, las confiuraciones por defecto 
# cumplen con lo especificado en el documento de hardening

##################
# 5.1 Configure Cron
##################
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

####################
# 5.2 SSH Server Configuration
##################
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

echo "Protocol 2" >> /etc/ssh/sshd_config

sed -i "s/^X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config

sed -i "s/^#MaxAuthTries 6/MaxAuthTries 2/g" /etc/ssh/sshd_config

echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config

sed -i "s/^#ClientAliveCountMax 3/ClientAliveCountMax 2/g" /etc/ssh/sshd_config
sed -i "s/^#ClientAliveInterval 0/ClientAliveInterval 300/g" /etc/ssh/sshd_config
sed -i "s/^#LoginGraceTime 2m/LoginGraceTime 1m/g" /etc/ssh/sshd_config
sed -i "s/^#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
sed -i "s/^#PrintLa stLog yes/PrintLastLog yes/g" /etc/ssh/sshd_config

sed -i "s/^#AllowTcpForwarding.*/AllowTcpForwarding no/g" /etc/ssh/sshd_config
sed -i "s/^#Compression.*/Compression no/g" /etc/ssh/sshd_config
sed -i "s/^#LogLevel.*/LogLevel VERBOSE/g" /etc/ssh/sshd_config
sed -i "s/^#MaxSessions.*/MaxSessions 2/g" /etc/ssh/sshd_config
sed -i "s/^#Port.*/Port 2222/g" /etc/ssh/sshd_config
sed -i "s/^#TCPKeepAlive.*/TCPKeepAlive no/g" /etc/ssh/sshd_config
sed -i "s/^#AllowAgentForwarding.*/AllowAgentForwarding no/g" /etc/ssh/sshd_config


####################
# 5.3 Configure PAM
##################

sed -i "s/^# minlen = 8/minlen = 14/g" /etc/security/pwquality.conf
sed -i "s/^# dcredit = 0/dcredit = -1/g" /etc/security/pwquality.conf
sed -i "s/^# ucredit = 0/ucredit = -1/g" /etc/security/pwquality.conf
sed -i "s/^# lcredit = 0/lcredit = -1/g" /etc/security/pwquality.conf
sed -i "s/^# ocredit = 0/ocredit = -1/g" /etc/security/pwquality.conf

echo " auth required   pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
sed -i "s/required.*/required   pam_pwhistory.so   remember=5/g" /etc/pam.d/common-password

sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/g" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/g" /etc/login.defs
sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/g" /etc/login.defs


useradd -D -f 30
####################
# 5.4.2 Ensure system accounts are non-login
###################

for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
    if [ $user != "root" ]; then
        usermod -L $user
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
        usermod -s /usr/sbin/nologin $user
    fi
    fi
done


printf "umask 027 \nTMOUT=600" >> /etc/profile
printf "umask 027 \nTMOUT=600" >> /etc/bash.bashrc
printf "umask 027 \nTMOUT=600" >> /etc/profile.d/*.sh
sed -i "s/^UMASK.*/UMASK     027/g" /etc/login.defs

echo "auth required pam_wheel.so" >> /etc/pam.d/su

#####################
# 6.1 System File Permissions
#####################

chown root:root /etc/passwd
chmod 644 /etc/passwd

chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

chown root:root /etc/group
chmod 644 /etc/group

chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-

chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

#NO GRUB
sed -i "s/^GRUB_TIMEOUT=5/GRUB_TIMEOUT=0/g" /etc/default/grub
update-grub

sudo adduser noise sudo
apt purge -y `dpkg --list | grep ^rc | awk '{ print $2; }'`
