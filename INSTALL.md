
##Python libs req:
>> pip install requests python-telegram-bot watchdog

##fail2ban on Rocky Linux setup:
>> vi /etc/fail2ban/jail.local
"""
[ai-apache]
enabled = true
backend = polling
filter = ai-apache
logpath = /opt/en_log/ssl_access_log #copied file by lsyncd
maxretry = 1
findtime = 60
bantime = 24h
"""

>> vi /etc/fail2ban/filter.d/ai-apache.conf
"""
[Definition]
failregex = ^<HOST>$
ignoreregex =

"""

Test with root
"""
systemctl restart fail2ban
fail2ban-client set {ai-apache} banip <IP>
fail2ban-client set {ai-apache} unbanip <IP>
fail2ban-client status ai-apache
"""

#Make user service:
>> useradd --system --no-create-home --shell /sbin/nologin kuro
>> usermod -aG apache kuro

Add SUDO patterns to sudoer
>> visudo
"""
kuro ALL=(root) NOPASSWD: /usr/bin/fail2ban-client set ai-apache banip *
kuro ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status
kuro ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status *
kuro ALL=(root) NOPASSWD: /usr/sbin/ipset add blacklisted_subnets *
kuro ALL=(root) NOPASSWD: /usr/sbin/ipset del blacklisted_subnets *
kuro ALL=(root) NOPASSWD: /usr/sbin/ipset list blacklisted_subnets
"""

Test SUDO with kuro
"""
sudo -u kuro sudo fail2ban-client set {ai-apache} banip <IP>
sudo -u kuro sudo fail2ban-client status ai-apache
"""

#Make system service
>> vi /etc/systemd/system/aiscan.service
"""
[Unit]
Description=KURO-I Apache AI Monitor
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/aiscan/KURO-I.py
Restart=always
RestartSec=5
User=kuro

[Install]
WantedBy=multi-user.target
"""

Initial services
"""
systemctl daemon-reload
systemctl enable aiscan
systemctl status aiscan
"""

# Set Permissions for Everything Hermes Touches
Ex: Scripts location = "pathTo"
"""
mkdir -p /pathTo/aiscan
cp KURO-I.py /pathTo/aiscan/
chown root:kuro /pathTo/aiscan/KURO-I.py
chmod 750 /pathTo/aiscan/KURO-I.py
"""

# Audit log — kuro must write, others cannot read
Ex: pathTo = /pathToLog/aiscan/log
"""
touch /pathToLog/AI_audit.log
touch /pathToLog/AI_ban_history.jsonl
chown kuro:kuro /pathToLog/AI_*
chmod 640 /pathToLog/AI_*
ln -s /pathToApacheLog/ssl_access_log /pathToLog/ssl_access_log
"""

# Apache log — kuro needs read only
"""
chown root:kuro /pathTo/ssl_access_log
chmod 640 /pathTo/ssl_access_log
"""

# Set ACLs access for kuro to read log
Ex: Rocky Linux 9.7
"""
setfacl -m u:kuro:rx /var/log/httpd
setfacl -d -m u:kuro:r /var/log/httpd
setfacl -m u:kuro:r /var/log/httpd/ssl_access_log
"""

# Telegram usages:
Ban one IP
"""/fban ip xx.xx.xx.xx"""
Unban one IP
"""/funban ip xx.xx.xx.xx"""
Ban one subnet class CHAT_ID
"""/fban subnet xx.xx.xx"""
Unban one subnet class CHAT_ID
"""/funban subnet xx.xx.xx"""
