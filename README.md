# InvokeRogueDC
```

     ___                 _        ____                        ____   ____
    |_ _|_ ____   _____ | | _____|  _ \ ___   __ _ _   _  ___|  _ \ / ___|
     | || '_ \ \ / / _ \| |/ / _ \ |_) / _ \ / _` | | | |/ _ \ | | | |
     | || | | \ V / (_) |   <  __/  _ < (_) | (_| | |_| |  __/ |_| | |___
    |___|_| |_|\_/ \___/|_|\_\___|_| \_\___/ \__, |\__,_|\___|____/ \____|
                                             |___/

    ________________
    |               |
    |  ___________  |
    | |           | |
    | |  ROGUE    | |
    | |    DC     | |
    | |___________| |
    |               |
    |  [|||||||]    |
    |  [|||||||]    |
    |  [|||||||]    |
    |               |
    |    ____       |
    |   |    |      |
    |   '----'      |
    |_______________|

        Made by Wuentin


usage: DC.py [-h] --dc-host DC_HOST [--ldap-encryption {ldaps,ldap-starttls}] --username USERNAME [--password PASSWORD] [--nthash NTHASH] --domain DOMAIN [--kerberos] --computer COMPUTER
             [--computer-pass COMPUTER_PASS] [--delete]

Create a computer account that will act as a domain controller.

options:
  -h, --help            show this help message and exit
  --dc-host DC_HOST     Domain Controller.
  --ldap-encryption {ldaps,ldap-starttls}
                        LDAP encryption method (Default : ldap-starttls).
  --username USERNAME, -u USERNAME
                        Username for authentication.
  --password PASSWORD, -p PASSWORD
                        Password for NTLM authentication.
  --nthash NTHASH, -H NTHASH
                        NT hash for NTLM authentication.
  --domain DOMAIN, -d DOMAIN
                        Domain name for authentication.
  --kerberos, -k        Use Kerberos authentication instead NTLM. NOT YET IMPLEMENTED!
  --computer COMPUTER   Name of the computer to create in LDAP.
  --computer-pass COMPUTER_PASS
                        Password for the new computer account.
  --delete              Delete an existing computer.
         Delete an existing computer.

```

# Purpose


# Ethical Only
The intended use of InvokeRogueDC is strictly for educational purposes, promoting ethical understanding and responsible learning in the realm of cybersecurity. This tool is not meant for any malicious activities or unauthorized access.
Using this tool against hosts that you do not have explicit permission to test is illegal. You are responsible for any trouble you may cause by using this tool.
