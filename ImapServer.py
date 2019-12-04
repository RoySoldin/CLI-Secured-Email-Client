import imaplib  # IMAP a standard email protocol that stores email messages on a mail server.
import email    # Used to read, write and send emails from our python script.
import os       # Manipulate directories of files present on our local desktop.
import time
import re
import hashlib

from virus_total_apis import PublicApi
from tqdm import tqdm
from colorama import Style, Back, Fore


class ImapServer:

    # Set Globals
    IMAP_SERVER = 'imap.gmail.com'
    EMAIL_REGEX = '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'

    def is_malicious(self, file_to_scan):
        """Parse the sending information entered by the user

        Args:
            file_to_scan (str): file data of the email attachment

        Returns:
            bool: Returns True if the file is malicious, otherwise False """

        virus_total_scanner = PublicApi(self.api_key)
        f_md5 = hashlib.md5(file_to_scan).hexdigest()
        try:
            file_report = virus_total_scanner.get_file_report(f_md5)
            if file_report['results']['positives'] > 0:
                return True
        except Exception as e:
            print('Scan file Failed: {}'.format(e))
        return False

    def downloading_attachments(self, mail, email_id, email_msg, extract_mail):
        """ Loop through all the available multiparts in one mail
            return:
                bool: Indicates whether the download was successful or failed
        """
        for part in email_msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            file_name = part.get_filename()
            if bool(file_name):
                file_data = part.get_payload(decode=True)
                if self.is_malicious(file_data):
                    print(Back.LIGHTRED_EX + Fore.BLACK + '<secure email> Found virus! Deleting email from {} that contain virus'.format(extract_mail) + Style.RESET_ALL)
                    mail.store(email_id, '+FLAGS', '\\Deleted')
                    mail.expunge()
                    return False
                if not os.path.isdir(os.path.join(os.getcwd(), "SecurityEmailSystem")):
                    os.mkdir(os.path.join(os.getcwd(), "SecurityEmailSystem"))
                file_path = os.path.join(os.getcwd(), "SecurityEmailSystem", file_name)
                # if not os.path.isfile(file_path):
                fp = open(file_path, 'wb')
                fp.write(file_data)
                fp.close()

        return True

    def decrypt_body_msg(self, body):
        """ logic: Caesar shift - Each letter in the body (ciphertext) is replaced by a letter with a right SHIFT of 3
        of positions down the alphabet. Impl according the Notes in the assignment. """

        result = ''
        for i in range(0, len(body)):
            result += chr(ord(body[i]) - 3)
        return result

    def extract_email_body_message(self,email_msg):
        """ Extract the email_id message body
            return:
                str: message body
        """

        body = ''
        if email_msg.is_multipart():
            for payload in email_msg.get_payload():
                if payload.get_content_type() == 'text/plain':
                    body += payload.get_payload()
        elif email_msg.get_content_type() == 'text/plain':
            body = email_msg.get_payload()

        if email_msg['Encrypt'] == 'True':
            body = self.decrypt_body_msg(email_msg.get_payload())

        return body

    def read_mailbox(self):
        try:
            print('<secure email> connecting your email ...')
            mail = imaplib.IMAP4_SSL(self.IMAP_SERVER)  # imaplib module implements connection based on IMAPv4 protocol
            mail.login(self.username, self.password)
            mail.select('Inbox')
            _, data = mail.search(None, 'ALL')
            mail_ids = data[0]
            id_list = mail_ids.split()
            ans = ''
            print('\tconnecting your email Succeed ...'.expandtabs(15))
            time.sleep(1)
            for email_id in tqdm(reversed(id_list), desc='\tfetching your emails'.expandtabs(15), total=len(id_list)):
                _, email_data = mail.fetch(email_id, '(RFC822)')
                # converts byte literal to string removing b''
                raw_email = email_data[0][1].decode("utf-8")
                email_msg = email.message_from_string(raw_email)
                extract_mail = re.findall(self.EMAIL_REGEX, email_msg['From'])[0]
                if extract_mail not in self.contacts:
                    print(Back.LIGHTRED_EX + Fore.BLACK + '\n<secure email> The system noticed email sent from: {} , Not from your contacts.\n\tAre you ready to receive it ? Enter  y/n\n'.format(extract_mail).expandtabs(15) + Style.RESET_ALL)
                    if input() == 'n':
                        mail.store(email_id, '+FLAGS', '\\Deleted')
                        mail.expunge()
                        continue
                if not self.downloading_attachments(mail, email_id, email_msg, extract_mail):
                    continue
                body = self.extract_email_body_message(email_msg)
                ans += '\tEmail From: {}\n\t' \
                       'Email Subject: {}\n\t' \
                       'Date: {}\n\t' \
                       'Body: {}\n'.format(extract_mail, email_msg['Subject'], ' '.join(email_msg['Date'].split()[:5]), body).expandtabs(15)
            time.sleep(1)
            mail.logout()
            print('\tYour mailbox:\n\n{}'.format(ans).expandtabs(15))
        except Exception as e:
            print('DEBUG: read_mailbox() Failed: {} '.format(e))

    def __init__(self, user_email, password, api_key, my_contacts):
            self.username = user_email
            self.password = password
            self.api_key = api_key
            self.contacts = my_contacts
