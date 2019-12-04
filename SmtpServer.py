import smtplib  # Create an Gmail SMTP object, used for connection with a mail server.
import hashlib


from email.message import EmailMessage  # Used to read, write and send emails from our python script.
from virus_total_apis import PublicApi
from colorama import Style, Back, Fore


class SmtpServer:

    # Set Globals
    PORT = 587
    SMTP_SERVER = 'smtp.gmail.com'

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
            print('Scan file error: {}'.format(e))
        return False

    def split_args(self, args, seps):
        """Parse the sending information entered by the user

        Args:
            args (str): the user input sendForm
            seps (list): Separation tokens

        Returns:
            list: list of the information divided by the separation tokens"""

        default_sep = seps[0]
        for sep in seps[1:]:
            args = args.replace(sep, default_sep)
        return [i.strip() for i in args.split(default_sep)][1:]

    def encrypt_body_msg(self, body):
        """ logic: Caesar shift - Each letter in the body (plaintext) is replaced by a letter with a left SHIFT of 3
        of positions down the alphabet. Impl according the Notes in the assignment. """

        result = ''
        for i in range(0, len(body)):
            result += chr(ord(body[i]) + 3)
        return result

    def get_user_msg_info(self):
        """ Receives all the information needed from the user to send an email Args:

        Returns:
            attachments (list): list of files attachments to email
            message (message): email message data"""

        while True:
            args = input('<secure email> Please enter a valid sendForm: \'-t <receiver email here> -s <Subject here> -b <body content here> -f <attachFile here>\'\n')
            required = ['-t', '-s']  # In order to send an email we must have receiving email and a subject message
            if all(x in args for x in required):
                break
            print('<secure email> Not a valid sendForm, you must fill -t -s')
        parse_args = self.split_args(args, (',', '-t', '-s', '-b', '-f'))
        message = EmailMessage()
        message['From'] = self.username
        message['To'] = parse_args[0]
        message['Subject'] = parse_args[1]
        body = parse_args[2]
        print('<secure email> do you want to encrypt your email? Enter  y/n'.format().expandtabs(15))
        if input() == 'y':
            message.__setitem__('Encrypt', 'True')
            body = self.encrypt_body_msg(body)
        # message.set_content("""\
        # <!DOCTYPE html>
        # <html>
        #     <body>
        #         <h1 style='color:SlateGray;'>{}</h1>
        #     </body>
        # </html>
        # """.format(self.encrypt_body_msg(parse_args[2])), subtype='html')
        message.set_content('{}'.format(body))
        attachments = parse_args[3:]
        return attachments, message

    def add_files_to_email(self, stmp, attachments, message):
        """ Add all attachments to message prior the sending action:

        Returns:
            bool: indicate if succeed to add files to message
            message (message): email message data """

        for file in attachments:
            try:
                with open(file, 'rb') as f:
                    file_data = f.read()
                    file_name = f.name
                if not self.is_malicious(file_data):
                    message.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=file_name)
                else:
                    print(Back.LIGHTRED_EX + Fore.BLACK + '<secure email> An error has occurred.The system detected a virus in the file: {}'.format(file_name).expandtabs(15) + Style.RESET_ALL)
                    print(Back.LIGHTRED_EX + Fore.BLACK + '\tDo you want to send the email without the file? Enter:  y/n\n'.expandtabs(15) + Style.RESET_ALL)
                    if input() == 'n':
                        stmp.quit()
                        return False, message

            except FileNotFoundError as e:
                print('<secure email> DEBUG: File {} failed to open.\nError message: {}'.format(file, e))
                stmp.quit()
                return False, message

        return True, message

    def send_email(self):
        try:
            with smtplib.SMTP(self.SMTP_SERVER, self.PORT) as stmp:
                stmp.ehlo()
                stmp.starttls()
                stmp.ehlo()
                try:
                    stmp.login(self.username, self.password)
                except Exception as e:
                    print('<secure email> DEBUG: Email login failed.\nError message: {}'.format(e).expandtabs(15))
                attachments, message = self.get_user_msg_info()  # construct email message with headers and body and files
                if attachments is not []:
                    did_add_files, message = self.add_files_to_email(stmp, attachments, message)
                    if not did_add_files:
                        return
                stmp.send_message(message)
                stmp.quit()
                print(Back.LIGHTGREEN_EX + Fore.BLACK + '<secure email> Successfully sent the mail to {} '.format(message['To']) + Style.RESET_ALL)
        except Exception as e:
            print(Back.LIGHTRED_EX + Fore.BLACK + '<secure email> Failed to send mail.\nError message: {}'.format(e) + Style.RESET_ALL)

    def __init__(self, user_email, password, api_key):
            self.username = user_email
            self.password = password
            self.api_key = api_key
