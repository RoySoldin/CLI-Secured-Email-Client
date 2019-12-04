import smtplib  # Create an Gmail SMTP object, used for connection with a mail server.
import imaplib  # IMAP a standard email protocol that stores email messages on a mail server.
import email    # Used to read, write and send emails from our python script.
import click
import sys
import re

from ImapServer import ImapServer
from SmtpServer import SmtpServer
from virus_total_apis import PublicApi
from colorama import Style, Back, Fore

# Set Globals
PORT = 587
SMTP_SERVER = 'smtp.gmail.com'
IMAP_SERVER = 'imap.gmail.com'
USER_EMAIL = ''
PASSWORD = ''
API_KEY = '5bb94055abb3b821d4fe06632b354b242c8286a7f697fee2425f33bc4329b673'
SYSTEM_COMMANDS = ['read', 'send', 'exit']
MY_CONTACTS = []
VIRUS_TOTAL_SCANNER = PublicApi(API_KEY)
EMAIL_REGEX = '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'


def exit_system():
    click.echo('<secure email> Exiting the system, Goodbye...')
    sys.exit()


def get_contacts():
    """ Function to read the contacts from the User Email
    Returns:
        list: returns a list of email addresses"""

    my_contacts = []
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USER_EMAIL, PASSWORD)
        mail.select('Inbox')

        _, data = mail.search(None, 'ALL')
        mail_ids = data[0]
        id_list = mail_ids.split()
        for email_id in reversed(id_list):
            _, email_data = mail.fetch(email_id, '(RFC822)')
            raw_email = email_data[0][1].decode("utf-8")
            email_msg = email.message_from_string(raw_email)
            extract_mail = re.findall(EMAIL_REGEX, email_msg['From'])
            my_contacts.append(extract_mail)

    except Exception as e:
        print('DEBUG: get_contacts() error: {}'.format(e))
    return [contact for contact in my_contacts for contact in contact]


def send_email():
    s = SmtpServer(USER_EMAIL, PASSWORD, API_KEY)
    s.send_email()


def read_emails():
    r = ImapServer(USER_EMAIL, PASSWORD, API_KEY, MY_CONTACTS)
    r.read_mailbox()


def validate_username_and_password(username, password):
    """ Checks if the login details are correct,
     if the login fails, asks the user to re-enter the details

    Args:
        username (str): the user E-mail address
        password (str): the user E-mail password """

    global USER_EMAIL, PASSWORD
    with smtplib.SMTP(SMTP_SERVER, PORT) as stmp:
        stmp.ehlo()
        stmp.starttls()
        stmp.ehlo()
        try:
            stmp.login(username, password)
            USER_EMAIL = username
            PASSWORD = password
            stmp.quit()
        except Exception as e:
            click.echo(Back.LIGHTRED_EX + Fore.BLACK + '<secure email> Username and Password not accepted. please try again' + Style.RESET_ALL)
            security_email_system()


def validate_email_form(ctx, param, username):
    """ Check the user email match to a valid e-mail form, if not,
     the user must enter valid one """

    if not re.match(EMAIL_REGEX, username):
        print('<secure email> Incorrect email address given, a valid one should be: example@gmail.com')
        security_email_system()
    else:
        return username


def switcher_program_menu():
    """ switch case in python for the program menu options """
    return {'exit': exit_system,
            'send': send_email,
            'read': read_emails
            }


@click.command()
@click.option('--username', required=True, prompt='<secure email> Please enter a valid E-mail address',
              callback=validate_email_form)
@click.option('--password', required=True, prompt='<secure email> Please enter a password',
              hide_input=True, confirmation_prompt=True)
def security_email_system(username, password):
    """ This is an infinent-loop program menu , the user has 3 options:
    send - send a mail
    read - read all income e-mails
    exit - exit the program

    Args:
        username (str): the user E-mail address
        password (str): the user E-mail password """

    validate_username_and_password(username, password)
    global MY_CONTACTS
    click.echo('Connecting to the security email system...')
    MY_CONTACTS = get_contacts()
    click.echo(Fore.LIGHTBLUE_EX + Back.LIGHTBLACK_EX + '<secure email> Welcome to Security Email System.' + Style.RESET_ALL)
    while True:
        click.echo(Fore.LIGHTBLUE_EX+'<secure email> Please choose option:\n'
                   '               1) Enter \'send\' for sending email\n'
                   '               2) Enter \'read\' for seeing your mailbox\n'
                   '               3) Enter \'exit\' for exit the system\n ')
        prompt = input()
        if prompt not in SYSTEM_COMMANDS:
            click.echo(Back.LIGHTRED_EX + Fore.BLACK + '<secure email> Not valid option' + Style.RESET_ALL)
            continue
        switcher_program_menu().get(prompt)()


if __name__ == '__main__':
    security_email_system()

