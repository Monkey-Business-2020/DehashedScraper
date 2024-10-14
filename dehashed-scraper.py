#/bin/bash/python3
import requests, json, csv, sys, time, argparse, os.path, os

class Dehashed_Scraper():
    # Statistical information on returned data
    usernameCount = 0
    emailCount = 0
    passCount = 0
    hashCount = 0
    originCount = 0
    remainingCredit = 0
    export_flag = False

    # Search Dehashed and return results
    def fetch_data(self, company, myEmail, myAPI):
        '''try:'''
        url = f'https://api.dehashed.com/search?query=domain%3A{company}&size=10000'
        response = requests.get(url, headers={'Accept': 'application/json'}, auth=(myEmail, myAPI))
        data = json.loads(response.content)
        self.remainingCredit = data['balance']
        if "valid subscription" in response.text:
            print("\n[!] No valid subscription [!]\n")
            sys.exit()
        elif data['entries'] == None:
            print(f"\n[!] No Entries Found for {company} [!]\n\nExiting...\n")
            sys.exit()
        else:
            print("\nGrabbing Leaks...")
            self.parse_results(company, data)
        '''except:
            print("\nIssue in fetching breached data from Dehashed...")'''

    # Parse results
    def parse_results(self, company, data_dump, export=False):
        breached_emails = [emails['email'] for emails in data_dump['entries']]
        breached_username = [users['username'] for users in data_dump['entries']]
        breached_passwords = [passwords['password'] for passwords in data_dump['entries']]
        breached_hashes = [hashes['hashed_password'] for hashes in data_dump['entries']]
        breached_origin = [origin['database_name'] for origin in data_dump['entries']]
        self.usernameCount = set(breached_username)
        self.emailCount = set(breached_emails)
        self.passCount = set(breached_passwords)
        self.hashCount = set(breached_hashes)
        self.originCount = set(breached_origin)
        for e, u, p, h, bo in zip(breached_emails, breached_username, breached_passwords, breached_hashes, breached_origin):
            print(f'Email: {e} | Username: {u} | Password: {p} | Hashes: {h} | Origin: {bo}')
        if self.export_flag:
            self.save_results(company, breached_emails, breached_username, breached_passwords, breached_hashes, breached_origin)

    # Save formatted results to csv and txt
    def save_results(self, company, bem, bus, bpa, bha, bor):
        # Save as CSV
        directory = os.getcwd() + f"/Dehashed_{company}"
        if os.path.exists(directory):
            pass
        else:
            os.mkdir(directory)

        with open(f'{directory}/results-domain-{company.split(".")[0]}.csv', 'w', encoding="utf-8") as breached_fileCSV:
            writer = csv.writer(breached_fileCSV, lineterminator='\n')
            writer.writerow(['EMAIL', 'USERNAME', 'PASSWORD', 'HASHES', 'BREACH ORIGIN'])
            for e, u, p, h, b in zip(bem, bus, bpa, bha, bor):
                writer.writerow([e, u, p, h, b])
        print(f"\nSaved breach results to {directory}/results-domain-{company.split('.')[0]}.csv")
        
        # Save as TXT
        with open(f'{directory}/results-domain-{company.split(".")[0]}.txt', 'w', encoding="utf-8") as breached_fileTXT:
            for e, u, p, h, b in zip(bem, bus, bpa, bha, bor):
                breached_fileTXT.write(f'Email: {e} | Username: {u}| Password: {p} | Hashes: {h} |Origin: {b}\n')
        print(f"Saved breach results to {directory}/results-domain-{company.split('.')[0]}.txt")

        # Save Username and password in seperate files
        usernamesTXT = open(f'{directory}/{company.split(".")[0]}-USERNAMES.txt', 'w', encoding="utf-8")
        passwordTXT = open(f'{directory}/{company.split(".")[0]}-PASSWORDS.txt', 'w', encoding="utf-8")
        bus = set(bus)
        bpa = set(bpa)
        for usernames in bus:
            usernamesTXT.write(f"{usernames}\n")
        print(f"Saved {len(bus)} USERNAMES to {directory}/{company.split('.')[0]}-USERNAMES.txt")
        for password in bpa:
            passwordTXT.write(f"{password}\n")
        print(f"Saved {len(bpa)} PASSWORDS to {directory}/{company.split('.')[0]}-PASSWORDS.txt")

    # Run program
    def run(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', '--company', help='provide the DOMAIN (example: nccgroup.com)', required=True)
        parser.add_argument('-a', '--api', help='provide an API key for Dehashed authentication', required=True)
        parser.add_argument('-e', '--email', help='provide an email for Dehashed authentication (Email used when you signed up to dehashed)', required=True)
        parser.add_argument('-x', '--export', help='Export USERNAMES and PASSWORDS to seperate TXT files', action='store_true', default=False)
        args = parser.parse_args()

        if args.export:
            self.export_flag = True

        if args.api and args.email:
            t1 = time.perf_counter()
            self.fetch_data(args.company, args.email, args.api)
            t2 = time.perf_counter()
            print(f"\nTotals Found:\nEmails: {len(self.emailCount)} \nUsernames: {len(self.usernameCount)} \nPasswords: {len(self.passCount)} \nHashes: {len(self.hashCount)} \nUnique Origins: {len(self.originCount)} \nRemaining Credit: {self.remainingCredit}")
            if self.remainingCredit < 10:
                print(f"\nREMAINING CREDIT IS GETTING LOW: {self.remainingCredit}")
            print(f"\nFinished in {round(t2-t1, 2)} seconds...\n")
        else:
            print("\nPlease enter your API and Email to the script\n")

if __name__ == '__main__':
    scraper = Dehashed_Scraper()
    scraper.run()
