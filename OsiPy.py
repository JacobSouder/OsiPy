import webbrowser #Used to open webpages in the default browser
from termcolor import colored 
import vt #VirusTotal API 3
import time
import requests #Used for URL validation in scan_file function

#VirusTotal setup and API Key - Please add your own free VT API key
client = vt.Client("<INSERT API KEY>")
print("""
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░     ░░░░░░░░░░░░░░░░░░        ░░░░░░░░░░░░
▒▒▒   ▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒▒  ▒   ▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒
▒   ▒▒▒▒▒▒▒▒   ▒▒     ▒▒▒▒▒▒   ▒▒▒▒   ▒   ▒▒▒   
▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓▓▓▓   ▓        ▓▓▓▓   ▓   ▓
▓   ▓▓▓▓▓▓▓▓   ▓▓▓    ▓▓   ▓   ▓▓▓▓▓▓▓▓▓▓▓    ▓▓
▓▓▓   ▓▓▓▓▓   ▓▓▓▓▓▓   ▓   ▓   ▓▓▓▓▓▓▓▓▓▓▓▓   ▓▓
█████     ██████      ██   █   ███████████   ███
█████████████████████████████████████████   ████

""")
def validate_phone_number(phone_number):


    
    return len(phone_number) == 10 and phone_number.isdigit()

def print_menu():
    print(colored("Welcome to OsiPy!", "cyan"))
    print(colored("This is a collection of OSINT tools.", "cyan"))
    print(colored("It aims to save you time by checking multiple databases.", "cyan"))
    print("\n")
    print(colored("Please select a tool:", "blue"))
    print("[1] " + colored("Reverse Phone Number Search", "magenta"))
    print("[2] " + colored("(Placeholder - Email Search)", "grey"))
    print("[3] " + colored("(Placeholder - Full Name and Location Search)", "grey"))
    print("[4] " + colored("Link and File Scanner", 'light_red'))

def get_user_choice(options):
    
    while True:
        try:
            choice = int(input("\nEnter your selection: "))
            if choice in range(1, len(options) + 1):
                return choice
            else:
                print(colored(f"Invalid choice. Please choose from {options}.", "red"))
        except ValueError:
            print(colored("Invalid input. Please enter a number.", "red"))

def get_phone_number():
    
    while True:
        phone_number = input("Enter a 10-digit US phone number (no dashes or special characters) or type exit: ")
        if phone_number.lower() == "exit":
            main()
        elif validate_phone_number(phone_number):
            return phone_number
        else:
            print(colored("Invalid phone number or command. Please try again.", "red"))
            



def open_phone_search_tabs(phone_number):
   
    first = phone_number[0:3]
    middle = phone_number[3:6]
    last = phone_number[6:10]

    phone_websites = [   
        f"https://www.411.com/phone/1-{first}-{middle}-{last}",
        f"https://800notes.com/Phone.aspx/1-{first}-{middle}-{last}",
        f"https://www.advancedbackgroundchecks.com/{first}-{middle}-{last}",
        f"https://www.fastpeoplesearch.com/{first}-{middle}-{last}",
        f"https://numpi.com/phone-info/{first}{middle}{last}",
        f"https://nuwber.com/search/phone?phone={first}{middle}{last}",
        f"https://www.okcaller.com/{first}{middle}{last}",
        f"https://www.peoplesearchnow.com/phone/{first}-{middle}-{last}",
        f"https://www.spytox.com/reverse-phone-lookup/{first}-{middle}-{last}",
        f"https://thatsthem.com/phone/{first}-{middle}-{last}",
        f"https://www.truepeoplesearch.com/results?phoneno=({first}){middle}-{last}",
        f"https://www.usphonebook.com/{first}-{middle}-{last}",
        f"https://www.whitepages.com/phone/1-{first}-{middle}-{last}",
        f"https://www.whoseno.com/search/US/{first}{middle}{last}",
        f"https://people.yellowpages.com/whitepages/phone-lookup?phone={first}{middle}{last}",
    ]  

    print(colored("\nOpening search results in new tabs...", "blue"))
    for website in phone_websites:
        webbrowser.open(website)


def get_email_address():

    while True: 
        domain = input("Please enter the emails domain with NO '.' - (com, net, co, edu): ")
        provider = input("Please enter email provider, or custom domain (COMMON: Yahoo!, gMail, iCloud): ")
        local_part = input("Please enter the local-part of the email (string before @ sign)")
        return domain, provider, local_part

def open_email_search_tabs(local_part, provider, domain):
    email_websites = [
        f"https://www.ipqualityscore.com/reverse-email-lookup/search/{local_part}%{provider}.{domain}",
    ]

    print(colored("\nOpening search results in new tabs...", "blue"))
    for website in email_websites:
        webbrowser.open(website)




def scan_file():
    def is_valid_url(url):
        try:
            response = requests.get(url)
            return response.status_code == 200
        except:
            return False

    vtscan_choice = int(input("[1] Local File Scan\n[2] URL Scan\n[3] Return to the main menu\n\nEnter your selection: "))
    if vtscan_choice == 1: 
        try:
            vt_file_path = input("Enter the file path (No quotes): ")

            with vt.Client('API KEY') as client:
                print("Scanning File... (This could take a while)")
                with open(vt_file_path, 'rb') as f:
                    analysis = client.scan_file(f, wait_for_completion=True)
                print("File scan completed.")

                results = analysis.results

                if results is not None:
                    print(results)
                else:
                    print("No results found.")

            return results
        except Exception as e:
            print(f"An error occurred: {e}")
        
    elif vtscan_choice == 2:
        try:
            vt_url = input("Enter a URL: ")

            if not is_valid_url(vt_url):
                print("Invalid URL. Please try again.")
                return

            with vt.Client('API KEY') as client:
                print("Scanning URL... (This could take a while)")
                # Scan the URL
                analysis = client.scan_url(vt_url)

                while True:
                    analysis = client.get_object(analysis.id)
                    if analysis.status == "completed":
                        break
                    time.sleep(5) 

                print("URL scan completed.")

                results = analysis.last_analysis_stats

                if results is not None:
                    print(results)
                else:
                    print("No results found.")

            return results
        except Exception as e:
            print(f"An error occurred: {e}")

    elif vtscan_choice == 3:
        main()

def print_scan_results(results):
    for engine, data in results.items():
        print(f"Engine: {data['engine_name']}")
        print(f"Version: {data['engine_version']}")
        print(f"Update: {data['engine_update']}")
        print(f"Category: {data['category']}")
        print(f"Result: {data['result']}")
        print("------------------------")


def main():
    

    while True:
        print_menu()
        choice = get_user_choice([str(i) for i in range(1, 5)])

        if choice == 1:
            phone_number = get_phone_number()
            open_phone_search_tabs(phone_number) 
            print(colored("\nProcess completed!", "green"))
            
        elif choice == 2:
            
            print(colored("WARNING: Reverse lookup for Email addresses usually yields no results - \nespecially when searching from big mail providers like Yahoo or Gmail.", "red"))
            print("")
            print(colored("It is recommended to use other methods like a reverse phone number search.", 'light_green'))
            print("")
            print(colored("Press [1] to go back to the main menu Press [2] if you would still like to continue, even though it is highly unlikely you will not get any results."))
            print("")
            int(input("Enter your selection: "))
            if input == 1:
                main()

            if input == 2:
                email_address = get_email_address()
                open_email_search_tabs(email_address)
                print(colored("\nProcess completed!", "green"))
                
            
        elif choice == 3:
            print(colored("Online username search is currently under development.", "magenta"))
            main()
        
            
        elif choice == 4:
            print(colored("This tool checks files against multiple databses to check for viruses, malware, or other backdoors.", "magenta"))
            scan_file()
            print("Process completed!")
            

    

if __name__ == "__main__":
    main()
