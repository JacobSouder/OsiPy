OsiPy: A simple Python Open-Source Intelligence Tool 

Easily automate OSINT searches by combining the most popular free OSINT search websites into one interface. 

Features: 
Phone Number Search - Currently Supports United States Phone Numbers
Name and location search
Email Search (Usually not reliable for an OSINT search)
Virus scanner, via virustotal

Prerequisites

    Python 3.7+
    Required Python libraries:
        webbrowser
        termcolor
        vt (VirusTotal API 3)
        requests
    A VirusTotal API key

    How to Use
1. Main Menu

When the program starts, you'll see the main menu:

    [1] Reverse Phone Number Search
    [2] (Placeholder - Email Search)
    [3] (Placeholder - Full Name and Location Search)
    [4] Link and File Scanner

Enter the number corresponding to your desired action.
2. Reverse Phone Number Search

    Enter a 10-digit US phone number (e.g., 1234567890).
    The program validates the input and opens multiple browser tabs with search results on various platforms.
    Supported platforms include:
        411.com
        AdvancedBackgroundChecks
        WhitePages
        TruePeopleSearch, and more.

3. Link and File Scanner

Select either:

    Local File Scan:
    Provide the file path for the file you want to scan. The program uploads it to VirusTotal and retrieves scan results.

    URL Scan:
    Enter the URL you wish to scan. The program validates the URL and sends it to VirusTotal for analysis.

Results

The results are displayed directly in the terminal, showing details such as:

    Detection engines used
    Detection categories
    Analysis results
