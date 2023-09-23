# Web Directory Enumerator

# This Python script helps you discover web directory paths through two methods:
# 1. Enumerating paths using href links.
# 2. Performing wordlist-based directory attacks.

# Simply input your target URL, choose the method, and let the script do the rest. It saves discovered
# paths for your analysis. Press [Ctrl + C] at any time to skip stages or exit.

# Author: github.com/Mr1llusion


try:
    # Standard library imports
    import time
    import requests
    from urllib.parse import urljoin
    import os

    # Import Special libraries
    from termcolor import colored
    from bs4 import BeautifulSoup

except ModuleNotFoundError:
    from subprocess import call
    modules = ["termcolor", "beautifulsoup4"]
    call("pip install " + ' '.join(modules), shell=True)


def main():
    banner = r"""
 ________  ___  ________  ________  ___  ___  ________  _________  _______   ________     
|\   ___ \|\  \|\   __  \|\   __  \|\  \|\  \|\   ____\|\___   ___\\  ___ \ |\   __  \    
\ \  \_|\ \ \  \ \  \|\  \ \  \|\ /\ \  \\\  \ \  \___|\|___ \  \_\ \   __/|\ \  \|\  \   
 \ \  \ \\ \ \  \ \   _  _\ \   __  \ \  \\\  \ \_____  \   \ \  \ \ \  \_|/_\ \   _  _\  
  \ \  \_\\ \ \  \ \  \\  \\ \  \|\  \ \  \\\  \|____|\  \   \ \  \ \ \  \_|\ \ \  \\  \| 
   \ \_______\ \__\ \__\\ _\\ \_______\ \_______\____\_\  \   \ \__\ \ \_______\ \__\\ _\ 
    \|_______|\|__|\|__|\|__|\|_______|\|_______|\_________\   \|__|  \|_______|\|__|\|__|
                                                \|_________|                                                                                                  
    """
    colored_banner = colored(banner, color="magenta", attrs=["bold"])
    print(colored_banner)
    try:
        base_url = input(colored("[+] Enter the base target URL: ", 'red', attrs=["bold"]))
    except KeyboardInterrupt:
        exit()
    tool_kit = WebEnumerator(base_url)
    while True:
        print(colored("\n[*] Recommended steps:", 'red', attrs=["bold"]))
        print(colored("[1] -> Enumerate web directories path by href links", 'green', attrs=["bold"]))
        print(colored("[2] -> Perform a wordlist attack", 'green', attrs=["bold"]))

        print(colored("\n[Exit] -> Exit", attrs=["bold"]))
        try:
            choice = input(colored("Enter your choice (1/2/Exit): ", 'blue', attrs=["bold"]))
        except KeyboardInterrupt:
            exit()
        if choice == '1':
            tool_kit.was_enumerated_by_href = True
            tool_kit.run()
        elif choice == '2':
            print(colored("\n[*] Press [Ctrl + C] to skip href-path/stages.",
                          'red', attrs=["bold"]))
            print(colored("[+] Option 2: Perform a wordlist attack", 'yellow', attrs=["bold"]))
            tool_kit.dirhunt()
        elif choice.lower() == 'exit':
            exit()
        else:
            print("\n[!] Invalid choice. Please select a valid option.")


class WebEnumerator:
    def __init__(self, url):
        self.base_url = url
        self.max_depth = 3
        self.visited_urls = set()
        self.full_base_url = None
        self.was_enumerated_by_href = False

    def run(self):
        """
        This method is the entry point of the web enumeration process.
        It initiates the exploration of the website starting from the base URL.
        """
        try:
            self.full_base_url = self.get_valid_url()
            if self.full_base_url:
                soup = self.get_soup(self.full_base_url)
                links = self.extract_links(soup)
                self.visited_urls.add(self.full_base_url)
                self.explore_links(self.full_base_url, links, 0)  # Add the 'depth' parameter here
                self.save_href_paths()
            else:
                print(colored("[!] Unable to establish a connection to the webpage.\n", 'yellow'))
        except KeyboardInterrupt:
            print(colored("\n        [!] [KeyboardInterrupt] -> Scan stopped\n\n", 'red', attrs=["bold"]))
            pass

    def get_valid_url(self):
        """
        This method tries different protocols (http and https) to connect to the base URL.
        It returns the full URL if a successful connection is made, or None if all attempts fail.
        """
        if not self.base_url.startswith("http://") and not self.base_url.startswith("https://"):
            protocols = ['http://', 'https://']
            for protocol in protocols:
                try:
                    full_base_url = protocol + self.base_url
                    response = requests.get(full_base_url)
                    if response.status_code == 200:
                        return full_base_url
                except requests.exceptions.RequestException:
                    print(colored(f"\n[!] Error connecting to {protocol}{self.base_url}", 'red'))
        else:
            try:
                response = requests.get(self.base_url)
                if response.status_code == 200:
                    return self.base_url
            except requests.exceptions.RequestException:
                print(colored(f"\n[!] Error connecting to {self.base_url}", 'red'))
        return None

    @staticmethod
    def get_soup(url):
        """
        This function fetches a webpage HTML content and turns it into a format that's easy to work with.
        """
        response = requests.get(url)
        return BeautifulSoup(response.text, 'html.parser')

    @staticmethod
    def extract_links(soup):
        """
        This method extracts all the href links from the source web-page.
        """
        links = []
        for link in soup.find_all('a', href=True):
            href_value = link.get('href')
            links.append(href_value)
        return links

    def explore_links(self, b_url, directories, depth):
        """
        This method explores links starting from a given base URL.
        It stops when the specified depth is reached.
        """
        if depth >= self.max_depth:
            return

        for directory in directories:
            full_url = urljoin(b_url, directory)

            if (
                    full_url.startswith(self.full_base_url)
                    and full_url not in self.visited_urls
                    and "#" not in full_url  # Exclude URLs containing "#"
            ):

                print(f"[+] Scoping in: {full_url}")
                try:
                    inner_soup = self.get_soup(full_url)
                    inner_links = self.extract_links(inner_soup)
                    self.visited_urls.add(full_url)

                    self.explore_links(full_url, inner_links, depth + 1)
                except requests.exceptions.RequestException as e:
                    print(f"[!] Error connecting to {full_url}: {e}")

    def save_href_paths(self):
        """
        This method saves the visited directories to a text file, sorted by URL length and then by name.
        """
        unique_directories = set()
        with open("href_paths.txt", 'w') as directories_file:
            for visited_path in self.visited_urls:
                relative_path = visited_path.replace(self.full_base_url, '')
                if not relative_path:
                    continue  # if url is empty

                # Split the path by '/' and remove file extensions like .php, .html, etc.
                path_parts = relative_path.split('/')
                cleaned_parts = []
                for part in path_parts:
                    should_append = True
                    for extension in ['.php', '.html', '.pdf']:
                        if part.endswith(extension):
                            should_append = False
                            break
                    if should_append:
                        cleaned_parts.append(part)

                # after filter extension, join url parts
                cleaned_path = '/'.join(cleaned_parts)

                # if url is not slash, add to directories list.
                if cleaned_path != '/':
                    unique_directories.add(cleaned_path.strip())

            # write directories to txt file
            for directory in sorted(unique_directories):
                if directory.endswith('/'):
                    directory = directory[:-1]  # Remove '/' at the end
                directories_file.write(directory + '\n')

        print(colored("\n   [+] Href paths saved in -> [ href_paths.txt ]", 'red', attrs=["bold"]))

    def dirhunt(self):
        busted_dirs = []
        if not self.base_url.startswith("http://") and not self.base_url.startswith("https://"):
            self.full_base_url = self.get_valid_url()
        while True:
            try:
                file_name = input(colored('\n[*] wordlist path: ', attrs=["bold"]))
                if os.path.isfile(file_name):
                    break
                else:
                    print(colored("\n        [!] -> [ File not found ] <- [!]\n", 'blue', attrs=["bold"]))
            except KeyboardInterrupt:
                exit()

        print(colored("\n[+] Stage 1 - wordlist scan\n\n", 'yellow', attrs=["bold"]))
        with open(file_name, 'r') as wordlist:
            try:
                for line in wordlist:
                    directory = line.strip()
                    full_url_bust = self.full_base_url + f'/{directory}'  # Include a leading slash
                    response = requests.get(full_url_bust)
                    if response:
                        print(colored(f"    [*] Directory busted at: {full_url_bust}", 'red', attrs=["bold"]))
                        busted_dirs.append(full_url_bust)
            except KeyboardInterrupt:
                print(colored("\n        [!] -> [ Passing Stage 1 ]\n\n", 'blue', attrs=["bold"]))
                pass

        print(colored("\n[+] Stage 2 - href link scan\n\n", 'yellow', attrs=["bold"]))
        if os.path.isfile('href_paths.txt'):
            with open('href_paths.txt', 'r') as href:
                try:
                    for path in href:
                        href_path = path.strip()
                        if os.path.isfile(file_name):
                            with open(file_name, 'r') as wordlist:
                                try:
                                    for word in wordlist:
                                        word = word.strip()
                                        full_url_bust = self.full_base_url + f'{href_path}/{word}'
                                        response = requests.get(full_url_bust)
                                        if response:
                                            print(colored(f"    [*] Directory busted at: {full_url_bust}", 'red',
                                                          attrs=["bold"]))
                                            busted_dirs.append(full_url_bust)
                                except KeyboardInterrupt:
                                    print(colored("\n        [!] -> [ Skip path scan in 1 sec ]", 'blue',
                                                  attrs=["bold"]))
                                    print(colored("        [!] -> [ Ctrl + C to Exit ]\n\n", 'cyan',
                                                  attrs=["bold"]))

                                    time.sleep(1)
                                    pass
                        else:
                            print("[!] wordlist not found, restart!")
                            break
                except KeyboardInterrupt:
                    print(colored("\n\n        [!] -> [ Scan stopped! ]\n\n", 'blue',
                                  attrs=["bold"]))
        else:
            print(colored("\n    [+] To proceed to Stage 2, "
                          "run 'Enumerating web directories using href links' \n\n", 'red', attrs=["bold"]))

        with open("busted_directories.txt", 'w') as busted_file:
            for directory in busted_dirs:
                busted_file.write(directory + '\n')
        print(colored("\n   [+] busted directories saved in -> [ busted_directories.txt ]",
                      'red', attrs=["bold"]))


if __name__ == "__main__":
    main()
