from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
import csv
import datetime
import socket
import re
import webbrowser
import whois
import dns.resolver

class PhishingChecker(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)

        self.add_widget(Label(text="Enter IP or URL to Check:"))
        
        self.input_field = TextInput(multiline=False)
        self.add_widget(self.input_field)

        self.check_ip_btn = Button(text="Check IP")
        self.check_ip_btn.bind(on_press=self.check_ip)
        self.add_widget(self.check_ip_btn)
        
        self.check_url_btn = Button(text="Check URL")
        self.check_url_btn.bind(on_press=self.check_url)
        self.add_widget(self.check_url_btn)
        
        self.result_label = Label(text="")
        self.add_widget(self.result_label)

        self.report_btn = Button(text="Report Cyber Crime (India)")
        self.report_btn.bind(on_press=self.open_cybercrime_portal)
        self.add_widget(self.report_btn)

        self.about_dev_btn = Button(text="About Developer")
        self.about_dev_btn.bind(on_press=self.about_developer)
        self.add_widget(self.about_dev_btn)
    
    def validate_input(self, input_text):
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        url_pattern = re.compile(r'^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$')
        
        if ip_pattern.match(input_text):
            return "IP"
        elif url_pattern.match(input_text):
            return "URL"
        else:
            return None
    
    def check_ip(self, instance):
        ip = self.input_field.text.strip()
        if self.validate_input(ip) != "IP":
            self.result_label.text = "Invalid IP address!"
            return
        try:
            # Perform DNS resolution to check if the IP is reachable
            socket.gethostbyaddr(ip)
            result = "IP is active and reachable. No public blacklist checks performed."
        except socket.herror:
            result = "Suspicious: IP is not reachable!"
        except Exception as e:
            result = f"Error: {str(e)}"
        
        self.result_label.text = result
        self.log_result("IP", ip, result)
    
    def check_url(self, instance):
        url = self.input_field.text.strip()
        if self.validate_input(url) != "URL":
            self.result_label.text = "Invalid URL!"
            return

        domain = re.sub(r'^https?://', '', url).split('/')[0]
        
        # WHOIS Lookup
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age = (datetime.datetime.now() - creation_date).days
                if age < 30:
                    whois_result = "⚠ Warning: Domain is newly registered (less than 30 days)."
                else:
                    whois_result = "✔ Domain appears legitimate."
            else:
                whois_result = "⚠ Could not determine domain registration date."
        except Exception as e:
            whois_result = f"⚠ WHOIS Error: {str(e)}"

        # DNS Lookup
        try:
            answers = dns.resolver.resolve(domain, 'A')
            dns_result = f"✔ DNS records found: {answers[0]}"
        except dns.resolver.NXDOMAIN:
            dns_result = "⚠ No DNS record found. Domain might be suspicious!"
        except Exception as e:
            dns_result = f"⚠ DNS Error: {str(e)}"

        # Google Safe Browsing (Manual Search)
        google_search_url = f"https://www.google.com/search?q={domain}+scam+phishing+report"
        safe_browsing_result = f"🔍 Open Google to check: {google_search_url}"

        # Final Result
        result = f"{whois_result}\n{dns_result}\n{safe_browsing_result}"
        self.result_label.text = result
        self.log_result("URL", url, result)
    
    def open_cybercrime_portal(self, instance):
        webbrowser.open("https://cybercrime.gov.in/Webform/Crime_AuthoLogin.aspx")

    def log_result(self, check_type, input_value, result):
        with open("checked_urls.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([check_type, input_value, str(datetime.datetime.now()), result])

    def about_developer(self, instance):
        self.result_label.text = "Developed by: Ashutosh\nML Enthusiast\nContact: ashutoshjena2001@yahoo.com"

class PhishingCheckerApp(App):
    def build(self):
        return PhishingChecker()

if __name__ == "__main__":
    PhishingCheckerApp().run()
