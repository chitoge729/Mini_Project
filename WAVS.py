import tkinter as tk
from tkinter import ttk  
from tkinter import scrolledtext, messagebox, filedialog
import requests
from bs4 import BeautifulSoup
from ttkthemes import ThemedTk 

ttk: ttk

class WebScannerApp:
    def __init__(self, root):
        self.root = ThemedTk(theme="radiance")
        self.root.title("Web Application Vulnerability Scanner")

        self.custom_style()  
        self.create_widgets()
        self.scan_history = []

    def custom_style(self):
        style = ttk.Style()

        # Configure label colors
        style.configure("Radiant.TLabel", foreground="#333", background="#F0E68C", font=("Helvetica", 12, "bold"))

        # Configure entry colors
        style.configure("Radiant.TEntry", fieldbackground="white", font=("Helvetica", 12))

        # Configure button colors
        style.configure("Radiant.TButton", background="#6BBE45", foreground="white", font=("Helvetica", 10, "bold"))

        # Configure text widget colors
        self.root.configure(bg="#FFF")
        style.configure("Radiant.TText", background="#F0E68C", foreground="black", font=("Helvetica", 10))

    

    def create_widgets(self):
        self.url_label = ttk.Label(self.root, text="Enter Target URL:", style="Radiant.TLabel")
        self.url_label.pack(pady=10)

        self.url_entry = ttk.Entry(self.root, width=50, style="Radiant.TEntry")
        self.url_entry.pack(pady=5)

        bottom_button_frame = ttk.Frame(self.root)
        bottom_button_frame.pack()

        self.scan_button = ttk.Button(bottom_button_frame, text="Scan", command=self.scan, style="Radiant.TButton")
        self.scan_button.pack(side=tk.LEFT, padx=10)

        self.clear_url_button = ttk.Button(bottom_button_frame, text="Clear URL", command=self.clear_url_entry, style="Radiant.TButton")
        self.clear_url_button.pack(side=tk.LEFT, padx=10)

        self.history_button = ttk.Button(bottom_button_frame, text="Recent History", command=self.show_recent_history, style="Radiant.TButton")
        self.history_button.pack(side=tk.LEFT, padx=10)

        self.result_text = scrolledtext.ScrolledText(self.root, width=80, height=20, font=("Helvetica", 10))
        self.result_text.pack(padx=10, pady=10)
        self.result_text.configure(bg="#F0E68C", fg="black")

        bottom_button_frame = ttk.Frame(self.root)
        bottom_button_frame.pack()

        self.clear_button = ttk.Button(bottom_button_frame, text="Clear", command=self.clear_results, style="Radiant.TButton")
        self.clear_button.pack(side=tk.LEFT, padx=10, pady = 10)

        self.save_button = ttk.Button(bottom_button_frame, text="Save Results", command=self.save_results, style="Radiant.TButton")
        self.save_button.pack(side=tk.LEFT, padx=10, pady = 10)

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(self.result_text.get("1.0", tk.END))
            messagebox.showinfo("Saved", "Results saved successfully.")

    def clear_url_entry(self):
        self.url_entry.delete(0, tk.END)
    
    def clear_results(self):
        self.result_text.delete(1.0, tk.END)

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(self.result_text.get("1.0", tk.END))
            messagebox.showinfo("Saved", "Results saved successfully.")

    def add_to_history(self, url, vulnerabilities):
        self.scan_history.append({'url': url, 'vulnerabilities': vulnerabilities})
    
    def show_recent_history(self):
        if not self.scan_history:
            messagebox.showinfo("Recent History", "No recent history available.")
        else:
            history_window = tk.Toplevel(self.root)
            history_window.title("Recent History")

            for scan in self.scan_history:
                url_label = ttk.Label(history_window, text=f"URL: {scan['url']}", style="Radiant.TLabel")
                url_label.pack(padx=10, pady=5, anchor="w")

                vulnerabilities_text = tk.Text(history_window, wrap=tk.WORD, font=("Helvetica", 10))
                for vulnerability in scan['vulnerabilities']:
                    vulnerabilities_text.insert(tk.END, f"Vulnerability: {vulnerability}\n")
                    vulnerabilities_text.insert(tk.END, "-" * 40 + "\n")
                vulnerabilities_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)


    def scan(self):
        target_url = self.url_entry.get()
        if not target_url:
            messagebox.showerror("Error", "Please enter a valid URL.")
            return

        vulnerabilities_found = self.scan_for_vulnerabilities(target_url)

        self.result_text.delete(1.0, tk.END)
        if vulnerabilities_found:
            self.result_text.insert(tk.END, "Vulnerabilities found:\n")
            for vulnerability in vulnerabilities_found:
                self.result_text.insert(tk.END, "- " + vulnerability + "\n")
                self.display_vulnerability_details(vulnerability)  # Display vulnerability details

            suggestions = self.get_suggestions(vulnerabilities_found)
            self.result_text.insert(tk.END, "\nSuggestions:\n")
            for suggestion in suggestions:
                self.result_text.insert(tk.END, "- " + suggestion + "\n")
        else:
            self.result_text.insert(tk.END, "No vulnerabilities found.")

        if vulnerabilities_found:
            self.add_to_history(target_url, vulnerabilities_found)

    def scan_for_vulnerabilities(self, url):
        vulnerabilities = []
        try:
            response = requests.get(url)
            response.raise_for_status()  

            soup = BeautifulSoup(response.text, 'html.parser')

            if 'error in your SQL syntax' in response.text:
                vulnerabilities.append('SQL Injection vulnerability found')

            if '<script>' in response.text:
                vulnerabilities.append('Cross-Site Scripting (XSS) vulnerability found')

            if 'CSRFToken' not in response.text:
                vulnerabilities.append('Cross-Site Request Forgery (CSRF) vulnerability found')

            if 'password' in response.text:
                vulnerabilities.append('Sensitive information exposure: Password found in response')

            if 'admin' in response.text:
                vulnerabilities.append('Possible username exposure: Admin account name found')

            if 'error_reporting' in response.text:
                vulnerabilities.append('Information disclosure: PHP error reporting enabled')

            if 'robots.txt' in response.text:
                vulnerabilities.append('Information leakage: robots.txt file found')

            if 'wp-content' in response.text:
                vulnerabilities.append('WordPress directory exposure: wp-content found')

            if 'exec' in response.text:
                vulnerabilities.append('Command execution vulnerability: "exec" keyword detected')

            if 'config.php' in response.text:
                vulnerabilities.append('Sensitive file exposure: config.php file found')

            if 'adminer' in response.text:
                vulnerabilities.append('Adminer database tool detected: Potential security risk')


        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error scanning URL: {e}")
        
        return vulnerabilities

    
    def get_suggestions(self, vulnerabilities):
        suggestions = []

        for vulnerability in vulnerabilities:
            if 'SQL Injection' in vulnerability:
                suggestions.append('Recommendation: Use parameterized queries to prevent SQL injection.')

            if 'Cross-Site Scripting' in vulnerability:
                suggestions.append('Recommendation: Sanitize user input and encode output to prevent XSS attacks.')

            if 'CSRF' in vulnerability:
                suggestions.append('Recommendation: Implement anti-CSRF tokens and validate requests.')

            if 'Sensitive information exposure' in vulnerability:
                suggestions.append('Recommendation: Avoid exposing sensitive data in response messages.')

            if 'Possible username exposure' in vulnerability:
                suggestions.append('Recommendation: Avoid using predictable usernames like "admin".')

            if 'Information disclosure' in vulnerability:
                suggestions.append('Recommendation: Disable detailed error reporting in production environments.')

            if 'Information leakage' in vulnerability:
                suggestions.append('Recommendation: Review and restrict access to sensitive files like robots.txt.')

            if 'WordPress directory exposure' in vulnerability:
                suggestions.append('Recommendation: Ensure proper security configurations for WordPress sites.')

            if 'Command execution vulnerability' in vulnerability:
                suggestions.append('Recommendation: Validate and sanitize user input to prevent command execution.')

            if 'Sensitive file exposure' in vulnerability:
                suggestions.append('Recommendation: Securely manage access to sensitive files.')

            if 'Adminer database tool detected' in vulnerability:
                suggestions.append('Recommendation: Remove or secure access to the Adminer tool.')


        return suggestions
    
    def display_vulnerability_details(self, vulnerability):
        # Modify this method to fetch and display vulnerability details
        details = self.get_vulnerability_details(vulnerability)
        self.result_text.insert(tk.END, f"Severity: {details['severity']}\n")
        self.result_text.insert(tk.END, f"Description: {details['description']}\n")
        self.result_text.insert(tk.END, f"Impact: {details['impact']}\n")
        self.result_text.insert(tk.END, f"Mitigation: {details['mitigation']}\n")
        self.result_text.insert(tk.END, "-" * 40 + "\n")

    def get_vulnerability_details(self, vulnerability):
        details = {
            'SQL Injection vulnerability found': {
                'severity': 'High',
                'description': 'SQL injection is a type of security vulnerability...',
                'impact': 'An attacker can manipulate the application\'s database...',
                'mitigation': 'To mitigate SQL injection vulnerabilities...',
            },
            'Cross-Site Scripting (XSS) vulnerability found': {
            'severity': 'Medium',
            'description': 'Cross-Site Scripting (XSS) is a security vulnerability...',
            'impact': 'An attacker can inject malicious scripts into web pages...',
            'mitigation': 'To mitigate XSS vulnerabilities...',
            },
            'Cross-Site Request Forgery (CSRF) vulnerability found': {
                'severity': 'Medium',
                'description': 'Cross-Site Request Forgery (CSRF) is an attack...',
                'impact': 'An attacker can trick users into performing actions without their consent...',
                'mitigation': 'To mitigate CSRF vulnerabilities...',
            },
            'Sensitive information exposure: Password found in response': {
                'severity': 'Medium',
                'description': 'Sensitive information exposure occurs when...',
                'impact': 'An attacker can obtain passwords or other sensitive data...',
                'mitigation': 'To mitigate sensitive information exposure...',
            },
            'Possible username exposure: Admin account name found': {
                'severity': 'Low',
                'description': 'Possible username exposure occurs when...',
                'impact': 'An attacker can gather information about potential usernames...',
                'mitigation': 'To mitigate possible username exposure...',
            },
            'Information disclosure: PHP error reporting enabled': {
                'severity': 'Low',
                'description': 'Information disclosure occurs when error messages...',
                'impact': 'An attacker can gain insights into the application\'s structure...',
                'mitigation': 'To mitigate information disclosure...',
            },
            'Information leakage: robots.txt file found': {
                'severity': 'Low',
                'description': 'Information leakage occurs when sensitive information...',
                'impact': 'An attacker can learn about directories or files...',
                'mitigation': 'To mitigate information leakage...',
            },
            'WordPress directory exposure: wp-content found': {
                'severity': 'Low',
                'description': 'WordPress directory exposure occurs when...',
                'impact': 'An attacker can learn about the technology stack...',
                'mitigation': 'To mitigate WordPress directory exposure...',
            },
            'Command execution vulnerability: "exec" keyword detected': {
                'severity': 'High',
                'description': 'Command execution vulnerability occurs when...',
                'impact': 'An attacker can execute arbitrary commands...',
                'mitigation': 'To mitigate command execution vulnerabilities...',
            },
            'Sensitive file exposure: config.php file found': {
                'severity': 'High',
                'description': 'Sensitive file exposure occurs when...',
                'impact': 'An attacker can access sensitive configuration files...',
                'mitigation': 'To mitigate sensitive file exposure...',
            },
            'Adminer database tool detected: Potential security risk': {
                'severity': 'Medium',
                'description': 'Adminer database tool detected indicates...',
                'impact': 'Adminer tool can potentially be used to exploit...',
                'mitigation': 'To mitigate the Adminer tool risk...',
            },
        }
        return details.get(vulnerability, {})

    

if __name__ == "__main__":
    root = tk.Tk()
    app = WebScannerApp(root)
    root.mainloop()