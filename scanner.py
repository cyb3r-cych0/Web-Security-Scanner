#!usr/bin/env python3
"""Modules & Libraries"""
import tkinter
from tkinter import messagebox
from urllib.parse import urljoin  # convert relative URLs to full URLs
import re  # uses pythex to search strings in a bigger string
import sqlite3  # python database
import datetime
import time
import requests  # send get requests on the internet
from bs4 import BeautifulSoup  # parse HTML
import customtkinter  # external module built on top of tkinter
import socket
import threading

"""
App Module
"""


# sidebar widget
class SidebarFrame(customtkinter.CTkFrame):
    def __init__(self, *args, logo_name="D3DS3C", **kwargs):
        super().__init__(*args, **kwargs)

        self.logo_name = logo_name
        self.logo_label = customtkinter.CTkLabel(self, text=self.logo_name, text_color="aqua",
                                                 font=customtkinter.CTkFont(size=25, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 20))
        self.button_1 = customtkinter.CTkButton(self, text="Start Scanner", command=self.button_event_1)
        self.button_1.grid(row=1, column=0, padx=20, pady=10)
        self.button_2 = customtkinter.CTkButton(self, text="Stop", fg_color="brown",
                                                command=self.button_event_2)
        self.button_2.grid(row=2, column=0, padx=20, pady=10)
        self.button_3 = customtkinter.CTkButton(self, text="Reset", fg_color="dark red",
                                                command=self.button_event_3)
        self.button_3.grid(row=3, column=0, padx=20, pady=10)
        self.appearance_mode_label = customtkinter.CTkLabel(self, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(40, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self, values=["Light", "Dark", "System"],
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))
        self.scaling_label = customtkinter.CTkLabel(self, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=7, column=0, padx=20, pady=(10, 0))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self, values=["80%", "90%", "100%", "110%", "120%"],
                                                               command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 20))
        # set default values
        self.appearance_mode_optionemenu.set("Dark")
        self.scaling_optionemenu.set("100%")
        self.button_3.configure(state="disabled")

    # change appearance
    @staticmethod
    def change_appearance_mode_event(new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    # change scale
    @staticmethod
    def change_scaling_event(new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    # start app
    @staticmethod
    def button_event_1():
        print("Scanner Started")
        data.create_tables()
        app.target_entry.configure(state="normal")
        app.payload_entry.configure(state="normal")
        app.payload_entry.delete(0, "end")
        app.payload_entry.insert("end", "<sCript>alert('test');</scriPt>")
        app.progressbar.start()
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t<-----------------> Session Started <----------------->\n\n"
                                   f"[+] Enter Target Link in the entry box below\n\n"
                                   f"[+] Select choice of scan at the radio buttons below\n\n"
                                   f"[+] Specify type of payload in the payload entry and press Run.\n\n"
                                   f"[+] Syntax: http://192.168.122.196/mutillidae\n")
        customtkinter.CTkLabel(app, text="Initializing Modules...", text_color="aqua").grid(row=4, column=3,
                                                                                            padx=(5, 5),
                                                                                            pady=(5, 5),
                                                                                            sticky="nsew")

    # stop program
    @staticmethod
    def button_event_2():
        print("Scanner Stopped")
        app.run_scan_button.configure(fg_color="transparent", border_width=1, text="Run", state="enabled",
                                      border_color="green")
        app.target_entry.configure(state="disabled")
        app.payload_entry.configure(state="disabled")
        app.payload_entry.delete(0, "end")
        data.drop_tables()
        app.progressbar.stop()
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t<-----------------> Session Stopped <----------------->\n\n"
                                   f"[+] Terminating all processes...\n\n"
                                   f"[+] Dropping Report Tables...\n\n"
                                   f"[+] RESET COMPLETE >> PRESS START SCANNER TO SCAN AGAIN.")
        customtkinter.CTkLabel(app, text="Stopping Modules...", text_color="aqua").grid(row=4, column=3,
                                                                                        padx=(5, 5), pady=(5, 5),
                                                                                        sticky="nsew")

    # restart program
    @staticmethod
    def button_event_3():
        print("Scanner Restarted")


# tabview widget
class TabView(customtkinter.CTkTabview):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.add("Crawl")
        self.add("XSS")
        self.add("SQLI")
        self.add("Ports")
        self.tab("Crawl").grid_columnconfigure(0, weight=1)
        self.tab("XSS").grid_columnconfigure(0, weight=1)
        self.tab("SQLI").grid_columnconfigure(0, weight=1)
        self.tab("Ports").grid_columnconfigure(0, weight=1)
        self.query_button = customtkinter.CTkButton(self.tab("Crawl"), text="Crawler DB",
                                                    command=Database().get_crawled_links)
        self.query_button.grid(row=3, column=0, padx=20, pady=(10, 10))
        self.query_button = customtkinter.CTkButton(self.tab("XSS"), text="XSS DB",
                                                    command=Database().get_scanned_links)
        self.query_button.grid(row=4, column=0, padx=20, pady=(10, 10))
        self.query_button1 = customtkinter.CTkButton(self.tab("XSS"), text="Forms DB",
                                                     command=Database().get_scanned_forms)
        self.query_button1.grid(row=5, column=0, padx=20, pady=(10, 10))
        self.query_button = customtkinter.CTkButton(self.tab("SQLI"), text="SQLI DB",
                                                    command=Database().get_injected_links)
        self.query_button.grid(row=3, column=0, padx=20, pady=(10, 10))
        self.query_button = customtkinter.CTkButton(self.tab("Ports"), text="Ports DB",
                                                    command=Database().get_open_ports)
        self.query_button.grid(row=3, column=0, padx=20, pady=(10, 10))
        self.label_report = customtkinter.CTkLabel(self.tab("Crawl"), text="Query Crawler Report")
        self.label_report.grid(row=0, column=0, padx=20, pady=20)
        self.label_report = customtkinter.CTkLabel(self.tab("XSS"), text="Query XSS Scanner Report")
        self.label_report.grid(row=0, column=0, padx=20, pady=20)
        self.label_report = customtkinter.CTkLabel(self.tab("SQLI"), text="Query SQLI Scanner Report")
        self.label_report.grid(row=0, column=0, padx=20, pady=20)
        self.label_report = customtkinter.CTkLabel(self.tab("Ports"), text="Query SOpen Ports Report")
        self.label_report.grid(row=0, column=0, padx=20, pady=20)


# Build App
class App(customtkinter.CTk):
    customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
    customtkinter.set_default_color_theme("dark-blue")  # Themes: "blue" (standard), "green", "dark-blue"

    def __init__(self):
        super().__init__()
        # configure app window & grid layout
        self.title("Web-App Vuln-Scanner")
        self.geometry(f"{1100}x{650}")
        # noinspection PyTypeChecker
        self.grid_columnconfigure((2, 2), weight=1)
        # noinspection PyTypeChecker
        self.grid_rowconfigure((0, 1, 2), weight=1)

        self.var = tkinter.StringVar()
        self.var.set("Option 1")

        # sidebar frame with widgets
        self.sidebar_frame = SidebarFrame(master=self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=5, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        # app widgets
        self.text_box = customtkinter.CTkTextbox(self, width=550, height=400, text_color="aqua",
                                                 font=customtkinter.CTkFont(size=15))
        self.text_box.grid(row=0, column=1, columnspan=2, padx=(10, 10), pady=(20, 10), sticky="nsew")
        self.progressbar = customtkinter.CTkProgressBar(self, width=100)
        self.progressbar.grid(row=1, column=1, columnspan=2, padx=(20, 10), pady=(20, 10), sticky="ew")
        self.radio_button_1 = customtkinter.CTkRadioButton(self, text="XSS", variable=self.var, value="Option 1")
        self.radio_button_1.grid(row=2, column=1, padx=(20, 10), pady=(10, 10), sticky="nsew")
        # self.radio_label = customtkinter.CTkLabel(self, text="Select Action", text_color="aqua")
        # self.radio_label.grid(row=2, column=2, padx=(10, 10), pady=(10, 10), sticky="nsew")
        self.radio_button_2 = customtkinter.CTkRadioButton(self, text="SQLI", variable=self.var, value="Option 2")
        self.radio_button_2.grid(row=2, column=2, padx=(10, 10), pady=(10, 10), sticky="nsew")
        self.radio_button_3 = customtkinter.CTkRadioButton(self, text="PORT Scan", variable=self.var, value="Option 3")
        self.radio_button_3.grid(row=2, column=2, padx=(10, 5), pady=(10, 10))
        self.target_entry = customtkinter.CTkEntry(self, placeholder_text="Enter Target Link", text_color="white")
        self.target_entry.grid(row=3, column=1, columnspan=2, padx=(20, 10), pady=(20, 10), sticky="nsew")
        self.main_text_lbl = customtkinter.CTkLabel(self, text="On App Updates: ")
        self.main_text_lbl.grid(row=4, column=2, padx=(5, 5), pady=(5, 5), sticky="nsew")
        self.display_label = customtkinter.CTkLabel(self, text="Indexing...", text_color="aqua")
        self.display_label.grid(row=4, column=3, padx=(5, 5), pady=(5, 5), sticky="nsew")

        # configure grid of individual tabs
        self.tab_area = TabView(master=self, width=250, height=200)
        self.tab_area.grid(row=0, column=3, padx=(10, 10), pady=(10, 10), sticky="nsew")

        # payload and run
        self.payload_label = customtkinter.CTkLabel(self, text="XSS | SQLI | PORT", text_color="aqua")
        self.payload_label.grid(row=1, column=3, padx=(5, 5), pady=(5, 5), sticky="nsew")
        self.payload_entry = customtkinter.CTkEntry(self, placeholder_text="Payload", text_color="orange")
        self.payload_entry.grid(row=2, column=3, columnspan=2, padx=(20, 10), pady=(20, 10), sticky="nsew")
        self.run_scan_button = customtkinter.CTkButton(self, text="Run", command=run_button_event,
                                                       fg_color="transparent", border_width=2,
                                                       text_color=("gray10", "#DCE4EE"))
        self.run_scan_button.grid(row=3, column=3, padx=(20, 10), pady=(20, 10), sticky="nsew")

        # set default values
        self.text_box.insert("end", self.initializer())
        # self.text_box.configure(font=customtkinter.CTkFont(size=14))
        self.target_entry.configure(state="disabled")
        self.payload_entry.configure(state="disabled")
        # self.sidebar_button_2.configure(state="disabled")
        self.progressbar.configure(mode="indeterminate")

    @staticmethod
    def initializer():
        # Screen display string
        header_string = "\t|#|~|#| DEDSECURITY VULNERABILITY SCANNER |#|~|#|\t DvS --version 1.0\n\n"
        return header_string

    # update GUI tasks
    def update_app_tasks(self):
        # progress bar effects
        self.progressbar.configure(mode="determinate")
        self.progressbar.step()
        self.update_idletasks()
        self.progressbar.update()
        self.update()

    # quit button event
    def quit_button_event(self):
        response = messagebox.askyesno("DEDSECUR1TY", "Exit Program...?")
        if response == 1:
            data.drop_tables()
            self.destroy()
            print("Program terminated")
        else:
            pass


"""
Scanner Module
"""


class Scanner:
    def __init__(self, url, ignore_links):
        self.session = requests.session()
        self.target_url = url
        self.links_to_ignore = ignore_links
        self.payload = b""
        self.target_links = []
        self.vulnerable_links = []
        self.open_ports = []

    @staticmethod
    def current_datetime():
        now = datetime.datetime.now()
        formatted = now.strftime("%Y-%m-%d %H:%M:%S")
        return f" >> {formatted}"

    # Information gathering
    def extract_links_from(self, url):
        try:
            try:
                # Filtering and extracting useful data from response
                response = self.session.get(url)
                return re.findall('href="(.*?)"', str(response.content))
            except requests.exceptions.MissingSchema as e:
                print("Error", e.args[0])
                customtkinter.CTkLabel(app, text="Error! Invalid URL.", text_color="aqua").grid(row=4, column=3,
                                                                                                padx=(5, 5),
                                                                                                pady=(5, 5),
                                                                                                sticky="nsew")
                pass
        except requests.exceptions.ConnectionError as e:
            print("Error", e.args[0])
            customtkinter.CTkLabel(app, text="Connection Error!", text_color="aqua").grid(row=4, column=3,
                                                                                          padx=(5, 5),
                                                                                          pady=(5, 5),
                                                                                          sticky="nsew")
            pass

    # Map target | Discover paths, subdomains and directories
    def crawl(self, url=None):
        # GUI
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t*** <--------------> Crawling <--------------> ***\n\n"
                                   f"[+] Discovering Paths...\n\n"
                                   f"[+] Discovering Domains...\n\n"
                                   f"[+] Discovering Directories...\n\n"
                                   f"[+] Discovering Hidden Paths...\n\n")
        app.run_scan_button.configure(fg_color="green", border_width=1, text="Running", state="disabled")

        # check & set url
        if url is None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        # Set relative url to full url
        for link in href_links:
            link = urljoin(url, link)
            # Extracting unique links and storing them in a list
            if "#" in link:
                link = link.split("#")[0]
            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)

                # display on app progress & GUI
                text = "Links Found >> " + str(len(self.target_links))
                customtkinter.CTkLabel(app, text=text, text_color="aqua").grid(row=4, column=3, padx=(5, 5),
                                                                               pady=(5, 5), sticky="nsew")

                # dump links on entry box and  call method to insert data into DB
                app.target_entry.delete(0, "end")
                app.target_entry.insert("end", link)
                data.insert_into_crawled()
                app.update_app_tasks()
                app.target_entry.delete(0, "end")

                # Handling RecursionError
                try:
                    self.crawl(link)
                except RecursionError as e:
                    print("[-] Recursion Exceeded", e.args[0])
                    pass

    # Extracting forms
    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, features="lxml")
        return parsed_html.findAll("form")

    # Submitting forms
    def submit_form(self, form, value, url):
        # Extract HTML attributes
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method")
        input_list = form.findAll("input")
        post_data = {}
        # post forms
        for input in input_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value
        # Checking method type and returning parsed results
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    # Implementing method to run xss scanner
    def run_xss_scanner(self):
        # GUI Updates
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t*** <--------------> XSS Testing & Analysis <--------------> ***\n\n")
        customtkinter.CTkLabel(app, text="Scanning XSS...", text_color="aqua").grid(row=4, column=3, padx=(5, 5),
                                                                                    pady=(5, 5), sticky="nsew")
        # extract forms and submit payload
        for link in self.target_links:
            forms = self.extract_forms(link)
            # Testing POST request
            for form in forms:
                app.text_box.insert("end", "[+] Testing form in " + link + "\n")
                # call method to discover xss in forms and check if is vulnerable
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    self.vulnerable_links.append(link)
                    app.target_entry.insert("end", "[DETECTED XSS] <form> " + link)
                    data.insert_into_scanned()
                    app.target_entry.delete(0, "end")
                    app.target_entry.insert("end", str(form))
                    data.insert_into_forms()

            # progress bar effects
            app.update_app_tasks()
            app.target_entry.delete(0, "end")

            # Testing GET requests
            if "=" in link:
                app.text_box.insert("end", "[+] Testing " + link + "\n")
                # call method to discover xss in LINKS and check if vulnerable
                is_vulnerable_to_xss = self.test_xss_in_link(link)
                if is_vulnerable_to_xss:
                    self.vulnerable_links.append(link)
                    app.target_entry.insert("end", "[DETECTED XSS] <link> " + link)
                    data.insert_into_scanned()

            # progress bar effects
            app.update_app_tasks()
            app.target_entry.delete(0, "end")

        app.progressbar.configure(mode="indeterminate")
        app.progressbar.start()
        app.run_scan_button.configure(fg_color="transparent", border_width=1, text="Run", state="enabled")
        messagebox.showinfo("Complete", "Scanning Done")
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()} "
                                   f"\t<-----------------> Session Complete <----------------->\n\n"
                                   f"[+] Scan Done On: {self.current_datetime()} \n\n"
                                   f"[+] Target Scanned & Tested: {str(self.target_url)} \n\n"
                                   f"[+] Found Links: {str(len(self.target_links))} \n\n"
                                   f"[+] XSS Detected Links: {str(len(self.vulnerable_links))} \n\n"
                                   f"[+] Query DATABASE on the TabView for More Info\n\n")

    # Implementing method to run sqli scanner
    def run_sqli_scanner(self):
        # GUI updates
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()} "
                                   f"\t*** <--------------> SQLI Testing & Analysis <--------------> ***\n\n")
        customtkinter.CTkLabel(app, text="Scanning SQLI...", text_color="aqua").grid(row=4, column=3, padx=(5, 5),
                                                                                     pady=(5, 5), sticky="nsew")
        # extract forms and submit code
        for link in self.target_links:
            forms = self.extract_forms(link)
            # Testing POST request
            for form in forms:
                app.text_box.insert("end", "[+] Testing form in " + link + "\n")
                # call method to discover sqli in forms and check if is vulnerable
                is_vulnerable_to_sqli = self.test_sqli_in_form(form, link)
                if is_vulnerable_to_sqli:
                    self.vulnerable_links.append(link)
                    app.target_entry.insert("end", "[SQLI DETECTED] <form> " + link)
                    data.insert_into_injected()
                    data.insert_into_forms()

            # progress bar effects
            app.update_app_tasks()
            app.target_entry.delete(0, "end")

            # Testing GET requests
            if "=" in link:
                app.text_box.insert("end", "[+] Testing " + link + "\n")
                # call method to discover sqli in links and check if vulnerable
                is_vulnerable_to_sqli = self.test_sqli_in_link(link)
                if is_vulnerable_to_sqli:
                    self.vulnerable_links.append(link)
                    app.target_entry.insert("end", "[SQLI DETECTED] <link> " + link)
                    data.insert_into_injected()

            # progress bar effects
            app.update_app_tasks()
            app.target_entry.delete(0, "end")
        app.progressbar.configure(mode="indeterminate")
        app.progressbar.start()
        app.run_scan_button.configure(fg_color="transparent", border_width=1, text="Run", state="enabled")
        messagebox.showinfo("Complete", "Scanning Done")
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()} "
                                   f"\t<-----------------> Session Complete <----------------->\n\n"
                                   f"[+] Scan Done On: {self.current_datetime()} \n\n"
                                   f"[+] Target Scanned & Tested: {str(self.target_url)} \n\n"
                                   f"[+] Found Links:  {str(len(self.target_links))} \n\n"
                                   f"[+] SQLI Detected Links: {str(len(self.vulnerable_links))} \n\n"
                                   f"[+] Query DATABASE on the TabView for More Info\n\n")

    # Implementing method to run port scanner
    def run_port_scanner(self):
        # scan all ports in selected range
        port_range = app.payload_entry.get()
        for port in range(int(port_range)):
            thread = threading.Thread(target=self.test_open_ports, args=[port])
            thread.start()

            # GUI updates
            app.text_box.delete("0.0", "end")
            app.text_box.insert("end", f"{app.initializer()} "
                                       f"\t*** <--------------> PORT Scanning & Analysis <--------------> ***\n\n")
            app.text_box.insert("end", f"Scanned Ports: {port}")
            customtkinter.CTkLabel(app, text="Scanning PORTS...", text_color="aqua").grid(row=4, column=3,
                                                                                          padx=(5, 5),
                                                                                          pady=(5, 5),
                                                                                          sticky="nsew")

            # call method to discover open ports on target
            is_port_open = self.test_open_ports(port)
            if is_port_open:
                self.open_ports.append(port)
                app.target_entry.insert("end", f"[Open Ports] {port}")
                data.insert_into_ports()

            # progress bar effects
            app.update_app_tasks()
            app.target_entry.delete(0, "end")
        app.progressbar.configure(mode="indeterminate")
        app.progressbar.start()
        app.run_scan_button.configure(fg_color="transparent", border_width=1, text="Run", state="enabled")
        messagebox.showinfo("Complete", "Port Scanning Done")
        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()} "
                                   f"\t<-----------------> Session Complete <----------------->\n\n"
                                   f"[+] Port Scanning Done On : {self.current_datetime()} \n\n"
                                   f"[+] Target Scanned : {str(self.target_url)} \n\n"
                                   f"[+] Open Ports Found :  {str(len(self.open_ports))} \n\n"
                                   f"[+] Query DATABASE on the TabView for More Info\n\n")

    # Method to discover XSS in links/parameters
    def test_xss_in_link(self, url):
        self.payload = app.payload_entry.get()
        url = url.replace("=", "=" + str(self.payload))
        response = self.session.get(url)
        if bytes(self.payload, 'utf-8', errors='strict') in response.content:
            return True

    # Method to discover XSS in forms (Reflected XSS)
    def test_xss_in_form(self, form, url):
        self.payload = app.payload_entry.get()
        response = self.submit_form(form, self.payload, url)
        if bytes(self.payload, 'utf-8', errors='strict') in response.content:
            return True

    # Method to discover SQLI in forms
    def test_sqli_in_form(self, form, url):
        self.payload = app.payload_entry.get()  # UNION SELECT user, password FROM users# "1 or 1=1"
        response = self.submit_form(form, str(self.payload), url)
        if bytes(self.payload, 'utf-8', errors='strict') in response.content:
            return True

    # Method to discover SQLI in links
    def test_sqli_in_link(self, url):
        self.payload = app.payload_entry.get()
        url = url.replace("=", "=" + str(self.payload))
        response = self.session.get(url)
        if bytes(self.payload, "utf-8", errors="strict") in response.content:
            return True

    # Method to discover Open Ports target
    def test_open_ports(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_url, port))
            return port
        except ConnectionRefusedError:
            pass


"""
Sqlite3 Database Module
"""


class Database:
    def __init__(self):
        # Doc strings to execute sqlite3 code | (designate columns & data types (5))
        self.query_1 = """CREATE TABLE IF NOT EXISTS crawled (link_address text)"""
        self.query_2 = """CREATE TABLE IF NOT EXISTS scanned (weak_link text)"""
        self.query_3 = """CREATE TABLE IF NOT EXISTS injected (weak_sqlink text)"""
        self.query_13 = """CREATE TABLE IF NOT EXISTS forms (weak_form text)"""
        self.query_17 = """CREATE TABLE IF NOT EXISTS ports (open_port text)"""
        self.query_4 = "DROP TABLE IF EXISTS crawled"
        self.query_5 = "DROP TABLE IF EXISTS scanned"
        self.query_6 = "DROP TABLE IF EXISTS injected"
        self.query_14 = "DROP TABLE IF EXISTS forms"
        self.query_18 = "DROP TABLE IF EXISTS ports"
        self.query_7 = "SELECT DISTINCT (link_address) FROM crawled"
        self.query_8 = "SELECT DISTINCT (weak_link) FROM scanned"
        self.query_9 = "SELECT DISTINCT (weak_sqlink) FROM injected"
        self.query_19 = "SELECT DISTINCT (open_port) FROM ports"
        self.query_15 = "SELECT DISTINCT (weak_form) FROM forms"
        self.query_10 = "INSERT INTO crawled VALUES (:link_address)"
        self.query_11 = "INSERT INTO scanned VALUES (:weak_link)"
        self.query_12 = "INSERT INTO injected VALUES (:weak_sqlink)"
        self.query_16 = "INSERT INTO forms VALUES (:weak_form)"
        self.query_20 = "INSERT INTO ports VALUES (:open_port)"
        self.print_records = ""

    # Create Tables
    def create_tables(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        cur.execute(self.query_1)
        cur.execute(self.query_2)
        cur.execute(self.query_3)
        cur.execute(self.query_13)
        cur.execute(self.query_17)
        print("DB Tables Created...")
        con.commit()
        con.close()

    # Insert Crawler Data Into Tables
    def insert_into_crawled(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute(self.query_10,
                        # python dict. key = dv | value = entry box
                        {
                            "link_address": app.target_entry.get()
                        }
                        )
        except sqlite3.Error as e:
            print("Error", e.args[0])

        con.commit()
        con.close()

    # Insert Scanner Data Into Tables
    def insert_into_scanned(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute(self.query_11,
                        # python dict. key = dv | value = entry box
                        {
                            "weak_link": app.target_entry.get()
                        }
                        )
        except sqlite3.Error as e:
            print("Error", e.args[0])

        con.commit()
        con.close()

    def insert_into_forms(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute(self.query_16,
                        # python dict. key = dv | value = entry box
                        {
                            "weak_form": app.target_entry.get()
                        }
                        )
        except sqlite3.Error as e:
            print("Error", e.args[0])

        con.commit()
        con.close()

    def insert_into_injected(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute(self.query_12,
                        # python dict. key = dv | value = entry box
                        {
                            "weak_sqlink": app.target_entry.get()
                        }
                        )
        except sqlite3.Error as e:
            print("Error", e.args[0])

        con.commit()
        con.close()

    def insert_into_ports(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute(self.query_20,
                        # python dict. key = dv | value = entry box
                        {
                            "open_port": app.target_entry.get()
                        }
                        )
        except sqlite3.Error as e:
            print("Error", e.args[0])

        con.commit()
        con.close()

    def drop_tables(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute(self.query_4)
            cur.execute(self.query_5)
            cur.execute(self.query_6)
            cur.execute(self.query_14)
            cur.execute(self.query_18)
        except sqlite3.OperationalError as e:
            print("Error", e.args[0])
            pass

        print("Tables Dropped...")
        con.commit()
        con.close()

    def get_crawled_links(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()
        try:
            cur.execute(self.query_7)
            links = cur.fetchall()

            for link in links:
                self.print_records += ">> " + str(
                    link[0]) + "\n"  # create variable & its plusequal out link & concatenate linebreak
        except sqlite3.OperationalError as e:
            print("Crawled Error", e.args[0])

        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t*** <--------------> Displaying Mapped Links <--------------> ***\n\n")
        app.text_box.insert("end", self.print_records)

        print("Printing Crawled links...")
        con.commit()
        con.close()

    def get_scanned_links(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()

        try:
            cur.execute(self.query_8)
            links = cur.fetchall()

            for link in links:
                self.print_records += ">> " + str(
                    link[0]) + "\n"  # create variable & its plusequal out link & concatenate linebreak
        except sqlite3.OperationalError as e:
            print("Scanned Error", e.args[0])

        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t*** <--------------> Displaying XSS Vulnerable Links <--------------> ***\n\n")
        app.text_box.insert("end", self.print_records)

        print("Printing scanned links...")
        con.commit()
        con.close()

    def get_scanned_forms(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()

        try:
            cur.execute(self.query_15)
            forms = cur.fetchall()

            for form in forms:
                self.print_records += "[***] " + str(
                    form[0]) + "\n\n"  # create variable & its plusequal out link & concatenate linebreak
        except sqlite3.OperationalError as e:
            print("Scanned Error", e.args[0])

        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t*** <--------------> Displaying XSS Vulnerable Forms <--------------> ***\n\n")
        app.text_box.insert("end", self.print_records)

        print("Printing scanned forms...")
        con.commit()
        con.close()

    def get_injected_links(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()

        try:
            cur.execute(self.query_9)
            links = cur.fetchall()

            for link in links:
                self.print_records += ">> " + str(
                    link[0]) + "\n"  # create variable & its plusequal out link & concatenate linebreak
        except sqlite3.OperationalError as e:
            print("Injected Error", e.args[0])

        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t*** <--------------> Displaying SQL Injected Links <--------------> ***\n\n")
        app.text_box.insert("end", self.print_records)

        print("Printing injected links...")
        con.commit()
        con.close()

    def get_open_ports(self):
        con = sqlite3.connect("scanned.db")
        cur = con.cursor()

        try:
            cur.execute(self.query_19)
            ports = cur.fetchall()

            for port in ports:
                self.print_records += ">> " + str(
                    port[0]) + "\n"  # create variable & its plusequal out link & concatenate linebreak
        except sqlite3.OperationalError as e:
            print("Injected Error", e.args[0])

        app.text_box.delete("0.0", "end")
        app.text_box.insert("end", f"{app.initializer()}"
                                   f"\t*** <--------------> Displaying Open Ports <--------------> ***\n\n")
        app.text_box.insert("end", self.print_records)

        print("Printing Open Ports...")
        con.commit()
        con.close()


if __name__ == "__main__":
    # method to run program
    def run_button_event():
        radio_option = app.var.get()
        target = app.target_entry.get()
        links_to_ignore = ["http://192.168.122.196/dvwa/logout.php"]
        data_dict = {"username": "admin", "password": "password", "Login": "submit"}
        post_url = "http://192.168.122.196/dvwa/login.php"
        run_scan = Scanner(target, links_to_ignore)
        threading.Thread(target=Scanner, args=[target, links_to_ignore]).start()

        # check selected option
        if radio_option == "Option 1":
            start_time = time.time()
            run_scan.session.post(post_url, data=data_dict)
            run_scan.crawl()
            run_scan.run_xss_scanner()
            stop_time = time.time()
            label = customtkinter.CTkLabel(app, text=f"\nTime Elapsed: {stop_time - start_time:.2f} seconds.\n",
                                           text_color="aqua")
            label.grid(row=4, column=3, padx=(10, 10), pady=(10, 10), sticky="nsew")

        elif radio_option == "Option 2":
            start_time = time.time()
            run_scan.session.post(post_url, data=data_dict)
            run_scan.crawl()
            run_scan.run_sqli_scanner()
            stop_time = time.time()
            label = customtkinter.CTkLabel(app, text=f"\nTime Elapsed: {stop_time - start_time:.2f} seconds.\n",
                                           text_color="aqua")
            label.grid(row=4, column=3, padx=(10, 10), pady=(10, 10), sticky="nsew")

        elif radio_option == "Option 3":
            start_time = time.time()
            run_scan.session.post(post_url, data=data_dict)
            run_scan.run_port_scanner()
            stop_time = time.time()
            label = customtkinter.CTkLabel(app, text=f"\nTime Elapsed: {stop_time - start_time:.2f} seconds.\n",
                                           text_color="aqua")
            label.grid(row=4, column=3, padx=(10, 10), pady=(10, 10), sticky="nsew")


    # instance of gui
    app = App()

    # instance of database
    data = Database()

    # Add the on_closing function to the protocol method (x)
    app.protocol("WM_DELETE_WINDOW", app.quit_button_event)

    app.mainloop()
