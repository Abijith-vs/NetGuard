import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import psutil
import time
import csv
import threading
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
from collections import deque
import random

# --- CONFIGURATION ---
COLOR_BG = "#0d1117"        # Dark GitHub/Cyberpunk BG
COLOR_PANEL = "#161b22"     # Slightly lighter panel
COLOR_ACCENT = "#00f0ff"    # Cyberpunk Cyan
COLOR_DANGER = "#ff003c"    # Cyberpunk Red
COLOR_TEXT = "#c9d1d9"      # Soft White
COLOR_GRID = "#30363d"      # Subtle Grid

class NetGuardDashboard(ctk.CTk):
    def __init__(self, start_callback, stop_callback, log_queue):
        super().__init__()

        self.start_callback = start_callback
        self.stop_callback = stop_callback
        self.log_queue = log_queue
        self.is_running = False
        self.traffic_log = [] 
        
        # --- DATA STREAMS ---
        self.max_data_points = 60
        # Graph 1: Traffic Rate
        self.traffic_history = deque([0]*self.max_data_points, maxlen=self.max_data_points)
        # Graph 2: Threat Score (Simulated for visualization)
        self.threat_history = deque([0]*self.max_data_points, maxlen=self.max_data_points)
        
        # State
        self.last_anomaly_time = 0
        self.packet_count = 0
        self.start_time = 0

        # --- WINDOW SETUP ---
        self.title("NETGUARD // SYSTEM MONITOR")
        self.geometry("1400x900")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Configure Main Layout (Grid)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1) # Main content area grows

        # 1. SIDEBAR (Navigation & Controls)
        self.create_sidebar()

        # 2. HEADER (HUD Stats)
        self.create_header()

        # 3. MAIN CONTENT (Graphs & Logs)
        self.create_main_view()
        
        # Update Loop
        self.update_ui_loop()

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color=COLOR_PANEL)
        self.sidebar.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        # Logo
        lbl_logo = ctk.CTkLabel(self.sidebar, text="NETGUARD", font=("Orbitron", 24, "bold"), text_color=COLOR_ACCENT)
        lbl_logo.grid(row=0, column=0, padx=20, pady=(30, 10))
        lbl_ver = ctk.CTkLabel(self.sidebar, text="v2.0.4 PRO", font=("Roboto", 10), text_color="gray")
        lbl_ver.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Controls
        self.btn_start = ctk.CTkButton(self.sidebar, text="INITIATE SEQ", command=self.on_start, 
                                       fg_color=COLOR_ACCENT, text_color="black", hover_color="#00bdd6",
                                       font=("Roboto", 12, "bold"))
        self.btn_start.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_stop = ctk.CTkButton(self.sidebar, text="TERMINATE", command=self.on_stop,
                                      fg_color="transparent", border_width=1, border_color=COLOR_DANGER, text_color=COLOR_DANGER,
                                      state="disabled", hover_color=COLOR_PANEL)
        self.btn_stop.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        # Simulation Controls
        lbl_sim = ctk.CTkLabel(self.sidebar, text="SIMULATION / TEST", text_color="gray", font=("Roboto", 10, "bold"))
        lbl_sim.grid(row=4, column=0, padx=20, pady=(30, 5), sticky="w")
        
        self.btn_sim_ddos = ctk.CTkButton(self.sidebar, text="SIM: FLOOD ATTACK", command=lambda: self.simulate_attack("flood"),
                                          fg_color=COLOR_PANEL, border_width=1, border_color="orange", text_color="orange", hover_color="#332200")
        self.btn_sim_ddos.grid(row=5, column=0, padx=20, pady=5, sticky="ew")
        
        self.btn_export = ctk.CTkButton(self.sidebar, text="EXPORT LOGS", command=self.generate_report, fg_color="#333")
        self.btn_export.grid(row=6, column=0, padx=20, pady=20, sticky="ew")

    def create_header(self):
        self.header = ctk.CTkFrame(self, height=100, corner_radius=0, fg_color=COLOR_BG)
        self.header.grid(row=0, column=1, sticky="ew", padx=20, pady=10)
        
        # HUD Cards
        self.card_cpu = self.create_hud_card(self.header, "CPU LOAD", "0%", COLOR_ACCENT, 0)
        self.card_mem = self.create_hud_card(self.header, "MEMORY", "0%", COLOR_ACCENT, 1)
        self.card_net = self.create_hud_card(self.header, "NET FLOW", "0 pkts/s", "white", 2)
        self.card_threat = self.create_hud_card(self.header, "THREAT LEVEL", "SAFE", "#00ff00", 3)

    def create_hud_card(self, parent, title, value, color, col_idx):
        frame = ctk.CTkFrame(parent, fg_color=COLOR_PANEL, corner_radius=6, border_width=1, border_color="#333")
        frame.pack(side="left", expand=True, fill="both", padx=5, pady=5)
        
        lbl_title = ctk.CTkLabel(frame, text=title, font=("Roboto", 10), text_color="gray")
        lbl_title.pack(anchor="w", padx=10, pady=(5, 0))
        
        lbl_val = ctk.CTkLabel(frame, text=value, font=("Orbitron", 20, "bold"), text_color=color)
        lbl_val.pack(anchor="w", padx=10, pady=(0, 5))
        
        frame.lbl_val = lbl_val # Store ref
        return frame

    def create_main_view(self):
        # 3.1 GRAPHS (Top Half)
        self.graph_container = ctk.CTkFrame(self, fg_color="transparent")
        self.graph_container.grid(row=1, column=1, sticky="nsew", padx=20, pady=5)
        self.grid_rowconfigure(1, weight=0) # Graphs don't expand infinitely

        self.fig = Figure(figsize=(12, 3), dpi=90, facecolor=COLOR_BG)
        
        # Traffic Plot (Left)
        self.ax1 = self.fig.add_subplot(121)
        self.ax1.set_facecolor(COLOR_BG)
        self.ax1.set_title("LIVE TRAFFIC VOLUME", color="white", fontsize=8)
        self.line1, = self.ax1.plot([], [], color=COLOR_ACCENT, linewidth=1.5)
        self.ax1.grid(True, color=COLOR_GRID, linestyle='--')
        self.ax1.tick_params(colors='gray', labelsize=8)
        
        # Threat Plot (Right)
        self.ax2 = self.fig.add_subplot(122)
        self.ax2.set_facecolor(COLOR_BG)
        self.ax2.set_title("ANOMALY CONFIDENCE", color=COLOR_DANGER, fontsize=8)
        self.line2, = self.ax2.plot([], [], color=COLOR_DANGER, linewidth=1.5)
        self.ax2.set_ylim(0, 1) # Probability 0-1
        self.ax2.grid(True, color=COLOR_GRID, linestyle='--')
        self.ax2.tick_params(colors='gray', labelsize=8)

        # Canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_container)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # 3.2 LOGS (Bottom Half - Split)
        self.logs_container = ctk.CTkFrame(self, fg_color="transparent")
        self.logs_container.grid(row=2, column=1, sticky="nsew", padx=20, pady=10)
        self.logs_container.grid_columnconfigure(0, weight=3) # Traffic Log
        self.logs_container.grid_columnconfigure(1, weight=2) # Alert Log

        # -- Traffic Log (Treeview) --
        self.frame_log = ctk.CTkFrame(self.logs_container, fg_color=COLOR_PANEL, corner_radius=6)
        self.frame_log.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        
        ctk.CTkLabel(self.frame_log, text=" // PACKET STREAM", font=("Roboto", 10, "bold"), text_color="gray").pack(anchor="w", padx=10, pady=5)
        
        # Style for Treeview
        style = tk.ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                        background="#0f0f0f", 
                        foreground=COLOR_TEXT, 
                        fieldbackground="#0f0f0f",
                        borderwidth=0,
                        rowheight=25)
        style.configure("Treeview.Heading", 
                        background=COLOR_PANEL, 
                        foreground=COLOR_ACCENT, 
                        relief="flat",
                        font=("Roboto", 9, "bold"))
        style.map("Treeview", background=[('selected', COLOR_GRID)])

        columns = ("time", "proto", "src", "dst", "len")
        self.tree = tk.ttk.Treeview(self.frame_log, columns=columns, show="headings", style="Treeview")
        
        self.tree.heading("time", text="TIME")
        self.tree.heading("proto", text="PROTO")
        self.tree.heading("src", text="SOURCE")
        self.tree.heading("dst", text="DESTINATION")
        self.tree.heading("len", text="LEN")
        
        self.tree.column("time", width=80, anchor="center")
        self.tree.column("proto", width=60, anchor="center")
        self.tree.column("src", width=120, anchor="w")
        self.tree.column("dst", width=120, anchor="w")
        self.tree.column("len", width=60, anchor="center")
        
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)


        # -- Alert Log --
        self.frame_alerts = ctk.CTkFrame(self.logs_container, fg_color=COLOR_PANEL, corner_radius=6, border_width=1, border_color="#550000")
        self.frame_alerts.grid(row=0, column=1, sticky="nsew")
        
        ctk.CTkLabel(self.frame_alerts, text=" // INTRUSION ALERTS", font=("Roboto", 10, "bold"), text_color=COLOR_DANGER).pack(anchor="w", padx=10, pady=5)
        
        self.txt_alerts = ctk.CTkTextbox(self.frame_alerts, font=("Consolas", 11, "bold"), text_color=COLOR_DANGER, fg_color="#1a0505")
        self.txt_alerts.pack(fill="both", expand=True, padx=5, pady=5)


    # --- LOGIC ---
    def simulate_attack(self, type):
        if not self.is_running:
            messagebox.showwarning("ERR", "System must be INITIALIZED before simulation.")
            return

        # Inject fake alert into queue for visualization
        self.log_interface(f"--- SIMULATING {type.upper()} ---")
        
        if type == "flood":
             # Fake a rule alert
             fake_data = {
                 'timestamp': time.time(),
                 'protocol': 6,
                 'src_ip': '192.168.66.6',
                 'dst_ip': '192.168.1.5',
                 'src_port': 4444,
                 'dst_port': 80,
                 'ml_features': [],
                 'rule_alert': '[!] FLOOD DETECTED: 192.168.66.6 is sending 120 pkts/sec'
             }
             self.log_queue.put(fake_data)

    def on_start(self):
        self.is_running = True
        self.btn_start.configure(state="disabled", text="RUNNING...")
        self.btn_stop.configure(state="normal")
        self.start_time = time.time()
        self.packet_count = 0
        self.start_callback()
        self.log_interface(">>> SYSTEM INITIALIZED. LISTENING ON INTERFACE...")

    def on_stop(self):
        self.is_running = False
        self.btn_start.configure(state="normal", text="INITIATE SEQ")
        self.btn_stop.configure(state="disabled")
        self.stop_callback()
        self.log_interface(">>> PROCESS TERMINATED.")

    def log_interface(self, msg, is_alert=False, data=None):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if is_alert:
            formatted = f"[{timestamp}] {msg}\n"
            self.txt_alerts.insert("0.0", formatted)
        elif data:
            # Insert into Treeview
            self.tree.insert("", 0, values=(
                timestamp, 
                data.get('protocol', '?'), 
                data.get('src_ip', '?'), 
                data.get('dst_ip', '?'), 
                data.get('len', '?')
            ))
            # Keep tree manageable
            if len(self.tree.get_children()) > 100:
                self.tree.delete(self.tree.get_children()[-1])


    def update_hud_val(self, card_frame, value, color=None):
        card_frame.lbl_val.configure(text=value)
        if color:
             card_frame.lbl_val.configure(text_color=color)

    def update_ui_loop(self):
        """
        Main Loop: Updates HUD, Graphs, and handles both ML and Rule alerts.
        """
        if self.is_running:
            current_time = time.time()
            
            # 1. Update Resource Stats
            cpu_p = psutil.cpu_percent()
            mem_p = psutil.virtual_memory().percent
            self.update_hud_val(self.card_cpu, f"{cpu_p}%")
            self.update_hud_val(self.card_mem, f"{mem_p}%")
            
            # 2. Process Packet Queue
            packets_this_tick = 0
            max_threat = 0.0
            
            while not self.log_queue.empty():
                try:
                    data = self.log_queue.get_nowait()
                    packets_this_tick += 1
                    self.packet_count += 1
                    self.traffic_log.append(data)
                    
                    # Parsing
                    data['len'] = random.randint(40, 1500) # Mock length if missing
                    self.log_interface("", is_alert=False, data=data)
                    
                    # --- DETECTION LOGIC START ---
                    
                    # A. Check ML Result (The new string-based prediction)
                    ml_status = data.get('anomaly', 'Normal') 
                    
                    # B. Check Rule Alert
                    rule_msg = data.get('rule_alert')
                    
                    is_attack = False
                    alert_msgs = []

                    # 1. Handle ML Alerts (e.g. "DoS", "Probe")
                    # We check if it is NOT "Normal" and NOT just the number 1 (legacy support)
                    if ml_status != "Normal" and ml_status != 1: 
                        is_attack = True
                        alert_msgs.append(f"[ML] {ml_status} DETECTED: {data.get('src_ip')}")

                    # 2. Handle Rule Alerts
                    if rule_msg:
                        is_attack = True
                        alert_msgs.append(f"[RULE] {rule_msg}")

                    if is_attack:
                        self.last_anomaly_time = current_time
                        max_threat = 1.0
                        for msg in alert_msgs:
                             self.log_interface(f"⚠️ {msg}", is_alert=True)
                    
                    # --- DETECTION LOGIC END ---
                    
                except Exception:
                    break

            # 3. Update Traffic Stats
            elapsed = current_time - self.start_time
            if elapsed > 0:
                rate = self.packet_count / elapsed
                self.update_hud_val(self.card_net, f"{rate:.1f}/s")
            
            # 4. Updates Charts
            self.traffic_history.append(packets_this_tick)
            self.threat_history.append(max_threat if max_threat > 0 else (self.threat_history[-1]*0.9)) # Decay
            
            # Redraw Graphs
            self.line1.set_data(range(len(self.traffic_history)), self.traffic_history)
            self.line2.set_data(range(len(self.threat_history)), self.threat_history)
            
            # Rescale
            max_y = max(self.traffic_history) if self.traffic_history else 10
            self.ax1.set_ylim(0, max(10, max_y * 1.2))
            self.ax1.set_xlim(0, self.max_data_points)
            self.ax2.set_xlim(0, self.max_data_points)
            
            self.canvas.draw()
            
            # 5. Update Threat Level
            if current_time - self.last_anomaly_time < 5.0:
                 self.update_hud_val(self.card_threat, "CRITICAL", COLOR_DANGER)
            else:
                 self.update_hud_val(self.card_threat, "SECURE", "#00ff00")

        self.after(500, self.update_ui_loop) # Twice per second updates for smoother feel

    def generate_report(self):
        if not self.traffic_log:
            messagebox.showinfo("Info", "No data available.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".csv")
        if filename:
            pd.DataFrame(self.traffic_log).to_csv(filename, index=False)