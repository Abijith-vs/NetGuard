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

class NetGuardDashboard(ctk.CTk):
    def __init__(self, start_callback, stop_callback, log_queue):
        super().__init__()

        self.start_callback = start_callback
        self.stop_callback = stop_callback
        self.log_queue = log_queue
        self.is_running = False
        self.traffic_log = [] # List to store logs for export
        
        # Graph Data
        self.max_data_points = 60
        self.traffic_history = deque([0]*self.max_data_points, maxlen=self.max_data_points)
        self.time_history = deque(range(self.max_data_points), maxlen=self.max_data_points)

        # Threat Level State
        self.last_anomaly_time = 0
        self.threat_cooldown = 5.0 # Seconds to keep Critical status

        self.title("NetGuard - Intrusion Detection System")
        self.geometry("1100x800")

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # Layout configuration
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_main_view()
        
        # Stats initialization
        self.packet_count = 0
        self.start_time = 0
        
        self.update_ui_loop()

    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="NetGuard", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.sidebar_button_1 = ctk.CTkButton(self.sidebar_frame, text="Dashboard")
        self.sidebar_button_1.grid(row=1, column=0, padx=20, pady=10)
        
        self.sidebar_button_2 = ctk.CTkButton(self.sidebar_frame, text="Live Log")
        self.sidebar_button_2.grid(row=2, column=0, padx=20, pady=10)
        
        self.sidebar_button_3 = ctk.CTkButton(self.sidebar_frame, text="Settings")
        self.sidebar_button_3.grid(row=3, column=0, padx=20, pady=10)

    def create_main_view(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Top Cards
        self.cards_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.cards_frame.pack(fill="x", pady=(0, 20))
        
        self.card_traffic = self.create_card(self.cards_frame, "Traffic Rate", "0 pkts/s", "gray")
        self.card_threat = self.create_card(self.cards_frame, "Threat Level", "Pending", "gray")
        self.card_sys = self.create_card(self.cards_frame, "System Health", "CPU: 0%", "gray")
        
        self.card_traffic.pack(side="left", expand=True, fill="both", padx=5)
        self.card_threat.pack(side="left", expand=True, fill="both", padx=5)
        self.card_sys.pack(side="left", expand=True, fill="both", padx=5)

        # Graph Area
        self.graph_frame = ctk.CTkFrame(self.main_frame, fg_color="#2b2b2b", corner_radius=10) # Dark bg for graph container
        self.graph_frame.pack(fill="x", pady=10, padx=5)
        
        # Matplotlib Graph
        self.fig = Figure(figsize=(10, 3), dpi=100)
        self.fig.patch.set_facecolor('#2b2b2b') # Figure bg
        
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#2b2b2b') # Axis bg
        
        # Plot initial empty line
        self.line, = self.ax.plot([], [], color='#00ced1', linewidth=2) # Dark Turquoise/Cyan
        
        # Styling graph
        self.ax.set_ylim(0, 100)
        self.ax.set_xlim(0, self.max_data_points)
        self.ax.set_title("Network Traffic (Packets/sec)", color='white', pad=10)
        
        # Grid settings
        self.ax.grid(True, color='#444444', linestyle='--', alpha=0.5)
        
        # Tick parameters
        self.ax.tick_params(axis='x', colors='white')
        self.ax.tick_params(axis='y', colors='white')
        
        # Spines
        for spine in self.ax.spines.values():
            spine.set_edgecolor('#555555')

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)


        # Center Log Area
        self.log_label = ctk.CTkLabel(self.main_frame, text="Live Traffic Log", font=ctk.CTkFont(size=14, weight="bold"))
        self.log_label.pack(anchor="w", pady=(10,0))
        
        self.log_textbox = ctk.CTkTextbox(self.main_frame, width=800, height=200)
        self.log_textbox.pack(fill="both", expand=True, pady=10)
        
        # Bottom Controls
        self.controls_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.controls_frame.pack(fill="x", pady=10)
        
        self.start_btn = ctk.CTkButton(self.controls_frame, text="Start Sniffer", command=self.on_start, fg_color="green")
        self.start_btn.pack(side="left", padx=10)
        
        self.stop_btn = ctk.CTkButton(self.controls_frame, text="Stop Sniffer", command=self.on_stop, fg_color="red", state="disabled")
        self.stop_btn.pack(side="left", padx=10)
        
        self.export_btn = ctk.CTkButton(self.controls_frame, text="Generate Report", command=self.generate_report)
        self.export_btn.pack(side="right", padx=10)

    def create_card(self, parent, title, value, color):
        card = ctk.CTkFrame(parent, corner_radius=10)
        
        label_title = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12))
        label_title.pack(pady=(10, 0))
        
        label_value = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=24, weight="bold"), text_color=color)
        label_value.pack(pady=(5, 10))
        
        # Hack to store reference to value label to update it later
        card.value_label = label_value
        return card

    def update_card(self, card, value, color=None):
        card.value_label.configure(text=value)
        if color:
            card.value_label.configure(text_color=color)

    def on_start(self):
        self.is_running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.start_time = time.time()
        self.packet_count = 0
        # Reset history
        self.traffic_history = deque([0]*self.max_data_points, maxlen=self.max_data_points)
        self.last_anomaly_time = 0
        
        self.start_callback()
        self.log_message("System: Sniffer Started...")

    def on_stop(self):
        self.is_running = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.stop_callback()
        self.log_message("System: Sniffer Stopped...")

    def log_message(self, message):
        self.log_textbox.insert("0.0", message + "\n")
        # Keep logs manageable
        self.log_textbox.delete("200.0", "end") # Optional: clean up old logs

    def generate_report(self):
        if not self.traffic_log:
            messagebox.showinfo("Info", "No data to export.")
            return
            
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            try:
                df = pd.DataFrame(self.traffic_log)
                df.to_csv(filename, index=False)
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")

    def update_ui_loop(self):
        if self.is_running:
            current_time = time.time()
            
            # Update System Health
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.update_card(self.card_sys, f"CPU: {cpu}% | RAM: {ram}%")
            
            # Rate Calculation
            # This is cumulative average, instantaneous might be better for graph
            # Let's simple use global rate for card, and maybe instantaneous for graph if possible
            # Or just packet count in last sec.
            
            # We need to drain the queue but also keep track of packets per second for the graph
            packets_this_tick = 0
            
            # Process Queue
            while not self.log_queue.empty():
                try:
                    data = self.log_queue.get_nowait()
                    packets_this_tick += 1
                    self.packet_count += 1
                    
                    # Log to list
                    self.traffic_log.append(data)
                    
                    # Format Log Entry
                    ts = datetime.fromtimestamp(data['timestamp']).strftime('%H:%M:%S')
                    proto = data['protocol']
                    src = data['src_ip']
                    dst = data['dst_ip']
                    is_anomaly = data.get('anomaly', 1)
                    
                    log_text = f"[{ts}] [{proto}] {src} -> {dst}"
                    
                    if is_anomaly == -1:
                        # Found anomaly!
                        self.last_anomaly_time = time.time()
                        log_text += " [ALERT: ANOMALY DETECTED]"
                        # self.update_card(self.card_threat, "CRITICAL", "red") # Handled by sticky logic
                    else:
                        pass
                        
                    self.log_message(log_text)
                    
                except queue.Empty:
                    break
            
            # Update Traffic Card
            elapsed = current_time - self.start_time
            if elapsed > 0:
                rate = self.packet_count / elapsed
                self.update_card(self.card_traffic, f"{rate:.1f} pkts/s")
            
            # Update Graph Data
            # Note: loop runs every 1000ms, so packets_this_tick is approx packets/sec
            self.traffic_history.append(packets_this_tick)
            
            self.line.set_data(range(len(self.traffic_history)), self.traffic_history)
            
            # Dynamic Y-axis
            current_max = max(self.traffic_history) if self.traffic_history else 10
            if current_max > self.ax.get_ylim()[1]:
                self.ax.set_ylim(0, current_max * 1.2)
            elif current_max < self.ax.get_ylim()[1] * 0.5 and current_max > 10:
                 self.ax.set_ylim(0, current_max * 1.2)
            
            self.canvas.draw()
            
            # Sticky Threat Level Logic
            time_since_anomaly = current_time - self.last_anomaly_time
            if time_since_anomaly < self.threat_cooldown:
                self.update_card(self.card_threat, "CRITICAL", "red")
            else:
                self.update_card(self.card_threat, "Low", "green")
        
        self.after(1000, self.update_ui_loop)
