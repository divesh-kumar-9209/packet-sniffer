import tkinter as tk
from stats import get_stats

def start_gui():
    root = tk.Tk()
    root.title("Packet Sniffer Dashboard")

    label = tk.Label(root, text="Live Stats", font=("Arial", 16))
    label.pack()

    text = tk.Text(root, height=15, width=50)
    text.pack()

    def update():
        text.delete(1.0, tk.END)
        stats = get_stats()

        for k, v in stats.items():
            text.insert(tk.END, f"{k}: {v}\n")

        root.after(1000, update)

    update()
    root.mainloop()