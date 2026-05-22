from config import LOG_FILE

def save_log(data):
    try:
        with open(LOG_FILE, "a") as file:
            file.write(data + "\n")
    except Exception as e:
        print(f"[LOG ERROR] {e}")