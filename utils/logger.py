from config import LOG_FILE

def save_log(data):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(data + "\n")
    except Exception as e:
        print(f"[LOG ERROR] {e}")