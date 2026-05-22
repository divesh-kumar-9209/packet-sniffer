def save_log(data):
    with open("packets.log", "a") as file:
        file.write(data + "\n")