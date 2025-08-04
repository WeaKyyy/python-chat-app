import socket
from threading import Thread
import mysql.connector

# server's IP address
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002 # port we want to use
separator_token = "<SEP>" # we will use this to separate the client name & message

# setting up mysql
# uses a user/pass that's separate from the root password
db = mysql.connector.connect(
    host="0.0.0.0",
    user="chatuser",
    password="chatpass",
    database="chatdb"
)
#the cursor is what allows us to traverse and edit the database.
cursor=db.cursor()

# initialize list/set of all connected client's sockets
client_sockets = set()
# create a TCP socket
s = socket.socket()
# make the port as reusable port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# bind the socket to the address we specified
s.bind((SERVER_HOST, SERVER_PORT))
# listen for upcoming connections
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

def listen_for_client(cs, name):
    """
    This function keep listening for a message from `cs` socket
    Whenever a message is received, broadcast it to all other connected clients
    """
    while True:
        try:
            # keep listening for a message from `cs` socket
            msg = cs.recv(1024).decode()
            if not msg:
                break
            # adding an option to print chat history. This will only trigger if the history command is entered
            elif msg.strip().lower().startswith("/history"):
                histParts = msg.strip().split()
                histLimit = 12
                user_filter = None

                if len(histParts) == 2:
                    if histParts[1].isdigit():
                        histLimit = int(histParts[1])
                    else:
                        user_filter = histParts[1]
                elif len(histParts) == 3:
                    user_filter = histParts[1]
                    if histParts[2].isdigit():
                        histLimit = int(histParts[2])
                try:
                    #if the user has specified a specific user to search for, only grab messages from that user.
                    #otherwise, just grab the amount of messages requested from any user, either by the default value of 12 or by user specification
                    if user_filter:
                        cursor.execute("SELECT username, message, timestamp FROM messages WHERE username = %s ORDER BY id DESC LIMIT %s", (user_filter, histLimit))
                    else:
                        cursor.execute("SELECT username, message, timestamp FROM messages ORDER BY id DESC LIMIT %s", (histLimit,))

                    #fetch all of the selected data and store it in the rows variable, then arrange it into a cleaner format to display.
                    rows = cursor.fetchall()
                    history = "\n".join([f"[{r[2]}] {r[0]}: {r[1]}" for r in rows[::-1]])
                    #send the chat history to the client along with a confirmation that the history command was used.
                    cs.send(f"\n/history command entered...\nfetching chat history...\n".encode())
                    cs.send(f"--- Chat History ---\n{history}\n--- End ---\n".encode())

                except mysql.connector.Error as err:
                    cs.send(f"Error retrieving history: {err}".encode())
                continue

        except Exception as e:
            # client no longer connected
            # remove it from the set
            print(f"[!] Error: {e}")
            client_sockets.remove(cs)
            break
        else:
            #WW - edited this portion to print the client's username with every messsage
            full_msg = f"{name}: {msg}"

            #save the message to db
            try:
                cursor.execute("INSERT INTO messages (username, message) VALUE (%s, %s)",
                    (name, msg)
                )
                db.commit()
            except mysql.connector.Error as err:
                print(f"[!] DB Error: {err}")

        clients_to_remove = []
        # iterate over all connected sockets
        for client_socket in client_sockets:
            # and send the message
            try:
                client_socket.send(full_msg.encode())
            except:
                clients_to_remove.remove(client_socket)

        for client_socket in clients_to_remove:
            client_sockets.remove(client_socket)

while True:
    # we keep listening for new connections all the time
    client_socket, client_address = s.accept()
    print(f"[+] {client_address} connected.")

    # #receive the name from the client and store it
    # client_name = client_socket.recv(1024).decode()
    # # add the new connected client to connected sockets
    # client_sockets.add(client_socket)
    # #print a confirmation statement in the terminal that the username has been assigned.
    # print(f"[+] Username of {client_address} is {client_name}")

    try:
        data = client_socket.recv(1024).decode()
    except Exception as e:
        print(f"[!] Error: {e}")
        client_socket.close()
        continue

    # Sign up -- expecting: "/signup<SEP>username<SEP>password"
    if data.startswith("/signup"):
        parts = data.split(separator_token)
        if len(parts) != 3:
            client_socket.send("Invalid signup request.".encode())
            client_socket.close()
            continue

        _, new_username, new_password = parts
        # Check if username already exists in 'users' table
        cursor.execute("SELECT 1 FROM users WHERE username = %s", (new_username,))
        if cursor.fetchone():
            client_socket.send("Username already exists.".encode())
            client_socket.close()
            continue

    # Insert new user into 'users' table
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (new_username, new_password))
        db.commit()
        client_socket.send("Signup successful.".encode())
        print(f"[+] {new_username} signed up.")
        client_socket.close()
        continue

    # LOGIN -- expecting: "username<SEP>password""
    try:
        client_name, client_password = data.split(separator_token, 1)
    except ValueError:
        client_socket.send("Authentication failed.".encode())
        client_socket.close()
        continue

    # Check credentials in 'users' table
    cursor.execute(
        "SELECT * FROM users WHERE username = %s AND password = %s",
        (client_name, client_password)
    )

    if cursor.fetchone():
        client_socket.send("Authentication successful.".encode())
        print(f"[+] {client_name} logged in.")
    else:
        client_socket.send("Authentication failed.".encode())
        client_socket.close()
        print(f"[-] {client_name} failed to log in.")
        continue

    client_sockets.add(client_socket)
    # start a new thread that listens for each client's messages
    t = Thread(target=listen_for_client, args=(client_socket, client_name))
    # make the thread daemon so it ends whenever the main thread ends
    t.daemon = True
    # start the thread
    t.start()

# close client sockets
for cs in client_sockets:
    cs.close()
# close server socket
s.close()