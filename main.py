from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, join_room, leave_room, send
import random
from string import ascii_uppercase

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choices(ascii_uppercase, k=16))
socketio = SocketIO(app)

rooms = {}

def generate_room_code(length=4):
    """Generate a random room code of specified length."""
    # while True:
    #     room_code = ''.join(random.choices(ascii_uppercase, k=length))
    #     if room_code not in rooms:
    #         return room_code
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        if code not in rooms:
            break

    return code

@app.route('/', methods=['GET', 'POST'])
def home():
    session.clear()
    if request.method == 'POST':
        username = request.form.get('username')
        room_code = request.form.get('room_code')
        join_room = request.form.get('join_room', False)
        create_room = request.form.get('create_room', False)

        if not username:
            return render_template('home.html', error="Username is required.", room_code=room_code, username=username)
        
        if join_room != False and not room_code:
            return render_template('home.html', error="Room code is required to join a room.", room_code=room_code, username=username)
        
        room = room_code

        if create_room != False:
            room = generate_room_code(4)
            rooms[room] = {"members": 0, "messages": []}
        elif room_code not in rooms:
            return render_template('home.html', error="Room code does not exist.", room_code=room_code, username=username)
        
        session['room'] = room
        session['username'] = username

        return redirect(url_for('room'))

    return render_template('home.html')

@app.route('/room')
def room():
    room = session.get('room')
    if room is None or session.get('username') is None or room not in rooms:
        return redirect(url_for('home'))

    return render_template('room.html', code=room, messages=rooms[room]["messages"])

@socketio.on('handle_message')
def handle_message(data):
    room = session.get('room')
    if room not in rooms:
        return
    
    content = {"username": session.get('username'), "message": data['data']}

    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"Message from {content['username']} in room {room}: {content['message']}")

@socketio.on('connect')
def connect(auth):
    room = session.get('room')
    username = session.get('username')
    if not (room and username):
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"username": username, "message": f"{username} has joined the room."}, to=room)
    rooms[room]["members"] += 1
    print(f"{username} has joined room {room}. Total members: {rooms[room]['members']}")

@socketio.on('disconnect')
def disconnect():
    room = session.get('room')
    username = session.get('username')
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]

    send({"username": username, "message": f"{username} has left the room."}, to=room)
    print(f"{username} has left room {room}. Total members: {rooms[room]['members'] if room in rooms else 0}")

if __name__ == '__main__':
    socketio.run(app, debug=True)