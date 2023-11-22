import socket
import hashlib
import sys
import json
import datetime
import random

sessions = {}
sesID = []
def post(headers, accounts):
    username = headers.get("username", "")
    password = headers.get("password", "")
    if not username or not password:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        print(f"SERVER LOG: {current_time} LOGIN FAILED")
        return "HTTP/1.0 501 Not Implemented\r\n\r\n"
   
    
    with open(accounts, "r") as file:
        accounts_data = json.load(file)

    if username not in accounts_data:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        print(f"SERVER LOG: {current_time} LOGIN FAILED")
        return "HTTP/1.0 501 Not Implemented\r\n\r\n"
  
    storedHash, salt = accounts_data[username]
    attempt = hash_pw(password, salt)

    if attempt == storedHash:
        session_id = generateID()
        createSes(session_id, username)
        global sesID
        sesID.append(session_id)

        current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        print(f"SERVER LOG: {current_time} LOGIN SUCCESSFUL: {username} : {password}")

        response_body = "Logged in!"
        headers['Set-Cookie'] = f"sessionID={session_id}"

        return http_ok(headers, response_body)
    else:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        print(f"SERVER LOG: {current_time} LOGIN FAILED: {username} : {password}")
        return http_ok(headers, "Login failed!")

def get(headers, root_directory, session_timeout,target):
    session_id = getID(headers)
    if checkID(session_id):
        session_id = session_id.strip()
        username, timestamp = sessions[session_id]['username'], sessions[session_id]['timestamp']
        
        current_time = datetime.datetime.now()
        sessionTime = current_time - timestamp
        if sessionTime.total_seconds() < session_timeout:
            sessions[session_id]['timestamp'] = current_time
            filename = target[1:]

            user_directory = f"{root_directory}/{username}"
            file_path = f"{user_directory}/{filename}"

            if file_exists(file_path):
                with open(file_path, 'r') as file:
                    file_content = file.read()
                current_time2 = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
                log_message = f"SERVER LOG: {current_time2} GET SUCCEEDED: {username} : {target}"
                print(log_message)
                response_body = file_content
                return http_ok(headers, response_body)
            else:
                current_time2 = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
                log_message = f"SERVER LOG: {current_time2} GET FAILED: {username} : {target}"
                print(log_message)
                return "HTTP/1.0 404 NOT FOUND\r\n\r\n"
        else:
            current_time2 = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            log_message = f"SERVER LOG: {current_time2} SESSION EXPIRED: {username} : {target}"
            print(log_message)
            return "HTTP/1.0 401 Unauthorized\r\n\r\n"
    else:
        current_time2 = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        log_message = f"SERVER LOG: {current_time2} COOKIE INVALID: {target}"
        print(log_message)
        return "HTTP/1.0 401 Unauthorized\r\n\r\n"
def checkID(session_id):
    session_id = session_id.strip()
    
    if session_id in sessions:
        return True
    else:
        return False


def http_ok(headers, response_body):
    response = f"HTTP/1.0 200 OK\r\n"
    if headers:
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
    response += "\r\n" + response_body
    return response
    
def file_exists(file_path):
    try:
        open(file_path, 'r').close()
        return True
    except FileNotFoundError:
        return False

def getID(headers):
    cookies = headers.get('cookie', '').split(':')
    session_id = None

    for cookie in cookies:
        if cookie.startswith('sessionID='):
            session_id = cookie.split('=')[1]
            break
    return session_id


def hash_pw(password, salt):
    hasher = hashlib.sha256()
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()

def generateID():
    return '0x' + ''.join(random.choice('0123456789abcdef') for _ in range(16))

def createSes(session_id, username):
    global sessions
    sessions[session_id] = {'username': username, 'timestamp': datetime.datetime.now()}
    
def parse(request):
    lines = request.split("\r\n")
    request_line = lines[0]
    method, target, version = request_line.split(" ")

    headers = {}
    for line in lines[1:]:
        if line:
            key, value = line.split(": ", 1)
            headers[key.lower()] = value
    
    return method, target, version, headers

def startServer(HOST, PORT, accounts, sessionTime, rootDir): 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(20)

    while True:
        
        client_socket, client_address = sock.accept()
        request = client_socket.recv(1024).decode("utf-8")
        
        method, target, version, headers = parse(request)
        
        
        if method == "POST" and target == "/":
            response = post(headers, accounts)
            client_socket.sendall(response.encode("ASCII"))
        elif method == "GET":
            response = get(headers, rootDir, sessionTime,target)
            client_socket.sendall(response.encode("ASCII"))
        else:
            response = "HTTP/1.0 501 Not Implemented\r\n\r\n"
            client_socket.sendall(response.encode("ASCII"))
        client_socket.close()

def main():  
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    accounts = sys.argv[3]
    sessionTime = int(sys.argv[4])
    rootDir = sys.argv[5]
    startServer(HOST, PORT, accounts, sessionTime, rootDir)
if __name__ == "__main__":
    main()
