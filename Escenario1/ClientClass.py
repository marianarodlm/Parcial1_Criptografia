import socket
class Client:
    """Una clase para gestionar la comunicación con el servidor."""
    
    def __init__(self, server_ip, port, header_size=64, format='utf-8'):
        """Inicializa un cliente y establece la conexión con el servidor."""
        self.HEADER = header_size
        self.FORMAT = format
        self.DISCONNECT_MESSAGE = "!DISCONNECT"
        self.SERVER = server_ip
        self.PORT = port
        self.ADDR = (self.SERVER, self.PORT)
        
        # Crear y conectar el socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()
    
    def connect(self):
        """Establece la conexión con el servidor."""
        try:
            self.socket.connect(self.ADDR)
            print(f"Conectado al servidor en {self.SERVER}:{self.PORT}")
        except Exception as e:
            print(f"Error al conectar: {e}")
            raise
    
    def send(self, msg):
        """Enviar un mensaje formateado al servidor."""
        message = msg.encode(self.FORMAT)
        msg_length = len(message)
        send_length = str(msg_length).encode(self.FORMAT)
        send_length += b' ' * (self.HEADER - len(send_length))
        self.socket.send(send_length)
        self.socket.send(message)
    
    def send_bytes(self, data):
        """Enviar bytes sin formatear al servidor."""
        msg_length = len(data)
        send_length = str(msg_length).encode(self.FORMAT)
        send_length += b' ' * (self.HEADER - len(send_length))
        self.socket.send(send_length)
        self.socket.send(data)
    
    def receive(self):
        """Recibe un mensaje formateado del servidor."""
        try:
            msg_length = self.socket.recv(self.HEADER).decode(self.FORMAT)
            if msg_length:
                msg_length = int(msg_length.strip())
                msg = self.socket.recv(msg_length).decode(self.FORMAT)
                return msg
        except Exception as e:
            print(f"Error al recibir mensaje: {e}")
        return None
    
    def receive_bytes(self):
        """Recibe datos en bruto del servidor sin decodificar."""
        try:
            msg_length = self.socket.recv(self.HEADER).decode(self.FORMAT)
            if msg_length:
                msg_length = int(msg_length.strip())
                data = self.socket.recv(msg_length)
                return data
        except Exception as e:
            print(f"Error al recibir bytes: {e}")
        return None
    
    def close(self):
        """Cierra la conexión con el servidor."""
        try:
            self.socket.close()
            print("Conexión cerrada.")
        except Exception as e:
            print(f"Error al cerrar la conexión: {e}")