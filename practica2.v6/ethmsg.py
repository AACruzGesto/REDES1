'''
    ethmsg.py
    Implementación del protocolo de mensajeria basica para emision de mensajes en tiempo real sobre ethernet.
    Autor: Manuel Ruiz <manuel.ruiz.fernandez@uam.es>
    2024 EPS-UAM
'''

from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

ETHTYPE = 0x0AA0
#Dirección de difusión (Broadcast)
broadcast = bytes([0xFF]*6)


def _mac_to_str(srcMac:bytes) -> str:
    return ':'.join(f"{b:02x}"for b in srcMac)

def process_ethMsg_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_EthMsg_frame
        Descripción: Esta función procesa las tramas mensajes sobre ethernet. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype ETHTYPE (si ha sido registrada en initEth). 
                - Imprimir el contenido de los datos indicando la direccion MAC del remitente así como el tiempo de recepcion del mensaje, según el siguiente formato:
					[<segundos.microsegundos>] <MAC>: <mensaje> 
                - En caso de que no exista retornar
            
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ethMsg. Los dos primeros bytes tienen la longitud del mensaje en orden de red. El resto de bytes son el mensaje en sí mismo.
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    if len(data)<2 :
        logging.warning("EthMsg: trama demasiado corta")
        return -1
    
    # La longitud viene en “orden de red” (big endian) en 2 bytes.
    # En Python se hace con struct.unpack:
    #   - "!H" significa:
    #         !  -> big endian (network order)
    #         H  -> unsigned short (2 bytes)
    #   - data[0:2] es un slice: coge los bytes 0 y 1 (el 2 no lo incluye).
    # struct.unpack devuelve SIEMPRE una tupla, aunque solo tenga un valor,
    # por eso ponemos [0] al final para quedarnos con el entero.
    length = struct.unpack("!H", data[0:2])[0]
    raw_msg = data[2:2+length]

    try:
        # raw_msg son bytes. Para poder imprimir texto en Python necesitamos str.
        # decode("utf-8") pasa de bytes -> str.
        # errors="replace" hace que si viene un carácter raro, lo sustituya,
        # en vez de lanzar una excepción.
        msg = raw_msg.decode("utf_8", errors = "replace")
    except Exception:
        msg = "<Mensaje no decodificado>"

    # El callback de pcap (tu rc1_pcap.py) te pasa un header con marca de tiempo.
    # Sueles tener header.ts.tv_sec (segundos desde 1970) y header.ts.tv_usec (microsegundos).
    ts_sec = header.ts.tv_sec
    ts_usec = header.ts.tv_usec
    # time.localtime(ts_sec) convierte esos segundos en una estructura de fecha/hora local.
    t = time.localtime(ts_sec)
    # time.strftime formatea esa fecha en el formato que pide el enunciado:
    # "YYYY/MM/DD HH:MM:SS"
    fecha = time.strftime('%Y/%m/%d %H:%M:%S', t)
    # Convertimos la MAC origen (que nos la pasó Ethernet como 6 bytes)
    # a una cadena legible tipo "00:11:22:33:44:55"
    macStr = _mac_to_str(srcMac)
    print(f'[{fecha}.{ts_usec:06d}] {macStr} : {length} bytes : <{msg}>')
   
    #TODO implementar aquí



def initEthMsg(interface:str) -> int:
    '''
        Nombre: initEthMsg
        Descripción: Esta función construirá inicializará el nivel ethMsg. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_ethMsg_frame con el Ethertype ETHTYPE
        Argumentos:   
			interfaz
    '''
    if interface is None:
        return -1
    registerEthCallback(process_ethMsg_frame, ETHTYPE)
    return 0

def sendEthMsg(message:bytes) -> bytes:
    '''
        Nombre: sendEthMsg
        Descripción: Esta función mandara un mensaje en broacast 
            
            Esta función debe realizar, al menos, las siguientes tareas:
                - Crear una trama Ehernet con el mensaje remitido. Los datos de la trama tienen que incluir la longitud del mensaje en orden de red, seguido del mensaje.
                - Enviar un mensaje en broadcast. La llamada a Ethernet debe tener en cuenta la longitud total (longitud+mensaje)
		Argumentos:
			message: datos con el mensaje a remitir.
                
        Retorno: 
			Numero de Bytes transmitidos en el mensaje.
			None en caso de que no haya podido emitir el mensaje
                
          
    '''
    # 1) asegurarnos de que tenemos bytes
    if isinstance(message, str):
        msg_bytes = message.encode('utf-8')
    else:
        # por si alguien ya pasa bytes
        msg_bytes = message
    lenght = len(msg_bytes)

    # 3) Empaquetamos la longitud en 2 bytes en orden de red.
    #    struct.pack("!H", n) -> devuelve b'\x00\x0a' por ejemplo
    #    !  = big endian (network order)
    #    H  = unsigned short (2 bytes)
    len_field = struct.pack("!H", lenght)

    # 4) Construimos el payload final:
    #     longitud (2 bytes) + mensaje
    payload = len_field + msg_bytes

    # 5) Llamamos al nivel Ethernet.
    #    - data/payload: lo que acabamos de construir
    #    - len(payload): lo que ocupa
    #    - ETHMSG_TYPE: 0x0AA0 (nuestro protocolo)
    #    - BROADCAST_MAC: para que lo reciban todos
    #
    #    IMPORTANTE: aquí NO ponemos padding; eso lo hace el nivel Ethernet
    #    porque es quien sabe si la trama llega a los 60 bytes mínimos
    ret = sendEthernetFrame(payload, len(payload), ETHTYPE, broadcast)
    if ret == 0 :
        return lenght

    return None
