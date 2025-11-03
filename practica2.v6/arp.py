'''
    arp.py
    Implementación del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''



from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

#Semáforo global 
globalLock =Lock()
#Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP común a peticiones y respuestas. Específica para la combinación Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera común ARP
ARP_HLEN = 6

#Variable que alamacenará que dirección IP se está intentando resolver
requestedIP = None
#Variable que alamacenará que dirección MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que alamacenará True mientras estemos esperando una respuesta ARP
awaitingResponse = False

# info propia
# estado ARP (versión compatible con Python 3.8)
myIP = None          # IP propia (entero en orden de red)
myMAC = None         # MAC propia (bytes de 6)
arpInitialized = False


#Variable para proteger la caché
cacheLock = Lock()
#Caché de ARP. Es un diccionario similar al estándar de Python solo que eliminará las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)



def _get_mac_from_ethernet():
    """
    Devuelve la MAC actual del nivel Ethernet.
    Si en este módulo estaba a None (porque se importó antes),
    la vuelve a pedir al módulo 'ethernet'.
    """
    global macAddress
    if macAddress is not None:
        return macAddress
    # aquí hacemos una importación NORMAL, no cambiamos el import de arriba
    import ethernet
    return ethernet.macAddress




def getIP(interface:str) -> int:
    '''
        Nombre: getIP
        Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
        Argumentos:
            -interface: nombre de la interfaz
        Retorno: Entero de 32 bits con la dirección IP de la interfaz
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]
'''
def printCache()->None:
    
    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    with cacheLock:
        for k in cache:
            if k in cache:
                print ('{:>12}\t\t{:>12}'.format(socket.inet_ntoa(struct.pack('!I',k)),':'.join(['{:02X}'.format(b) for b in cache[k]])))

'''
def printCache() -> None:
    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    # 1) Tomamos una foto estable de la caché bajo el candado
    with cacheLock:
        snapshot = list(cache.items())   # [(ip_int, mac_bytes), ...]

    # 2) Imprimimos la foto, fuera del lock
    for ip_int, mac_bytes in snapshot:
        ip_str  = socket.inet_ntoa(struct.pack('!I', ip_int))
        mac_str = ':'.join(f'{b:02X}' for b in mac_bytes)
        print(f'{ip_str:>12}\t\t{mac_str:>12}')

def processARPRequest(data:bytes,MAC:bytes)->None:

    '''
        Nombre: processARPRequest
        Decripción: Esta función procesa una petición ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Construir una respuesta ARP llamando a createARPReply (descripción más adelante)
                    -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''

    global myIP, myMAC

    if len(data) < 20:
        return 
    
    srcMac = data[2:8]
    srcIP = struct.unpack("!I", data[8:12])[0]
    dstMac = data[12:18]
    dstIP = struct.unpack("!I",data[18:22])[0]

    if MAC != srcMac :
        return 
    with cacheLock:
        cache[srcIP] = srcMac
    
    if dstIP != myIP :
        return
    
    reply = createARPReply(dstIP, srcMac)
    sendEthernetFrame(reply, len(reply), 0x0806, srcMac)
   
def processARPReply(data:bytes,MAC:bytes)->None:
    '''
        Nombre: processARPReply
        Decripción: Esta función procesa una respuesta ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la MAC destino contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
                    -Copiar la MAC origen a la variable global resolvedMAC
                    -Añadir a la caché ARP la asociación MAC/IP.
                    -Cambiar el valor de la variable awaitingResponse a False
                    -Cambiar el valor de la variable requestedIP a None
        Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la función ARPResolution y deben ser protegidas mediante un Lock.
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    global requestedIP,resolvedMAC,awaitingResponse,cache
    
    if len(data) < 20:
        return 
    
    srcMac = data[2:8]
    srcIP = struct.unpack("!I", data[8:12])[0]
    dstMac = data[12:18]
    dstIP = struct.unpack("!I",data[18:22])[0] 
    
    if srcMac != MAC:
        return 
    if dstIP != myIP:
        return 
    with cacheLock:
        cache[srcIP]= srcMac
    
    with globalLock:
        if awaitingResponse == True and requestedIP == srcIP:
            resolvedMAC = srcMac
            awaitingResponse = False
            requestedIP = None
    
    return 
        



def createARPRequest(ip:int) -> bytes:
    '''
    Construye una petición ARP estándar Ethernet/IPv4.
    Usa:
      - ARPHeader (6 bytes)
      - opcode 0x0001
      - nuestra MAC y nuestra IP
      - MAC destino = 00..00
      - IP destino = ip_to_resolve


        Nombre: createARPRequest
        Descripción: Esta función construye una petición ARP y devuelve la trama con el contenido.
        Argumentos: 
            -ip: dirección a resolver 
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP

    opcode = struct.pack("!H", 0x0001)
    zeroMAC = bytes ([0x00]*6)
    frame = bytes()
    frame = (ARPHeader + opcode + myMAC + struct.pack("!I", myIP)  + zeroMAC + struct.pack("!I", ip))
    
    return frame

    
def createARPReply(IP:int ,MAC:bytes) -> bytes:
    '''
        Nombre: createARPReply
        Descripción: Esta función construye una respuesta ARP y devuelve la trama con el contenido.
        Argumentos: 
            -IP: dirección IP a la que contestar
            -MAC: dirección MAC a la que contestar
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP
    frame = bytes()
    opcode = struct.pack("!H", 0x0002)
    frame = (ARPHeader + opcode + myMAC + struct.pack("!I", myIP) + MAC + struct.pack("!I", IP))
    return frame


def process_arp_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_arp_frame
        Descripción: Esta función procesa las tramas ARP. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP). 
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer la cabecera común de ARP (6 primeros bytes) y comprobar que es correcta
                -Extraer el campo opcode
                -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripción más adelante)
                -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripción más adelante)
                -Si es otro opcode retornar de la función
                -En caso de que no exista retornar
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ARP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    if len(data) < ARP_HLEN + 2 :
        return

    headerARP = data[0:ARP_HLEN]
    if headerARP != ARPHeader:
        return 
    
    opcode = struct.unpack("!H", data[ARP_HLEN:ARP_HLEN + 2])[0]

    rest = data[ARP_HLEN:]

    if opcode == 0x0001:
        processARPRequest(rest, srcMac)
    elif opcode == 0x0002:
        processARPReply(rest, srcMac)
    else :
        return 

def sendGratuitousARP() -> int:
    """
    Envía un ARP gratuito (ARP request preguntando por MI propia IP)
    en difusión, 3 veces, para detectar IPs duplicadas.
    La IP y la MAC las tomamos de las globales myIP y myMAC.
    """
    global myIP

    # si aún no se ha inicializado ARP, no podemos
    if myIP is None:
        return -1

    # construyo una petición ARP "normal" pero con mi IP como IP destino
    pkt = createARPRequest(myIP)

    # la envío en broadcast 3 veces, con una pequeña pausa
    for _ in range(3):
        sendEthernetFrame(pkt, len(pkt), 0x0806, broadcastAddr)
        time.sleep(0.3)

    return 0


def initARP(interface: str) -> int:
    global myIP, myMAC, arpInitialized
    global requestedIP, resolvedMAC, awaitingResponse

    if arpInitialized:
        return 0

    # 1) registrar callback ARP
    registerEthCallback(process_arp_frame, 0x0806)

    # 2) obtener mis datos
    myMAC = _get_mac_from_ethernet()
    myIP = getIP(interface)

    # 3) meterme en caché
    with cacheLock:
        cache[myIP] = myMAC

    # 4) preparar espera de respuesta (por si hay IP duplicada)
    with globalLock:
        requestedIP = myIP
        resolvedMAC = None
        awaitingResponse = True

    # 5) mandar el ARP gratuito
    sendGratuitousARP()

    # 6) esperar un poco a ver si alguien contesta
    dup = False
    for _ in range(10):  # 10 x 0.1s = 1 segundo
        time.sleep(0.1)
        with globalLock:
            if not awaitingResponse:   # alguien ha contestado
                # si el que ha contestado NO soy yo → IP duplicada
                if resolvedMAC is not None and resolvedMAC != myMAC:
                    dup = True
                break

    if dup:
        logging.error("ARP: IP duplicada detectada. No se inicializa.")
        return -1

    # si llegamos aquí, o no contestó nadie o contestamos nosotros mismos
    with globalLock:
        awaitingResponse = False
        requestedIP = None

    arpInitialized = True
    return 0

def ARPResolution(ip:int) -> bytes:
    '''
        Nombre: ARPResolution
        Descripción: Esta función intenta realizar una resolución ARP para una IP dada y devuelve la dirección MAC asociada a dicha IP 
            o None en caso de que no haya recibido respuesta. Esta función debe realizar, al menos, las siguientes tareas:
                -Comprobar si la IP solicitada existe en la caché:
                -Si está en caché devolver la información de la caché
                -Si no está en la caché:
                    -Construir una petición ARP llamando a la función createARPRequest (descripción más adelante)
                    -Enviar dicha petición
                    -Comprobar si se ha recibido respuesta o no:
                        -Si no se ha recibido respuesta reenviar la petición hasta un máximo de 3 veces. Si no se recibe respuesta devolver None
                        -Si se ha recibido respuesta devolver la dirección MAC
            Esta función necesitará comunicarse con el la función de recepción (para comprobar si hay respuesta y la respuesta en sí) mediante 3 variables globales:
                -awaitingResponse: indica si está True que se espera respuesta. Si está a False quiere decir que se ha recibido respuesta
                -requestedIP: contiene la IP por la que se está preguntando
                -resolvedMAC: contiene la dirección MAC resuelta (en caso de que awaitingResponse) sea False.
            Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
    '''
    global requestedIP,awaitingResponse,resolvedMAC
    with cacheLock:
            if ip in cache:
                return cache[ip]

    print(f"Enviando solicitud ARP a {socket.inet_ntoa(struct.pack('!I', ip))}...")      

    for _ in range(3):
        req = createARPRequest(ip)

        with globalLock:
            requestedIP = ip
            resolvedMAC = None
            awaitingResponse = True
        
        sendEthernetFrame(req, len(req), 0x0806, broadcastAddr)

        for _ in range(10):
            time.sleep(0.1)
            with globalLock:
                if (not awaitingResponse) and (resolvedMAC is not None):
                    mac = resolvedMAC

                    with cacheLock:
                        cache[ip] = mac               
                    return mac
        
        with globalLock:
            requestedIP = None
            awaitingResponse = False
    return None
