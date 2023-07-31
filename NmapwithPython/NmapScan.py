import nmap
import subprocess

def escaneoPuertoE():
    iphost = input("Ingrese la ip a escanear: ")
    puerto = input("Ingrese el puerto que desea escanear: ")
    NmapScan = nmap.PortScanner()
    escaneo = NmapScan.scan(iphost, puerto)
    for host in NmapScan.all_hosts():
        print(f"Host: {host}")
        print(f"State: {escaneo['scan'][host]['status']['state']}")
        print(f"Port: {puerto} - State: {escaneo['scan'][host]['tcp'][int(puerto)]['state']}")
    

def escaneoRangoP():
    local="127.0.0.1"
    rangoIn = int(input("Ingrese el rango Inicial: "))
    rangoFin= int(input("Ingrese el rango Final: "))
    scanner=nmap.PortScanner()
    for puerto in range(rangoIn,rangoFin+1):
        respuesta=scanner.scan(local,str(puerto))
        respuesta=respuesta['scan'][local]['tcp'][puerto]['state']
        resultado=(f"{puerto}:{respuesta}")
        print(resultado)

def escaneoVuln():
    v = "vuln"
    ip = input("Ingrese la ip a escanear: ")
    comando = f"nmap --script {v} {ip}"
    try:
        output = subprocess.check_output(comando, shell=True, text=True)
        print(output)
    except subprocess.CalledProcessError:
        print(f"IP: {ip} - Error al ejecutar el comando")

r = 0
while r != 4:
    print("Bienvenido al menu de opciones de Nmap")
    print("1.Escaneo de un puerto Especifico.")
    print("2.Escaneo de un rango de puertos.")
    print("3.Escaneo de Vulnerabilidades.")
    print("4.Finalizar.")
    try:
        r = int(input("Ingrese su respuesta: "))
        if r > 4:
            print("Ingrese una opcion del menu.")
    except:
        print("Error")
        break
    if r == 1:
        escaneoPuertoE()
        r = 0
    elif r == 2:
        escaneoRangoP()
        r = 0
    elif r == 3:
        escaneoVuln()
        r = 0
    elif r == 4:
        print("Fin")
        break
    



