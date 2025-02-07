import os
import time
import socket
import requests
import ipaddress
import netifaces as ni
import nmap
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP
from rich.console import Console
from rich.spinner import Spinner
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from functools import wraps
import hashlib

ascii_art = """⠀⠀⠀⠀


⠀     ⠀⠀⠀     ⠀⠀⠀⠀⠀⠀⣀⣀⣠⣤⣤⣤⣦⣶⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ▄▀▀▀▄ ▀▀█▀▀ █   █ █▀▀▀▀ █▄  █ ▄▀▀▀▄ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        █▀▀▀█   █   █▀▀▀█ █▀▀   █ ▀▄█ █▀▀▀█ 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣿⣿⣿⣿⡿⠿⠛⠛⠉⠉⠁⠀⠀⣀⣀⣀⣀⡀⠀⠀⠀⠈⠉⠛⠛⠿⢿⣿⣿⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀        ▀   ▀   ▀   ▀   ▀ ▀▀▀▀▀ ▀   ▀ ▀   ▀ 
⠀⠲⢶⣶⣶⣶⣶⣿⣿⣿⠿⠿⠛⠋⠉⠀⠀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣀⠀⠀⠀⠉⠙⠻⠿⢿⣿⣷⣶⣦⣤⣤⣄⡄        ▄▀▀▀▀ ▄▀▀▀▀ ▄▀▀▀▄ █▄  █ █▄  █ █▀▀▀▀ █▀▀▀▄ 
⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⣀⣠⣴⣶⣿⣿⣿⠿⠿⠛⠋⣩⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣶⣦⣄⣀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀         ▀▀▀▄ █     █▀▀▀█ █ ▀▄█ █ ▀▄█ █▀▀   █▀▀▀▄ 
⠀⠀⠀⠀⠀⠀⣀⣀⣤⣴⣶⣿⣿⣿⠿⠟⠋⠉⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠈⠉⠛⠿⢿⣿⣶⣶⣤⣄⣀⣀⣀⣀⡀⠀        ▀▀▀▀   ▀▀▀▀ ▀   ▀ ▀   ▀ ▀   ▀ ▀▀▀▀▀ ▀   ▀ 
⢰⣶⣶⣶⣾⣿⣿⣿⣿⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⢉⣽⣿⣿⣿⣿⣿⣿⠃⠀        @xM4skByt3z - Deivid Kelven           v2.0
⢸⣿⡿⠛⠛⠻⢿⣿⣷⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⢀⣠⣴⣾⣿⠿⠛⠋⠁⠀⠀⠀⠀⠀        
⠘⠁⠀⠀⠀⠀⠀⠈⠛⠿⣿⣿⣿⣷⣦⣤⣄⣀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠿⢿⣿⠿⠟⠛⠁⢀⣀⣤⣴⣾⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⠿⣿⣿⣿⣿⣷⣶⣶⣦⣤⣤⣤⣤⣤⣤⣤⣴⣶⣶⣿⣿⣿⣿⣿⠟⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⢋⣽⣿⡿⠏⠁⠀⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⠏⠁⠀⠀⠀⣿⣿⣧⡀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⠟⠁⠀⠀⠀⠀⠀⣿⣿⣿⣿⣷⣶⣶⣾⡟⠁⠀⠀⠀⠀        
⠀⠀⠀⠀⢀⣤⣴⣶⣶⣦⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⣴⣿⣿⠿⠛⠛⠻⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢰⣿⣿⠃⠀⣶⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢸⣿⣿⠀⠀⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⢸⣿⣿⡀⠀⠙⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⡿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⢿⣿⣿⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠻⣿⣿⣿⣷⣶⣤⣤⣶⣶⣿⣿⣿⡿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        
⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠛⠛⠛⠋⠉⠀



"""

os.system(f'echo "{ascii_art}" | lolcat')

# Inicializa o console com o rich
console = Console()

# Cache para armazenar resultados da API
mac_vendor_cache = {}

# Rate limiter para controlar o número de requisições por segundo
class RateLimiter:
    def __init__(self, max_calls, period):
        self.max_calls = max_calls
        self.period = period
        self.timestamps = []
        self.lock = threading.Lock()

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with self.lock:
                now = time.time()
                # Remove timestamps mais antigos que o período
                self.timestamps = [t for t in self.timestamps if now - t < self.period]
                if len(self.timestamps) >= self.max_calls:
                    # Espera até que o período expire
                    time_to_wait = self.period - (now - self.timestamps[0])
                    time.sleep(time_to_wait)
                    # Atualiza a lista de timestamps
                    self.timestamps = self.timestamps[1:]
                self.timestamps.append(now)
            return func(*args, **kwargs)
        return wrapper

# Aplica o rate limiter: 1 requisição a cada 2 segundos
rate_limiter = RateLimiter(max_calls=1, period=2)

# Função para exibir um spinner de loading
def show_loading(message):
    spinner = Spinner("dots", text=message, style="bold blue")
    return console.status(spinner)

# Função para consultar o fabricante do MAC address com rate limiting
@rate_limiter
def get_mac_vendor(mac):
    if mac in mac_vendor_cache:
        return mac_vendor_cache[mac]

    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            vendor = response.text
        else:
            vendor = "Desconhecido"
    except requests.exceptions.RequestException:
        vendor = "Desconhecido"

    mac_vendor_cache[mac] = vendor
    return vendor

# Função de Scan de Vulnerabilidades
def Scan():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    interfaces = ni.interfaces()

    for interface in interfaces:
        try:
            addrs = ni.ifaddresses(interface)
            if ni.AF_INET in addrs:
                ip_info = addrs[ni.AF_INET][0]
                ip_address = ip_info['addr']
                netmask = ip_info['netmask']

                if ip_address.startswith('127.'):
                    continue

                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                result = f"""
------------------ INFORMAÇÕES DA REDE ------------------

  IP Address        : {ip_address}
  Netmask           : {netmask}
  Network           : {network.network_address}
  Broadcast         : {network.broadcast_address}
  HostMin           : {network.network_address + 1}
  HostMax           : {network.broadcast_address - 1}
  Hosts/Net         : {network.num_addresses - 2}  (Exclui rede e broadcast)

-----------------------------------------------------------
                """
                return result, network
        except ValueError:
            continue

    return "No active network interface found.", None

# Função para identificar o sistema operacional com base no TTL
def get_os_by_ttl(ttl):
    if ttl <= 64:
        return "[bold cyan]Linux  [/bold cyan]"
    elif ttl <= 128:
        return "[bold yellow]Windows[/bold yellow]"
    else:
        return "Desconhecido"

# Função para processar um único IP
def process_ip(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    ans, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

    if ans:
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            manufacturer = get_mac_vendor(mac)

            icmp_request = IP(dst=ip) / ICMP()
            icmp_response = sr1(icmp_request, timeout=2, verbose=False)

            if icmp_response:
                ttl = icmp_response.ttl
                os = get_os_by_ttl(ttl)

                manufacturer_lower = manufacturer.lower()
                if "samsung" in manufacturer_lower or "motorola" in manufacturer_lower:
                    device_type = "Notebook"
                elif "epson" in manufacturer_lower:
                    device_type = "Impressora"
                elif "huawei" in manufacturer_lower:
                    device_type = "Roteador"
                elif "xiaomi" in manufacturer_lower:
                    device_type = "Celular Android"
                elif "intelbras" in manufacturer_lower:
                    device_type = "Cam"
                elif "apple" in manufacturer_lower:
                    device_type = "Celular IOS"
                elif "inpro" in manufacturer_lower:
                    device_type = "Câmera IP"
                elif "intel" in manufacturer_lower:
                    device_type = "Desktop"
                elif "del" in manufacturer_lower:
                    device_type = "Notebook"
                elif "lenovo" in manufacturer_lower:
                    device_type = "Notebook"
                else:
                    device_type = "Desktop"

                return ip, mac, manufacturer, ttl, os, device_type

    return None

# Função para escanear portas abertas e serviços usando Nmap com decoy
def scan_ports_with_nmap(target_ip):
    nm = nmap.PortScanner()
    decoy_ips = "192.168.1.100,192.168.1.101"

    try:
        nm.scan(target_ip, arguments=f"-D {decoy_ips} --open --top-ports=100 -T4 -sV --host-timeout 2m")

        if target_ip in nm.all_hosts():
            port_info = {}
            for proto in nm[target_ip].all_protocols():
                ports = nm[target_ip][proto].keys()
                for port in ports:
                    state = nm[target_ip][proto][port]['state']
                    if state == "open":
                        service = nm[target_ip][proto][port]['name']
                        product = nm[target_ip][proto][port]['product']
                        version = nm[target_ip][proto][port]['version']
                        port_info[port] = f"{service} {version}".strip()
            return port_info
        else:
            return None
    except Exception as e:
        console.print(f"[bold red]Erro ao escanear {target_ip}: {e}[/bold red]")
        return None

# Função para validar vulnerabilidades usando a API do Gemini
def validate_vulnerability(ip, port, service):
    # Serviços que não devem ser considerados vulneráveis por padrão
    non_vulnerable_services = ["tcpwrapped", "unknown", "generic"]

    if any(non_vuln in service.lower() for non_vuln in non_vulnerable_services):
        return f"""
IP: {ip}
Porta: {port}
Status: open
Serviço: {service}
Sistema Operacional: Linux
✅ O serviço {service} não é vulnerável.
"""

    # Verifica se o serviço possui uma versão específica
    if " " not in service:  # Se não houver versão no nome do serviço
        return f"""
IP: {ip}
Porta: {port}
Status: open
Serviço: {service}
Sistema Operacional: Linux
✅ O serviço {service} não é vulnerável (versão não especificada).
"""

    api_key = "AIzaSyC-cV4CqQ9LxendOtc4ZW6V29_q0US0YaI"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    data = {
        "contents": [{
            "parts": [{
                "text": f"com base na versao do serviço {service} na porta {port} do IP {ip} é vulnerável. Forneça uma resposta direta: 'Sim, é vulnerável' ou 'Não, não é vulnerável'. Se for vulnerável, liste os CVEs conhecidos, métodos de exploração, impacto e mitigação de forma organizada. e com poucos emogis"
            }]
        }]
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)  # Timeout de 10 segundos
        if response.status_code == 200:
            result = response.json()
            if "candidates" in result and len(result["candidates"]) > 0:
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                if "sim, é vulnerável" in text.lower():
                    return f"""
IP: {ip}
Porta: {port}
Status: open
Serviço: {service}
Sistema Operacional: Linux
[bold yellow]⚠️ O serviço {service} é vulnerável![/bold yellow]

🔍 **Detalhes da vulnerabilidade:**
{text}
"""
                else:
                    return f"""
IP: {ip}
Porta: {port}
Status: open
Serviço: {service}
Sistema Operacional: Linux
✅ O serviço {service} não é vulnerável.
"""
        return f"""
IP: {ip}
Porta: {port}
Status: open
Serviço: {service}
Sistema Operacional: Linux
❌ Não foi possível validar a vulnerabilidade.
"""
    except requests.exceptions.Timeout:
        return f"""
IP: {ip}
Porta: {port}
Status: open
Serviço: {service}
Sistema Operacional: Linux
❌ A validação de vulnerabilidade atingiu o tempo limite.
"""
    except Exception as e:
        return f"""
IP: {ip}
Porta: {port}
Status: open
Serviço: {service}
Sistema Operacional: Linux
❌ Erro ao validar vulnerabilidade: {e}
"""

# Função de ARP Sweep e Classificação dos dispositivos
def arp_sweep_and_classify(target_ip):
    network = ipaddress.IPv4Network(target_ip, strict=False)
    ip_list = [str(ip) for ip in network.hosts()]

    devices = []

    with show_loading("Realizando ARP Sweep..."):
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(process_ip, ip) for ip in ip_list]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip, mac, manufacturer, ttl, os, device_type = result
                    devices.append(f"{'=' * 90}")
                    devices.append(f" IP: {ip:<15} | MAC: {mac:<20}       | Fabricante: {manufacturer}")
                    devices.append(f" TTL: {ttl:<3}            | Sistema Operacional: {os:<10}    | Tipo: {device_type}")
                    devices.append(f"{'-' * 90}")

    if devices:
        console.print("\n".join(devices), style="bold white")
    else:
        console.print("[bold red]Nenhum host encontrado.[/bold red]\n")

    console.print("\n[bold white]Iniciando escaneamento de portas abertas nos hosts encontrados...[/bold white]\n")

    host_ports = {}

    with show_loading("Escaneando portas abertas..."):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(scan_ports_with_nmap, ip): ip for ip in [d.split("|")[0].split(":")[1].strip() for d in devices if "IP:" in d]}

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    port_info = future.result()
                    if port_info:
                        host_ports[ip] = port_info
                        console.print(f"[bold green]Escaneamento concluído para {ip}[/bold green]")
                except Exception as e:
                    console.print(f"[bold red]Erro ao escanear {ip}: {e}[/bold red]")

    return host_ports

# Função para verificar arquivos maliciosos usando a API do VirusTotal
def verificar_arquivo_malicioso(api_key):
    """
    Verifica se um arquivo é malicioso usando a API do VirusTotal.

    :param api_key: Chave de API do VirusTotal.
    """
    # Solicita ao usuário o caminho do arquivo
    caminho_arquivo = input("Digite o caminho completo do arquivo que deseja verificar: ")

    # Verifica se o arquivo existe
    try:
        with open(caminho_arquivo, 'rb') as arquivo:
            # Calcula o hash SHA-256 do arquivo
            hash_sha256 = hashlib.sha256(arquivo.read()).hexdigest()
    except FileNotFoundError:
        console.print("[bold red]Arquivo não encontrado. Verifique o caminho e tente novamente.[/bold red]")
        return
    except Exception as e:
        console.print(f"[bold red]Erro ao abrir o arquivo: {e}[/bold red]")
        return

    # Verifica se o arquivo já foi analisado anteriormente
    url_relatorio = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': hash_sha256}

    try:
        response = requests.get(url_relatorio, params=params)
        response.raise_for_status()  # Lança uma exceção para códigos de status HTTP inválidos
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Erro ao conectar ao VirusTotal: {e}[/bold red]")
        return

    if response.status_code == 200:
        resultado = response.json()
        if resultado.get('response_code') == 1:
            # O arquivo já foi analisado, exibe o resultado
            console.print(f"[bold green]Resultado da análise:[/bold green]")
            console.print(f"Arquivo: {caminho_arquivo}")
            console.print(f"Hash SHA-256: {hash_sha256}")
            console.print(f"Detecções: {resultado['positives']}/{resultado['total']}")
            if resultado['positives'] > 0:
                console.print("[bold red]Arquivo malicioso detectado![/bold red]")
            else:
                console.print("[bold green]Arquivo seguro.[/bold green]")
        else:
            # O arquivo não foi analisado anteriormente, envia para análise
            console.print("[bold yellow]Arquivo não analisado anteriormente. Enviando para análise...[/bold yellow]")
            try:
                files = {'file': (caminho_arquivo, open(caminho_arquivo, 'rb'))}
                params = {'apikey': api_key}
                response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
                response.raise_for_status()

                if response.status_code == 200:
                    console.print("[bold green]Arquivo enviado com sucesso para análise.[/bold green]")
                    console.print(f"Scan ID: {response.json()['scan_id']}")
                else:
                    console.print("[bold red]Erro ao enviar o arquivo para análise.[/bold red]")
            except requests.exceptions.RequestException as e:
                console.print(f"[bold red]Erro ao enviar o arquivo para análise: {e}[/bold red]")
            except Exception as e:
                console.print(f"[bold red]Erro inesperado: {e}[/bold red]")
    else:
        console.print("[bold red]Erro ao verificar o arquivo.[/bold red]")

# Função principal
def main():
    api_key = '36055ad24d6fd4404ba1ca96b0c130a5446b763ed095599778af1e01e4ad3baf'  # Substitua pela sua chave de API do VirusTotal

    # Exibição do menu inicial
    console.print("1 - Scan de Vulnerabilidades", style="bold white")
    time.sleep(0.1)
    console.print("2 - Sistema de Monitoramento (IDS)", style="bold white")
    time.sleep(0.1)
    console.print("3 - Verificador de arquivos Maliciosos", style="bold white")
    time.sleep(0.1)

    opcao = input("Insira uma opção: ")

    if opcao == "1":
        console.print("[bold cyan]Selecionou a opção 1 - Scan de Vulnerabilidades[/bold cyan]")
        time.sleep(0.5)
        console.print("\n[bold white]Coletando informações da rede...[/bold white]")
        time.sleep(1.5)
        scan_result, network = Scan()
        console.print(scan_result)
        time.sleep(0.5)

        if network:
            target_ip = f"{network.network_address}/{network.prefixlen}"
            console.print(f"\n[bold white]Realizando ARP Sweep para:[/bold white] {target_ip}\n")
            host_ports = arp_sweep_and_classify(target_ip)

            console.print("\n[bold green]Resultado do escaneamento de portas:[/bold green]")
            for ip, ports in host_ports.items():
                console.print(f"\n[bold cyan]{ip}:[/bold cyan]")
                for port, service in ports.items():
                    vulnerability_status = validate_vulnerability(ip, port, service)
                    console.print(vulnerability_status)
        else:
            console.print("[bold red]Não foi possível determinar a rede para escaneamento.[/bold red]")
    elif opcao == "2":
        console.print("[bold cyan]Selecionou a opção 2 - Sistema de Monitoramento (IDS)[/bold cyan]")
    elif opcao == "3":
        console.print("[bold cyan]Selecionou a opção 3 - Verificador de arquivos Maliciosos[/bold cyan]")
        verificar_arquivo_malicioso(api_key)
    else:
        console.print("[bold red]Opção inválida[/bold red]")

# Executa o programa
if __name__ == "__main__":
    main()
