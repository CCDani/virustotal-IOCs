import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
import re

# Función para consultar VirusTotal
def consultar_virustotal(ioc, api_key):
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Función para filtrar y extraer hashes, URLs, dominios e IPv4
def filtrar_iocs(texto):
    lines = texto.split('\n')
    hashes = []
    urls = []
    domains = []
    ips = []

    hash_pattern = re.compile(r"FileHash-(MD5|SHA1|SHA256)\s+([a-f0-9]+)")
    url_pattern = re.compile(r"https?://[^\s]+")
    domain_pattern = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b")
    ipv4_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    for line in lines:
        if hash_match := hash_pattern.search(line):
            hashes.append(hash_match.group(2))
        if url_match := url_pattern.search(line):
            urls.append(url_match.group(0))
        if domain_match := domain_pattern.search(line):
            domains.append(domain_match.group(0))
        if ipv4_match := ipv4_pattern.search(line):
            ips.append(ipv4_match.group(0))

    return hashes, urls, domains, ips

# Función para procesar los IOCs
def procesar_iocs():
    texto = text_input.get("1.0", tk.END).strip()
    api_key = api_key_entry.get().strip()
    if not api_key:
        messagebox.showerror("Error", "Por favor, introduce la API Key de VirusTotal.")
        return

    if modo_var.get() == "Filtrado":
        hashes, urls, domains, ips = filtrar_iocs(texto)
        iocs = hashes + urls + domains + ips
    else:
        iocs = texto.split('\n')

    resultados_text = ""

    for ioc in iocs:
        resultado = consultar_virustotal(ioc, api_key)
        if resultado and 'data' in resultado and len(resultado['data']) > 0:
            attributes = resultado['data'][0]['attributes']
            detected_urls = attributes.get('last_analysis_stats', {}).get('malicious', 0)
            if detected_urls > 0:  # Excluir los IOCs con detecciones 0
                resultados_text += f"IOC: {ioc} - {detected_urls}\n"

    # Mostrar los resultados en el widget de texto
    text_resultados.config(state=tk.NORMAL)
    text_resultados.delete("1.0", tk.END)
    text_resultados.insert(tk.END, resultados_text)
    text_resultados.config(state=tk.DISABLED)

# Función para copiar resultados al portapapeles
def copiar_resultados():
    resultados = text_resultados.get("1.0", tk.END)
    app.clipboard_clear()
    app.clipboard_append(resultados)
    messagebox.showinfo("Copiado", "Resultados copiados al portapapeles.")

# Configuración de la interfaz de usuario con Tkinter
app = tk.Tk()
app.title("Consulta de IOCs en VirusTotal")
app.geometry("1000x1000")

tk.Label(app, text="API Key de VirusTotal:").pack(pady=5)
api_key_entry = tk.Entry(app, width=50)
api_key_entry.pack(pady=5)

tk.Label(app, text="Introduce los IOCs:").pack(pady=5)
text_input = scrolledtext.ScrolledText(app, width=150, height=15)
text_input.pack(pady=5)

# Opción de modo de entrada
modo_var = tk.StringVar(value="Filtrado")
tk.Radiobutton(app, text="Filtrado (extraer hashes, URLs, dominios e IPs)", variable=modo_var, value="Filtrado").pack()
tk.Radiobutton(app, text="Uno por línea", variable=modo_var, value="Línea").pack()

tk.Button(app, text="Consultar", command=procesar_iocs).pack(pady=10)

tk.Label(app, text="Resultados: \n\nEl número asignado a cada IOC indica la cantidad de proveedores de seguridad que han identificado el archivo como malicioso.").pack(pady=5)
text_resultados = scrolledtext.ScrolledText(app, width=150, height=15, state=tk.DISABLED)
text_resultados.pack(pady=5)

copy_button = tk.Button(app, text="Copiar Resultados", command=copiar_resultados)
copy_button.pack(pady=10)

app.mainloop()
