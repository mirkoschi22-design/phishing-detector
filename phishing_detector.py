# Phishing Detector - By Mirko David Schiavi - Roldán, Santa Fe 🇦🇷
# Uso educativo - Detecta URLs sospechosas

import re
import ipaddress
from urllib.parse import urlparse

def es_ip(url):
    try:
        host = urlparse(url).hostname
        ipaddress.ip_address(host)
        return True
    except:
        return False

def analizar_url(url):
    if not url.startswith("http"):
        url = "http://" + url
        
    parsed = urlparse(url)
    dominio = parsed.netloc
    puntaje = 0
    motivos = []

    # 1. Usa IP en lugar de dominio
    if es_ip(url):
        puntaje += 3
        motivos.append("⚠️ Usa una dirección IP en lugar de un dominio")

    # 2. Tiene @ en la URL
    if "@" in url:
        puntaje += 2
        motivos.append("⚠️ Contiene '@' - técnica común de phishing")

    # 3. URL muy larga
    if len(url) > 75:
        puntaje += 1
        motivos.append(f"⚠️ URL muy larga ({len(url)} caracteres)")

    # 4. Acortadores
    acortadores = ['bit.ly', 'tinyurl', 'goo.gl', 't.me', 'is.gd', 'cutt.ly']
    if any(x in dominio for x in acortadores):
        puntaje += 2
        motivos.append("⚠️ Usa acortador de URL (oculta destino real)")

    # 5. Sin HTTPS
    if parsed.scheme != "https":
        puntaje += 1
        motivos.append("⚠️ No usa HTTPS")

    # 6. Muchos guiones o números en dominio
    if dominio.count('-') > 3 or sum(c.isdigit() for c in dominio) > 4:
        puntaje += 1
        motivos.append("⚠️ Dominio con muchos guiones/números (típico de phishing)")

    # 7. Palabras sospechosas
    palabras = ['login', 'secure', 'bank', 'verify', 'account', 'update']
    if any(p in url.lower() for p in palabras) and "google" not in dominio and "facebook" not in dominio:
        puntaje += 1
        motivos.append("⚠️ Usa palabras como 'login', 'verify', 'secure' para engañar")

    # Resultado
    print(f"\n🔍 Analizando: {url}")
    print(f"🌐 Dominio: {dominio}")
    print("-" * 50)
    
    if motivos:
        for m in motivos:
            print(m)
    else:
        print("✅ No se detectaron patrones sospechosos obvios")
        
    print("-" * 50)
    if puntaje >= 4:
        print(f"🚨 RIESGO ALTO ({puntaje}/10) - Probable PHISHING")
    elif puntaje >= 2:
        print(f"⚠️ RIESGO MEDIO ({puntaje}/10) - Sospechosa, verificar")
    else:
        print(f"✅ RIESGO BAJO ({puntaje}/10) - Parece segura")
    print()

if __name__ == "__main__":
    print("=== PHISHING DETECTOR - Mirko Schiavi ===")
    while True:
        url = input("\nPegá una URL para analizar (o 'salir'): ").strip()
        if url.lower() in ['salir', 'exit', 'q']:
            break
        if url:
            analizar_url(url)