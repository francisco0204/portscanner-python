import sys
import json
import argparse
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from portscan import scan_port
from banner import get_banner
from service import identify_service, extract_software_info
from cve import search_cve
from colorama import Fore, Style, init

init(autoreset=True)


parser = argparse.ArgumentParser(
    description="Scanner profesional de puertos + banners + vulnerabilidades (CVE)"
)

parser.add_argument("host", help="Host o IP a escanear")
parser.add_argument("range", nargs="?", default="1-1024", help="Rango de puertos (1-500)")

parser.add_argument("--no-cve", action="store_true", help="Desactiva el CVE lookup")
parser.add_argument("--no-banner", action="store_true", help="Desactiva el banner grabbing")
parser.add_argument("--threads", type=int, default=100, help="Cantidad de threads")
parser.add_argument("--json", help="Guardar reporte en JSON")
parser.add_argument("--txt", help="Guardar reporte en TXT")

args = parser.parse_args()


host = args.host

try:
    start, end = map(int, args.range.split("-"))
except ValueError:
    print("Formato inválido, usa 1-500 (ejemplo: 1-200)")
    sys.exit(1)

print(f"{Fore.BLUE}📡 Escaneando {host} puertos {start}-{end}...{Style.RESET_ALL}\n")

results = []


# ============================================================
# Función principal de escaneo
# ============================================================
def process_port(port):
    if not scan_port(host, port):
        return

    banner = None if args.no_banner else get_banner(host, port)
    service = identify_service(port, banner)

    print(f"{Fore.GREEN} Puerto {port} abierto{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}Servicio:{Style.RESET_ALL} {service}")

    if banner:
        print(f"   {Fore.YELLOW}Banner:{Style.RESET_ALL} {banner[:80]}...")

    cves_sorted = []
    vendor = product = None

    # ====================================================
    # CVE LOOKUP
    # ====================================================
    if banner:
        vendor, product = extract_software_info(banner)

        if not args.no_cve:
            print(f"DEBUG → vendor={vendor}, product={product}")

        if not args.no_cve and product:
            cves = search_cve(product)

            if cves:
                print(f"   {Fore.RED}Vulnerabilidades encontradas:{Style.RESET_ALL}")

                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

                cves_sorted = sorted(
                    cves,
                    key=lambda c: severity_order.get(c["severity"], 0),
                    reverse=True
                )

                current_group = None

                for cve in cves_sorted:
                    sev = cve["severity"]
                    score = cve["score"]
                    summary = cve["summary"][:80]

                    color = (
                        Fore.RED if sev == "CRITICAL" else
                        Fore.YELLOW if sev == "HIGH" else
                        Fore.BLUE if sev == "MEDIUM" else
                        Fore.WHITE
                    )

                    if sev != current_group:
                        print(f"\n   {color}── {sev} ─────────────{Style.RESET_ALL}")
                        current_group = sev

                    print(f"      ⚠ {color}{cve['id']} ({score}){Style.RESET_ALL} — {summary}")

                print()
            else:
                print(f"   {Fore.YELLOW}No se encontraron CVEs para: {product}{Style.RESET_ALL}")

    # ====================================================
    # LIMPIEZA DE BANNER (FIX DEFINITIVO)
    # ====================================================
    if banner:
        # 1. Mantener solo caracteres imprimibles
        banner_clean = "".join(c for c in banner if 32 <= ord(c) <= 126)

        # 2. Normalizar espacios
        clean = (
            banner_clean.replace("\n", " ")
                        .replace("\r", " ")
                        .replace("\t", " ")
                        .strip()
        )
        clean = " ".join(clean.split())

        # 3. CORTAR ANTES DE CUALQUIER "date" 
        match = re.search(r"date", clean, re.IGNORECASE)
        if match:
            clean = clean[:match.start()].strip()

        # 4. Recortar longitud fija
        clean_banner = clean[:24] if clean else "N/A"

    else:
        clean_banner = "N/A"

    # Guardar resultados
    results.append({
        "port": port,
        "service": service,
        "banner": clean_banner,
        "cves": cves_sorted
    })


# ============================================================
# THREAD POOL
# ============================================================
with ThreadPoolExecutor(max_workers=args.threads) as executor:
    executor.map(process_port, range(start, end + 1))

# ============================================================
# TABLA FINAL
# ============================================================
print(f"\n{Fore.GREEN}✔ Escaneo completado.{Style.RESET_ALL}")
print(f"{Fore.BLUE}Tabla final:{Style.RESET_ALL}\n")

print("┌─────────┬──────────────┬────────────────────────┬───────────────┐")
print("│ Puerto  │ Servicio     │ Banner                 │ CVEs          │")
print("├─────────┼──────────────┼────────────────────────┼───────────────┤")

for r in results:
    port = str(r["port"]).ljust(7)
    service = r["service"][:12].ljust(12)
    banner = r["banner"][:24].ljust(24)

    cves_count = len(r["cves"])
    critical_count = sum(1 for c in r["cves"] if c["severity"] == "CRITICAL")

    cve_text = f"{cves_count} ({critical_count} CRIT)" if cves_count else "0"
    cve_text = cve_text.ljust(13)

    print(f"│ {port} │ {service} │ {banner} │ {cve_text} │")

print("└─────────┴──────────────┴────────────────────────┴───────────────┘")

print(f"\n{Fore.MAGENTA}Puertos abiertos:{Style.RESET_ALL} {[r['port'] for r in results]}\n")

# ============================================================
# EXPORTAR JSON
# ============================================================
if args.json:
    json_output = {
        "host": host,
        "range": f"{start}-{end}",
        "datetime": datetime.now().isoformat(),
        "open_ports": results
    }

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(json_output, f, indent=4)

    print(f"{Fore.GREEN}💾 Reporte JSON guardado en:{Style.RESET_ALL} {args.json}")

# ============================================================
# EXPORTAR TXT
# ============================================================
if args.txt:
    with open(args.txt, "w", encoding="utf-8") as f:
        f.write("=== PORT SCAN REPORT ===\n")
        f.write(f"Host: {host}\n")
        f.write(f"Fecha: {datetime.now()}\n\n")

        for r in results:
            f.write(f"[{r['port']}] {r['service']}\n")
            f.write(f"  Banner: {r['banner']}\n")

            cves = r["cves"]
            if cves:
                critical = sum(1 for c in cves if c["severity"] == "CRITICAL")
                f.write(f"  CVEs: {len(cves)} ({critical} Critical)\n\n")
            else:
                f.write("  CVEs: 0\n\n")

    print(f"{Fore.GREEN}Reporte TXT guardado en:{Style.RESET_ALL} {args.txt}")
