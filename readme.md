# Python Port & Vulnerability Scanner

Este proyecto es un escáner de puertos escrito en Python que permite:

- Detectar puertos abiertos
- Obtener banners de servicios (banner grabbing)
- Identificar servicios según puerto o banner
- Buscar vulnerabilidades (CVE) relacionadas con el software detectado
- Ordenar CVEs por criticidad (Critical, High, Medium, Low)
- Exportar resultados en JSON
- Exportar reportes en TXT (estilo auditoría)
- Ejecutar escaneos multithreaded para mayor velocidad
- Usar parámetros desde la línea de comandos

---

## Características principales

### Escaneo de puertos
Permite escanear un rango completo, por ejemplo:  
`1-1024`.

### Banner grabbing
Obtiene banners de servicios como SSH, HTTP, FTP, etc.

### CVE Lookup
Busca vulnerabilidades asociadas al software detectado en el banner.

### Reportes
- Exportación en formato JSON
- Exportación en formato TXT

---

## Ejemplos de uso

Escaneo normal:
```bash
python run.py scanme.nmap.org 1-200
```

Escaneo rápido:
```bash
python run.py scanme.nmap.org 1-500 --threads 300
```

Exportar JSON:
```bash
python run.py scanme.nmap.org 1-200 --json reporte.json
```

Exportar TXT:
```bash
python run.py scanme.nmap.org 1-200 --txt reporte.txt
```

Sin buscar  CVEs:
```bash
python run.py scanme.nmap.org --no-cve
```

Sin obtener banners:
```bash
python run.py scanme.nmap.org --no-banner
```

### INSTALACIÓN
git clone https://github.com/francisco0204/portscanner-python
cd portscanner-python
pip install -r requirements.txt

### TECNOLOGÍAS USADAS

Python 3
sockets
threading
colorama
argparse
requests // urllib
JSON / TXT para reportes

### AUTOR

Desarrollado por Francisco Cherbavaz.
Proyecto orientado al aprendizaje y práctica de ciberseguridad.
Este proyecto es únicamente para fines educativos.
No debe utilizarse para escanear sistemas sin autorización.
