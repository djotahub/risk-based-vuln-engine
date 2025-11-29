import json
import xml.etree.ElementTree as ET
import os
import csv  

# --- 1. CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ASSET_FILE = os.path.join(SCRIPT_DIR, 'activos_criticos.json')
SCAN_FILE = os.path.join(SCRIPT_DIR, 'input_scan.xml')
EXPORT_FILE = os.path.join(SCRIPT_DIR, 'reporte_seguridad_final.csv') # <--- Archivo de Salida

# Business Risk Factors
RISK_FACTORS = {
    "ALTA": 1.5,
    "MEDIA": 1.2,
    "BAJA": 1.0
}

# --- 2. INGESTION FUNCTIONS ---

def load_asset_database(file_path):
    print(f"[*] Loading asset database from {file_path}...")
    if not os.path.exists(file_path):
        print("[X] Error: Asset database file not found.")
        return {}
    try:
        with open (file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print(f"[OK] Loaded {len(data)} assets.")
            return data
    except json.JSONDecodeError:
        print("[X] Error decoding JSON.")
        return {}

def parse_scan_report(file_path):
    print(f"[*] Parsing scan report from {file_path}...")
    vuln_list = []
    if not os.path.exists(file_path):
        print("[X] Scan report file not found.")
        return []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for host in root.findall('host'):
            ip_obj = host.find('address')
            ip = ip_obj.get('addr') if ip_obj is not None else 'Unknown'

            for vuln in host.findall('vulnerability'):
                name = vuln.get('name')
                cvss_raw = vuln.get('cvss')
                vuln_list.append({
                    'ip': ip,
                    'vuln_name': name,
                    'cvss_base': float(cvss_raw) if cvss_raw else 0.0
                })
        print(f"[OK] Found {len(vuln_list)} vulnerabilities.")
        return vuln_list
    except Exception as e:
        print(f"[X] Error parsing XML: {e}")
        return []

# --- 3. CORE LOGIC ---

def process_risk_analysis(vuln_data, asset_db):
    print("[*] Processing Risk Logic and Zero Trust Rules...")
    prioritized_list = []
    rogue_devices = [] 

    for finding in vuln_data:
        ip = finding['ip']
        cvss = finding['cvss_base']
        vuln_name = finding['vuln_name']

        if ip in asset_db:
            # Activo Conocido
            asset_info = asset_db[ip]
            criticality = asset_info.get('criticidad', 'BAJA')
            hostname = asset_info.get('hostname', 'Unknown')
            
            factor = RISK_FACTORS.get(criticality, 1.0)
            business_risk = round(cvss * factor, 2)
            
            prioritized_list.append({
                'priority_score': business_risk,
                'ip': ip,
                'hostname': hostname,
                'criticality': criticality,
                'vuln_name': vuln_name,
                'cvss_base': cvss
            })
        else:
            # Intruso
            rogue_devices.append({
                'ip': ip,
                'vuln_name': vuln_name,
                'action': "BLOCK & INVESTIGATE"
            })

    prioritized_list.sort(key=lambda x: x['priority_score'], reverse=True)
    return prioritized_list, rogue_devices

# --- 4. REPORTING (Console & CSV) ---

def print_console_report(legit_vulns, rogues):
    # Reporte en Pantalla (Para el técnico)
    if rogues:
        print("\n" + "!"*60)
        print(f"[ALERTA] {len(rogues)} UNAUTHORIZED DEVICES DETECTED")
        print("!"*60)
        for item in rogues:
            print(f"{item['ip']:<15} | {item['action']}")
            
    print("\n" + "="*80)
    print("BUSINESS PRIORITIZED PLAN")
    print("="*80)
    print(f"{'PRIORITY':<10} | {'IP':<15} | {'CRITICALITY':<12} | {'VULN'}")
    print("-" * 80)
    for row in legit_vulns:
        print(f"{row['priority_score']:<10} | {row['ip']:<15} | {row['criticality']:<12} | {row['vuln_name']}")

def export_to_csv(legit_vulns, rogues, filename):
    """
    Genera un archivo CSV compatible con Excel.
    """
    print(f"\n[*] Exporting data to Excel format ({filename})...")
    
    try:
        # 'w' es modo escritura, 'newline' evita lineas en blanco en Windows
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # --- PARTE 1: INTRUSOS ---
            if rogues:
                writer.writerow(["--- HIGH PRIORITY: ROGUE DEVICES DETECTED ---"])
                writer.writerow(["IP Address", "Vulnerability Found", "Required Action"])
                for r in rogues:
                    writer.writerow([r['ip'], r['vuln_name'], r['action']])
                writer.writerow([]) # Espacio en blanco

            # --- PARTE 2: VULNERABILIDADES ---
            writer.writerow(["--- BUSINESS PRIORITIZED REMEDIATION PLAN ---"])
            # Encabezados de columnas
            writer.writerow(["Business Priority", "IP Address", "Hostname", "Asset Criticality", "CVSS Base", "Vulnerability Name"])
            
            for item in legit_vulns:
                writer.writerow([
                    item['priority_score'],
                    item['ip'],
                    item['hostname'],
                    item['criticality'],
                    item['cvss_base'],
                    item['vuln_name']
                ])
                
        print(f"[OK] Report saved successfully: {filename}")
        
    except Exception as e:
        print(f"[X] Error saving CSV: {e}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("--- STARTING PRIORITY ENGINE ---\n")

    asset_db = load_asset_database(ASSET_FILE)
    scan_data = parse_scan_report(SCAN_FILE)

    if asset_db and scan_data:
        legit_vulns, intruders = process_risk_analysis(scan_data, asset_db)
        
        # 1. Mostrar en pantalla (Rápido)
        print_console_report(legit_vulns, intruders)
        
        # 2. Guardar en Excel/CSV (Entregable)
        export_to_csv(legit_vulns, intruders, EXPORT_FILE)
            
    else:
        print("\n[X] CRITICAL ERROR: Missing data inputs.")