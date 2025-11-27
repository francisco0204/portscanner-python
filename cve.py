import requests

def search_cve(product):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}"

    try:
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return []

        data = response.json()

        vulns = data.get("vulnerabilities", [])

        cve_list = []
        for item in vulns[:5]:  # solo 5 primeros
            cve_data = item["cve"]

            cve_id = cve_data["id"]
            description = cve_data["descriptions"][0]["value"]

            # Obtener severidad (puede estar en varios lugares)
            metrics = cve_data.get("metrics", {})

            severity = "N/A"
            score = "N/A"

            # CVSS v3.1
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = metrics["cvssMetricV31"][0]["baseSeverity"]
                score = cvss["baseScore"]

            # CVSS v3.0
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                severity = metrics["cvssMetricV30"][0]["baseSeverity"]
                score = cvss["baseScore"]

            # CVSS v2 (fallback)
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss["baseScore"]
                # severidad basada en score CVSS2
                if score >= 9:
                    severity = "CRITICAL"
                elif score >= 7:
                    severity = "HIGH"
                elif score >= 4:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            cve_list.append({
                "id": cve_id,
                "summary": description,
                "severity": severity,
                "score": score
            })

        return cve_list

    except Exception:
        return []
