# Demo purpose mini vulnerability database

VULN_SIGNATURES = [
    {
        "service": "FTP",
        "banner_contains": "vsftpd 2.3.4",
        "risk": "High",
        "description": "vsftpd 2.3.4 backdoor zafiyeti ile bilinir."
    },
    {
        "service": "SSH",
        "banner_contains": "OpenSSH_5.",
        "risk": "Medium",
        "description": "Eski OpenSSH sürümleri bilinen zafiyetlere sahiptir. Güncelleme önerilir."
    },
]