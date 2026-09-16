import re
from typing import Any

ACTIONS = {"accept":"allow","accepted":"allow","allow":"allow","allowed":"allow","permit":"allow","permitted":"allow","pass":"allow","built":"allow","deny":"deny","denied":"deny","block":"deny","blocked":"deny","drop":"deny","dropped":"deny","reject":"deny"}
PROTOCOLS = {"6":"tcp","17":"udp","1":"icmp"}


def action(value: Any) -> str:
    val = str(value).strip().lower()
    return ACTIONS.get(val, val)


def protocol(value: Any) -> str:
    val = str(value).strip().lower()
    return PROTOCOLS.get(val, val)


def identify_vendor(attrs: dict[str, Any], fmt: str) -> tuple[str, float, str]:
    vendor = str(attrs.get("deviceVendor") or attrs.get("device.vendor") or "")
    product = str(attrs.get("deviceProduct") or attrs.get("device.product") or "")
    devname = str(attrs.get("devname") or "")
    devid = str(attrs.get("devid") or "")
    if re.search(r"fortinet", vendor, re.I) or re.search(r"fortigate", product, re.I) or devid.startswith("FG") or (devname and "policyid" in attrs and "sentbyte" in attrs):
        return "Fortinet", 0.98, "Fortinet vendor/product, FortiGate device ID, or FortiOS field set"
    if re.search(r"cisco", vendor, re.I) or re.search(r"\bASA\b", product, re.I) or attrs.get("facility") == "ASA":
        return "Cisco", 0.99, "Cisco vendor/product or ASA message identifier"
    if re.search(r"palo alto", vendor, re.I) or re.search(r"pan.?os", product, re.I) or (fmt == "csv" and "Serial Number" in attrs and "Source address" in attrs):
        return "Palo Alto Networks", 0.97, "PAN-OS vendor/product or firewall CSV field set"
    if vendor:
        return vendor, 0.9, "Explicit deviceVendor field"
    return "Unknown", 0.0, "No reliable vendor evidence"
