"""SOAP/WSDL adapter — parses a WSDL document and returns one
DiscoveredEndpoint per SOAP operation."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from agent.logger import get_logger
from agent.recon.fingerprint import DiscoveredEndpoint

log = get_logger(__name__)

_DEFAULT_SOAP_PATH = "/ws"


def _find_soap_address(root: ET.Element) -> str:
    """Extract the SOAP service URL from a WSDL document."""
    for elem in root.iter():
        local = elem.tag.split("}")[-1].lower()
        if local == "address":
            loc = elem.get("location", "")
            if loc:
                return loc
    return ""


def extract_operation_names(wsdl_xml: str) -> list[str]:
    """Return a deduplicated list of operation names from a WSDL document."""
    try:
        root = ET.fromstring(wsdl_xml)
    except ET.ParseError as exc:
        log.warning("soap.wsdl_parse_error", error=str(exc))
        return []

    names: list[str] = []
    for elem in root.iter():
        if elem.tag.split("}")[-1].lower() == "operation":
            name = elem.get("name")
            if name:
                names.append(name)

    return list(dict.fromkeys(names))


def parse_wsdl(
    wsdl_xml: str,
    default_path: str = _DEFAULT_SOAP_PATH,
) -> list[DiscoveredEndpoint]:
    """Parse WSDL and return one DiscoveredEndpoint per SOAP operation."""
    try:
        root = ET.fromstring(wsdl_xml)
    except ET.ParseError as exc:
        log.warning("soap.wsdl_parse_error", error=str(exc))
        return []

    soap_path = default_path
    address = _find_soap_address(root)
    if address:
        parsed = urlparse(address)
        if parsed.path:
            soap_path = parsed.path

    endpoints: list[DiscoveredEndpoint] = []
    seen: set[str] = set()

    for elem in root.iter():
        if elem.tag.split("}")[-1].lower() != "operation":
            continue
        name = elem.get("name")
        if not name or name in seen:
            continue
        seen.add(name)

        params: list[str] = []
        for child in elem:
            if child.tag.split("}")[-1].lower() == "input":
                msg = child.get("message", "").split(":")[-1]
                if msg:
                    params.append(msg)

        endpoints.append(DiscoveredEndpoint(
            method="POST",
            path=soap_path,
            params=params,
            description=f"SOAP operation: {name}",
        ))

    if not endpoints:
        endpoints.append(DiscoveredEndpoint(
            method="POST",
            path=soap_path,
            description="SOAP endpoint (no operations parsed)",
        ))

    return endpoints
