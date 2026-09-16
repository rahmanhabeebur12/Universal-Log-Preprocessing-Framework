import re
from app.parsers.base import BaseParser, ParsedEvent

SYSLOG = re.compile(r"^(?:<(?P<priority>\d{1,3})>)?(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+))\s+(?P<hostname>\S+)\s+(?P<body>.*)$")
ASA = re.compile(r"%(?P<facility>ASA)-(?P<severity>\d)-(?P<message_id>\d+):\s*(?P<message>.*)")
CONNECTION = re.compile(r"(?P<action>Built|Teardown|Deny|Denied)\s+(?:inbound|outbound\s+)?(?P<protocol>TCP|UDP|ICMP)\s+connection\s+\d+\s+for\s+\w+:(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})/(?P<srcport>\d+)\s+to\s+\w+:(?P<dstip>\d{1,3}(?:\.\d{1,3}){3})/(?P<dstport>\d+)", re.I)
ASA_DENY = re.compile(r"(?P<action>Deny|Denied|Built|Teardown)\s+(?P<protocol>tcp|udp|icmp)\s+src\s+\S+:(?P<srcip>\S+?)/(?P<srcport>\d+)\s+dst\s+\S+:(?P<dstip>\S+?)/(?P<dstport>\d+)", re.I)


class SyslogParser(BaseParser):
    name, priority, formats = "syslog", 80, ("syslog",)

    def can_parse(self, raw_event: str) -> float:
        return 0.95 if SYSLOG.match(raw_event) else (0.8 if ASA.search(raw_event) else 0.0)

    def parse(self, raw_event: str) -> ParsedEvent:
        match = SYSLOG.match(raw_event)
        attrs: dict[str, str] = {}
        body = raw_event
        if match:
            attrs.update({k: v for k, v in match.groupdict().items() if v is not None and k != "body"})
            body = match.group("body")
        asa = ASA.search(body)
        if asa:
            attrs.update(asa.groupdict())
            body = asa.group("message")
            attrs["deviceVendor"] = "Cisco"
            attrs["deviceProduct"] = "ASA"
        attrs["message"] = body
        conn = ASA_DENY.search(body) or CONNECTION.search(body)
        if conn:
            attrs.update({k: v for k, v in conn.groupdict().items() if v})
        return ParsedEvent(attrs, "syslog")
