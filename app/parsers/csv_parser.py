import csv
import io
from app.parsers.base import BaseParser, ParsedEvent


class CSVParser(BaseParser):
    name, priority, formats = "csv", 65, ("csv",)

    def can_parse(self, raw_event: str) -> float:
        try:
            rows = list(csv.reader(io.StringIO(raw_event)))
        except csv.Error:
            return 0.0
        if len(rows) >= 2 and len(rows[0]) >= 3 and len(rows[0]) == len(rows[1]):
            return 0.92
        return 0.0

    def parse(self, raw_event: str) -> ParsedEvent:
        rows = list(csv.DictReader(io.StringIO(raw_event)))
        if len(rows) != 1:
            raise ValueError("CSV event must contain one header and one data row")
        if None in rows[0]:
            raise ValueError("CSV row has more values than headers")
        return ParsedEvent(dict(rows[0]), "csv")
