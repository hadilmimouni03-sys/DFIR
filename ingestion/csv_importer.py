import csv, sys
csv.field_size_limit(sys.maxsize)

def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        for i, row in enumerate(csv.DictReader(f)):
            yield i, row

def headers(path):
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        return next(csv.reader(f), [])
