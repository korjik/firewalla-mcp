"""Descriptive page-level observations, never behavioral or threat attribution."""
from collections import defaultdict
from datetime import datetime, timezone


def summarize_page(page):
    totals={"upload_bytes":0,"download_bytes":0,"records_with_unknown_bytes":0}
    known={"upload_bytes":0,"download_bytes":0}
    destinations={}
    hours=defaultdict(int)
    for row in page["records"]:
        hour=datetime.fromtimestamp(row["timestamp"],timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")
        hours[hour]+=1
        key=(row["domains"][0] if row["domains"] else row["destination_ip"]) or "unattributed"
        entry=destinations.setdefault(key,{"destination":key,"records":0,"upload_bytes":0,"download_bytes":0,"hours":set(),"known_byte_records":0})
        entry["records"]+=1;entry["hours"].add(hour)
        if row["upload_bytes"] is None or row["download_bytes"] is None:
            totals["records_with_unknown_bytes"]+=1
        if row["upload_bytes"] is not None or row["download_bytes"] is not None:entry["known_byte_records"]+=1
        for field in ("upload_bytes","download_bytes"):
            if row[field] is not None:
                known[field]+=1
                totals[field]+=row[field];entry[field]+=row[field]
    ranked=sorted(destinations.values(),key=lambda x:x["upload_bytes"]+x["download_bytes"],reverse=True)
    recurring=[{"destination":r["destination"],"distinct_utc_hours":len(r["hours"]),"records":r["records"]} for r in ranked if len(r["hours"])>=3]
    for entry in ranked:
        entry["hours"]=sorted(entry["hours"])
        if entry["known_byte_records"]==0:entry["upload_bytes"]=entry["download_bytes"]=None
    for field in known:
        if page["records"] and known[field]==0:
            totals[field]=None
    totals["records_with_known_upload_bytes"]=known["upload_bytes"]
    totals["records_with_known_download_bytes"]=known["download_bytes"]
    return {"coverage":page.get("coverage",{}),"timezone":page.get("timezone","UTC"),
            "source_limitations":page.get("limitations"),"pagination":page.get("pagination"),"page_records":len(page["records"]),"page_totals":totals,"page_byte_totals_complete":totals["records_with_unknown_bytes"]==0,"top_destinations":ranked[:10],
            "utc_hourly_record_counts":dict(sorted(hours.items())),"repeated_destinations":recurring[:10],
            "next_offset":page["next_offset"],"index_counts_before_filters":page["index_counts_before_filters"],
            "anomaly_verdict":"not_assessed_without_baseline",
            "limitations":"Page-level descriptive aggregates only; not full-range totals. Repeated records can be background traffic or overlapping aggregates. No inference about deliberate browsing, sensitive interests, compromise, or application identity. Attribution/retention and pagination limits from the source page apply."}
