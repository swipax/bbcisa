#!/usr/bin/env python3
"""
CISA KEV + EPSS Yama Önceliği Panosu — veri toplama ve puanlama script'i.

Akış:
  1) CISA KEV kataloğunu indir (aktif olarak istismar edilen CVE'ler).
  2) Her CVE için FIRST.org EPSS skorunu al (istismar olasılığı, 0-1).
  3) Her kayıt için bir "urgency_score" hesapla:
       - Süresi geçmiş (overdue) kayıtlar her zaman en üstte.
       - Kalan gün sayısı azaldıkça puan artar.
       - EPSS skoru ikincil ağırlık olarak eklenir (yüksek EPSS = daha acil).
  4) Sonucu site/data.json olarak yaz (statik site bunu okuyup render eder).

Bu script GitHub Actions üzerinde periyodik olarak çalışacak şekilde tasarlandı
(cti-bulletin projesindeki aynı mimari: fetch -> process -> commit -> Pages).
"""

import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100  # FIRST.org API tek istekte çok sayıda CVE kabul eder; ihtiyat payı bırakıyoruz
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "site" / "data.json"
USER_AGENT = "cisa-kev-epss-dashboard/1.0 (+github actions bot)"


def http_get_json(url: str, retries: int = 3, backoff: float = 2.0):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_err = e
            print(f"[warn] {url} denemesi {attempt}/{retries} başarısız: {e}", file=sys.stderr)
            time.sleep(backoff * attempt)
    raise RuntimeError(f"{url} adresinden veri alınamadı: {last_err}")


def fetch_kev():
    data = http_get_json(KEV_URL)
    vulns = data.get("vulnerabilities", [])
    print(f"[info] KEV kataloğunda {len(vulns)} kayıt bulundu.")
    return vulns


def fetch_epss_scores(cve_ids):
    """CVE listesi için EPSS skorlarını toplu şekilde çeker -> {cve_id: {score, percentile}}"""
    scores = {}
    ids = list(cve_ids)
    for i in range(0, len(ids), EPSS_BATCH_SIZE):
        batch = ids[i:i + EPSS_BATCH_SIZE]
        url = f"{EPSS_URL}?cve={','.join(batch)}"
        try:
            data = http_get_json(url)
        except RuntimeError as e:
            print(f"[warn] EPSS batch alınamadı, bu grup atlanıyor: {e}", file=sys.stderr)
            continue
        for row in data.get("data", []):
            scores[row["cve"]] = {
                "score": float(row.get("epss", 0.0)),
                "percentile": float(row.get("percentile", 0.0)),
            }
    print(f"[info] {len(scores)} CVE için EPSS skoru alındı.")
    return scores


def days_until(date_str):
    """dueDate string'ini (YYYY-MM-DD) bugüne göre kalan gün sayısına çevirir. Negatifse süresi geçmiş demektir."""
    try:
        due = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    today = datetime.now(timezone.utc)
    return (due - today).days


def compute_urgency(days_remaining, epss_score):
    """
    Yüksek skor = daha acil.
    - Süresi geçmişse: 1000 tabanından başlayıp ne kadar geciktiyse o kadar artan bir puan.
    - Süresi geçmemişse: kalan güne ters orantılı bir puan (0-500 aralığı).
    - EPSS skoru (0-1) ek ağırlık olarak eklenir (x100), yani aynı vade grubunda
      istismar olasılığı daha yüksek olan CVE öne çıkar.
    """
    epss_bonus = (epss_score or 0.0) * 100
    if days_remaining is None:
        return 50 + epss_bonus  # vade bilgisi yoksa orta öncelik
    if days_remaining < 0:
        return 1000 + min(abs(days_remaining), 900) + epss_bonus
    return max(0, 500 - days_remaining) + epss_bonus


def build_dataset():
    kev_entries = fetch_kev()
    cve_ids = [v["cveID"] for v in kev_entries if v.get("cveID")]
    epss_scores = fetch_epss_scores(cve_ids)

    records = []
    for v in kev_entries:
        cve_id = v.get("cveID")
        due_date = v.get("dueDate")
        remaining = days_until(due_date)
        epss = epss_scores.get(cve_id, {})
        urgency = compute_urgency(remaining, epss.get("score"))
        records.append({
            "cve_id": cve_id,
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "due_date": due_date,
            "days_remaining": remaining,
            "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            "short_description": v.get("shortDescription"),
            "epss_score": epss.get("score"),
            "epss_percentile": epss.get("percentile"),
            "urgency_score": round(urgency, 2),
        })

    records.sort(key=lambda r: r["urgency_score"], reverse=True)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_catalog_version": None,
        "count": len(records),
        "records": records,
    }
    return output


def main():
    dataset = build_dataset()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(dataset, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[info] {dataset['count']} kayıt {OUTPUT_PATH} dosyasına yazıldı.")


if __name__ == "__main__":
    main()
