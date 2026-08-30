#!/usr/bin/env python3


import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, date
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EUVD_SEARCH_URL = "https://euvdservices.enisa.europa.eu/api/vulnerabilities"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100
EUVD_PAGE_SIZE = 100
RECENCY_HALF_LIFE_DAYS = 14   # bu süre geçtikçe güncellik puanı yarıya iner
RANSOMWARE_BONUS = 150
EPSS_WEIGHT = 250             # epss_score (0-1) * bu katsayı = ek puan
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "site" / "data.json"
USER_AGENT = "cisa-kev-epss-dashboard/1.1 (+github actions bot)"


def http_get_json(url: str, retries: int = 3, backoff: float = 2.0):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            last_err = e
            print(f"[warn] {url} denemesi {attempt}/{retries} başarısız: {e}", file=sys.stderr)
            time.sleep(backoff * attempt)
    raise RuntimeError(f"{url} adresinden veri alınamadı: {last_err}")


# ---------- Kaynak 1: CISA KEV ----------

def fetch_kev():
    data = http_get_json(KEV_URL)
    vulns = data.get("vulnerabilities", [])
    print(f"[info] CISA KEV kataloğunda {len(vulns)} kayıt bulundu.")
    return vulns


def parse_iso_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


# ---------- Kaynak 2: ENISA EUVD ----------

def parse_euvd_date(date_str):
    """EUVD tarih formatı: 'May 7, 2025, 12:00:00 AM'"""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%b %d, %Y, %I:%M:%S %p").date()
    except ValueError:
        return None


def extract_cve_from_aliases(aliases_str):
    if not aliases_str:
        return None
    for token in aliases_str.split("\n"):
        token = token.strip()
        if token.upper().startswith("CVE-"):
            return token.upper()
    return None


def fetch_euvd_exploited():
    """/api/vulnerabilities?exploited=true adresinden sayfalayarak tüm aktif istismar edilen kayıtları çeker."""
    records = []
    page = 0
    total = None
    while True:
        params = {"exploited": "true", "size": str(EUVD_PAGE_SIZE), "page": str(page)}
        url = f"{EUVD_SEARCH_URL}?{urllib.parse.urlencode(params)}"
        try:
            data = http_get_json(url)
        except RuntimeError as e:
            print(f"[warn] EUVD sayfa {page} alınamadı, EUVD çekimi burada durduruluyor: {e}", file=sys.stderr)
            break
        items = data.get("items", [])
        if total is None:
            total = data.get("total", len(items))
            print(f"[info] EUVD'de exploited=true olarak toplam {total} kayıt bildiriliyor.")
        if not items:
            break
        records.extend(items)
        page += 1
        if page * EUVD_PAGE_SIZE >= total:
            break
        time.sleep(0.3)  # API'ye nazik davranalım
    print(f"[info] EUVD'den {len(records)} kayıt çekildi.")
    return records


# ---------- EPSS (tek kaynak, tutarlılık için) ----------

def fetch_epss_scores(cve_ids):
    scores = {}
    ids = sorted(set(cve_ids))
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


# ---------- Puanlama ----------

def compute_urgency(age_days, epss_score, ransomware_known):
    """
    Yüksek puan = daha acil / daha güncel.
    - Güncellik: age_days arttıkça üstel olarak azalır (yarı ömür: RECENCY_HALF_LIFE_DAYS gün).
      Bugün eklenen bir kayıt ~1000 puan alır, 14 gün sonra ~500, 90 gün sonra ~12'ye düşer.
    - EPSS skoru (0-1) ek ağırlık olarak eklenir.
    - Bilinen ransomware kullanımı sabit bir bonus ekler.
    """
    if age_days is None or age_days < 0:
        recency = 200.0  # tarih bilgisi yoksa/gelecekteyse orta bir değer ver
    else:
        recency = 1000.0 * (0.5 ** (age_days / RECENCY_HALF_LIFE_DAYS))
    epss_bonus = (epss_score or 0.0) * EPSS_WEIGHT
    ransomware_bonus = RANSOMWARE_BONUS if ransomware_known else 0.0
    return recency + epss_bonus + ransomware_bonus


def days_between(d: date, today: date):
    if d is None:
        return None
    return (today - d).days


# ---------- Birleştirme ----------

def build_dataset():
    today = datetime.now(timezone.utc).date()

    kev_entries = fetch_kev()
    euvd_entries = fetch_euvd_exploited()

    kev_cve_ids = {v["cveID"] for v in kev_entries if v.get("cveID")}

    # Tüm CVE'ler için tek kaynaktan (FIRST) tutarlı EPSS skoru çek
    euvd_cve_ids = {extract_cve_from_aliases(e.get("aliases")) for e in euvd_entries}
    euvd_cve_ids.discard(None)
    all_cve_ids = kev_cve_ids | euvd_cve_ids
    epss_scores = fetch_epss_scores(all_cve_ids)

    records = []

    # --- CISA KEV kayıtları ---
    for v in kev_entries:
        cve_id = v.get("cveID")
        date_added = parse_iso_date(v.get("dateAdded"))
        due_date = v.get("dueDate")
        age_days = days_between(date_added, today)
        due_days_remaining = None
        if due_date:
            due_d = parse_iso_date(due_date)
            if due_d:
                due_days_remaining = (due_d - today).days
        epss = epss_scores.get(cve_id, {})
        ransomware_known = (v.get("knownRansomwareCampaignUse") == "Known")
        urgency = compute_urgency(age_days, epss.get("score"), ransomware_known)

        records.append({
            "source": "CISA KEV",
            "cve_id": cve_id,
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "short_description": v.get("shortDescription"),
            "date_added": v.get("dateAdded"),
            "age_days": age_days,
            "due_date": due_date,
            "due_days_remaining": due_days_remaining,
            "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            "epss_score": epss.get("score"),
            "epss_percentile": epss.get("percentile"),
            "urgency_score": round(urgency, 2),
        })

    # --- EUVD kayıtları (KEV'de zaten olan CVE'leri tekrar eklemiyoruz) ---
    for e in euvd_entries:
        cve_id = extract_cve_from_aliases(e.get("aliases"))
        if cve_id and cve_id in kev_cve_ids:
            continue  # zaten CISA KEV'den geldi, mükerrer olmasın

        ref_date_str = e.get("exploitedSince") or e.get("dateUpdated") or e.get("datePublished")
        ref_date = parse_euvd_date(ref_date_str)
        age_days = days_between(ref_date, today)

        products = e.get("enisaIdProduct") or []
        vendors = e.get("enisaIdVendor") or []
        product_name = products[0]["product"]["name"] if products else None
        vendor_name = vendors[0]["vendor"]["name"] if vendors else None

        epss = epss_scores.get(cve_id, {}) if cve_id else {}
        # EUVD'nin kendi epss alanı 0-100 ölçeğinde; FIRST'te bulamazsak yedek olarak onu kullan (100'e bölerek)
        epss_score = epss.get("score")
        if epss_score is None and e.get("epss") is not None:
            epss_score = float(e["epss"]) / 100.0

        urgency = compute_urgency(age_days, epss_score, ransomware_known=False)

        records.append({
            "source": "EUVD",
            "cve_id": cve_id or e.get("id"),
            "vendor": vendor_name,
            "product": product_name,
            "vulnerability_name": None,
            "short_description": e.get("description"),
            "date_added": ref_date_str,
            "age_days": age_days,
            "due_date": None,
            "due_days_remaining": None,
            "ransomware_use": "Unknown",
            "epss_score": epss_score,
            "epss_percentile": epss.get("percentile"),
            "urgency_score": round(urgency, 2),
            "euvd_id": e.get("id"),
        })

    records.sort(key=lambda r: r["urgency_score"], reverse=True)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(records),
        "sources": {"cisa_kev": len(kev_cve_ids), "euvd_only": sum(1 for r in records if r["source"] == "EUVD")},
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
