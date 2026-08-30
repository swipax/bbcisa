# Yama Önceliği Panosu — CISA KEV + EPSS

CISA'nın **Known Exploited Vulnerabilities (KEV)** kataloğunu ve FIRST.org'un
**EPSS** (Exploit Prediction Scoring System) skorlarını birleştirip, hangi
CVE'nin önce yamanması gerektiğini gösteren, kendi kendini güncelleyen statik
bir dashboard.

Mimari, [Otomatik CTI Bülteni] projesindeki ile aynıdır: GitHub Actions ile
periyodik veri çekme + statik GitHub Pages sitesi.

## Nasıl çalışır

1. `scripts/fetch_and_rank.py`:
   - CISA KEV JSON kataloğunu indirir.
   - Kataloğdaki her CVE için FIRST.org EPSS API'sinden istismar olasılığı skorunu çeker.
   - Her kayıt için bir **urgency_score** hesaplar:
     - Süresi geçmiş (overdue) kayıtlar her zaman en üstte.
     - Son tarihe (dueDate) yaklaştıkça puan artar.
     - EPSS skoru ek ağırlık olarak eklenir.
   - Sonucu `site/data.json` dosyasına yazar.
2. `.github/workflows/update.yml`:
   - Her gün 06:00 UTC'de (istersen cti-bulletin'deki gibi 2 günde bire çevirebilirsin) script'i çalıştırır.
   - `data.json`'daki değişikliği commit'ler.
   - `site/` klasörünü GitHub Pages'e deploy eder.
3. `site/index.html`:
   - `data.json`'u okuyup arama, ransomware filtresi ve sıralama seçenekleriyle
     bir tablo halinde gösterir. Sunucu tarafı yok — tamamen statik.

## Kurulum

1. Bu klasörü yeni bir GitHub reponun köküne kopyala.
2. Repo ayarlarında **Settings → Pages → Source: GitHub Actions** seç.
3. **Settings → Actions → General → Workflow permissions** kısmından
   "Read and write permissions" seçeneğini aç (script'in `data.json`'u
   commit'leyebilmesi için gerekli).
4. `workflow_dispatch` ile Actions sekmesinden elle bir kere çalıştır, ilk
   `data.json` üretilsin.
5. Pages URL'in birkaç dakika içinde yayına alınır.

## Sonraki adımlar (henüz yapılmadı)

- **Watchlist**: KEV'de olmayan ama EPSS skoru çok yüksek (örn. >%90) CVE'leri
  ayrı bir "izleme listesi" bölümünde göstermek — henüz KEV'e girmemiş ama
  girme ihtimali yüksek zafiyetleri erken yakalamak için.
- CTI bülteni sitesindeki görsel kimlikle hizalamak.
- Vendor/ürün bazlı filtre eklemek.
- Geçmiş veriyi arşivleyip trend grafiği (KEV giriş hızı, ortalama yama süresi vb.) eklemek.

[Otomatik CTI Bülteni]: ../cti-bulletin
