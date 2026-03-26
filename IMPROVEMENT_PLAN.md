# OTrap v2.0 — Geliştirme Planı

Her faz tamamlandığında **bekle**, kullanıcı **"devam et"** deyince bir sonraki faza geç.

---

## TAMAMLANAN FAZLAR

### FAZ A — Hızlı Düzeltmeler ✅
- A1 IOC Extractor: IP adresini her severity'de yaz
- A2 Users: Kullanıcı düzenleme formu
- A2b Şifre Değiştirme / Sıfırlama
- A3 Session Detail: Eksik alanları göster
- A4 Session Detail: Timeline'da dst_port göster
- A5 Session Detail: Event metadata modal
- A6 Session Detail: MITRE description göster
- A7 Audit Log: Filtreleme paneli
- A8 Audit Log: Eksik ACTION_COLORS + CSV export

### FAZ B — Session Triage Workflow ✅
- B1 Session status alanı (DB kolonu: triage_status, triage_note)
- B2 `PATCH /sessions/{id}/triage` API endpoint
- B3 Sessions listesine Status kolonu + triage_status filtresi
- B4 Session detail: triage panel

### FAZ C — Dashboard Güçlendirme ✅
- C1 3 yeni KPI: Active Sensors, Sessions Today, Unique IPs (24h)
- C2 Protocol Distribution bar chart
- C3 Events — Last 24 Hours histogram
- C4 Live feed satırları tıklanabilir → session detayına navigate

### FAZ D — Sensor Geliştirmeleri ✅
- D1 Sensor rename (UI + API)
- D2 Sensor linked sessions (expand row)

### FAZ E — Entegrasyon Genişletme ✅
- E1 Syslog / CEF export
- E2 Generic Webhook alert
- E3 Alert throttle / dedup (Redis cooldown)

### FAZ F — UX / Export ✅
- F1 Sessions tablosunda kolon sıralama
- F2 JSON / STIX 2.1 export
- F3 Notification bell

### FAZ G — Altyapı ✅
- G1 `make update-ip` komutu
- G2 Backup/Restore scripti
- G3 DB index optimizasyonu

### FAZ H — Güvenilirlik ✅
- H1 Sensor heartbeat timeout → auto-offline
- H2 DB migration kontrolü (run_migrations idempotent)

### FAZ I — GeoIP Entegrasyonu ✅
- I1 Backend GeoIP lookup (MaxMind MMDB + Redis cache)
- I2 Session detail ve list'te ülke bayrağı
- I3 Dashboard: Top Attacker Countries

### FAZ J — IOC Global View ✅
- J1 Global IOC endpoint
- J2 IOC Global View sayfası (UI)

### FAZ K — Güvenlik Sertleştirme ✅
- K1 CSP nonce tabanlı, unsafe-inline kaldır
- K2 Login rate limiting

### FAZ N — Dashboard Derinleştirme ✅
- N1 KPI trend okları (24h vs önceki 24h karşılaştırması)
- N2 Dashboard zaman aralığı seçici (24h / 7d / 30d)

### FAZ O — Operasyonel İyileştirmeler ✅
- O1 Toplu session triage (bulk triage — checkbox + action bar)
- O2 SMTP delivery log (model + API + UI)

### FAZ P — Saldırgan İstihbarat Sayfası ✅
- P1 Attacker IP profil sayfası `/attackers/{ip}`
- P2 Session detayında aynı IP'den ilişkili sessionlar
- Attackers index sayfası `/attackers` (Top 50 IPs, 24h/7d/30d toggle)

### FAZ Q — Gelişmiş Konfigürasyon ✅
- Q1 Sensor protokol konfigürasyonu (UI'dan enable/disable + PLC kimliği)
- Q2 Alert rule engine (CRUD + condition matcher + notify/auto-triage)

### FAZ R1 — Raporlama: Temel Sistem ✅
- Reports tablosu (DB model: id, title, range_label, range_hours, generated_at, data JSONB)
- `GET/POST /reports`, `GET/DELETE /reports/{id}`, `POST /reports/bulk-delete` API endpoints
- `/reports` sayfası: rapor listesi, checkbox ile tekli/toplu silme
- "Generate Report" modal: başlık + zaman aralığı seçimi, tüm verileri snapshot olarak kaydeder
- `/print/report?id=xxx` ile kaydedilmiş raporu açma

---

## BEKLEYEN FAZLAR

---

### FAZ R2 — Rapor Görüntüleme UX ⏳

**Sorun:** "View / Print" butonu yeni sekme açıyor. Kullanıcı raporu görür, Close'a basar → sekme kapanır. Bu akış mantıksız ve kullanışsız.

**Çözüm:** Ayrı sekme yerine `/reports` sayfası içinde **tam ekran overlay modal**.
- "View / Print" butonuna basınca rapor içeriği aynı sayfa içinde tam ekran overlay olarak açılır
- Overlay'in üstünde ince action bar: rapor başlığı + "Print / Save as PDF" + "✕ Close"
- ✕'e basınca overlay kapanır, kullanıcı rapor listesine döner
- `window.print()` ile yazdırma tetiklenir; `@media print` overlay dışını gizler
- Yeni sekme açılmaz, `window.close()` çağrılmaz

**Değişecek dosyalar:**
- `ui/app/(operator)/reports/page.tsx` — modal state + overlay renderer eklenir
- `ui/app/print/report/page.tsx` — artık sadece standalone fallback (doğrudan URL açılırsa), overlay versiyonu `reports/page.tsx` içinde inline olur

---

### FAZ R3 — Rapor Dark Theme Tasarımı ⏳

**Sorun:** Mevcut rapor beyaz/kurumsal görünümlü. Uygulama koyu tema kullanıyor; rapor bununla uyumsuz.

**Çözüm:** Uygulamanın koyu teması PDF'e taşınır. `print-color-adjust: exact` ile arka plan renkleri baskıda korunur. Kullanıcı "Background graphics" aktif ederse full dark, etmezse beyaz üzerine düşer — her iki durumda okunabilir.

**Renk Paleti:**

| Kullanım | Renk |
|---|---|
| Sayfa zemini | `#080c14` |
| Kart / surface | `#0f1623` |
| Yükseltilmiş alan | `#162032` |
| Kenarlık | `#1e2d45` |
| Ana metin | `#f0f4ff` |
| İkincil metin | `#94a3b8` |
| Accent | `#3b82f6` |

**Tasarım Detayları:**

1. **Header** — koyu panel, sol kenarda 4px mavi accent şerit; sağda CONFIDENTIAL rozeti (amber)
2. **Bölüm başlıkları** — `border-left: 3px solid accent` + uppercase + sağa uzanan `#1e2d45` divider
3. **KPI kartlar** — `#162032` bg + `#1e2d45` border; alert kartlarda kırmızı tint
4. **Dağılım barları** — koyu kart içinde; bar zemini `#1e2d45`, dolgu uygulamadaki severity/protocol renkleri
5. **Event Timeline** — SVG koyu bg, ızgara `#1e2d45`, barlar kırmızı/turuncu/mavi yoğunluk skalası
6. **Tablolar** — header `#162032`, tek/çift satır `#0f1623`/`#111827`, kenarlık `#1e2d45`; severity badge'leri uygulamadaki tam renkli rozetler
7. **Footer** — `#0f1623` panel, CONFIDENTIAL amber

**Print CSS eklentileri:**
```css
* { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
@page { size: A4 portrait; margin: 14mm 12mm; }
```

Action bar'a bilgi notu eklenir: _"Enable Background graphics in print dialog for dark theme"_

**Değişecek dosyalar:**
- `ui/app/(operator)/reports/page.tsx` — overlay renderer bölümündeki tüm inline style'lar güncellenir

---

### FAZ L — Bug Düzeltmeleri (Sensör Doğruluğu) ⏳

**L1 — HMI POST Body Parse Hatası**
- **Dosya:** `sensor/internal/protocols/hmi/server.go`
- **Sorun:** POST body okunmuyor (`body := ""`). SQLi / XSS payload'ları kaçırılıyor.
- **Düzeltme:** `io.LimitReader` ile max 4KB oku, `combined`'a ekle, `r.Body.Close()` çağır.

**L2 — Attack Phase Güncellenmesi**
- **Dosya:** `manager/analyzer/worker.py`
- **Sorun:** `attack_phase` ilk event'e bakılarak set ediliyor, hiç güncellenmiyor. CPU STOP gelse bile `initial_access` kalıyor.
- **Düzeltme:** `_update_session`'da her event'te `_infer_attack_phase` daha ileri aşamayı döndürüyorsa güncelle. Sıra: `initial_access < discovery < lateral_movement < impact`.

**L3 — Modbus MEI Yanlış Etiketleniyor**
- **Dosya:** `sensor/internal/protocols/modbus/server.go`
- **Sorun:** MEI (0x2B) isteği `MODBUS_UNKNOWN_FUNCTION` olarak loglanıyor. Shodan/Nmap taramaları gömülü kalıyor.
- **Düzeltme:** `fcEncapsulatedTransport` case'ini `MODBUS_SCANNER_DETECTED` (severity: MEDIUM) olarak emit et.

---

### FAZ M — Veri Zenginleştirme ⏳

**M1 — GeoIP Org/ASN Alanı UI'da Göster**
- Session detail'e "ASN/Org" card'ı ekle (`session.geo.org` varsa).
- Sessions listesinde flag'e hover tooltip olarak göster.

**M2 — Password IOC Extraction**
- `manager/analyzer/ioc_extractor.py` — `artifact_type == "password"` → `type: "password"`, `confidence: 0.85` ile IOC oluştur.

**M3 — IOC Sayfasında Value Bazlı Session Filtreleme**
- Session count butonunu tıklanınca IP tipi IOC'ta `/sessions?source_ip={value}` yönlendir.

---

## Uygulama Sırası

```
✅  A → B → C → D → E → F → G → H → I → J → K
✅  N → O → P → Q → R1

⏳  R2  Rapor görüntüleme UX (in-page modal)
⏳  R3  Rapor dark theme tasarımı
⏳  L   Bug düzeltmeleri (sensör)
⏳  M   Veri zenginleştirme
```

Her faz öncesi **bekle** — "devam et" komutu alınınca uygula.
