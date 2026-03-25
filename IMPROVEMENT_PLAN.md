# OTrap v2.0 — Geliştirme ve Düzeltme Planı

Her adım tamamlandığında onay beklenir. Küçük, test edilebilir parçalar halinde ilerlenecektir.

---

## BLOK A — Hızlı Düzeltmeler (Mevcut veriyi daha iyi göster)

### A1 — IOC Extractor: IP adresini her severity'de yaz
**Dosya:** `manager/analyzer/ioc_extractor.py`
**Sorun:** Kaynak IP IOC'u sadece HIGH ve CRITICAL eventlerde yazılıyor.
Bu yüzden Modbus sessionlarının çoğunda (medium severity) attacker IP IOC olarak görünmüyor.
**Düzeltme:** Severity koşulunu kaldır, her event için kaynak IP'yi IOC olarak yaz.
**Test:** Yeni bir Modbus bağlantısı aç → session IOC tab'ında IP görünmeli.

---

### A2 — Users: Kullanıcı düzenleme formu
**Dosya:** `ui/app/(admin)/admin/users/page.tsx`
**Sorun:** `editTarget` state'i ve `Pencil` ikonu import edilmiş ama edit formu hiç implement edilmemiş.
Kullanıcının şifresini, rolünü veya email'ini değiştirmenin yolu yok.
**Düzeltme:**
- Tabloya "Edit" (kalem) butonu ekle
- Edit form: email, role, opsiyonel yeni şifre alanları
- `PUT /admin/users/{id}` API'yi çağır
**Test:** Kullanıcıya tıkla → form açılsın → rol değiştir → kaydet → listede güncellensin.

---

### A2b — Şifre Değiştirme / Sıfırlama
**İlgili dosyalar:**
- `manager/api/admin/users.py` (admin → kullanıcı şifresi sıfırlama)
- `manager/api/auth.py` (kullanıcı kendi şifresini değiştirme)
- `ui/app/(admin)/admin/users/page.tsx` (admin panel)
- `ui/app/login/page.tsx` (login sayfası)

**Parça 1 — Admin: kullanıcı şifresini sıfırlama**
- `PUT /admin/users/{id}` endpoint'ine `new_password` alanı ekle (opsiyonel, min 12 karakter)
- Users edit formuna "New Password" alanı ekle (boş bırakılırsa şifre değişmez)
- Test: Admin → edit user → yeni şifre gir → kaydet → eski şifreyle giriş yapılamadığını doğrula

**Parça 2 — Kullanıcı: kendi şifresini değiştirme**
- `POST /auth/change-password` endpoint'i ekle: `{ current_password, new_password }`
- Mevcut şifre doğrulanır, yeni şifre min 12 karakter kontrolü yapılır
- UI: Header/profil alanına "Change Password" modal ekle (tüm roller erişebilir)
- Test: Giriş yap → şifre değiştir → yeni şifreyle çıkış/giriş yap

**Parça 3 — Login sayfası: "Şifremi unuttum" akışı**
- SMTP yapılandırılmışsa: reset token üret, email gönder, token ile yeni şifre set et
- SMTP yapılandırılmamışsa: "Şifrenizi yöneticinizle sıfırlatın" mesajı göster
- `POST /auth/forgot-password` → token üret + mail gönder
- `POST /auth/reset-password` → token doğrula + şifreyi güncelle
- Test: SMTP aktifken → email gel → link tıkla → şifre sıfırla

---

### A3 — Session Detail: Eksik alanları göster
**Dosya:** `ui/app/(operator)/sessions/[id]/page.tsx`
**Sorun:** API `source_port`, `sensor_id`, `closed_at`, `metadata` döndürüyor ama UI'da hiçbiri gösterilmiyor.
**Düzeltme:** Meta cards grid'ine şu alanları ekle:
- Source Port (varsa)
- Sensor (sensor_id — tıklanabilir olursa daha iyi)
- Closed At (varsa, yoksa "Active")
**Test:** Session detail aç → yeni alanlar meta cards'da görünmeli.

---

### A4 — Session Detail: Timeline'da dst_port göster
**Dosya:** `ui/app/(operator)/sessions/[id]/page.tsx`
**Sorun:** Timeline event card'larında `dst_port` alanı mevcut ama gösterilmiyor.
Her event hangi porta gittiğini göstermek forensics için değerlidir.
**Düzeltme:** Timeline card'ının alt satırına `→ port :XXX` bilgisini ekle (sadece varsa).
**Test:** S7 session timeline aç → eventlerde `:102` gibi port görünmeli.

---

### A5 — Session Detail: Event metadata modal
**Dosya:** `ui/app/(operator)/sessions/[id]/page.tsx`
**Sorun:** Timeline'daki her event'e tıklanınca `event_metadata` JSON içeriği görünmüyor.
Modbus'ta function_code/register_address, S7'de szl_id gibi kritik alanlar bu metadata'da.
**Düzeltme:** Timeline event card'ına tıklanabilir yapı ekle → altında expand eden JSON detay bölümü açılsın (accordion).
**Test:** Modbus eventine tıkla → metadata JSON açılsın (function_code: 3 vs.).

---

### A6 — Session Detail: MITRE description göster
**Dosya:** `ui/app/(operator)/sessions/[id]/page.tsx` + `manager/api/sessions.py`
**Sorun:** `mitre_ics.py`'de her technique için açıklama yazılmış ama API'den dönülmüyor, UI'da da gösterilmiyor.
**Düzeltme:**
- `sessions.py` → `_session_summary` içinde mitre_techniques listesine `description` alanını ekle
- MITRE tab card'larına description paragrafı ekle
**Test:** Session MITRE tab → technique card altında açıklama metni görünmeli.

---

### A7 — Audit Log: Filtreleme paneli
**Dosya:** `ui/app/(admin)/admin/audit/page.tsx`
**Sorun:** 10.000 satırlık audit log'da belirli bir kullanıcının veya action türünün kaydını bulmak imkânsız. Filtre yok.
**Düzeltme:** Sayfa başına filter panel ekle:
- Username (text input)
- Action (select — mevcut ACTION_COLORS key'lerinden)
- Date range (from/to, sadece tarih — datetime-local değil)
- Filtreler API query param'a bağlansın: `?username=&action=&from=&to=`
**Test:** Filtrele → sadece ilgili kayıtlar dönsün.

---

### A8 — Audit Log: Eksik ACTION_COLORS + CSV export
**Dosya:** `ui/app/(admin)/admin/audit/page.tsx`
**Sorun A:** `purge_audit_log` ve `update_audit_retention` action'ları renk map'inde yok, gri (badge-noise) gösteriyor.
**Sorun B:** Session export var ama audit log export yok. Compliance için kritik.
**Düzeltme A:** ACTION_COLORS'a iki yeni entry ekle.
**Düzeltme B:** "Export CSV" butonu ekle → `GET /admin/audit/export/csv` endpoint'i + indirme.
**Test:** Audit log aç → purge satırı renkli görünsün; Export CSV tıkla → dosya insin.

---

## BLOK B — Session Triage Workflow

### B1 — Session status alanı (backend)
**Dosya:** `manager/db/models.py`
**Sorun:** SOC analisti bir session'ı incelediğinde "incelendi", "false positive", "eskalasyon" gibi işaretleyemiyor.
**Düzeltme:** `Session` modeline `triage_status` alanı ekle (new / investigating / reviewed / false_positive / escalated).
`create_all` ile otomatik oluşacak.
**Test:** `docker compose restart manager` → alan DB'de görünmeli.

---

### B2 — Session status: API endpoint
**Dosya:** `manager/api/sessions.py`
**Düzeltme:** `PATCH /sessions/{id}/triage` endpoint'i ekle — sadece `triage_status` ve opsiyonel `triage_note` alanlarını günceller.
Response olarak güncel session döner.
**Test:** `curl -X PATCH .../sessions/{id}/triage -d '{"triage_status":"reviewed"}'` → 200 OK.

---

### B3 — Session list: triage_status kolonu + filtresi
**Dosya:** `ui/app/(operator)/sessions/page.tsx`
**Düzeltme:**
- Tablo kolonuna triage_status ekle (badge: new=mavi, reviewing=sarı, reviewed=yeşil, fp=gri, escalated=kırmızı)
- Filter paneline "Status" dropdown ekle
**Test:** Sessions listesinde yeni kolon görünsün, filtrelenebilsin.

---

### B4 — Session detail: triage panel
**Dosya:** `ui/app/(operator)/sessions/[id]/page.tsx`
**Düzeltme:** Session header'ının altına küçük bir triage satırı ekle:
- Status dropdown (new/investigating/reviewed/false_positive/escalated)
- Note textarea (max 500 karakter)
- Save butonu
**Test:** Session aç → status değiştir → kaydet → listede yansısın.

---

## BLOK C — Dashboard Güçlendirme

### C1 — Dashboard: Eksik KPI'lar
**Dosya:** `ui/app/(operator)/dashboard/page.tsx`
**Sorun:** 4 KPI var. Eksik olanlar: active sensors, unique attacker IPs (24h), yeni sessions (24h).
**Düzeltme:**
- `GET /health` zaten sensor count'u veriyor → "Active Sensors" KPI
- `GET /events/top-attackers` zaten unique IP döndürüyor → count'u KPI olarak göster
- Sessions API'ye `?from_dt=<24h_önce>` ile çekip count al → "Sessions Today" KPI
**Test:** Dashboard'da 6-7 KPI görünsün.

---

### C2 — Dashboard: Protokol dağılımı grafiği
**Dosya:** `ui/app/(operator)/dashboard/page.tsx` + `manager/api/sessions.py`
**Sorun:** S7 / Modbus / HTTP dağılımı hiç görünmüyor.
**Düzeltme:**
- `GET /sessions/stats` endpoint'i ekle → protocol başına session count döner
- Dashboard'a pie veya bar chart ekle (recharts zaten mevcut)
**Test:** Dashboard'da protokol dağılımı grafiği görünsün.

---

### C3 — Dashboard: Zaman serisi histogram (events 24h)
**Dosya:** `ui/app/(operator)/dashboard/page.tsx` + `manager/api/events.py`
**Sorun:** Olayların zamansal dağılımı yok. "Saldırı dalgası saat 03:00'te geldi" görülemiyor.
**Düzeltme:**
- `GET /events/histogram?hours=24&bucket=1h` endpoint'i ekle → saat başı event count dizisi döner
- Dashboard'a BarChart ekle
**Test:** Dashboard'da 24 saatlik bar chart görünsün.

---

### C4 — Dashboard: Live feed tıklanabilir satır
**Dosya:** `ui/app/(operator)/dashboard/page.tsx`
**Sorun:** Live feed'deki event satırlarına tıklanınca ilgili session'a gitmiyor.
**Düzeltme:** Her event satırına `onClick={() => router.push('/sessions/' + ev.session_id)}` ekle.
**Test:** Live feed'de event satırına tıkla → session detail açılsın.

---

## BLOK D — Sensor Geliştirmeleri

### D1 — Sensor rename
**Dosya:** `manager/api/sensors.py` + `ui/app/(operator)/sensors/page.tsx`
**Sorun:** Sensor oluşturulunca adı değiştirilemiyor. Sadece delete var.
**Düzeltme:**
- `PATCH /sensors/{id}` endpoint'i ekle (sadece `name` güncellesin)
- Sensors tablosuna inline edit: isim hücresine tıkla → input → enter ile kaydet
**Test:** Sensör adını değiştir → listede güncellensin.

---

### D2 — Sensor detail: bağlı sessionlar
**Dosya:** `manager/api/sensors.py` + `ui/app/(operator)/sensors/page.tsx`
**Sorun:** Sensöre tıklanınca o sensörden gelen sessionlar görülemiyor.
**Düzeltme:**
- `GET /sensors/{id}/sessions` endpoint'i ekle (sessions tablosunu sensor_id ile filtrele)
- Sensör satırına "expand" butonu ekle → altında mini session listesi açılsın
**Test:** Sensör genişlet → o sensörden gelen sessionlar listelensin.

---

## BLOK E — Integrations Genişletme

### E1 — Syslog/CEF çıktısı
**Dosya:** `manager/notifications/siem_forwarder.py`
**Sorun:** Sadece Splunk HEC var. OT ortamlarında Syslog → SIEM pipeline çok yaygın.
**Düzeltme:** `siem_type = "syslog_cef"` seçeneği ekle → UDP/TCP syslog socket ile CEF format event gönder.
Admin SIEM sayfasında type seçimine "Syslog (CEF)" opsiyonu ekle.
**Test:** siem_type=syslog_cef ile local syslog'a test gönder → CEF format doğru gelsin.

---

### E2 — Generic Webhook
**Dosya:** `manager/notifications/siem_forwarder.py` + SIEM config
**Sorun:** Teams, Slack, PagerDuty, OpsGenie entegrasyonu için Generic Webhook yok.
**Düzeltme:** `siem_type = "webhook"` seçeneği ekle → JSON POST olarak event gönder.
Opsiyonel custom headers desteği (Authorization: Bearer xxx gibi).
**Test:** Webhook URL'e POST gönder → payload doğru JSON gelsin.

---

### E3 — Alert throttle/dedup
**Dosya:** `manager/notifications/smtp_sender.py`
**Sorun:** Aynı IP 500 event üretirse 500 email gidiyor. Rate limiting yok.
**Düzeltme:** Redis'te `alert.throttle:{source_ip}:{severity}` key'i kullan → 15 dakikada aynı IP+severity kombinasyonu için max 1 email.
**Test:** 10 event gönder → sadece 1 email gitsin.

---

## BLOK F — Küçük UX Dokunuşları

### F1 — Sessions: Kolon sort
**Dosya:** `ui/app/(operator)/sessions/page.tsx`
**Sorun:** Severity, event count, started_at kolonlarına tıklayarak sort edilemiyor.
**Düzeltme:** Tablo başlıklarına sort toggle ekle → API'ye `?sort_by=severity&sort_dir=desc` parametresi gönder.
Backend `list_filtered` metoduna sort desteği ekle.
**Test:** "Events" kolonuna tıkla → event sayısına göre sırala.

---

### F2 — Sessions: JSON + STIX export
**Dosya:** `manager/api/sessions.py` + `ui/app/(operator)/sessions/page.tsx`
**Sorun:** Sadece CSV export var.
**Düzeltme:**
- `GET /sessions/export/json` endpoint'i ekle
- IOC'ları içeren basit STIX 2.1 bundle export: `GET /sessions/{id}/export/stix`
- Sessions sayfasındaki export butonuna dropdown ekle (CSV / JSON / STIX)
**Test:** JSON export → valid JSON insin. STIX export → STIX bundle formatında insin.

---

### F3 — In-app notification bell
**Dosya:** `ui/app/(operator)/layout.tsx` (veya layout bileşeni)
**Sorun:** SMTP email gidiyor ama uygulama içinde bildirim yok. Başka sekmede çalışan analist uyarı almıyor.
**Düzeltme:** SSE stream'den gelen `attack_event` mesajlarında severity critical/high ise:
- Sağ üst köşede bir notification bell sayacı arttır
- Tıklanınca son 5 critical/high session listesi açılsın
**Test:** Critical event üret → bell'de sayaç görünsün.

---

## Uygulama Sırası

```
A1 → A2 → A3 → A4 → A5 → A6 → A7 → A8
B1 → B2 → B3 → B4
C1 → C2 → C3 → C4
D1 → D2
E1 → E2 → E3
F1 → F2 → F3
```

Her adım için:
1. Değişikliği yap
2. Docker rebuild gerekiyorsa: `docker compose build <servis> && docker compose up -d <servis>`
3. Kullanıcı manuel test eder
4. "devam et" komutu alındığında bir sonraki adıma geç

---

## Tamamlanan Adımlar

- [x] A1
- [x] A2
- [ ] A2b
- [ ] A3
- [ ] A4
- [ ] A5
- [ ] A6
- [ ] A7
- [ ] A8
- [ ] B1
- [ ] B2
- [ ] B3
- [ ] B4
- [ ] C1
- [ ] C2
- [ ] C3
- [ ] C4
- [ ] D1
- [ ] D2
- [ ] E1
- [ ] E2
- [ ] E3
- [ ] F1
- [ ] F2
- [ ] F3
