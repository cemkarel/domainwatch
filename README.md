# DomainWatch

Ortak takip listesi ve Slack ayarları olan bir alan adı ve HTTPS sertifikası takip uygulaması. React ve Tailwind arayüzü, Hono API, D1 ve Cron aynı Cloudflare Worker dağıtımında çalışır. Canlı TLS sertifikası kontrolü Cloudflare Browser Run üzerinden yapılır.

Panelin sağ üstünden Türkçe veya İngilizce seçilebilir. Dil tercihi tarayıcıda saklanır.

## Yerelde çalıştırma

Node.js 22.13+ ve npm gerekir.

```sh
npm ci
cp .dev.vars.example .dev.vars
openssl rand -base64 32
```

İlk giriş için `.dev.vars` dosyasında `ADMIN_PASSWORD` değerini en az 12 karakterlik rastgele bir parola ile doldurun. Slack ayarlarını kullanmak için OpenSSL çıktısını aynı dosyaya `WEBHOOK_KEY` olarak ekleyin. Paneli `http://localhost:8787` adresinden açıp `admin` kullanıcısıyla giriş yapın.

```sh
npx wrangler d1 migrations apply domainwatch --local
npm run dev
```

Bir adres ekledikten sonra yerel cron çalıştırmak için:

```sh
curl -fsS 'http://localhost:8787/cdn-cgi/local/scheduled?format=json&cron=*/5+*+*+*+*'
```

### Canlı HTTPS sertifikası

`wrangler.jsonc` içindeki `TLS_BROWSER` bağlantısı, Worker dağıtılırken Cloudflare Browser Run'a bağlanır. Worker, hedefin genel DNS kayıtlarını kontrol eder ve HTTPS yanıtındaki sertifikanın bitiş tarihini okur. Her cron turu bir tarayıcı oturumunu paylaşır. Sertifika ve zincir doğrulaması başarısız olursa, okunabilen bitiş tarihi **Sertifika güvenilir değil** durumuyla gösterilir. CDN'in sunduğu sertifika bağlantının yapıldığı konuma göre değişebilir. [Cloudflare Browser Run](https://developers.cloudflare.com/browser-run/puppeteer/) · [Plan limitleri](https://developers.cloudflare.com/browser-run/limits/)

Yerel Wrangler çalıştırmasında gerçek Browser Run kullanmak için `browser` yapılandırmasına geçici olarak `"remote": true` ekleyin ve Cloudflare hesabınıza giriş yapın. Bu yerel test hesabınızın Browser Run kotasını kullanır. [Yerel test](https://developers.cloudflare.com/browser-run/faq/)

### Slack

**Ayarlar → Bildirim ayarları → Slack** alanına Slack'in verdiği `https://hooks.slack.com/services/…` adresini yapıştırın. **Test mesajı gönder** alandaki adrese gerçek bir Slack mesajı gönderir ve ayarları kaydetmeden veya otomatik bildirimleri açmadan kullanılabilir. Eşikleri ve bildirim durumunu kaydetmek için **Kaydet** düğmesini kullanın. Test isteği ortak çalışma alanı başına sınırlandırılır. [Slack Incoming Webhooks](https://api.slack.com/incoming-webhooks)

Webhook URL'si D1'e AES-256-GCM ile ve çalışma alanı sahibinin kimliğine bağlı olarak şifreli yazılır. Admin oturumu açıkken kayıtlı adres, ayar alanında açıkça görünür. Boş webhook alanıyla kaydetmek mevcut değeri korur.

## GitHub üzerinden Cloudflare'a dağıtım

Bu dağıtım dosyalarını GitHub'daki `main` dalına gönderin. Cloudflare'da **Workers & Pages → Create application → Import a repository** yolundan bağlı GitHub hesabını seçin ve aşağıdaki ayarlarla Worker'ı oluşturun.

| Ayar | Değer |
| --- | --- |
| Repo / üretim dalı | `ersinkirbulut/domainwatch` / `main` |
| Worker name | `domainwatch` |
| Root directory | `/` |
| Build command | `npm run build` |
| Deploy command | `npm run deploy:cloudflare` |

Build token'ında Worker'ın bağlı olduğu hesap için **Workers Scripts Edit** ve **D1 Edit** izinleri bulunmalıdır. Cloudflare'ın oluşturduğu varsayılan token'a **My Profile → API Tokens** üzerinden D1 Edit ekleyin. İlk build izin hatası alırsa token'ı güncelledikten sonra build'i yeniden çalıştırın. [Workers Builds token izinleri](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/#api-token)

Deploy komutu, build'in çalıştığı hesapta `domainwatch` adlı D1 veritabanını bulur veya oluşturur, bekleyen migrasyonları uygular ve Worker'ı yayınlar. Repo herhangi bir hesaba veya D1 UUID'sine bağlı değildir. Herhangi bir adım başarısız olursa sonraki adım çalışmaz. Aynı akışı terminalden çalıştırmak için doğru hesapta `npx wrangler login` yapın, ardından `npm ci` ve `npm run deploy` çalıştırın.

İlk girişten önce **Settings → Variables and Secrets** bölümüne `ADMIN_PASSWORD` adında bir Worker secret ekleyin ve `admin` kullanıcısıyla giriş yapın. İlk başarılı girişte parolanın tuzlanmış özeti D1'e kaydedilir. Bundan sonra `ADMIN_PASSWORD` kaldırılabilir. **Ayarlar → Parolayı değiştir** bölümünde mevcut parolanızı girerek yeni parola belirleyebilirsiniz. Değişiklik tüm oturumları kapatır. [Cloudflare Workers secrets](https://developers.cloudflare.com/workers/configuration/secrets/)

Gerekirse **Settings → Variables and Secrets** bölümünde şu değerleri girin.

- Eski bir hesabın listesini, bildirim geçmişini ve Slack ayarlarını ortak çalışma alanı olarak kullanmak için `WORKSPACE_OWNER_ID` değerine D1'deki `users.id` değerini girin. Şifreli Slack ayarları için önceki `WEBHOOK_KEY` değerini kullanın. Bu değişken boşken panel ve Cron yeni ortak çalışma alanını kullanır.
- Yazma istekleri varsayılan olarak Worker'a geldikleri origin ile eşleşmelidir. `APP_ORIGIN` ayarlıysa yazma işlemleri o origin ile sınırlanır. Worker adresi değiştiğinde eski değeri kaldırın veya yeni origin ile güncelleyin.

Dağıtım komutu ilk Slack kaydından önce eksik `WEBHOOK_KEY` değerini üretip Worker secret olarak yükler. D1'de önceden şifrelenmiş Slack adresleri varsa özgün anahtarı koruyun veya aynı değerle geri yükleyin.

TLS kontrolü dağıtımda otomatik bağlanır. Önceki kurulumdan kalan `SCANNER_URL` ve `SCANNER_TOKEN` değerlerini kaldırabilirsiniz. Daha önce TLS bitiş tarihi okunamayan adresler, migrasyon sonrası Cron sırasına alınır.

## Kontrol ve bildirim davranışı

- RDAP için Public Suffix List ile kayıt edilebilir alan adı bulunur. IANA'nın bootstrap listesi, TLD'nin HTTPS RDAP adreslerini belirler. İlk adres başarısızsa sıradaki denenir. `.com`, `.net` ve `.org` için kayıt operatörü adresleri ek fallback olarak tanımlıdır. RDAP desteği, kayıt bulunamaması, tarihin paylaşılmaması ve bağlantı hatası ayrı durumlar olarak görünür. [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json)
- Yeni adres eklenirken alan adı ve TLS bitiş tarihleri sorgulanır. Sonuçlar ekleme işlemi tamamlandığında listede görünür. İlk kontrol yarıda kesilirse adres Cron tarafından tekrar alınır.
- Her tamamlanan kontrolden 24 saat sonra adres yeniden kontrol için uygun hale gelir. Cron beş dakikada bir, aktif çalışma alanında süresi gelen en fazla iki adresi ve dört bildirimi işler. MVP sınırı çalışma alanı başına 25 ve veritabanında toplam 400 adrestir. Trafik ve Cron CPU kullanımı gerçek dağıtımda gözlemlenmelidir. [Workers limitleri](https://developers.cloudflare.com/workers/platform/limits/) · [D1 fiyatlandırması](https://developers.cloudflare.com/d1/platform/pricing/)
- 30/14/7/3/1 günlük pencerelerden en yakın seçili eşiğe bildirim yazılır. Örneğin ilk kontrolde 5 gün kaldıysa 7 günlük bildirim hazırlanır. D1'de adres, tarih türü, bitiş tarihi ve eşik kombinasyonu tekrar planlamayı önler.
- Ağ hataları, Slack 429 ve 5xx yanıtları artan bekleme süresiyle beş denemeye kadar yeniden denenir. Ayarı değişmiş veya güncel bitiş tarihi artık eşleşmeyen bekleyen bildirimler iptal edilir. Slack'in kabul ettiği isteğin yanıtı kaybolursa nadiren tekrar mesaj oluşabilir. Son teslim sonucu D1'de, denemeler yapılandırılmış Worker loglarında tutulur.
- Panel ve Cron sorguları aktif çalışma alanıyla sınırlıdır. Rate limit bağları Cloudflare lokasyonu başına çalışır. Webhook isteklerinde yönlendirme kapalıdır. TLS kontrolü genel DNS kaydı olan hedeflere HTTPS üzerinden gider.

## Doğrulama

```sh
npm test
npm run typecheck
npm run build
npx wrangler deploy --dry-run
```

Otomatik testler admin girişini, oturum iptalini, çalışma alanı kapsamını, origin kontrolünü, webhook URL doğrulamasını, şifrelemeyi, Slack test gönderimini ve Cron bildirim tekrarlarını denetler. Canlı Slack mesajı için gerçek webhook yapılandırması gerekir.
