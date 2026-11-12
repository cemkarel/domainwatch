# DomainWatch

Ortak takip listesi ve Slack ayarları olan bir alan adı ve HTTPS sertifikası takip uygulaması. React ve Tailwind arayüzü, Hono API, D1 ve Cron aynı Cloudflare Worker dağıtımında çalışır. Canlı TLS sertifikası kontrolü için ayrıca küçük bir Node tarayıcısı çalıştırılır.

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

Workers Static Assets ile sunulan panelde **TLS tarayıcısı bağlı değil** durumu, TLS adaptörünün yapılandırılmasını bekler. `poc/index.mjs` ile yapılan yerel Wrangler denemesinde `example.com:443` TLS bağlantısındaki `TLSSocket.getPeerCertificate()` çağrısı `Error: getPeerCertificate is not implemented` döndürdü. Yeniden üretmek için `npm run poc:tls` komutundan sonra `curl http://localhost:8788/` çalıştırın. [Cloudflare node:tls belgeleri](https://developers.cloudflare.com/workers/runtime-apis/nodejs/tls/)

Tarayıcı, host adının A kaydını çözer, genel IPv4 adresini filtreler ve DNS'i ikinci kez çözmeden o IP'nin 443 portuna özgün host adıyla SNI üzerinden bağlanır. Sunucunun sunduğu leaf sertifikanın `notAfter` alanını okur. Zincir veya hostname doğrulaması başarısız olsa da okunabilen tarih **Sertifika güvenilir değil** uyarısıyla gösterilir. IPv6-only adresler bu sürümde desteklenmez. CDN'in tarayıcıya sunduğu sertifika konuma ve TLS istemcisine göre değişebilir.

```sh
openssl rand -hex 32
# Üretilen değeri yerel süreç ortamına SCANNER_TOKEN olarak verin.
npm run scanner
```

Worker'ın `.dev.vars` dosyasına aynı `SCANNER_TOKEN` değerini, `SCANNER_URL=http://127.0.0.1:9090/check` ve `APP_ORIGIN=http://localhost:8787` satırlarını ekleyip Worker'ı yeniden başlatın. Canlıda Node sürecini ağ erişimi olan ayrı bir makinede veya platformda çalıştırın. `npm ci --omit=dev` ve `npm run scanner` yeterlidir. Varsayılan olarak 127.0.0.1:9090 dinler. HTTPS reverse proxy'nin `POST /check` uç noktasını tarayıcıya yönlendirmesini sağlayın. Gerekirse `BIND_HOST` ve `PORT` ayarlayın. Tarayıcıyı özel ağlara erişimi olmayan bir ortamda çalıştırın ve egress'te özel/yerel ağlar ile platform metadata adreslerini engelleyin. TLS dışı bağlantı yalnız yerel geliştirmede etkin.

### Slack

**Ayarlar → Bildirim ayarları → Slack** alanına Slack'in verdiği `https://hooks.slack.com/services/…` adresini yapıştırın. Eşikleri seçin, bildirimleri etkinleştirin ve kaydedin. **Test mesajı gönder** kaydedilmiş adresle gerçek bir POST yapar ve otomatik bildirimler kapalıyken de çalışır. Test isteği ortak çalışma alanı başına sınırlandırılır. [Slack Incoming Webhooks](https://api.slack.com/incoming-webhooks)

Webhook URL'si D1'e AES-256-GCM ile ve çalışma alanı sahibinin kimliğine bağlı olarak şifreli yazılır. Ayar yanıtı sabit bir maske döndürür. Boş webhook alanıyla kaydetmek mevcut değeri korur. Anahtarı değiştirirseniz webhook adresini yeniden kaydedin.

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

- Slack için `WEBHOOK_KEY` değerini secret olarak ekleyin. Yeni kurulumda `openssl rand -base64 32` ile anahtar oluşturun.
- Eski bir hesabın listesini, bildirim geçmişini ve Slack ayarlarını ortak çalışma alanı olarak kullanmak için `WORKSPACE_OWNER_ID` değerine D1'deki `users.id` değerini girin. Şifreli Slack ayarları için önceki `WEBHOOK_KEY` değerini kullanın. Bu değişken boşken panel ve Cron yeni ortak çalışma alanını kullanır.
- Yazma istekleri varsayılan olarak Worker'a geldikleri origin ile eşleşmelidir. `APP_ORIGIN` ayarlıysa yazma işlemleri o origin ile sınırlanır. Worker adresi değiştiğinde eski değeri kaldırın veya yeni origin ile güncelleyin.

**TLS izlemesini etkinleştirmek için** bu repodaki Node tarayıcısı ayrı bir ağ ortamında çalışmalıdır. `SCANNER_URL` o servisin HTTPS `/check` adresidir. `SCANNER_TOKEN` sizin ürettiğiniz rastgele anahtardır ve Worker ile Node servisine aynı değer girilir. Bu iki ayar yalnızca sertifika izlemesini etkinleştirir. GitHub dağıtımı, RDAP ve Slack alan adı bildirimleri bunlar olmadan çalışır.

## Kontrol ve bildirim davranışı

- RDAP için Public Suffix List ile kayıt edilebilir alan adı bulunur. IANA'nın bootstrap listesi, TLD'nin HTTPS RDAP adreslerini belirler. İlk adres başarısızsa sıradaki denenir. `.com`, `.net` ve `.org` için kayıt operatörü adresleri ek fallback olarak tanımlıdır. RDAP desteği, kayıt bulunamaması, tarihin paylaşılmaması ve bağlantı hatası ayrı durumlar olarak görünür. [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json)
- Yeni adres eklenirken alan adı bitiş tarihi ve tarayıcı yapılandırılmışsa TLS bitiş tarihi sorgulanır. Sonuçlar ekleme işlemi tamamlandığında listede görünür. İlk kontrol yarıda kesilirse adres Cron tarafından tekrar alınır.
- Her tamamlanan kontrolden 24 saat sonra adres yeniden kontrol için uygun hale gelir. Cron beş dakikada bir, aktif çalışma alanında süresi gelen en fazla iki adresi ve dört bildirimi işler. MVP sınırı çalışma alanı başına 25 ve veritabanında toplam 400 adrestir. Trafik ve Cron CPU kullanımı gerçek dağıtımda gözlemlenmelidir. Tarayıcı barındırma maliyeti Cloudflare planına dahil değildir. [Workers limitleri](https://developers.cloudflare.com/workers/platform/limits/) · [D1 fiyatlandırması](https://developers.cloudflare.com/d1/platform/pricing/)
- 30/14/7/3/1 günlük pencerelerden en yakın seçili eşiğe bildirim yazılır. Örneğin ilk kontrolde 5 gün kaldıysa 7 günlük bildirim hazırlanır. D1'de adres, tarih türü, bitiş tarihi ve eşik kombinasyonu tekrar planlamayı önler.
- Ağ hataları, Slack 429 ve 5xx yanıtları artan bekleme süresiyle beş denemeye kadar yeniden denenir. Ayarı değişmiş veya güncel bitiş tarihi artık eşleşmeyen bekleyen bildirimler iptal edilir. Slack'in kabul ettiği isteğin yanıtı kaybolursa nadiren tekrar mesaj oluşabilir. Son teslim sonucu D1'de, denemeler yapılandırılmış Worker loglarında tutulur.
- Panel ve Cron sorguları aktif çalışma alanıyla sınırlıdır. Rate limit bağları Cloudflare lokasyonu başına çalışır. Webhook isteklerinde yönlendirme kapalıdır. TLS tarayıcısı hedef olarak yalnız genel IPv4 ve 443 portunu kullanır.

## Doğrulama

```sh
npm test
npm run typecheck
npm run build
npx wrangler deploy --dry-run
```

Otomatik testler admin girişini, oturum iptalini, çalışma alanı kapsamını, origin kontrolünü, webhook URL doğrulamasını, şifrelemeyi, maskelemeyi, Slack istek biçimini ve Cron bildirim tekrarlarını denetler. Canlı Slack mesajı için gerçek webhook yapılandırması gerekir.
