import { useEffect, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

interface Target {
  id: string; hostname: string; domain: string; domain_status: string; domain_expiry: string | null;
  tls_status: string; tls_expiry: string | null; checked_at: number | null;
}
interface Settings { configured: boolean; enabled: boolean; thresholds: number[]; maskedUrl: string | null }
interface Alert {
  id: string; hostname: string; kind: 'tls' | 'domain'; threshold: number; state: string;
  attempts: number; last_result: string | null; updated_at: number;
}

const labels: Record<string, string> = {
  pending: 'Sırada', ok: 'Kontrol edildi', unsupported: 'RDAP desteklenmiyor',
  bootstrap_unavailable: 'RDAP listesi erişilemiyor', no_expiration: 'Sicil tarih paylaşmıyor',
  not_found: 'Sicilde bulunamadı', rdap_error: 'RDAP sorgusu başarısız',
  scanner_unconfigured: 'TLS tarayıcısı bağlı değil', scanner_error: 'TLS tarayıcısına erişilemedi',
  scanner_configuration_error: 'TLS tarayıcısı ayarı geçersiz',
  no_public_address: 'Genel IPv4 adresi bulunamadı', tls_unreachable: 'TLS bağlantısı kurulamadı',
  tls_untrusted: 'Sertifika güvenilir değil', sent: 'Gönderildi', failed: 'Gönderilemedi'
};
const errors: Record<string, string> = {
  invalid_hostname: 'example.com biçiminde bir alan adı veya alt alan adı girin.',
  duplicate_hostname: 'Bu adres zaten listenizde.', target_limit: 'Takip sınırına ulaşıldı.',
  invalid_webhook: 'Geçerli bir Slack Incoming Webhook adresi girin.',
  webhook_required: 'Önce webhook adresini kaydedin.',
  invalid_settings: 'En az bir bildirim eşiği seçin.',
  settings_changed: 'Ayarlar başka bir oturumda değişti. Sayfayı yenileyin.',
  encryption_unconfigured: 'Sunucuda webhook şifreleme anahtarı eksik.',
  rate_limited: 'Çok fazla istek. Bir dakika sonra tekrar deneyin.'
};
const formatDate = (value: string | number) => new Intl.DateTimeFormat('tr-TR', {
  dateStyle: 'medium', timeStyle: 'short'
}).format(new Date(value));

class ApiError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

async function api<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
  const response = await fetch('/api' + path, {
    method, headers: data === undefined ? {} : { 'Content-Type': 'application/json' },
    body: data === undefined ? undefined : JSON.stringify(data)
  });
  if (!response.ok) {
    const result = await response.json() as { error: string };
    throw new ApiError(response.status, result.error);
  }
  return await response.json() as T;
}

function expiryView(status: string, expiry: string | null) {
  if (!expiry) return <span className="muted">{labels[status] ?? status}</span>;
  const days = Math.ceil((Date.parse(expiry) - Date.now()) / 86_400_000);
  const expired = Date.parse(expiry) <= Date.now();
  return <div className="space-y-1">
    <div className="font-medium">{formatDate(expiry)}</div>
    <span className={'pill ' + (days <= 7 || status !== 'ok' ? 'warn' : '')}>
      {expired ? 'Süresi doldu' : `${days} gün kaldı`}
    </span>
    {status !== 'ok' && <div className="muted">{labels[status] ?? status}</div>}
  </div>;
}

function App() {
  const [user, setUser] = useState<string | null>();
  const [initialError, setInitialError] = useState(false);
  const [targets, setTargets] = useState<Target[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [settings, setSettings] = useState<Settings>();
  const [page, setPage] = useState<'targets' | 'settings' | 'alerts'>('targets');
  const [host, setHost] = useState('');
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ message: string; error?: boolean }>();

  function showError(error: unknown) {
    if (error instanceof ApiError && error.status === 401) {
      setUser(null);
      return;
    }
    const code = error instanceof ApiError ? error.code : '';
    setNotice({ error: true, message: errors[code] ??
      (code.startsWith('slack_') ? 'Slack teslimi başarısız (' + code + ').' : 'İşlem başarısız. Tekrar deneyin.') });
  }

  const loadTargets = async () => setTargets(await api<Target[]>('/targets'));
  const loadAlerts = async () => setAlerts(await api<Alert[]>('/alerts'));
  const loadSettings = async () => setSettings(await api<Settings>('/settings/slack'));

  useEffect(() => {
    api<{ login: string }>('/me').then(result => setUser(result.login)).catch(error => {
      if (error instanceof ApiError && error.status === 401) setUser(null);
      else setInitialError(true);
    });
  }, []);

  useEffect(() => {
    if (!user) return;
    const load = page === 'targets' ? loadTargets : page === 'settings' ? loadSettings : loadAlerts;
    void load().catch(showError);
    const interval = page === 'settings' ? undefined : setInterval(() => void load().catch(showError), 30_000);
    return () => clearInterval(interval);
  }, [user, page]);

  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setNotice(undefined);
    try { await action(); } catch (error) { showError(error); } finally { setBusy(false); }
  }

  function add(event: FormEvent) {
    event.preventDefault();
    void run(async () => {
      await api('/targets', 'POST', { hostname: host });
      setHost('');
      await loadTargets();
      setNotice({ message: 'Adres kontrol sırasına eklendi.' });
    });
  }

  function save(event: FormEvent) {
    event.preventDefault();
    if (!settings) return;
    void run(async () => {
      await api('/settings/slack', 'PUT', { url, enabled: settings.enabled, thresholds: settings.thresholds });
      setUrl('');
      await loadSettings();
      setNotice({ message: 'Slack ayarları kaydedildi.' });
    });
  }

  if (!user) return <main className="login">
    <section className="panel p-8 sm:p-12">
      <Brand />
      <h1 className="mt-9 text-4xl font-semibold tracking-tight">Alan adlarınızın süresini takip edin.</h1>
      <p className="muted mt-4 leading-relaxed">Alan adı ve TLS sertifikası bitiş tarihlerini izleyin. Süre yaklaştığında Slack’te bildirim alın.</p>
      {initialError ? <p role="alert" className="mt-6">Sunucuya erişilemedi. <a href="/" className="underline">Yeniden yükle</a></p>
        : user === undefined ? <p className="muted mt-6">Yükleniyor…</p>
        : <a href="/auth/github" className="button mt-8">GitHub ile giriş yap</a>}
      {new URLSearchParams(location.search).has('auth') && <p role="alert" className="mt-4 text-amber-300">GitHub girişi tamamlanamadı.</p>}
    </section>
  </main>;

  return <>
    <header className="topbar"><div className="shell flex flex-wrap items-center justify-between gap-3 py-4">
      <Brand />
      <div className="flex items-center gap-4 text-sm"><span className="muted">@{user}</span>
        <button className="quiet" disabled={busy} onClick={() => void run(async () => {
          await api('/logout', 'POST');
          location.assign('/');
        })}>Çıkış</button>
      </div>
    </div></header>
    <main className="shell py-10">
      <nav className="tabs" aria-label="Ana menü">
        {([['targets', 'Takip listesi'], ['settings', 'Ayarlar'], ['alerts', 'Bildirim geçmişi']] as const)
          .map(([id, text]) => <button key={id} aria-current={page === id ? 'page' : undefined} onClick={() => {
            setPage(id); setNotice(undefined);
          }}>{text}</button>)}
      </nav>
      {notice && <p className={'notice ' + (notice.error ? 'warn' : '')} role={notice.error ? 'alert' : 'status'}>{notice.message}</p>}
      {page === 'targets' && <>
        <div className="mt-8 mb-6 flex flex-wrap items-end justify-between gap-4">
          <div><h1>Takip listesi</h1><p className="muted mt-2">Alan adı kaydı ve HTTPS sertifikası için günlük kontrol.</p></div>
          <button className="quiet" disabled={busy} onClick={() => void run(loadTargets)}>Listeyi yenile</button>
        </div>
        <form className="panel flex flex-wrap items-end gap-3 p-5" onSubmit={add}>
          <label className="min-w-52 flex-1">Alan adı veya alt alan adı
            <input value={host} onChange={e => setHost(e.target.value)} placeholder="app.example.com" required maxLength={253} />
          </label>
          <button className="button" disabled={busy}>Takibe ekle</button>
        </form>
        <section className="panel mt-5 overflow-x-auto" aria-label="İzlenen adresler">
          {targets.length ? <table>
            <thead><tr><th>Adres</th><th>Alan adı bitişi</th><th>TLS bitişi</th><th>Son kontrol</th><th>İşlem</th></tr></thead>
            <tbody>{targets.map(target => <tr key={target.id}>
              <td><strong>{target.hostname}</strong>{target.hostname !== target.domain && <div className="muted">{target.domain}</div>}</td>
              <td>{expiryView(target.domain_status, target.domain_expiry)}</td>
              <td>{expiryView(target.tls_status, target.tls_expiry)}</td>
              <td className="muted">{target.checked_at ? formatDate(target.checked_at) : 'Sırada'}</td>
              <td><button className="quiet" disabled={busy} aria-label={target.hostname + ' takibini kaldır'}
                onClick={() => { if (confirm(target.hostname + ' takip listesinden kaldırılsın mı?')) void run(async () => {
                  await api('/targets/' + target.id, 'DELETE'); await loadTargets();
                }); }}>Kaldır</button></td>
            </tr>)}</tbody>
          </table> : <p className="muted p-8">Takibe başlamak için yukarıdan bir adres ekleyin.</p>}
        </section>
      </>}
      {page === 'settings' && <>
        <h1 className="mt-8">Bildirim ayarları</h1>
        {settings && <form className="panel mt-6 max-w-2xl space-y-6 p-6" onSubmit={save}>
          <div><h2 className="text-xl font-semibold">Slack</h2>
            <p className="muted mt-1">Bitiş bildirimlerini Slack kanalınıza gönderin.</p></div>
          <label>Incoming Webhook URL
            <input type="password" autoComplete="off" maxLength={400} value={url}
              placeholder={settings.maskedUrl ?? 'https://hooks.slack.com/services/…'} onChange={e => setUrl(e.target.value)} />
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={settings.enabled}
              onChange={e => setSettings({ ...settings, enabled: e.target.checked })} />
            Slack bildirimlerini etkinleştir
          </label>
          <fieldset>
            <legend>Bildirim eşikleri</legend>
            <div className="mt-3 flex flex-wrap gap-2">{[30, 14, 7, 3, 1].map(days =>
              <label className="threshold" key={days}>
                <input type="checkbox" checked={settings.thresholds.includes(days)} onChange={e =>
                  setSettings({ ...settings, thresholds: e.target.checked
                    ? [...settings.thresholds, days] : settings.thresholds.filter(day => day !== days) })} />
                {days} gün
              </label>)}</div>
          </fieldset>
          <div className="flex flex-wrap gap-3">
            <button className="button" disabled={busy}>Kaydet</button>
            <button type="button" className="quiet" disabled={busy || !settings.configured || Boolean(url)} onClick={() =>
              void run(async () => {
                await api('/settings/slack/test', 'POST');
                setNotice({ message: 'Slack test mesajı gönderildi.' });
              })}>Test mesajı gönder</button>
          </div>
        </form>}
      </>}
      {page === 'alerts' && <>
        <h1 className="mt-8">Bildirim geçmişi</h1>
        <section className="panel mt-6 overflow-x-auto">
          {alerts.length ? <table>
            <thead><tr><th>Adres</th><th>Eşik</th><th>Durum</th><th>Deneme</th><th>Son işlem</th></tr></thead>
            <tbody>{alerts.map(alert => <tr key={alert.id}>
              <td>{alert.hostname}</td><td>{alert.kind === 'tls' ? 'TLS' : 'Alan adı'} · {alert.threshold} gün</td>
              <td>{labels[alert.state] ?? alert.state}<div className="muted">{alert.last_result}</div></td>
              <td>{alert.attempts}</td><td>{formatDate(alert.updated_at)}</td>
            </tr>)}</tbody>
          </table> : <p className="muted p-8">Henüz planlanan bir bildirim yok.</p>}
        </section>
      </>}
    </main>
  </>;
}

function Brand() {
  return <div className="flex items-center gap-3 font-semibold tracking-tight">
    <span className="brand-mark" aria-hidden="true">◉</span>DomainWatch
  </div>;
}

createRoot(document.getElementById('root')!).render(<App />);
