import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';
import { label, slackHttpStatus, translations, type Copy, type Language } from './i18n.ts';
import './style.css';

interface Target {
  id: string; hostname: string; domain: string; domain_status: string; domain_expiry: string | null;
  tls_enabled: number; tls_status: string; tls_expiry: string | null; checked_at: number | null;
}
interface TargetPage { targets: Target[]; hasNext: boolean; total: number; matched: number }
interface Settings { enabled: boolean; thresholds: number[]; url: string | null; webhookError: string | null }
interface BulkResult { added: number; duplicates: number; invalid: string[] }
type TargetSort = 'hostname' | 'domain_expiry' | 'tls_expiry';
interface Alert {
  id: string; hostname: string; kind: 'tls' | 'domain'; threshold: number; state: string;
  attempts: number; last_result: string | null; updated_at: number;
}

const languageKey = 'domainwatch-language';

type Notice = { message: 'addedPending' | 'slackSaved' | 'testSent' | 'passwordChanged' } | { error: string };

function initialLanguage(): Language {
  try {
    return localStorage.getItem(languageKey) === 'en' ? 'en' : 'tr';
  } catch {
    return 'tr';
  }
}

function errorMessage(code: string, copy: Copy) {
  const status = slackHttpStatus(code);
  return status ? copy.slackHttpError(status) : label(copy.errors, code) ?? copy.genericError;
}

function deliveryResult(code: string, copy: Copy) {
  const status = slackHttpStatus(code);
  return status ? `Slack HTTP ${status}` : label(copy.statuses, code) ?? label(copy.errors, code) ?? code;
}

class ApiError extends Error {
  constructor(public code: string) { super(code); }
}

async function api<T>(path: string, method = 'GET', data?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch('/api' + path, {
    method, signal, headers: data === undefined ? {} : { 'Content-Type': 'application/json' },
    body: data === undefined ? undefined : JSON.stringify(data)
  });
  if (!response.ok) {
    const result = await response.json() as { error: string };
    throw new ApiError(result.error);
  }
  return await response.json() as T;
}

function expiryView(status: string, expiry: string | null, copy: Copy, formatDate: (value: string) => string) {
  const statusText = label(copy.statuses, status) ?? status;
  if (!expiry) return <span className="muted">{statusText}</span>;
  const days = Math.ceil((Date.parse(expiry) - Date.now()) / 86_400_000);
  const expired = Date.parse(expiry) <= Date.now();
  return <div className="space-y-1">
    <div className="font-medium">{formatDate(expiry)}</div>
    <span className={'pill ' + (days <= 7 || status !== 'ok' ? 'warn' : '')}>
      {expired ? copy.expired : copy.daysLeft(days)}
    </span>
    {status !== 'ok' && <div className="muted">{statusText}</div>}
  </div>;
}

function NoticeView({ notice, copy }: { notice?: Notice; copy: Copy }) {
  if (!notice) return null;
  const isError = 'error' in notice;
  return <p className={'notice ' + (isError ? 'warn' : '')} role={isError ? 'alert' : 'status'}>
    {isError ? errorMessage(notice.error, copy) : copy[notice.message]}
  </p>;
}

function errorCode(error: unknown) {
  return error instanceof ApiError ? error.code : '';
}

function App() {
  const [language, setLanguage] = useState<Language>(initialLanguage);
  const copy = translations[language];
  const [signedIn, setSignedIn] = useState<boolean>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>();

  useEffect(() => {
    document.documentElement.lang = language;
    try {
      localStorage.setItem(languageKey, language);
    } catch {
      // The current selection still works when storage is unavailable.
    }
  }, [language]);

  useEffect(() => {
    void api('/auth/session').then(() => setSignedIn(true)).catch(error => {
      setSignedIn(false);
      if (errorCode(error) !== 'unauthenticated') setNotice({ error: errorCode(error) });
    });
  }, []);

  function signedOut(changed = false) {
    setSignedIn(false);
    setNotice(changed ? { message: 'passwordChanged' } : undefined);
  }

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy(true);
    setNotice(undefined);
    try {
      await api('/auth/login', 'POST', { username: data.get('username'), password: data.get('password') });
      setSignedIn(true);
    } catch (error) {
      setNotice({ error: errorCode(error) });
    } finally {
      form.reset();
      setBusy(false);
    }
  }

  async function logout() {
    setBusy(true);
    setNotice(undefined);
    try {
      await api('/auth/logout', 'POST');
      signedOut();
    } catch (error) {
      if (errorCode(error) === 'unauthenticated') signedOut();
      else setNotice({ error: errorCode(error) });
    } finally {
      setBusy(false);
    }
  }

  return <>
    <header className="topbar"><div className="shell flex items-center justify-between gap-3 py-4">
      <Brand />
      <div className="flex items-center gap-2">
        <select className="quiet" aria-label={copy.language} value={language}
          onChange={event => setLanguage(event.target.value === 'en' ? 'en' : 'tr')}>
          <option value="tr" lang="tr">Türkçe</option>
          <option value="en" lang="en">English</option>
        </select>
        {signedIn && <button className="quiet" disabled={busy} onClick={() => void logout()}>{copy.signOut}</button>}
      </div>
    </div></header>
    {signedIn ? <>
      {notice && <div className="shell"><NoticeView notice={notice} copy={copy} /></div>}
      <Dashboard copy={copy} onSignOut={signedOut} />
    </> : <main className="shell py-10">
      {signedIn === undefined ? <p role="status" className="muted">{copy.checkingSession}</p> :
        <form className="panel mx-auto max-w-sm space-y-5 p-6" onSubmit={login}>
          <h1>{copy.signIn}</h1>
          <NoticeView notice={notice} copy={copy} />
          <label className="block">{copy.username}
            <input name="username" defaultValue="admin" autoComplete="username" required maxLength={64} />
          </label>
          <label className="block">{copy.password}
            <input name="password" type="password" autoComplete="current-password" required maxLength={128} />
          </label>
          <button className="button" disabled={busy}>{copy.signIn}</button>
        </form>}
    </main>}
  </>;
}

function Dashboard({ copy, onSignOut }: { copy: Copy; onSignOut: (changed?: boolean) => void }) {
  const dateFormat = useMemo(() => new Intl.DateTimeFormat(copy.locale, {
    dateStyle: 'medium', timeStyle: 'short'
  }), [copy.locale]);
  const formatDate = (value: string | number) => dateFormat.format(new Date(value));
  const domainDateFormat = useMemo(() => new Intl.DateTimeFormat(copy.locale, {
    dateStyle: 'medium', timeZone: 'UTC'
  }), [copy.locale]);
  const formatDomainDate = (value: string) => domainDateFormat.format(new Date(value));
  const [watchlist, setWatchlist] = useState<{ request: string; data?: TargetPage }>();
  const [targetPage, setTargetPage] = useState(1);
  const [targetRefresh, setTargetRefresh] = useState(0);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [settings, setSettings] = useState<Settings>();
  const [page, setPage] = useState<'targets' | 'settings' | 'alerts'>('targets');
  const [host, setHost] = useState('');
  const [bulkHosts, setBulkHosts] = useState('');
  const [bulkResult, setBulkResult] = useState<BulkResult>();
  const [search, setSearch] = useState('');
  const [targetSort, setTargetSort] = useState<TargetSort>('hostname');
  const [url, setUrl] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>();
  const query = search.trim().toLowerCase();
  const targetRequest = '/targets/page?' + new URLSearchParams({ page: String(targetPage), q: query, sort: targetSort });
  const currentWatchlist = watchlist?.request === targetRequest ? watchlist : undefined;
  const visibleTargets = currentWatchlist?.data?.targets ?? [];
  const refreshTargets = () => setTargetRefresh(current => current + 1);

  function showError(error: unknown) {
    const code = errorCode(error);
    if (code === 'unauthenticated') onSignOut();
    else setNotice({ error: code });
  }

  const loadAlerts = async () => setAlerts(await api<Alert[]>('/alerts'));
  const loadSettings = async () => setSettings(await api<Settings>('/settings/slack'));

  useEffect(() => {
    if (page === 'targets') return;
    const load = page === 'settings' ? loadSettings : loadAlerts;
    void load().catch(showError);
    const interval = page === 'settings' ? undefined : setInterval(() => void load().catch(showError), 30_000);
    return () => clearInterval(interval);
  }, [page]);

  useEffect(() => {
    if (page !== 'targets') return;
    const controller = new AbortController();
    const { signal } = controller;
    let fastUntil: number | undefined;
    async function load() {
      let delay = 30_000;
      try {
        const data = await api<TargetPage>(targetRequest, 'GET', undefined, signal);
        if (signal.aborted) return;
        if (!data.targets.length && targetPage > 1) {
          setTargetPage(current => current === targetPage ? current - 1 : current);
          return;
        }
        setWatchlist({ request: targetRequest, data });
        if (data.targets.some(target => target.domain_status === 'pending' ||
          (target.tls_enabled && target.tls_status === 'pending'))) {
          fastUntil ??= Date.now() + 25_000;
          if (Date.now() < fastUntil) delay = 2500;
        } else fastUntil = undefined;
      } catch (error) {
        if (signal.aborted) return;
        setWatchlist(current => current?.request === targetRequest ? current : { request: targetRequest });
        showError(error);
      }
      timer = setTimeout(() => void load(), delay);
    }
    let timer = setTimeout(() => void load(), query ? 200 : 0);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [page, query, targetPage, targetRefresh, targetRequest]);

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
      refreshTargets();
      setNotice({ message: 'addedPending' });
    });
  }

  function addBulk(event: FormEvent) {
    event.preventDefault();
    void run(async () => {
      setBulkResult(undefined);
      const result = await api<BulkResult>('/targets/bulk', 'POST', { hostnames: bulkHosts });
      setBulkResult(result);
      setBulkHosts(result.invalid.join('\n'));
      if (result.added) refreshTargets();
    });
  }

  function toggleTls(id: string, enabled: boolean) {
    void run(async () => {
      await api('/targets/' + id + '/tls', 'PUT', { enabled });
      refreshTargets();
    });
  }

  function save(event: FormEvent) {
    event.preventDefault();
    if (!settings) return;
    void run(async () => {
      const updatedUrl = url?.trim();
      await api('/settings/slack', 'PUT', {
        url: updatedUrl === settings.url ? undefined : updatedUrl,
        enabled: settings.enabled, thresholds: settings.thresholds
      });
      await loadSettings();
      setUrl(undefined);
      setNotice({ message: 'slackSaved' });
    });
  }

  function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    if (data.get('newPassword') !== data.get('confirmPassword')) {
      setNotice({ error: 'password_mismatch' });
      return;
    }
    void run(async () => {
      await api('/auth/password', 'PUT', {
        currentPassword: data.get('currentPassword'), newPassword: data.get('newPassword')
      });
      form.reset();
      onSignOut(true);
    });
  }

  return <main className="shell py-10">
      <nav className="tabs" aria-label={copy.navigation}>
        {(['targets', 'settings', 'alerts'] as const)
          .map(id => <button key={id} aria-current={page === id ? 'page' : undefined} onClick={() => {
            setPage(id); setNotice(undefined);
          }}>{copy[id]}</button>)}
      </nav>
      <NoticeView notice={notice} copy={copy} />
      {page === 'targets' && <>
        <div className="mt-8 mb-6 flex flex-wrap items-end justify-between gap-4">
          <div><h1>{copy.targets}</h1><p className="muted mt-2">{copy.schedule}</p></div>
          <button className="quiet" disabled={busy} onClick={() => {
            setNotice(undefined);
            refreshTargets();
          }}>{copy.refresh}</button>
        </div>
        <form className="panel flex flex-wrap items-end gap-3 p-5" onSubmit={add}>
          <label className="min-w-52 flex-1">{copy.hostname}
            <input value={host} onChange={e => setHost(e.target.value)} placeholder="app.example.com" required maxLength={253} />
          </label>
          <button className="button" disabled={busy}>{copy.add}</button>
        </form>
        <details className="panel mt-3 p-5">
          <summary className="cursor-pointer text-sm font-semibold">{copy.bulkAdd}</summary>
          <form className="mt-4 space-y-3" onSubmit={addBulk}>
            <label className="block">{copy.bulkDomains}
              <textarea rows={5} value={bulkHosts} onChange={event => setBulkHosts(event.target.value)}
                placeholder={'example.com\napp.example.net'} spellCheck={false} autoCapitalize="none"
                aria-describedby="bulk-import-hint" disabled={busy} required />
            </label>
            <p className="muted text-sm" id="bulk-import-hint">{copy.bulkHint}</p>
            <button className="button" disabled={busy || !bulkHosts.trim()}>{copy.bulkSubmit}</button>
            {bulkResult && <p className="muted text-sm" role="status">
              {copy.bulkSummary(bulkResult.added, bulkResult.duplicates)}
              {bulkResult.invalid.length > 0 && <> {copy.bulkInvalid}</>}
            </p>}
          </form>
        </details>
        <div className="mt-5 flex flex-wrap items-end justify-between gap-3">
          <label className="block w-full max-w-sm">{copy.searchTargets}
            <input type="search" value={search} onChange={event => {
              setSearch(event.target.value);
              setTargetPage(1);
            }} spellCheck={false} />
          </label>
          <label className="block">{copy.sortTargets}
            <select className="quiet mt-2 block" value={targetSort} onChange={event => {
              setTargetSort(event.target.value as TargetSort);
              setTargetPage(1);
            }}>
              <option value="hostname">{copy.sortByHostname}</option>
              <option value="domain_expiry">{copy.sortByDomainExpiry}</option>
              <option value="tls_expiry">{copy.sortByTlsExpiry}</option>
            </select>
          </label>
        </div>
        <section className="panel mt-3 overflow-x-auto" aria-label={copy.trackedAddresses} aria-busy={!currentWatchlist}>
          {visibleTargets.length ? <table>
            <thead><tr><th>{copy.address}</th><th>{copy.domainExpiry}</th><th>{copy.tlsExpiry}</th><th>{copy.lastCheck}</th><th>{copy.actions}</th></tr></thead>
            <tbody>{visibleTargets.map(target => <tr key={target.id}>
              <td><strong>{target.hostname}</strong>{target.hostname !== target.domain && <div className="muted">{target.domain}</div>}</td>
              <td>{expiryView(target.domain_status, target.domain_expiry, copy,
                target.domain.endsWith('.tr') ? formatDomainDate : formatDate)}</td>
              <td><div className="flex items-center gap-3">
                <input className="tls-switch" type="checkbox" role="switch" checked={Boolean(target.tls_enabled)}
                  aria-label={copy.tlsToggle(target.hostname)} disabled={busy}
                  onChange={event => toggleTls(target.id, event.target.checked)} />
                {target.tls_enabled ? expiryView(target.tls_status, target.tls_expiry, copy, formatDate)
                  : <span className="muted">{copy.tlsOff}</span>}
              </div></td>
              <td className="muted">{target.checked_at ? formatDate(target.checked_at) : copy.statuses.pending}</td>
              <td><button className="quiet" disabled={busy} aria-label={copy.removeLabel(target.hostname)}
                onClick={() => { if (confirm(copy.confirmRemoval(target.hostname))) void run(async () => {
                  await api('/targets/' + target.id, 'DELETE'); refreshTargets();
                }); }}>{copy.remove}</button></td>
            </tr>)}</tbody>
          </table> : <p className="muted p-8" role="status">
            {!currentWatchlist ? copy.loadingTargets : !currentWatchlist.data ? copy.targetsUnavailable
              : query ? copy.noMatchingTargets : copy.emptyTargets}
          </p>}
        </section>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          {currentWatchlist?.data && <p className="muted text-sm" role="status">
            {copy.totalTargets(currentWatchlist.data.total)}
            {query && <> · {copy.matchingTargets(currentWatchlist.data.matched)}</>}
          </p>}
          {(targetPage > 1 || currentWatchlist?.data?.hasNext) && <nav className="ml-auto flex items-center gap-3"
            aria-label={copy.targetPagination}>
            <button className="quiet" disabled={busy || targetPage === 1} onClick={() => setTargetPage(current => current - 1)}>
              {copy.previousPage}
            </button>
            <span className="muted text-sm" role="status">{copy.pageNumber(targetPage)}</span>
            <button className="quiet" disabled={busy || !currentWatchlist?.data?.hasNext}
              onClick={() => setTargetPage(current => current + 1)}>{copy.nextPage}</button>
          </nav>}
        </div>
      </>}
      {page === 'settings' && <>
        <h1 className="mt-8">{copy.settings}</h1>
        <form className="panel mt-6 max-w-2xl space-y-5 p-6" onSubmit={changePassword}>
          <div>
            <h2 className="text-xl font-semibold">{copy.changePassword}</h2>
            <p className="muted mt-1">{copy.passwordRules}</p>
          </div>
          <input type="hidden" name="username" autoComplete="username" value="admin" />
          <label className="block">{copy.currentPassword}
            <input name="currentPassword" type="password" autoComplete="current-password" required maxLength={128} />
          </label>
          <label className="block">{copy.newPassword}
            <input name="newPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={128} />
          </label>
          <label className="block">{copy.confirmPassword}
            <input name="confirmPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={128} />
          </label>
          <button className="button" disabled={busy}>{copy.changePassword}</button>
        </form>
        {settings && <form className="panel mt-6 max-w-2xl space-y-6 p-6" onSubmit={save}>
          <div><h2 className="text-xl font-semibold">{copy.notificationSettings} · Slack</h2>
            <p className="muted mt-1">{copy.slackDescription}</p></div>
          <label>{copy.webhook}
            <input type="text" inputMode="url" autoComplete="off" spellCheck={false} maxLength={400}
              value={url ?? settings.url ?? ''} placeholder="https://hooks.slack.com/services/…"
              onChange={e => setUrl(e.target.value)} />
          </label>
          {settings.webhookError && <p className="muted" role="status">{errorMessage(settings.webhookError, copy)}</p>}
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={settings.enabled}
              onChange={e => setSettings({ ...settings, enabled: e.target.checked })} />
            {copy.enableSlack}
          </label>
          <fieldset>
            <legend>{copy.thresholds}</legend>
            <div className="mt-3 flex flex-wrap gap-2">{[30, 14, 7, 3, 1].map(days =>
              <label className="threshold" key={days}>
                <input type="checkbox" checked={settings.thresholds.includes(days)} onChange={e =>
                  setSettings({ ...settings, thresholds: e.target.checked
                    ? [...settings.thresholds, days] : settings.thresholds.filter(day => day !== days) })} />
                {copy.days(days)}
              </label>)}</div>
          </fieldset>
          <div className="flex flex-wrap gap-3">
            <button className="button" disabled={busy}>{copy.save}</button>
            <button type="button" className="quiet" disabled={busy || !(url ?? settings.url)?.trim()} onClick={() =>
              void run(async () => {
                await api('/settings/slack/test', 'POST', { url: url?.trim() });
                setNotice({ message: 'testSent' });
              })}>{copy.sendTest}</button>
          </div>
        </form>}
      </>}
      {page === 'alerts' && <>
        <h1 className="mt-8">{copy.alerts}</h1>
        <section className="panel mt-6 overflow-x-auto">
          {alerts.length ? <table>
            <thead><tr><th>{copy.address}</th><th>{copy.threshold}</th><th>{copy.status}</th><th>{copy.attempts}</th><th>{copy.lastUpdate}</th></tr></thead>
            <tbody>{alerts.map(alert => <tr key={alert.id}>
              <td>{alert.hostname}</td><td>{alert.kind === 'tls' ? 'TLS' : copy.domain} · {copy.days(alert.threshold)}</td>
              <td>{label(copy.statuses, alert.state) ?? alert.state}
                {alert.last_result && <div className="muted">{deliveryResult(alert.last_result, copy)}</div>}</td>
              <td>{alert.attempts}</td><td>{formatDate(alert.updated_at)}</td>
            </tr>)}</tbody>
          </table> : <p className="muted p-8">{copy.emptyAlerts}</p>}
        </section>
      </>}
  </main>;
}

function Brand() {
  return <div className="flex items-center gap-3 font-semibold tracking-tight">
    <span className="brand-mark" aria-hidden="true">◉</span>DomainWatch
  </div>;
}

createRoot(document.getElementById('root')!).render(<App />);
