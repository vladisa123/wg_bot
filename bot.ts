// AmneziaWG Telegram Bot v3 — простая модель состояний
// Админ: Пользователи / Конфиги / Создать конфиг
// Юзеры (вайтлист): свои конфиги, создают сами.
// Бот на голландском, правит wg0.conf на российском через SSH.

const TOKEN = Deno.env.get("WG_BOT_TOKEN") ?? "";
const ADMIN_ID = Number(Deno.env.get("WG_BOT_ADMIN") ?? "293556094");
const DATA_DIR = Deno.env.get("WG_BOT_DATA") ?? "/opt/wg-bot";
const SERVER_ENDPOINT = Deno.env.get("WG_ENDPOINT") ?? "178.214.211.135:46879";
const WG_HOST = Deno.env.get("WG_SSH_HOST") ?? "127.0.0.1";
const WG_USER = "root";
const WG_CONF_REMOTE = "/etc/amnezia/amneziawg/awg0.conf";
const DNS = "1.1.1.1";
const MTU = "1420";
const AWG = { Jc: "4", Jmin: "40", Jmax: "70", S1: "48", S2: "32", H1: "1234567891", H2: "1234567892", H3: "1234567893", H4: "1234567894" };
const AWG_BLOCK = `Jc = ${AWG.Jc}\nJmin = ${AWG.Jmin}\nJmax = ${AWG.Jmax}\nS1 = ${AWG.S1}\nS2 = ${AWG.S2}\nH1 = ${AWG.H1}\nH2 = ${AWG.H2}\nH3 = ${AWG.H3}\nH4 = ${AWG.H4}`;
const API = `https://api.telegram.org/bot${TOKEN}`;
const WHITELIST_FILE = `${DATA_DIR}/whitelist.json`;
const CLIENTS_FILE = `${DATA_DIR}/clients.json`;
const NAMES_FILE = `${DATA_DIR}/names.json`;
const REQUESTS_FILE = `${DATA_DIR}/requests.json`;
const TICKETS_FILE = `${DATA_DIR}/tickets.json`;
const TICKET_SEQ_FILE = `${DATA_DIR}/ticket_seq.json`;
const SERVER_PUBKEY = Deno.env.get("WG_SERVER_PUB") ?? "oq6RmahE4n2jwaRXDTe2g6Bbo4lGpaw1/i7VlkAiHkM=";
const PSK = Deno.env.get("WG_PSK") ?? "";

// ---- Shadowsocks резервный канал (46.8.29.95:8388, контейнер ss-reserve) ----
const SS_ENDPOINT = "46.8.29.95";
const SS_PORT = "8388";
const SS_PASSWORD = "fOd3pCB3O4ytZiTDs7RD";
const SS_METHOD = "chacha20-ietf-poly1305";
// Полная ss:// ссылка для раздачи (метод:пароль@хост:порт#Имя)
function ssLink(name: string): string {
  const userinfo = btoa(`${SS_METHOD}:${SS_PASSWORD}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `ss://${userinfo}@${SS_ENDPOINT}:${SS_PORT}#${encodeURIComponent(name)}`;
}
function protoLabel(proto?: string): string { return proto === "shadowsocks" ? "🔒 Shadowsocks (белые списки)" : "🛡 AmneziaWG"; }

// ---- Состояния (чат -> {mode}) ----
// mode: none | waiting_new_proto | waiting_new_name | waiting_add_user | waiting_admin_msg | waiting_ticket_text | waiting_ticket_reply
// waiting_new_proto: { mode, uid, targetUid } — выбран протокол, ждём имя
// waiting_new_name: { mode, uid, targetUid, proto }
// Для waiting_add_user: { mode }
const states: Record<number, any> = {};
function setState(chatId: number, s: any) { states[chatId] = s; }
function getState(chatId: number): any { return states[chatId] || { mode: "none" }; }
function clearState(chatId: number) { states[chatId] = { mode: "none" }; }

// ---- SSH ----
// Таймауты: без них зависшее соединение (нестабильный РФ-сервер) вешает бота навсегда.
const SSH_OPTS = [
  "-o", "StrictHostKeyChecking=no",
  "-o", "BatchMode=yes",
  "-o", "ConnectTimeout=10",
  "-o", "ServerAliveInterval=5",
  "-o", "ServerAliveCountMax=3",
];
function sshRun(cmd: string): { ok: boolean; out: string } {
  try {
    // ssh сам выполнит команду через shell на удалённой стороне — без явного bash -lc
    const p = new Deno.Command("ssh", {
      args: [...SSH_OPTS, `${WG_USER}@${WG_HOST}`, cmd],
      stdout: "piped", stderr: "piped",
    }).outputSync();
    const out = new TextDecoder().decode(p.stdout) + new TextDecoder().decode(p.stderr);
    console.log("[ssh]", cmd.slice(0, 70), "=> code", p.code);
    if (p.code !== 0 && out.trim()) console.log("[ssh-err]", out.slice(0, 200));
    return { ok: p.code === 0, out };
  } catch (e) { console.log("[ssh-exc]", cmd.slice(0, 70), String(e)); return { ok: false, out: String(e) }; }
}
function readRemoteConf(): string { const r = sshRun(`cat ${WG_CONF_REMOTE}`); return r.ok ? r.out : ""; }
function writeRemoteConf(c: string): boolean {
  // Защита от катастрофы: если собрался конфиг с меньшим числом пиров, чем реально
  // живёт, — не заливаем (иначе wg syncconf снесёт всех и у клиентов упадёт VPN).
  const newPeers = (c.match(/^\[Peer\]/gm) || []).length;
  const livePeers = readPeersFromMemory().length;
  if (livePeers > 0 && newPeers < livePeers) {
    console.log(`[guard] отказ записи: пиров в конфиге ${newPeers} < живых ${livePeers}`);
    return false;
  }
  try { Deno.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
  const tmp = `${DATA_DIR}/wg0.tmp`;
  Deno.writeTextFileSync(tmp, c);
  const p = new Deno.Command("scp", {
    args: [...SSH_OPTS, tmp, `${WG_USER}@${WG_HOST}:${WG_CONF_REMOTE}`],
    stdout: "piped", stderr: "piped",
  }).outputSync();
  if (p.code !== 0) return false;
  // scp может оборваться молча — сверяем, что на сервере реально лежит то же число пиров.
  const remote = readRemoteConf();
  const remotePeers = (remote.match(/^\[Peer\]/gm) || []).length;
  if (remotePeers !== newPeers) {
    console.log(`[guard] scp не долетел: на сервере ${remotePeers} != ${newPeers}`);
    return false;
  }
  return true;
}
function remoteApply(): boolean {
  // Применяем текущий wg0.conf к интерфейсу. Избегаем bash-специфики <() —
  // используем wg-quick strip и применяем через временный файл/поток.
  const ok = sshRun(`awg-quick strip awg0 > /tmp/awg0.strip && awg syncconf awg0 /tmp/awg0.strip && rm -f /tmp/awg0.strip `);
  return ok.ok;
}
function getServerPubkey(): string { return SERVER_PUBKEY; }

// ---- Файлы ----
function readJson(p: string, d: unknown): any { try { return JSON.parse(Deno.readTextFileSync(p)); } catch { return d; } }
function writeJson(p: string, d: unknown) { try { Deno.mkdirSync(DATA_DIR, { recursive: true }); } catch {} Deno.writeTextFileSync(p, JSON.stringify(d, null, 2)); }
function getWhitelist(): number[] { return readJson(WHITELIST_FILE, []); }
function setWhitelist(l: number[]) { writeJson(WHITELIST_FILE, l); }
// Заявки на доступ: { [chatId]: { id, name, username, ts } }
function getRequests(): Record<string, any> { return readJson(REQUESTS_FILE, {}); }
function setRequests(r: Record<string, any>) { writeJson(REQUESTS_FILE, r); }
function getTickets(): Record<string, any> { return readJson(TICKETS_FILE, {}); }
function setTickets(t: Record<string, any>) { writeJson(TICKETS_FILE, t); }
function nextTicketId(): number {
  const cur = readJson(TICKET_SEQ_FILE, { n: 1000 });
  const n = Number(cur.n) + 1;
  writeJson(TICKET_SEQ_FILE, { n });
  return n;
}
function getClients(): Record<string, any> { return readJson(CLIENTS_FILE, {}); }
function setClients(c: Record<string, any>) { writeJson(CLIENTS_FILE, c); }
function getUserName(id: number): string {
  if (id === ADMIN_ID) return "Админ";
  const names = readJson(NAMES_FILE, {});
  if (names[String(id)]) return names[String(id)];
  return `ID ${id}`; // не раскрываем сырой ID как имя
}
function setUserName(id: number, name: string) {
  const names = readJson(NAMES_FILE, {}); names[String(id)] = name; writeJson(NAMES_FILE, names);
}

// ---- Пиры ----
const WG0_SERVER_PRIV = Deno.env.get("WG_SERVER_PRIVKEY") ?? ""; // приватный ключ wg0 (из env)
const WG0_SERVER_PUB = "jXqWMqih1ydsHmDsfYlv7M2TjvtsPFTpPV1hrspGUnw=";
// MTU серверного интерфейса wg0. Клиенты — двойной туннель (wg0 поверх wg1 с MTU 1360),
// поэтому 1360 — проверенное рабочее значение. Должно быть в КАЖДОЙ записи конфига,
// иначе после рестарта wg0 MTU слетает на дефолт 1420 → фрагментация.
const WG0_MTU = Deno.env.get("WG_MTU") ?? "1420";
// PostUp: MASQUERADE для подсети AmneziaWG
// (wg1-up.sh, идемпотентно). Без него после рестарта wg0 DNS-запросы клиентов
// уходят в Голландию и VPN «не грузит» интернет.
const WG0_POSTUP = Deno.env.get("WG_POSTUP") ?? ""; // пусто = PostUp не пишем
// Единый заголовок [Interface] для wg0 — во всех трёх местах записи конфига,
// чтобы MTU и PostUp никогда не терялись при перезаписи файла ботом.
function serverInterfaceHeader(): string {
  const postUp = WG0_POSTUP ? `PostUp = ${WG0_POSTUP}\n` : "";
  return `[Interface]\nAddress = 10.77.77.1/24\nListenPort = 46879\nPrivateKey = ${WG0_SERVER_PRIV}\n${AWG_BLOCK}\n${postUp}`;
}
function ensureHeader(header: string): string {
  if (header.includes("[Interface]") && header.includes("PrivateKey")) {
    // Дополняем недостающими критичными строками, если их нет (старые конфиги).
    let h = header;
    if (!/^MTU\s*=/m.test(h)) h = h.replace(/^(PrivateKey\s*=.*)$/m, `$1\nMTU = ${WG0_MTU}`);
    if (WG0_POSTUP && !/^PostUp\s*=/m.test(h)) h = h.replace(/^(SaveConfig\s*=.*)$/m, `$1\nPostUp = ${WG0_POSTUP}`);
    // чужой PostUp от старого сервера — вычищаем
    h = h.split("\n").filter((l) => !(l.startsWith("PostUp") && WG0_POSTUP && !l.includes(WG0_POSTUP))).join("\n");
    return h.endsWith("\n") ? h : h + "\n";
  }
  return serverInterfaceHeader();
}
// Читаем пиры ИЗ ПАМЯТИ сервера (awg show awg0 dump) — это источник истины, никогда не "забывает" реально работающие пиры.
// wg dump:  tab-separated: pubkey	presharedkey	endpoint	allowed-ips	latest-handshake	transfer-rx	transfer-tx	persistent-keepalive
function readPeersFromMemory(): { pub: string; ip: string; name?: string }[] {
  const r = sshRun(`awg show awg0 dump | tail -n +2`);
  if (!r.ok) return [];
  const out: { pub: string; ip: string; name?: string }[] = [];
  for (const line of r.out.split("\n")) {
    const parts = line.split("\t");
    if (parts.length < 4 || !parts[0]) continue;
    const ip = (parts[3] || "").split("/")[0];
    // Пиры без AllowedIPs (wg отдаёт "(none)") и прочий мусор пропускаем:
    // иначе в конфиг попадёт "AllowedIPs = (none)/32" и wg syncconf упадёт с parsing error.
    if (!isValidIp(ip)) continue;
    out.push({ pub: parts[0], ip });
  }
  return out;
}
// Добавить пир с гарантией сохранения всех существующих (из памяти + из файла)
function upsertPeerRemote(name: string, pub: string, ip: string): boolean {
  // Собираем пиры из памяти (все реально работающие) + из файла (все с # имя)
  const mem = readPeersFromMemory();
  // Пиры из файла (чтобы не потерять имена тех, что не в памяти)
  const txt = readRemoteConf();
  const fileBlocks = txt.split(/\[Peer\]/).slice(1);
  const filePeers = new Map<string, { name?: string; ip: string }>();
  for (const b of fileBlocks) {
    const m = b.match(/PublicKey = ([A-Za-z0-9+/=]+)/);
    const ipm = b.match(/AllowedIPs = ([0-9.]+)/);
    const nm = b.match(/^#\s*(.+)$/m);
    if (m && ipm) filePeers.set(m[1], { name: nm?.[1].trim(), ip: ipm[1].split("/")[0] });
  }
  // Строим полный список: все пиры из памяти + уникальные из файла + новый
  const merged = new Map<string, { name?: string; ip: string }>();
  for (const p of mem) merged.set(p.pub, { ip: p.ip });
  for (const [pk, v] of filePeers) if (!merged.has(pk)) merged.set(pk, v);
  // Добавляем/обновляем целевой пир
  merged.set(pub, { name, ip });
  // Имя для пиров из памяти: если в файле было имя — берём его
  for (const [pk, v] of filePeers) if (merged.has(pk) && !merged.get(pk)!.name) merged.get(pk)!.name = v.name;
  // Собираем конфиг
  let conf = serverInterfaceHeader();
  for (const [pk, v] of merged) {
    conf += `\n[Peer]\n${v.name ? `# ${v.name}\n` : ""}PublicKey = ${pk}\nPresharedKey = ${PSK}\nAllowedIPs = ${v.ip}/32\n`;
  }
  if (!writeRemoteConf(conf)) return false;
  if (!remoteApply()) return false;
  return true;
}
// Удалить пир: из памяти, файла и применить
function removePeerRemote(name: string, pub?: string): boolean {
  // Публичный ключ пира: если не передан — ищем по имени в файле
  let targetPub = pub;
  if (!targetPub) {
    const txt = readRemoteConf();
    for (const b of txt.split(/\[Peer\]/).slice(1)) {
      const nm = b.match(/^#\s*(.+)$/m);
      const pk = b.match(/PublicKey = ([A-Za-z0-9+/=]+)/);
      if (nm && nm[1].trim() === name && pk) { targetPub = pk[1]; break; }
    }
    // И/или в памяти
    if (!targetPub) {
      const mem = readPeersFromMemory();
      for (const p of mem) if (p.name === name) { targetPub = p.pub; break; }
    }
  }
  if (!targetPub) return true; // нет пира — считаем удалённым
  // Удаляем из памяти (wg set wg0 peer <pub> remove)
  sshRun(`wg set wg0 peer ${targetPub} remove`);
  // Пересобираем файл без этого пира (из памяти + файла)
  const mem = readPeersFromMemory();
  const txt = readRemoteConf();
  const fileBlocks = txt.split(/\[Peer\]/).slice(1);
  const merged = new Map<string, { name?: string; ip: string }>();
  for (const p of mem) merged.set(p.pub, { ip: p.ip });
  for (const b of fileBlocks) {
    const pk = b.match(/PublicKey = ([A-Za-z0-9+/=]+)/);
    const ipm = b.match(/AllowedIPs = ([0-9.]+)/);
    const nm = b.match(/^#\s*(.+)$/m);
    if (pk && ipm && pk[1] !== targetPub) merged.set(pk[1], { name: nm?.[1].trim(), ip: ipm[1].split("/")[0] });
  }
  merged.delete(targetPub);
  let conf = serverInterfaceHeader();
  for (const [pk, v] of merged) {
    conf += `\n[Peer]\n${v.name ? `# ${v.name}\n` : ""}PublicKey = ${pk}\nPresharedKey = ${PSK}\nAllowedIPs = ${v.ip}/32\n`;
  }
  writeRemoteConf(conf);
  return remoteApply();
}
function nextFreeIp(clients: Record<string, any>): string {
  // Занятые IP: из clients.json + реально живые пиры на сервере.
  // Без второго источника можно выдать IP, который уже занят пиром,
  // которого нет в базе (например, после чистки clients.json).
  const used = new Set<number>([1]);
  for (const c of Object.values(clients)) { const l = Number(c.ip?.split(".")[3]); if (!isNaN(l)) used.add(l); }
  for (const p of readPeersFromMemory()) { const l = Number(p.ip.split(".")[3]); if (!isNaN(l)) used.add(l); }
  for (let i = 2; i < 255; i++) if (!used.has(i)) return `10.77.77.${i}`;
  throw new Error("Нет свободных IP");
}
function isValidIp(s: string): boolean {
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) <= 255);
}
async function genKeypair(): Promise<{ priv: string; pub: string }> {
  const priv = new TextDecoder().decode(new Deno.Command("awg", { args: ["genkey"], stdout: "piped" }).outputSync().stdout).trim();
  const proc = new Deno.Command("awg", { args: ["pubkey"], stdin: "piped", stdout: "piped" }).spawn();
  const w = proc.stdin.getWriter(); w.write(new TextEncoder().encode(priv + "\n")); w.close();
  const out = await proc.output();
  return { priv, pub: new TextDecoder().decode(out.stdout).trim() };
}
function clientConf(name: string, ip: string, priv: string, sp: string): string {
  return `[Interface]\nPrivateKey = ${priv}\nAddress = ${ip}/32\nDNS = ${DNS}\n${AWG_BLOCK}\n\n[Peer]\nPublicKey = ${sp}\nPresharedKey = ${PSK}\nEndpoint = ${SERVER_ENDPOINT}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n`;
}

// ---- Telegram API ----
async function api(method: string, params: Record<string, unknown>): Promise<any> {
  try {
    const r = await fetch(`${API}/${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(params) });
    const j = await r.json();
    if (!j.ok) console.log("API", method, "err:", JSON.stringify(j).slice(0, 200));
    return j;
  } catch (e) { console.log("API", method, "EXC:", String(e)); return { ok: false }; }
}
async function sendMessage(chatId: number, text: string, extra: Record<string, unknown> = {}) {
  console.log("SEND:", text.slice(0, 30));
  return api("sendMessage", { chat_id: chatId, text, ...extra });
}
async function answerCb(id: string, text?: string) { return api("answerCallbackQuery", { callback_query_id: id, text }); }
async function editMsg(chatId: number, msgId: number, text: string, extra: Record<string, unknown> = {}) {
  return api("editMessageText", { chat_id: chatId, message_id: msgId, text, ...extra });
}

// ---- Клавиатуры ----
// Админ: все кнопки

const HELP_TEXT = `❓ *ПОМОЩЬ*

*Как подключиться*
1️⃣ Нажми «➕ Создать конфиг»
2️⃣ Выбери протокол (AmneziaWG — основной)
3️⃣ Введи название (например: iPhone)
4️⃣ Бот пришлёт конфиг и QR-код
5️⃣ Скачай приложение AmneziaWG и импортируй конфиг
6️⃣ Включи туннель

*Где взять приложение*
• iPhone / iPad — AmneziaWG в App Store
• Android — AmneziaWG в Play Маркет
• Mac — AmneziaWG в App Store
• Windows — с сайта amnezia.org

*Не работает интернет при включённом VPN*
1. Выключи VPN, включи заново
2. Переключись между Wi-Fi и мобильным интернетом
3. Удали конфиг и создай новый в боте
4. Если не помогло — напиши админу

*Не открывается Telegram*
Нажми «📡 Telegram-прокси» в меню — это отдельный прокси, работает даже когда VPN не поднят.

*Что выбрать: AmneziaWG или Shadowsocks*
• AmneziaWG — обычный вариант, работает у большинства
• Shadowsocks — если оператор блокирует по белым спискам (часто на мобильном интернете)

*Нужна помощь человека*
Напиши админу: @vladisa_s`;

const HELP_KB = {
  inline_keyboard: [[{ text: "✉️ Написать админу (тикет)", callback_data: "newticket" }]],
};

const MAIN_MENU = {
  keyboard: [["👥 Пользователи", "📋 Конфиги"], ["➕ Создать конфиг"], ["✉️ Сообщение"], ["📡 Telegram-прокси"], ["🛜 Роутер", "❓ Помощь"], ["🆘 Поддержка"], ["⚠️ Важно"]] ,
  resize_keyboard: true, is_persistent: true,
};
// Юзер: без «Пользователи» (только свои конфиги и создание)
const USER_MENU = {
  keyboard: [["📋 Конфиги"], ["➕ Создать конфиг"], ["📡 Telegram-прокси"], ["🛜 Роутер", "❓ Помощь"], ["🆘 Поддержка"], ["⚠️ Важно"]],
  resize_keyboard: true, is_persistent: true,
};

// Telegram MTProto-прокси (общий для всех). Поднят на голландской 194.147.115.228:443 (вне РФ, откуда Telegram доступен)
const TELEGRAM_PROXY_LINK = "tg://proxy?server=194.147.115.228&port=443&secret=543a1620dab94e0b71410cd5a8650e60";
const TELEGRAM_PROXY_TEXT = `📡 *Прокси для Telegram*\n\nНажми кнопку ниже, чтобы подключиться.`;
const TELEGRAM_PROXY_KB = { inline_keyboard: [[{ text: "🔌 Подключить прокси", url: TELEGRAM_PROXY_LINK }]] };

// Дисклеймер про приложения и белые списки (кнопка «⚠️ Важно»)

const ROUTER_MENU = {
  inline_keyboard: [
    [{ text: "🆕 KeeneticOS 5.2+ (штатно)", callback_data: "rt:new" }],
    [{ text: "🔧 KeeneticOS 4.x–5.1 (Entware)", callback_data: "rt:old" }],
  ],
};

const ROUTER_INTRO = `🛜 *AmneziaWG на роутере Keenetic*

Сначала посмотри версию прошивки:
зайди в веб-конфигуратор роутера (192.168.1.1 или my.keenetic.net), версия KeeneticOS написана внизу главной страницы.

⚠️ *Важно:* штатный компонент «WireGuard VPN» в KeeneticOS ниже 5.2 *не подойдёт* — он не понимает параметры обфускации AmneziaWG. Конфиг загрузится, но туннель не поднимется.

Выбери свою версию:`;

const ROUTER_NEW = `🆕 *KeeneticOS 5.2 Alpha 11 и новее*

Проверка: версия должна начинаться с 5.2. Если у тебя 4.x или 5.1 — жми кнопку «4.x–5.1» в предыдущем сообщении.

*1. Бэкап (обязательно)*
Управление → Настройки системы → вкладка «Файлы» → скачай два файла: firmware и startup-config.

*2. Обнови прошивку*
Управление → Настройки системы → Обновления и компоненты → смени канал на «Канал разработчика» → обнови систему.
Сразу после обновления отключи автообновление — dev-сборки бывают нестабильными.

*3. DNS*
Сетевые правила → Интернет-фильтры → вкладка «Настройка DNS» → Добавить сервер.
Добавь по очереди: 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9

*4. Отключи IPv6 (важно!)*
Интернет → Кабель Ethernet (или твоё подключение):
• поставь галочку «Игнорировать DNSv4 интернет-провайдера»
• Настройка IPv6 → «Не используется»

*5. Загрузи конфиг*
Управление → Настройки системы → Изменить набор компонентов → найди «wireguard» → поставь галочку «WireGuard VPN» → Обновить NDMS.
Потом: Интернет → Другие подключения → «Загрузить из файла» → выбери .conf из бота.
Поставь галочку «Использовать для выхода в интернет» → Сохранить → переключатель в «Включено».

*6. DNS через VPN*
Сетевые правила → Маршрутизация → IPv4-маршруты → Добавить:
• Тип: Маршрут до узла
• Адрес: 8.8.8.8
• Интерфейс: твоё VPN-подключение
• Галочка «Добавлять автоматически» → Сохранить
Повтори для 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9

*7. Что пускать через VPN*
• Весь трафик — просто, но российские сайты могут тормозить
• Всё кроме .ru/.рф/.su — оптимально
• Только нужные сайты — для избранного

*Проверка:* подключи телефон к Wi-Fi роутера → открой 2ip.ru → должен показать 178.214.211.135`;

const ROUTER_OLD = `🔧 *KeeneticOS 4.x – 5.1 (через Entware)*

Этот путь сложнее, но работает на обычной прошивке.

⚠️ Не все модели Keenetic поддерживают OPKG. Если в списке компонентов его нет — этот вариант не подойдёт, остаётся обновление до 5.2.

*1. Компоненты*
Управление → Настройки системы → Изменить набор компонентов.
Установи:
• WireGuard VPN
• OPKG (менеджер пакетов)
• USB-накопитель и файловая система
Подключи USB-флешку к роутеру.

*2. Установи Entware*
Управление → OPKG → выбери USB-накопитель → Установить.
Роутер сам скачает и развернёт Entware, дождись перезагрузки.

*3. Зайди по SSH*
С компьютера в той же сети:
ssh root@192.168.1.1
Пароль — тот, что задан в веб-конфигураторе.

*4. Установи AWG Manager*
opkg update
opkg install curl
curl -L -o /tmp/awg.sh https://raw.githubusercontent.com/arturbikbaev/AmneziaWG-for-KeeneticOS-RU/main/install.sh
sh /tmp/awg.sh

В конце скрипт покажет адрес панели (обычно http://192.168.1.1:8080).

*5. Импортируй конфиг*
Открой AWG Manager в браузере → «Добавить туннель» → вставь конфиг из бота → Сохрани → включи.

*6. Маршрутизация*
В AWG Manager есть AllowedIPs:
• 0.0.0.0/0 — весь трафик через VPN
• или перечисли нужные подсети — остальное напрямую

*Проверка:* подключи телефон к Wi-Fi → 2ip.ru → должен показать 178.214.211.135`;

const ROUTER_TROUBLE = `🔧 *Если не работает*

*VPN включён, но интернета нет*
• Проверь, что IPv6 отключён
• Пересоздай конфиг в боте — параметры обфускации менялись 10.11.2026, старые конфиги не работают
• Напиши в поддержку с номером тикета

*Роутер не принимает .conf*
• В конфиге должны быть строки Jc, Jmin, Jmax, S1, S2, H1–H4 — без них это не AmneziaWG
• Штатный Keenetic принимает AmneziaWG только на 5.2 Alpha 11+

*Скорость низкая*
• Пускай через VPN только нужные сайты, остальное напрямую

*Чего не делать*
• Не заливай конфиг в штатный WireGuard на прошивках ниже 5.2
• Не ставь IPv6 обратно в «Автоматически»
• Не используй старые конфиги (до 10.11.2026)`;

const INFO_TEXT = `⚠️ *ВАЖНАЯ ИНФОРМАЦИЯ*

🛡 *Протоколы:*
• *AmneziaWG* — основной (обход DPI), для дома и мобильного интернета
• *Shadowsocks* — для случая, когда оператор блокирует трафик по белым спискам IP (особенно на мобильном интернете / LTE)

📱 *Какие приложения скачать:*
• *iPhone / iPad*: AmneziaWG или [OneClick](https://apps.apple.com/ru/app/oneclick-safe-easy-fast/id1545555197) (Shadowsocks) из App Store
• *Android*: AmneziaWG или Shadowsocks из Play Маркет
• *Mac*: AmneziaWG (App Store) или ShadowsocksX-NG

📡 *Если не работает Telegram:*
Когда всё работает, а Telegram нет — нажми «📡 Telegram-прокси» в меню и подключись через него (отдельная кнопка).

🔒 *Про белые списки:*
Если оператор/провайдер блокирует трафик по белым спискам IP — AmneziaWG может не работать. Тогда создай конфиг Shadowsocks и переключись на него.

Подключение: скачай приложение → отсканируй QR / вставь конфиг → включи.`;

// ---- Помощники ----
function clientsOfUser(uid: number): Record<string, any> {
  const o: Record<string, any> = {};
  for (const [k, v] of Object.entries(getClients())) if (v.tg_id === uid) o[k] = v;
  return o;
}
function isAllowed(uid: number): boolean {
  return uid === ADMIN_ID || getWhitelist().includes(uid);
}

// ---- Главное меню ----
async function showMain(uid: number, chatId: number, firstName?: string, username?: string) {
  clearState(chatId);
  if (uid === ADMIN_ID) return sendMessage(chatId, "Главное меню", { reply_markup: MAIN_MENU });
  if (!isAllowed(uid)) {
    // Не в белом списке — оформить/обновить заявку админу
    await requestAccess(uid, chatId, firstName, username);
    return sendMessage(chatId, "⛔ Нет доступа. Твоя заявка отправлена администратору.\n\nКак только тебя одобрят, нажми /start ещё раз.");
  }
  return sendMessage(chatId, "Главное меню", { reply_markup: USER_MENU });
}

// Заявка на доступ от нового юзера — шлём админу инлайн с кнопками
async function requestAccess(uid: number, chatId: number, firstName?: string, username?: string) {
  const reqs = getRequests();
  const name = firstName || username || String(uid);
  setUserName(uid, name);
  const existing = Object.values(reqs).find((r: any) => r.id === uid);
  if (existing) {
    // Заявка уже есть — не спамим админа повторно, но юзеру скажем
    return;
  }
  reqs[String(chatId)] = { id: uid, name, username: username || "", ts: Date.now() };
  setRequests(reqs);
  // Уведомить админа
  await sendMessage(ADMIN_ID, `📨 Новая заявка на доступ\n👤 ${name}${username ? " (@" + username + ")" : ""}\nID: ${uid}`, {
    reply_markup: { inline_keyboard: [
      [{ text: "✅ Одобрить", callback_data: `approve:${uid}` }],
      [{ text: "❌ Отклонить", callback_data: `reject:${uid}` }],
    ] },
  });
}

// ---- Создать конфиг ----
async function beginNew(uid: number, chatId: number) {
  if (!isAllowed(uid)) return sendMessage(chatId, "⛔ Нет доступа.");
  return askProtoFirst(uid, chatId);
}
// Шаг 1: выбор протокола, затем спросим имя
async function askProtoFirst(uid: number, chatId: number, targetUid?: number) {
  setState(chatId, { mode: "waiting_new_proto", uid, targetUid });
  return sendMessage(chatId, "🔧 Выбери протокол:", {
    reply_markup: { inline_keyboard: [
      [{ text: "🛡 AmneziaWG (основной)", callback_data: `proto:wireguard` }],
      [{ text: "🔒 Shadowsocks (для белых списков)", callback_data: `proto:shadowsocks` }],
    ] },
  });
}
// Шаг 2: протокол выбран, ждём имя и сразу создаём
async function askName(uid: number, chatId: number, proto: string, targetUid?: number) {
  setState(chatId, { mode: "waiting_new_name", uid, name: undefined, targetUid, proto });
  const label = proto === "shadowsocks" ? "🔒 Shadowsocks" : "🛡 AmneziaWG";
  return sendMessage(chatId, `✏️ Введи **название конфига** (${label}), например: iPhone, Ноутбук:`, { parse_mode: "Markdown" });
}
async function createConfig(uid: number, chatId: number, name: string, targetUid?: number, proto?: string) {
  const owner = targetUid ?? uid;
  name = name.replace(/[^A-Za-zА-Яа-яЁё0-9 _\-]/g, "").trim();
  if (!name || name.length > 40) { clearState(chatId); return sendMessage(chatId, "❌ Некорректное имя. Конфиг не создан. Нажми «➕ Создать конфиг» чтобы попробовать снова."); }
  const clients = getClients();
  if (clients[name]) { clearState(chatId); return sendMessage(chatId, `❌ Конфиг «${name}» уже существует. Нажми «➕ Создать конфиг» и введи другое имя.`); }

  // Shadowsocks: не создаём пир на сервере (SS уже поднят), просто сохраняем запись
  if (proto === "shadowsocks") {
    clients[name] = { name, tg_id: owner, proto: "shadowsocks", created: new Date().toISOString() };
    setClients(clients);
    clearState(chatId);
    const link = ssLink(name);
    // HTML (не Markdown): одиночное `_` в имени ломает Markdown-парсинг, HTML надёжнее.
    return sendMessage(chatId, `✅ <b>Конфиг «${name}» создан (Shadowsocks).</b>\n\n<b>Клиент:</b> скачай в App Store <a href="https://apps.apple.com/ru/app/oneclick-safe-easy-fast/id1545555197">OneClick</a> (или Shadowrocket).\n\n<b>Подключение:</b> скопируй ссылку ниже и вставь в приложение, или отсканируй QR:\n\n<code>${link}</code>`,
      { parse_mode: "HTML", disable_web_page_preview: true, reply_markup: { inline_keyboard: [[{ text: "📱 QR-код", callback_data: `qr:${name}` }, { text: "🗑 Удалить", callback_data: `delconf:${name}` }]] } });
  }

  // WireGuard: создаём пир на сервере
  const ip = nextFreeIp(clients);
  const { priv, pub } = await genKeypair();
  if (!upsertPeerRemote(name, pub, ip)) { clearState(chatId); return sendMessage(chatId, "❌ Ошибка применения на сервере. Попробуй ещё раз."); }
  clients[name] = { name, tg_id: owner, ip, private_key: priv, public_key: pub, proto: "wireguard", created: new Date().toISOString() };
  setClients(clients);
  clearState(chatId);
  // Сразу показываем меню конфига с кнопками Скачать/QR/Удалить
  return showClientMenu(owner, chatId, name);
}

// ---- Пользователи (админ) ----
async function showUsers(uid: number, chatId: number) {
  clearState(chatId);
  if (uid !== ADMIN_ID) return sendMessage(chatId, "⛔ Только админ.");
  return sendMessage(chatId, "👥 Управление пользователями:", {
    reply_markup: { inline_keyboard: [
      [{ text: "👥 Активные пользователи", callback_data: "activeusers" }],
      [{ text: "📨 Заявки", callback_data: "requests" }],
    ] },
  });
}
// ---- Тикеты поддержки ----
async function beginTicket(uid: number, chatId: number) {
  if (!isAllowed(uid)) return sendMessage(chatId, "⛔ Нет доступа.");
  setState(chatId, { mode: "waiting_ticket_text", uid });
  return sendMessage(chatId, "🆘 *Опиши проблему* одним сообщением.\n\nЧто случилось, на каком устройстве, что уже пробовал. /cancel — отмена.", { parse_mode: "Markdown" });
}
async function createTicket(uid: number, chatId: number, text: string, username?: string) {
  const id = nextTicketId();
  const tickets = getTickets();
  tickets[String(id)] = { id, user_id: uid, user_name: getUserName(uid), username: username ?? "", text, created: Date.now(), status: "open" };
  setTickets(tickets);
  await sendMessage(chatId, `✅ Обращение *#${id}* принято.\n\nАдмин ответит прямо здесь, в этом чате.`, { parse_mode: "Markdown", reply_markup: USER_MENU });
  const adminBody = `🆘 <b>Тикет #${id}</b>\n👤 ${getUserName(uid)}${username ? " (@" + username + ")" : ""}\nID: ${uid}\n\n<i>${text}</i>`;
  await api("sendMessage", { chat_id: ADMIN_ID, text: adminBody, parse_mode: "HTML", reply_markup: { inline_keyboard: [
    [{ text: "💬 Ответить", callback_data: `treply:${id}` }],
    [{ text: "✅ Закрыть", callback_data: `tclose:${id}` }],
  ] } });
  return true;
}
async function showTickets(uid: number, chatId: number) {
  if (uid !== ADMIN_ID) return sendMessage(chatId, "⛔ Только админ.");
  const tickets = Object.values(getTickets()).filter((t: any) => t.status === "open") as any[];
  if (tickets.length === 0) return sendMessage(chatId, "🆘 Открытых тикетов нет.", { reply_markup: MAIN_MENU });
  for (const t of tickets) {
    await sendMessage(chatId, `🆘 <b>Тикет #${t.id}</b>\n👤 ${t.user_name}${t.username ? " (@" + t.username + ")" : ""}\nID: ${t.user_id}\n\n<i>${t.text}</i>`,
      { parse_mode: "HTML", reply_markup: { inline_keyboard: [
        [{ text: "💬 Ответить", callback_data: `treply:${t.id}` }],
        [{ text: "✅ Закрыть", callback_data: `tclose:${t.id}` }],
      ] } });
  }
}

// Выбор получателя для сообщения от админа
async function showMsgTargets(uid: number, chatId: number) {
  clearState(chatId);
  if (uid !== ADMIN_ID) return sendMessage(chatId, "⛔ Только админ.");
  const wl = getWhitelist().filter((id) => id !== ADMIN_ID);
  if (wl.length === 0) return sendMessage(chatId, "Пользователей пока нет.");
  const kb = wl.map((id) => [{ text: getUserName(id), callback_data: `msg:${id}` }]);
  kb.push([{ text: "✉️ Написать всем", callback_data: "msgall" }]);
  return sendMessage(chatId, "✉️ Кому написать?", { reply_markup: { inline_keyboard: kb } });
}

// Список активных (одобренных) пользователей
async function showActiveUsers(uid: number, chatId: number) {
  if (uid !== ADMIN_ID) return sendMessage(chatId, "⛔ Только админ.");
  const wl = getWhitelist().filter((id) => id !== ADMIN_ID);
  if (wl.length === 0) return sendMessage(chatId, "Активных пользователей пока нет.");
  const kb = wl.map((id) => [{ text: getUserName(id), callback_data: `user:${id}` }]);
  kb.push([{ text: "✉️ Написать всем", callback_data: "msgall" }]);
  return sendMessage(chatId, "👥 Активные пользователи:", { reply_markup: { inline_keyboard: kb } });
}
// Список заявок на доступ
async function showRequests(uid: number, chatId: number) {
  if (uid !== ADMIN_ID) return sendMessage(chatId, "⛔ Только админ.");
  const reqs = Object.values(getRequests());
  if (reqs.length === 0) return sendMessage(chatId, "📨 Заявок пока нет.");
  for (const r of reqs as any[]) {
    await sendMessage(chatId, `📨 Заявка\n👤 ${r.name}${r.username ? " (@" + r.username + ")" : ""}\nID: ${r.id}`, {
      reply_markup: { inline_keyboard: [
        [{ text: "✅ Одобрить", callback_data: `approve:${r.id}` }],
        [{ text: "❌ Отклонить", callback_data: `reject:${r.id}` }],
      ] },
    });
  }
}
async function showUserDetail(chatId: number, targetId: number) {
  const his = Object.entries(getClients()).filter(([k, v]: any) => v.tg_id === targetId);
  const name = getUserName(targetId);
  const lines = his.length ? his.map(([n, c]: any) => `• ${protoLabel(c.proto)} ${n}${c.ip ? ` (${c.ip})` : ""}`).join("\n") : "Нет конфигов";
  const kb: any[] = [];
  if (his.length) kb.push([{ text: "📦 Его конфиги", callback_data: `hisconf:${targetId}` }]);
  kb.push([{ text: "➕ Добавить конфиг", callback_data: `addconf:${targetId}` }]);
  kb.push([{ text: "🗑 Удалить пользователя", callback_data: `deluser:${targetId}` }]);
  return sendMessage(chatId, `👤 ${name} (ID: ${targetId})\n\nКонфиги:\n${lines}`, { reply_markup: { inline_keyboard: kb } });
}
async function beginAddUser(chatId: number) {
  setState(chatId, { mode: "waiting_add_user" });
  return sendMessage(chatId, "Отправь пользователя одним из способов:\n• перешли его сообщение\n• пришли его @username\n• пришли его числовой Telegram ID", { reply_markup: MAIN_MENU });
}
async function addUserById(chatId: number, id: number, name?: string) {
  if (id === ADMIN_ID) { clearState(chatId); return sendMessage(chatId, "Это админ, добавлять не нужно.", { reply_markup: MAIN_MENU }); }
  const wl = getWhitelist();
  if (wl.includes(id)) { clearState(chatId); return sendMessage(chatId, "Этот пользователь уже в белом списке.", { reply_markup: MAIN_MENU }); }
  wl.push(id); setWhitelist(wl); setUserName(id, name || String(id));
  clearState(chatId);
  return sendMessage(chatId, `✅ Пользователь добавлен.`, { reply_markup: MAIN_MENU });
}

// ---- Конфиги ----
async function showConfigs(uid: number, chatId: number) {
  clearState(chatId);
  if (uid === ADMIN_ID) {
    // Админ: выбрать пользователя, чтобы посмотреть его конфиги (разделённые по протоколам)
    const all = getClients();
    // Пользователи, у которых есть конфиги
    const userIds = Array.from(new Set(Object.values(all).map((c: any) => c.tg_id)));
    // Админ первым
    userIds.sort((a, b) => (a === ADMIN_ID ? -1 : b === ADMIN_ID ? 1 : 0));
    const kb: any[] = [];
    for (const id of userIds) {
      const label = id === ADMIN_ID ? "Админ" : getUserName(id);
      const cnt = Object.values(all).filter((c: any) => c.tg_id === id).length;
      kb.push([{ text: `👤 ${label} (${cnt})`, callback_data: `confuser:${id}` }]);
    }
    if (kb.length === 0) return sendMessage(chatId, "Конфигов пока нет.", { reply_markup: MAIN_MENU });
    return sendMessage(chatId, "📋 Выбери пользователя, чтобы посмотреть его конфиги:", { reply_markup: { inline_keyboard: kb } });
  }
  // Юзер: сначала выбрать протокол, потом список конфигов
  return showProtoMenu(chatId, uid);
}

// Экран выбора протокола (WireGuard / Shadowsocks) для пользователя targetId
async function showProtoMenu(chatId: number, targetId: number) {
  const his = Object.entries(getClients()).filter(([k, v]: any) => v.tg_id === targetId);
  const wg = his.filter(([n, c]: any) => c.proto !== "shadowsocks");
  const ss = his.filter(([n, c]: any) => c.proto === "shadowsocks");
  if (!wg.length && !ss.length) {
    const label = targetId === ADMIN_ID ? "Админ" : getUserName(targetId);
    return sendMessage(chatId, `У ${label} нет конфигов.`);
  }
  const kb: any[] = [];
  if (wg.length) kb.push([{ text: `🛡 AmneziaWG (${wg.length})`, callback_data: `protolist:${targetId}:wg` }]);
  if (ss.length) kb.push([{ text: `🔒 Shadowsocks (${ss.length})`, callback_data: `protolist:${targetId}:ss` }]);
  return sendMessage(chatId, "📋 Выбери протокол:", { reply_markup: { inline_keyboard: kb } });
}

// Список конфигов конкретного пользователя по протоколу
async function showProtoConfigs(chatId: number, targetId: number, proto: string) {
  const his = Object.entries(getClients()).filter(([k, v]: any) => v.tg_id === targetId);
  const filtered = his.filter(([n, c]: any) => (proto === "ss") === (c.proto === "shadowsocks"));
  if (!filtered.length) return sendMessage(chatId, "Конфигов этого типа нет.");
  const kb = filtered.map(([name]) => [{ text: `📦 ${name}`, callback_data: `conf:${name}` }]);
  const title = proto === "ss" ? "🔒 Shadowsocks" : "🛡 AmneziaWG";
  return sendMessage(chatId, `${title}:\nВыбери конфиг:`, { reply_markup: { inline_keyboard: kb } });
}
// ---- Меню конфига ----

// ---- Меню конфига ----
async function showClientMenu(uid: number, chatId: number, name: string) {
  const all = getClients(); const c = all[name];
  if (!c || (c.tg_id !== uid && uid !== ADMIN_ID)) return sendMessage(chatId, "⛔ Нет доступа к этому конфигу.");
  const owner = c.tg_id === ADMIN_ID ? "Админ" : getUserName(c.tg_id);
  const proto = protoLabel(c.proto);
  // Shadowsocks: вместо файла — показываем ss:// ссылку (обычным текстом, для копирования/тапа)
  if (c.proto === "shadowsocks") {
    const link = ssLink(name);
    // Используем HTML, а не Markdown: в Markdown одиночное `_` внутри backtick-кода
    // (например в имени «Anastasiia_N») ломает парсинг — Telegram отклоняет сообщение
    // с «can't parse entities». В HTML `_` — обычный символ, ссылка остаётся чистой
    // и копируется без экранирования.
    return sendMessage(chatId, `🔒 <b>Конфиг «${name}» (Shadowsocks)</b>\n\n<b>Клиент для Shadowsocks:</b> скачай в App Store приложение <a href="https://apps.apple.com/ru/app/oneclick-safe-easy-fast/id1545555197">OneClick</a> (или Shadowrocket).\n\n<b>Подключение:</b> скопируй ссылку ниже и вставь в приложение, или отсканируй QR:\n\n<code>${link}</code>`,
      { parse_mode: "HTML", disable_web_page_preview: true, reply_markup: { inline_keyboard: [
        [{ text: "📱 QR-код", callback_data: `qr:${name}` }],
        [{ text: "🗑 Удалить конфиг", callback_data: `delconf:${name}` }],
      ] } });
  }
  return sendMessage(chatId, `📦 Конфиг «${name}»\n${proto}${c.ip ? `\nIP: ${c.ip}` : ""}\nВладелец: ${owner}`, {
    reply_markup: { inline_keyboard: [
      [{ text: "⬇️ Скачать", callback_data: `download:${name}` }],
      [{ text: "📱 QR-код", callback_data: `qr:${name}` }],
      [{ text: "🗑 Удалить конфиг", callback_data: `delconf:${name}` }],
    ] },
  });
}

// ---- Обработка сообщений ----
async function handleText(uid: number, chatId: number, text: string, firstName?: string, username?: string) {
  const st = getState(chatId);

  // Админ пишет сообщение пользователю (или всем)
  if (st.mode === "waiting_admin_msg") {
    if (text.trim() === "/cancel") {
      clearState(chatId);
      return sendMessage(chatId, "Отменено.", { reply_markup: MAIN_MENU });
    }
    if (!text.trim()) return sendMessage(chatId, "Пустое сообщение. Напиши текст или /cancel.");
    clearState(chatId);
    const body = `📩 <b>Сообщение от админа</b>\n\n${text}`;
    if (st.targetId === 0) {
      const ids = getWhitelist().filter((id) => id !== ADMIN_ID);
      let sent = 0;
      const failed: string[] = [];
      for (const id of ids) {
        const r = await api("sendMessage", { chat_id: id, text: body, parse_mode: "HTML" });
        if (r.ok) sent++;
        else failed.push(getUserName(id));
      }
      let report = `✅ Отправлено: ${sent} из ${ids.length}`;
      if (failed.length) report += `\n❌ Не доставлено: ${failed.join(", ")}`;
      return sendMessage(chatId, report, { reply_markup: MAIN_MENU });
    }
    const r = await api("sendMessage", { chat_id: st.targetId, text: body, parse_mode: "HTML" });
    return sendMessage(chatId, r.ok ? `✅ Отправлено: ${getUserName(st.targetId)}` : `❌ Не доставлено: ${getUserName(st.targetId)}`, { reply_markup: MAIN_MENU });
  }

  // Пользователь описывает проблему -> создаём тикет
  if (st.mode === "waiting_ticket_text") {
    if (text.trim() === "/cancel") { clearState(chatId); return sendMessage(chatId, "Отменено.", { reply_markup: USER_MENU }); }
    if (!text.trim()) return sendMessage(chatId, "Пустое сообщение. Опиши проблему или /cancel.");
    clearState(chatId);
    await createTicket(uid, chatId, text, username);
    return;
  }
  // Админ отвечает на тикет
  if (st.mode === "waiting_ticket_reply") {
    if (text.trim() === "/cancel") { clearState(chatId); return sendMessage(chatId, "Отменено.", { reply_markup: MAIN_MENU }); }
    if (!text.trim()) return sendMessage(chatId, "Пустой ответ. Напиши текст или /cancel.");
    clearState(chatId);
    const tickets = getTickets();
    const t = tickets[String(st.ticketId)];
    if (!t) return sendMessage(chatId, "❌ Тикет не найден.", { reply_markup: MAIN_MENU });
    const r = await api("sendMessage", { chat_id: t.user_id, text: `💬 <b>Ответ по тикету #${t.id}</b>\n\n${text}`, parse_mode: "HTML" });
    tickets[String(st.ticketId)].last_reply = Date.now();
    setTickets(tickets);
    return sendMessage(chatId, r.ok ? `✅ Ответ отправлен по тикету #${t.id}` : `❌ Не доставлено (тикет #${t.id})`, { reply_markup: MAIN_MENU });
  }

  // Состояние: ждём название конфига
  if (st.mode === "waiting_new_name") {
    // Проверяем валидность имени заранее, затем спрашиваем протокол
    const clean = text.replace(/[^A-Za-zА-Яа-яЁё0-9 _\-]/g, "").trim();
    if (!clean || clean.length > 40) { clearState(chatId); return sendMessage(chatId, "❌ Некорректное имя. Нажми «➕ Создать конфиг» чтобы попробовать снова."); }
    if (getClients()[clean]) { clearState(chatId); return sendMessage(chatId, `❌ Конфиг «${clean}» уже существует. Нажми «➕ Создать конфиг» и введи другое имя.`); }
    return createConfig(uid, chatId, clean, st.uid, st.proto);
  }
  // Состояние: ждём пользователя для добавления
  if (st.mode === "waiting_add_user") {
    // @username
    const m = text.match(/@([A-Za-z0-9_]+)/);
    if (m) {
      const res = await api("getChat", { chat_id: `@${m[1]}` });
      if (res.ok && res.result.type === "private") {
        return addUserById(chatId, res.result.id, res.result.first_name || res.result.username);
      }
      clearState(chatId);
      return sendMessage(chatId, "❌ Не нашёл пользователя по @username. Нужен точный username, и пользователь должен написать боту хотя бы раз.", { reply_markup: MAIN_MENU });
    }
    // Числовой ID
    const trim = text.trim();
    if (/^\d{5,12}$/.test(trim)) {
      return addUserById(chatId, Number(trim), undefined);
    }
    clearState(chatId);
    return sendMessage(chatId, "Не понял. Отправь пересылку сообщения, @username или числовой ID. Добавление отменено.", { reply_markup: MAIN_MENU });
  }

  // Не-админ и не в белом списке: любое сообщение создаёт/обновляет заявку
  if (uid !== ADMIN_ID && !isAllowed(uid)) {
    await requestAccess(uid, chatId, firstName, username);
    return sendMessage(chatId, "⛔ Нет доступа. Твоя заявка отправлена администратору.\n\nКак только одобрят — нажми /start.");
  }

  // Команды и кнопки главного меню
  if (text === "/start" || text === "🏠 Главное меню") return showMain(uid, chatId, firstName, username);
  if (text === "➕ Создать конфиг") return beginNew(uid, chatId);
  if (text === "👥 Пользователи") return showUsers(uid, chatId);
  if (text === "✉️ Сообщение") return showMsgTargets(uid, chatId);
  if (text === "📋 Конфиги") return showConfigs(uid, chatId);
  if (text === "🛜 Роутер") {
    clearState(chatId);
    return sendMessage(chatId, ROUTER_INTRO, { parse_mode: "Markdown", reply_markup: ROUTER_MENU });
  }
  if (text === "🆘 Поддержка") {
    if (uid === ADMIN_ID) return showTickets(uid, chatId);
    return beginTicket(uid, chatId);
  }
  if (text === "❓ Помощь") { clearState(chatId); return sendMessage(chatId, HELP_TEXT, { parse_mode: "Markdown", disable_web_page_preview: true, reply_markup: HELP_KB }); }
  if (text === "⚠️ Важно") { clearState(chatId); return sendMessage(chatId, INFO_TEXT, { parse_mode: "Markdown", disable_web_page_preview: true }); }
  if (text === "📡 Telegram-прокси") { clearState(chatId); return sendMessage(chatId, TELEGRAM_PROXY_TEXT, { parse_mode: "Markdown", reply_markup: TELEGRAM_PROXY_KB }); }

  // Юзер: нажатие на название своего конфига (в клавиатуре)
  if (uid !== ADMIN_ID) {
    const own = clientsOfUser(uid);
    if (own[text]) return showClientMenu(uid, chatId, text);
  }
  // Неизвестная команда
  return sendMessage(chatId, "Не понял. Используй кнопки меню.", { reply_markup: uid === ADMIN_ID ? MAIN_MENU : USER_MENU });
}

async function handleUpdate(upd: any) {
  console.log("UPDATE:", JSON.stringify(upd).slice(0, 200));
  // Текстовое сообщение
  if (upd.message?.text) {
    const msg = upd.message; const chatId = msg.chat.id; const uid = msg.from?.id;
    return handleText(uid, chatId, msg.text, msg.from?.first_name || msg.from?.username, msg.from?.username);
  }
  // Пересланное сообщение (добавление юзера админом)
  if (upd.message?.forward_from) {
    const msg = upd.message; const chatId = msg.chat.id; const uid = msg.from?.id;
    if (uid !== ADMIN_ID) return;
    const st = getState(chatId);
    if (st.mode !== "waiting_add_user") return sendMessage(chatId, "Нажми «👥 Пользователи» → «➕ Добавить», затем перешли сообщение.");
    const ff = upd.message.forward_from;
    return addUserById(chatId, ff.id, ff.first_name || ff.username);
  }
  // Контакт
  if (upd.message?.contact) {
    const msg = upd.message; const chatId = msg.chat.id; const uid = msg.from?.id;
    if (uid !== ADMIN_ID) return;
    const st = getState(chatId);
    if (st.mode !== "waiting_add_user") return sendMessage(chatId, "Нажми «👥 Пользователи» → «➕ Добавить», затем отправь контакт.");
    return addUserById(chatId, msg.contact.user_id, msg.contact.first_name);
  }
  // Callback
  if (upd.callback_query) {
    const cq = upd.callback_query; const uid = cq.from.id; const chatId = cq.message?.chat.id;
    const data = cq.data || ""; if (!chatId) return;
    const [action, arg] = data.split(":");

    if (action === "download") {
      const c = getClients()[arg];
      if (!c || (c.tg_id !== uid && uid !== ADMIN_ID)) return answerCb(cq.id, "⛔ Нет доступа");
      // Shadowsocks — отдаём ss:// ссылку файлом
      if (c.proto === "shadowsocks") {
        const link = ssLink(arg);
        const tmp = `${DATA_DIR}/${arg}.ss`; try { Deno.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
        Deno.writeTextFileSync(tmp, link);
        await answerCb(cq.id, "Скачиваю...");
        new Deno.Command("curl", { args: ["-s", "-F", `chat_id=${chatId}`, "-F", `document=@${tmp};filename=${arg}.ss`, "-F", `caption=🔒 Конфиг ${arg} (Shadowsocks)`, `${API}/sendDocument`] }).outputSync();
        return;
      }
      const conf = clientConf(arg, c.ip, c.private_key, getServerPubkey());
      const tmp = `${DATA_DIR}/${arg}.conf`; try { Deno.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
      Deno.writeTextFileSync(tmp, conf);
      await answerCb(cq.id, "Скачиваю...");
      new Deno.Command("curl", { args: ["-s", "-F", `chat_id=${chatId}`, "-F", `document=@${tmp};filename=${arg}.conf`, "-F", `caption=Конфиг ${arg}`, `${API}/sendDocument`] }).outputSync();
      return;
    }
    if (action === "qr") {
      const c = getClients()[arg];
      if (!c || (c.tg_id !== uid && uid !== ADMIN_ID)) return answerCb(cq.id, "⛔ Нет доступа");
      await answerCb(cq.id, "Генерирую QR...");
      // Shadowsocks — QR из ss:// ссылки
      const dataUrl = c.proto === "shadowsocks" ? ssLink(arg) : clientConf(arg, c.ip, c.private_key, getServerPubkey());
      const url = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(dataUrl)}`;
      const tmp = `${DATA_DIR}/${arg}.png`; try { Deno.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
      new Deno.Command("curl", { args: ["-s", "-o", tmp, url] }).outputSync();
      new Deno.Command("curl", { args: ["-s", "-F", `chat_id=${chatId}`, "-F", `photo=@${tmp}`, "-F", `caption=📱 QR для ${arg}`, `${API}/sendPhoto`] }).outputSync();
      return;
    }
    if (action === "delconf") {
      const c = getClients()[arg];
      if (!c || (c.tg_id !== uid && uid !== ADMIN_ID)) return answerCb(cq.id, "⛔ Нет доступа");
      // Shadowsocks не имеет пира на сервере — удаляем только запись
      if (c.proto !== "shadowsocks") {
        if (!removePeerRemote(arg, c.public_key)) return answerCb(cq.id, "❌ Не удалось удалить");
      }
      const all = getClients(); delete all[arg]; setClients(all);
      // Всплывающий тост + удаление сообщения с конфигом
      await answerCb(cq.id, `🗑 Конфиг «${arg}» удалён`);
      try { await api("deleteMessage", { chat_id: chatId, message_id: cq.message.message_id }); } catch {}
      return;
    }
    if (action === "user" && uid === ADMIN_ID) { await answerCb(cq.id); return showUserDetail(chatId, Number(arg)); }
    if (action === "rt") {
      await answerCb(cq.id);
      const body = arg === "new" ? ROUTER_NEW : arg === "old" ? ROUTER_OLD : ROUTER_TROUBLE;
      return sendMessage(chatId, body, { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🔧 Если не работает", callback_data: "rt:trouble" }]] } });
    }
    if (action === "newticket") {
      await answerCb(cq.id);
      try { await api("deleteMessage", { chat_id: chatId, message_id: cq.message.message_id }); } catch {}
      return beginTicket(uid, chatId);
    }
    if (action === "treply" && uid === ADMIN_ID) {
      await answerCb(cq.id);
      setState(chatId, { mode: "waiting_ticket_reply", ticketId: Number(arg) });
      return sendMessage(chatId, `💬 Ответ на тикет #${arg}. Напиши текст или /cancel.`);
    }
    if (action === "tclose" && uid === ADMIN_ID) {
      const tickets = getTickets();
      if (!tickets[arg]) return answerCb(cq.id, "Тикет не найден");
      tickets[arg].status = "closed";
      tickets[arg].closed_at = Date.now();
      setTickets(tickets);
      await answerCb(cq.id, "Закрыт");
      await api("sendMessage", { chat_id: tickets[arg].user_id, text: `✅ Обращение *#${arg}* закрыто.\n\nЕсли проблема осталась — создай новое через «🆘 Поддержка».`, parse_mode: "Markdown" });
      try { await editMsg(chatId, cq.message.message_id, `✅ Тикет #${arg} закрыт.`); } catch { return sendMessage(chatId, `✅ Тикет #${arg} закрыт.`, { reply_markup: MAIN_MENU }); }
      return;
    }
    if (action === "msg" && uid === ADMIN_ID) {
      await answerCb(cq.id);
      setState(chatId, { mode: "waiting_admin_msg", targetId: Number(arg) });
      return sendMessage(chatId, `✉️ Напиши сообщение для ${getUserName(Number(arg))}.\n\nОно уйдёт как есть, с пометкой «от админа». /cancel — отмена.`);
    }
    if (action === "msgall" && uid === ADMIN_ID) {
      await answerCb(cq.id);
      setState(chatId, { mode: "waiting_admin_msg", targetId: 0 });
      return sendMessage(chatId, "✉️ Напиши сообщение для ВСЕХ пользователей.\n\n/cancel — отмена.");
    }
    if (action === "activeusers" && uid === ADMIN_ID) { await answerCb(cq.id); return showActiveUsers(uid, chatId); }
    if (action === "requests" && uid === ADMIN_ID) { await answerCb(cq.id); return showRequests(uid, chatId); }
    if (action === "approve" && uid === ADMIN_ID) {
      const targetId = Number(arg);
      const wl = getWhitelist();
      if (!wl.includes(targetId)) { wl.push(targetId); setWhitelist(wl); }
      // Убрать заявку
      const reqs = getRequests();
      for (const [k, v] of Object.entries(reqs)) if (v.id === targetId) delete reqs[k];
      setRequests(reqs);
      await answerCb(cq.id, "✅ Доступ одобрен");
      // Сообщить юзеру
      await sendMessage(targetId, "✅ Твоя заявка одобрена! Нажми /start, чтобы начать пользоваться ботом.");
      // Обновить сообщение заявки у админа
      try { await editMsg(chatId, cq.message.message_id, `🟢 ${getUserName(targetId)} одобрен.`); } catch {}
      return;
    }
    if (action === "reject" && uid === ADMIN_ID) {
      const targetId = Number(arg);
      const reqs = getRequests();
      for (const [k, v] of Object.entries(reqs)) if (v.id === targetId) delete reqs[k];
      setRequests(reqs);
      await answerCb(cq.id, "❌ Заявка отклонена");
      // Сообщить юзеру (можно отправить повторно)
      try { await sendMessage(targetId, "❌ Твоя заявка отклонена.\n\nЕсли это ошибка — просто напиши боту ещё раз, и заявка отправится повторно."); } catch {}
      try { await editMsg(chatId, cq.message.message_id, `🔴 ${getUserName(targetId)} отклонён.`); } catch {}
      return;
    }
    if (action === "conf") { await answerCb(cq.id); return showClientMenu(uid, chatId, arg); }
    // Выбор протокола при создании нового конфига
    if (action === "proto") {
      const st = getState(chatId);
      if (st.mode !== "waiting_new_proto") return answerCb(cq.id, "⛔ Заверши создание конфига");
      const stUid = st.targetUid ?? st.uid;
      await answerCb(cq.id);
      try { await api("deleteMessage", { chat_id: chatId, message_id: cq.message.message_id }); } catch {}
      return askName(st.uid, chatId, arg, stUid);
    }
    if (action === "confuser" && uid === ADMIN_ID) {
      const t = arg === "admin" ? ADMIN_ID : Number(arg);
      await answerCb(cq.id);
      return showProtoMenu(chatId, t);
    }
    if (action === "hisconf" && uid === ADMIN_ID) {
      // вызов из деталей пользователя — тоже показываем выбор протокола
      await answerCb(cq.id);
      return showProtoMenu(chatId, Number(arg));
    }
    if (action === "protolist" && (uid === ADMIN_ID || uid === Number(data.split(":")[1]))) {
      const [tstr, proto] = [data.split(":")[1], data.split(":")[2]];
      const t = tstr === "admin" ? ADMIN_ID : Number(tstr);
      // доступ: админ ко всем, юзер только к своим
      if (uid !== ADMIN_ID && t !== uid) return answerCb(cq.id, "⛔ Нет доступа");
      await answerCb(cq.id);
      return showProtoConfigs(chatId, t, proto);
    }
    if (action === "adduser" && uid === ADMIN_ID) return beginAddUser(chatId);
    if (action === "addconf" && uid === ADMIN_ID) {
      await answerCb(cq.id);
      return askProtoFirst(uid, chatId, Number(arg));
    }
    if (action === "deluser" && uid === ADMIN_ID) {
      const targetId = Number(arg);
      if (targetId === ADMIN_ID) return answerCb(cq.id, "Нельзя удалить админа");
      // Удалить из whitelist
      setWhitelist(getWhitelist().filter((x) => x !== targetId));
      // Удалить все его конфиги из clients.json и с сервера
      const all = getClients();
      for (const [k, v] of Object.entries(all)) {
        if (v.tg_id === targetId) {
          if (v.proto !== "shadowsocks") removePeerRemote(k, v.public_key);
          delete all[k];
        }
      }
      setClients(all);
      // Убрать заявку, если осталась
      const reqs = getRequests();
      for (const [k, v] of Object.entries(reqs)) if (v.id === targetId) delete reqs[k];
      setRequests(reqs);
      await answerCb(cq.id, "🗑 Пользователь удалён");
      try { await api("deleteMessage", { chat_id: chatId, message_id: cq.message.message_id }); } catch {}
      return;
    }
    return answerCb(cq.id);
  }
}

// ---- setMyCommands - только /start ----
async function setCommands() {
  try {
    await api("setMyCommands", { commands: [{ command: "start", description: "Главное меню" }] });
    console.log("Commands set");
  } catch (e) { console.error("setCommands err", e); }
}

// ---- Main ----
async function main() {
  console.log("Bot v3 started. Admin:", ADMIN_ID, "WG host:", WG_HOST);
  const check = sshRun(`awg show awg0 public-key`);
  if (check.ok) console.log("SSH OK");
  else console.error("SSH FAIL", check.out);
  await setCommands();
  // Сбросить offset, чтобы не было конфликтов с прошлым
  await fetch(`${API}/deleteWebhook?drop_pending_updates=true`).catch(() => {});
  let offset = 0;
  while (true) {
    try {
      const r = await fetch(`${API}/getUpdates?timeout=25&offset=${offset}`);
      const j = await r.json();
      if (j.ok && j.result) {
        if (j.result.length) console.log("got", j.result.length, "updates, offset now", offset);
        for (const upd of j.result) {
          offset = upd.update_id + 1;
          handleUpdate(upd).catch((e) => console.error("handle err", e));
        }
      }
    } catch (e) { console.error("poll err", e); await new Promise((r) => setTimeout(r, 3000)); }
  }
}
main();
