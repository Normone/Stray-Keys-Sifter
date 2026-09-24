# Stray Keys Sifter

Собирает публичные VPN-ключи из открытых источников, отсеивает мёртвые, определяет страну сервера по IP, складывает живые в один файл для импорта в клиент.

## Что даёт на выходе

`data/exports/checked.txt` — список живых ключей. Что считается «живым» — зависит от режима проверки:

- **TCP-режим** (`mode="tcp"` или `tcp+tls`, дефолт) — у ключа **открыт TCP-порт**. Самая дешёвая проверка: отсеивает заведомо мёртвое (сервер не отвечает, порт закрыт, DNS не резолвится), но **не проверяет, что туннель реально работает**. Из прошедших TCP-чек рабочими в клиенте окажется **от 1% до 15%**. Быстро: ~22к ключей за 35 минут.
- **sing-box режим** (`mode="singbox"`) — **реальный HTTP-запрос через туннель**. Поднимает sing-box, гоняет URLTest через каждый ключ, оставляет те, что действительно проксируют. Список короче, но в клиенте работает большая его часть. Медленно: ~22к ключей за 20 минут, но проверка честная.

Почему TCP-режим не гарантирует: чтобы отличить «порт открыт» от «туннель работает», нужно поднять соединение через сам ключ (Xray или sing-box) и попробовать HTTP-запрос. Это тяжело, требует бинарь движка и чувствительно к его версии. Именно поэтому появился sing-box-режим: он берёт ту же работу на себя, отсеивая всё, что клиент отбросил бы. Но он и медленнее — компромисс между «быстро и много» и «медленно и точно».

**Практический смысл:** TCP-режим сокращает список с «десятки тысяч строк из подписок» до «несколько сотен кандидатов». sing-box-режим сразу даёт список, который можно залить в клиент и не перебирать вручную. Второй работает в 20+ раз быстрее Throne/Hiddify/Nekobox: 22к ключей за 20 минут против часов у GUI-клиентов.

Если в TCP-режиме нужен список гарантированно рабочих — его надо получить финальным тестом в клиенте. `checked.txt` — это входные данные для такого теста.

Делал для себя, чтобы автоматом раз в N часов собирались ключи из различных источников и отсеивались абсолютно мёртвые на случай, если всё имеющееся переблочат, а я давно подписки не обновлял.

### Hysteria2 — по-разному в разных режимах

Hysteria/hysteria2 — UDP-протоколы (QUIC). В TCP-режиме проверить их нельзя в принципе: TCP-коннект к ним провалится, а «пинг» через UDP-пакет бессмысленен — современный quic-go игнорирует VN-пакеты и отвечает только на полноценный handshake.

- **TCP-режим:** hysteria/hysteria2-ключи **не проверяются вообще**, идут отдельным файлом `data/exports/hysteria2_candidates.txt` — список всего, что нашлось, с флагом страны, но без пинга.
- **sing-box режим:** hysteria/hysteria2 проверяются наравне со всеми. Файл кандидатов не создаётся, живые hysteria-ключи попадают в общий `checked.txt`.

## Возможности

- Загрузка источников по списку URL. Список задаётся в `config.json → sources`, правится без изменения кода.
- Парсинг всех популярных форматов в одном источнике: `vless://`, `vmess://`, `trojan://`, `ss://`, `socks5://`, `http(s)://`, `mtproto://`, `hysteria://`, `hysteria2://`, `hy2://`, `tg://proxy?...`, base64-подписки (в т.ч. с мусором и BOM), Clash YAML, CSV с заголовком и без, plain `host:port`.
- Дедупликация по `<scheme>://<ident>@<host>:<port>` (ident = uuid / password / method; для схем без идентификатора — просто `host:port`).
- Два режима проверки: **TCP** (DNS + connect, широкий охват, быстро) и **sing-box** (DNS + HTTP через туннель, узкий охват, точно).
- TCP-connect всех stream-схем с мульти-IP резолвом (все A/AAAA-записи), 3 попытки с растущим таймаутом (3→6→9 с), опциональным TLS-handshake (`mode: "tcp+tls"`) и последовательным обходом для хостов с ≤3 IP.
- sing-box: батч-проверка через Clash API, failover на битых ключах (один кривой ключ не уносит весь batch).
- GeoIP по IP сервера: оффлайн-mmdb, HTTP-fallback через ip-api.com, постоянный кэш `IP → страна`. CDN-фронты (Cloudflare, Fastly, Akamai, AWS, GCP, Azure — по CIDR и по ASN) не считаются за страну origin — для них страна берётся из remark.
- Фильтр по странам: `checks.exclude_countries: ["RU"]` — ключи из этих стран не попадут в экспорт.
- Sanitize URI для клиентов на sing-box: удаление `?ed=N` из WebSocket path, замена `type=raw` → `type=tcp`.
- Экспорт: общий `checked.txt` + отдельный файл на каждую схему + `hysteria2_candidates.txt` (только в TCP-режиме).
- Статистика источников: сколько найдено, сколько уникальных, сколько живых, сколько есть только здесь, когда последний раз менялось, сколько уникально-живых.
- История прогонов.
- Фоновый сервис: Windows — detached subprocess, Linux/macOS — двойной fork. Без systemd и SCM.

## Установка

Требуется Python 3.10+.

```bash
git clone https://github.com/Normone/Stray-Keys-Sifter.git
cd Stray-Keys-Sifter
pip install -e .
```

Опционально — оффлайн-GeoIP:

```bash
pip install -e ".[geoip]"
straysifter geoip-update
```

Без mmdb работает HTTP-lookup через ip-api.com (100 IP за запрос, 15 запросов/мин бесплатно).

### Опционально — sing-box (для режима реальной проверки)

Скачай бинарник sing-box со [страницы релизов](https://github.com/SagerNet/sing-box/releases). Для Windows x64 это `sing-box-<version>-windows-amd64.zip`.

Распакуй и положи `sing-box.exe` в:

```
<корень проекта>/bin/sing-box/sing-box.exe
```

На Linux/macOS — `sing-box-<version>-linux-amd64.tar.gz` (или подходящую архитектуру), распаковать в `bin/sing-box/sing-box` и сделать `chmod +x`.

Путь можно переопределить через `checks.singbox_path` в `config.json` или env-переменную `SIFTER_SINGBOX_PATH`.

## Быстрый старт

```bash
# создать config.json с дефолтами
straysifter-service install

# отредактировать config.json → sources, вписать свои URL
# полный цикл (TCP-проверка, быстро)
straysifter collect

# или полный цикл через sing-box (медленнее, точнее)
straysifter collect --mode singbox

# результат
cat data/exports/checked.txt
cat data/exports/hysteria2_candidates.txt     # только в TCP-режиме
```

## Команды

| Команда | Описание |
|---|---|
| `straysifter collect` | Полный цикл: fetch → parse → check → GeoIP → save → export |
| `straysifter sources` | Только загрузить источники в архив, без проверок |
| `straysifter sources-stats` | Таблица по источникам: найдено / уникально / вклад / живых / статус |
| `straysifter inspect <pattern>` | Разбор одного источника: что нашли, DNS, TCP-чек |
| `straysifter export-source <pattern>` | Выгрузить один источник (`_alive.txt` + `_all.txt`) |
| `straysifter export` | Пересобрать `checked.txt` из рабочей базы, без новых проверок |
| `straysifter geoip-update` | Скачать mmdb для оффлайн-GeoIP |
| `straysifter geoip-clear` | Очистить кэш `data/geoip_cache.json` |
| `straysifter status` | Состояние базы, расписание, сводка по источникам |
| `straysifter history` | Последние N прогонов |
| `straysifter clean` | Очистить базу / историю / статистику |

### Флаги

| Флаг | Где применим | Описание |
|---|---|---|
| `-v`, `--verbose` | любая команда | DEBUG-уровень логов |
| `--mode tcp\|tcp+tls\|singbox` | `collect`, `export-source` | Метод проверки. `tcp` — только connect. `tcp+tls` — connect + TLS-handshake. `singbox` — реальный HTTP через туннель |
| `--exclude-country RU,CN` | `collect`, `export`, `export-source` | Исключить страны из экспорта (дополняет `config.json`) |
| `--no-geoip` | `collect`, `export`, `export-source` | Не использовать GeoIP в этом вызове |
| `--json` | `sources-stats` | Вывод в JSON |
| `--limit N` | `inspect` (по умолч. 10), `history` (по умолч. 20) | Сколько записей показать |
| `--check` | `inspect` | TCP-чек endpoints |
| `--resolve` | `inspect` | Показать DNS-резолв |
| `--check-timeout N` | `inspect` | Таймаут TCP-чека для inspect (по умолч. 4.0) |
| `--from URL` | `geoip-update` | Скачать mmdb из своего источника (без зеркал и fallback) |
| `--working` / `--history` / `--sources` | `clean` | Что именно очистить |

## Управление сервисом

Одна и та же команда на всех ОС:

```bash
straysifter-service install       # поставить + создать config.json
straysifter-service start
straysifter-service stop
straysifter-service restart
straysifter-service status
straysifter-service uninstall     # остановить и удалить PID-файл
straysifter-service debug         # раннер в консоли (Ctrl+C — выход)
```

Реализация по платформам:

- **Windows** — detached subprocess (`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`). Проверка живости через `OpenProcess`/`GetExitCodeProcess` (`STILL_ACTIVE=259`). Остановка — мгновенный `taskkill /F`.
- **Linux/macOS** — двойной fork (`os.fork` × 2 + `setsid`). Проверка живости через `os.kill(pid, 0)`. Остановка — мгновенный `SIGKILL`.

Graceful-остановка посреди активного цикла не поддерживается: цикл дорабатывает до конца, форс-килл обрывает его. Недописанные данные не теряются — все JSON-файлы пишутся атомарно в самом конце.

Логи — `straysifter.log` в корне проекта, ротация 5 MB × 5. Пишет **только сервис**, не ручные запуски.
PID — `straysifter.pid`.
Автозапуск при загрузке — на откуп системе: Task Scheduler, `cron @reboot`, launchd.

## Меню управления

`manage.cmd` (Windows) или `./manage.sh` (Linux/macOS) — текстовое меню для всех команд выше: циклы, конфиг, сервис, логи, папки. Пункты 1 и 2 — разные режимы проверки (TCP и sing-box).

```bash
chmod +x manage.sh
./manage.sh
```

Меню не требует ввода команд — выбор пункта цифрой или буквой.

## Конфиг

`config.json` создаётся при первом `straysifter-service install` с дефолтами.

```json
{
  "fetcher": {
    "proxy": null,
    "prefer": "direct",
    "timeout": 25,
    "workers": 5,
    "ua": "Mozilla/5.0 (straysifter/2.0)"
  },
  "checks": {
    "mode": "tcp",
    "tcp_timeout": 3.0,
    "tcp_timeout_step": 3.0,
    "tcp_timeout_max": 9.0,
    "tcp_workers": 120,
    "tcp_attempts": 3,
    "tcp_retry_jitter": 0.4,
    "tcp_sequential_max_ips": 3,
    "tcp_sequential_after": 2,
    "tcp_endpoint_budget": 30.0,
    "tls_timeout": 4.0,
    "tls_workers": 30,
    "singbox_path": "",
    "singbox_timeout": 8.0,
    "exclude_countries": []
  },
  "geoip": {
    "enabled": true,
    "proxy": null,
    "http_fallback": true,
    "db_path": "",
    "detect_cdn": true
  },
  "sources": [
    "https://example.com/sub.txt"
  ],
  "schedule": {
    "check_minutes": 360.0
  },
  "storage": {
    "dir": "data"
  }
}
```

### fetcher

| Поле | Тип | Описание |
|---|---|---|
| `proxy` | str \| null | `socks5h://127.0.0.1:1080` или `http://...`. Используется **только** для загрузки источников. Проверки всегда идут напрямую. |
| `prefer` | str | `direct` — сначала напрямую, потом через прокси. `proxy` — наоборот. `direct-only` / `proxy-only` — без fallback. |
| `timeout` | int | Таймаут одного HTTP-запроса, секунды. |
| `workers` | int | Параллельных загрузок источников. |
| `ua` | str | User-Agent. |

### checks

| Поле | Тип | Описание |
|---|---|---|
| `mode` | str | `tcp` — только TCP-connect (быстро). `tcp+tls` — дополнительно TLS-handshake. `singbox` — реальный HTTP-запрос через sing-box (медленно, точно). |
| `tcp_timeout` | float | Таймаут первой попытки, секунды. Дефолт 3.0. **Уменьшать не стоит** — публичные сервера часто отвечают на 2-3 секунде. |
| `tcp_timeout_step` | float | Прирост таймаута на каждой следующей попытке. Дефолт 3.0. |
| `tcp_timeout_max` | float | Потолок таймаута. Дефолт 9.0. |
| `tcp_workers` | int | Параллельных TCP-проверок. Дефолт 120 (безопасно для Windows). |
| `tcp_attempts` | int | Попыток на endpoint. Дефолт 3. RST-ответы не ретраятся независимо от этого числа. |
| `tcp_retry_jitter` | float | Случайная пауза перед повтором, до N секунд. Дефолт 0.4. **Меньше 0.3 — потеря 20-25% живых** (проверено A/B). |
| `tcp_sequential_max_ips` | int | Для хостов с числом IP ≤ N — последовательный обход. Дефолт 3. |
| `tcp_sequential_after` | int | С какой попытки переходить на последовательный обход. Дефолт 2. |
| `tcp_endpoint_budget` | float | Жёсткий бюджет на один endpoint, секунды. `0` — без ограничения. Дефолт 30.0. |
| `tls_timeout` | float | Таймаут TLS-handshake. Дефолт 4.0. |
| `tls_workers` | int | Параллельных TLS-handshake. Дефолт 30. |
| `singbox_path` | str | Путь к бинарнику sing-box. Пусто → `<home>/bin/sing-box/sing-box[.exe]`. |
| `singbox_timeout` | float | Таймаут на один ключ (URLTest через Clash API), секунды. Дефолт 8.0. |
| `exclude_countries` | list[str] | ISO-коды стран, которые не попадут в экспорт. Пусто — экспортировать все. |

### geoip

| Поле | Тип | Описание |
|---|---|---|
| `enabled` | bool | Определять страну по IP, а не по remark. |
| `proxy` | str \| null | Прокси **только** для HTTP-запросов geoip (ip-api.com). |
| `http_fallback` | bool | Разрешить HTTP-lookup, если нет mmdb. |
| `db_path` | str | Путь к `.mmdb`. Пусто → `data/dbip-country-lite.mmdb`. |
| `detect_cdn` | bool | Если IP принадлежит CDN — страна не ставится, берётся из remark. |

### sources

Массив URL. Один плоский список, без деления по протоколам. Парсер сам разбирается, что в тексте: список URI, base64-подписка, Clash YAML, CSV, plain `host:port`.

Пример:

```json
"sources": [
  "https://raw.githubusercontent.com/user/repo/main/sub.txt",
  "https://gitverse.ru/api/repos/user/repo/raw/branch/main/whitelist.txt",
  "https://gist.githubusercontent.com/user/id/raw/all.yaml"
]
```

### schedule

| Поле | Тип | Описание |
|---|---|---|
| `check_minutes` | float | Как часто прогонять полный цикл (fetch + check + export). |

### storage

| Поле | Тип | Описание |
|---|---|---|
| `dir` | str | Куда складывать базу, архив, экспорты. |

### Env-переменные

Перекрывают config:

- `SIFTER_PROXY` — прокси для fetch.
- `SIFTER_FETCH_PREFER` — `direct` / `proxy` / `direct-only` / `proxy-only`.
- `SIFTER_MODE` — `tcp` / `tcp+tls` / `singbox`.
- `SIFTER_EXCLUDE_COUNTRIES` — `RU,CN`.
- `SIFTER_GEOIP` — `1` / `0` / `true` / `false`.
- `SIFTER_GEOIP_PROXY`.
- `SIFTER_GEOIP_DETECT_CDN`.
- `SIFTER_DATA` — путь к `data/`.
- `SIFTER_SOURCES` — список URL через запятую.
- `SIFTER_SINGBOX_PATH` — путь к бинарнику sing-box.
- `straysifter_HOME` — корень проекта (регистр как есть). Используется в `paths.find_home()`.

## Режим sing-box

`--mode singbox` включает проверку через полноценный движок sing-box вместо голого TCP. Это даёт:

- **Реальную проверку.** URLTest через каждый ключ, а не просто «порт открыт». Список живых короче, но в клиенте работает почти всё.
- **Hysteria2 наравне со всеми.** UDP-протокол проверяется нативно, отдельный файл кандидатов не создаётся.
- **Failover на битых ключах.** Если sing-box падает на конкретном outbound — парсер stderr достаёт индекс битого, выкидывает его, batch перезапускается. Один кривой ключ не уносит остальные 4999.
- **Строгую валидацию полей.** Битый `pbk`, невалидный `uuid`, неизвестный `flow`/`fingerprint`/`transport` — отсеиваются до отправки в sing-box. Такие ключи не тратят слот в batch'е.

Ограничения:

- **XHTTP/SplitHTTP не проверяются.** sing-box не поддерживает эти Xray-транспорты. Такие ключи скипаются (в TCP-режиме они проверяются как обычно).
- **CDN-фронты.** Многие живые ноды стоят за Cloudflare и получают `XX` (не определяется страна) → не отфильтровываются `--exclude-country`. Это ожидаемое поведение.
- **Скорость.** ~18 ключей/сек против ~10/сек у TCP-чека. 22к ключей проходят за ~20 минут.

## GeoIP

Три источника данных, проверяются по порядку:

1. **Кэш** (`data/geoip_cache.json`) — уже виденные IP. Постоянный: IP → страна не меняется.
2. **mmdb** (оффлайн) — если установлен `maxminddb` и есть `.mmdb`.
3. **HTTP** (ip-api.com/batch) — если ни кэша, ни mmdb нет.

HTTP-лукап идёт только если накопилось ≥3 незнакомых IP. Для 1-2 IP не окупается: rate-limit у ip-api всё равно даст 1-2 секунды задержки, а одиночных доменов за прогон может набраться много.

CDN-детект работает по двум каналам: список CIDR Cloudflare/Fastly (захардкожен) + ASN Cloudflare/Fastly/Akamai/AWS/Google/Microsoft из ответа ip-api. Если сработал — страна не ставится, и `parse_country` откатывается на remark ключа.

Обновление mmdb:

```bash
straysifter geoip-update
```

Пробует по порядку:

- `github.com/P3TERX/GeoLite.mmdb` — обновляется ежедневно.
- `github.com/Loyalsoldier/geoip` — Country.mmdb из releases.
- `github.com/wp-statistics/GeoLite2-Country` — обновляется реже.
- `download.db-ip.com` — три последних месяца по кругу, `.mmdb.gz` распаковывается на лету; с браузерным User-Agent, иначе отдаёт 403.

Свой источник:

```bash
straysifter geoip-update --from https://example.com/Country.mmdb
```

Если передан `--from`, зеркала и db-ip fallback не используются — качается ровно этот URL.

Очистка кэша:

```bash
straysifter geoip-clear
```

## Вывод

`data/exports/checked.txt` (TCP-режим):

```
# VPN keys — только живые по TCP (excluded: RU)
# Обновлено: 2026-09-23 07:47:36
# Всего: 493

vless://...#🇩🇪 DE-001 [Reality] 45ms
vless://...#🇳🇱 NL-001 [WS+TLS] 82ms
trojan://...#🇸🇪 SE-001 [Trojan] 118ms
```

`data/exports/checked.txt` (sing-box режим — шапка отличается):

```
# VPN keys — sing-box verified (excluded: RU)
# Обновлено: 2026-09-24 12:10:18
# Всего: 367

vless://...#🇩🇪 DE-001 [Reality] 45ms
...
```

Формат строки одинаковый: `<URI>#<флаг> <ISO>-<NNN> [<протокол>] <пинг>ms`.

Отдельные файлы по схемам (создаются, только если такие ключи есть в базе):

- `data/exports/checked_vless.txt`
- `data/exports/checked_trojan.txt`
- `data/exports/checked_ss.txt`
- `data/exports/checked_vmess.txt`
- `data/exports/checked_socks.txt`
- `data/exports/checked_http.txt`

`data/exports/hysteria2_candidates.txt` — **только в TCP-режиме**. hysteria/hysteria2-ключи без проверки живости:

```
# Hysteria / Hysteria2 candidates — БЕЗ проверки живости
# Обновлено: 2026-09-23 07:47:36
# Всего: 37
#
# UDP-протоколы: TCP-connect к ним провалится; полноценная
# проверка требует sing-box. Импортируй файл в клиент и прогони
# тест задержки сам.

hysteria2://...#🇩🇪 DE-001 [Hysteria2] unverified
hysteria2://...#🇳🇱 NL-002 [Hysteria2] unverified
```

В sing-box режиме этот файл не создаётся — hysteria проверяется и идёт в общий `checked.txt`.

Экспорт одного источника через `export-source <pattern>` даёт два файла:

- `data/exports/source_<name>_alive.txt` — только прошедшие проверку (в том режиме, что был указан).
- `data/exports/source_<name>_all.txt` — все ключи источника (без hysteria2 в TCP-режиме).

## Статистика источников

```bash
straysifter sources-stats
```

```
status       found   uniq  contrib  alive   ratio  name
ok           26228   9817     7612    463    4.7%  update.txt
ok             106     21        0     15   71.4%  BLACK_VLESS_RUS.txt
no alive       256    163        0      0    0.0%  selected.txt
```

| Колонка | Описание |
|---|---|
| `status` | `ok`, `low_yield`, `no_alive`, `empty`, `stale`, `dead`, `not_updating`, `never_ok` |
| `found` | Всего URI в источнике (`raw_uris`) |
| `uniq` | Уникальных ключей в этом источнике |
| `contrib` | Живых ключей, которых нет ни в одном другом источнике (`unique_alive`) |
| `alive` | Прошло проверку |
| `ratio` | `alive / uniq` |

Статусы (порядок — как в сортировке вывода):

| Статус | Условие |
|---|---|
| `dead` | Последний успешный fetch > 7 дней назад |
| `never_ok` | Ни одного успешного fetch в истории |
| `empty` | 0 ключей в тексте |
| `no_alive` | 0 живых при `uniq > 0` |
| `not_updating` | Содержимое не менялось > 30 дней |
| `stale` | Последний fetch > 48 часов назад |
| `low_yield` | Живой, `ratio` < 3% |
| `ok` | Живой, `ratio` ≥ 3% |

Флаг `-v2` (в коде = `--verbose`) добавляет времена проблемных источников и unsupported схемы. Флаг `--json` — вывод в JSON.

## Управление базой

```bash
# показать состояние
straysifter status

# последние 20 прогонов (с колонкой mode — каким чекером гоняли)
straysifter history
straysifter history --limit 50

# очистить
straysifter clean --working                    # рабочая база
straysifter clean --history                    # история
straysifter clean --sources                    # статистика источников
straysifter clean --working --history --sources
```

## Файлы данных

```
data/
├── raw/                              # снапшоты источников по дням
├── exports/
│   ├── checked.txt                   # живое, общий список
│   ├── checked_<scheme>.txt          # по схемам (если есть)
│   └── hysteria2_candidates.txt      # hysteria/hysteria2, только TCP-режим
├── working.json                      # рабочая база (лимит 20 000 записей)
├── history.json                      # история прогонов (лимит 500 записей)
├── sources.json                      # статистика источников
├── geoip_cache.json                  # IP → страна
└── dbip-country-lite.mmdb            # GeoIP-база (опционально)

bin/
└── sing-box/
    └── sing-box.exe                  # бинарник, скачивается вручную
```

Ретеншен `data/raw/` — 7 дней. Остальное не чистится автоматически. `bin/` в `.gitignore`.

## Архитектура

```
Stray-Keys-Sifter/                    # корень (git, config.json, data/, логи)
├── straysifter/                      # python-пакет
│   ├── __init__.py                   # __version__, глушит urllib3
│   ├── __main__.py                   # python -m straysifter
│   ├── core/
│   │   ├── __init__.py               # реэкспорт Config, load_config, SourceFetcher
│   │   ├── config.py                 # dataclass-конфиг, env-override
│   │   ├── paths.py                  # find_home() — где живёт проект
│   │   ├── fetcher.py                # SourceFetcher — единственное место, где есть прокси
│   │   ├── archive.py                # снапшоты источников + ретеншен + fallback на кэш
│   │   ├── parsers.py                # URI → ProxyInfo (все схемы + base64)
│   │   ├── yaml_parser.py            # Clash YAML → ProxyInfo
│   │   ├── csv_parser.py             # CSV / plain host:port → ProxyInfo
│   │   ├── country.py                # определение страны + флаги
│   │   ├── geoip.py                  # IP → страна (cache, mmdb, ip-api)
│   │   ├── checks.py                 # TCP через asyncio, TLS-опция
│   │   ├── singbox.py                # sing-box: Clash API + batch failover
│   │   ├── pipeline.py               # fetch → parse → check → GeoIP → save
│   │   └── storage.py                # база, история, статистика, экспорт
│   ├── frontends/
│   │   ├── __init__.py
│   │   └── cli.py                    # python -m straysifter <команда>
│   └── service/
│       ├── __init__.py
│       ├── __main__.py               # straysifter-service <install|start|stop|...>
│       ├── runner.py                 # фоновый цикл
│       ├── daemon_posix.py           # двойной fork
│       └── daemon_windows.py         # detached subprocess
├── bin/
│   └── sing-box/                     # бинарник sing-box (опционально)
├── pyproject.toml
├── README.md
├── LICENSE
├── manage.cmd / manage.sh            # текстовое меню
├── smoke_test.py                     # оффлайн + сетевые smoke-тесты
├── config.json                       # создаётся при install, в .gitignore
├── straysifter.log                   # ротация 5 MB × 5, в .gitignore
├── straysifter.pid                   # в .gitignore
└── data/                             # создаётся при первом collect, в .gitignore
```

Прокси существует только в `core/fetcher.py`. Ни `checks.py`, ни `singbox.py`, ни `pipeline.py`, ни CLI, ни сервис о нём не знают — проверки никогда не идут через прокси, даже если он задан.

## Лицензия

MIT. См. `LICENSE`.