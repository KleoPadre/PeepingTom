# ТЗ: терминальная утилита для просмотра и анализа PCAP/PCAPNG с красивым TUI

## 1. Название проекта

Рабочее название:

```text
PacketScope TUI
```

Альтернативы:

```text
pcap-view
traffic-scope
netpeek
pcap-tui
```

## 2. Цель проекта

Создать бесплатную терминальную утилиту для macOS, Linux и, желательно, Windows, которая позволяет:

- открывать готовые файлы `.pcap` и `.pcapng`;
- запускать live-захват сетевого трафика;
- останавливать захват и сразу анализировать собранный файл;
- удобно просматривать пакеты в терминальном интерфейсе;
- быстро находить IP, домены, UDP/STUN/TURN, Telegram-звонки, DNS, TLS SNI;
- заменять Wireshark для простых задач анализа трафика.

Утилита не должна быть полноценной заменой Wireshark. Основная задача — **быстрый просмотр, фильтрация и анализ трафика без тяжёлого GUI**.

---

# 3. Основной сценарий использования

## 3.1. Открытие готового файла

Пользователь запускает:

```bash
packetscope open ~/Downloads/capture.pcapng
```

Открывается TUI-интерфейс:

```text
┌ PacketScope ─ capture.pcapng ─────────────────────────────────────────────┐
│ Filter: ip.addr == 192.168.1.4 && udp                         Packets: 842 │
├──────┬──────────┬──────────────┬──────────────┬───────┬──────────────────┤
│ No   │ Time     │ Source       │ Destination  │ Proto │ Info             │
├──────┼──────────┼──────────────┼──────────────┼───────┼──────────────────┤
│ 143  │ 5.097389 │ 192.168.1.4  │ 91.108.9.6   │ STUN  │ Binding Request  │
│ 144  │ 5.102331 │ 91.108.9.6   │ 192.168.1.4  │ STUN  │ Success Response │
│ 145  │ 5.147045 │ 192.168.1.4  │ 91.108.9.42  │ STUN  │ Allocate Request │
└──────┴──────────┴──────────────┴──────────────┴───────┴──────────────────┘
[F] Filter  [/] Search  [Enter] Details  [T] Top IP  [S] STUN  [Q] Quit
```

## 3.2. Live-захват

Пользователь запускает:

```bash
sudo packetscope capture --iface en0 --host 192.168.1.4
```

Утилита:

1. запускает `tshark`/`dumpcap`;
2. показывает live-статистику;
3. сохраняет файл во временную или указанную директорию;
4. по нажатию `Ctrl+C` или клавиши `S` останавливает захват;
5. автоматически открывает собранный `.pcapng` в TUI.

Пример:

```bash
sudo packetscope capture --iface en0 --host 192.168.1.4 --out telegram-call.pcapng
```

---

# 4. Технологический стек

## 4.1. Язык

Рекомендуемый язык:

```text
Python 3.11+
```

Причины:

- быстрое создание MVP;
- простая работа с `subprocess`;
- удобные CLI/TUI-библиотеки;
- легко поддерживать;
- подходит для macOS на Apple Silicon.

## 4.2. Зависимости

Обязательные:

```text
tshark
dumpcap
Python 3.11+
```

Python-библиотеки:

```text
typer        CLI-команды
rich         красивые таблицы, цвета, панели
textual      полноценный TUI
pydantic     модели данных
```

Опционально:

```text
orjson       быстрый JSON-парсинг
pandas       экспорт и агрегация, если понадобится
```

## 4.3. Внешний движок анализа

Утилита не должна самостоятельно парсить PCAP. Для чтения и декодирования используется:

```text
tshark
```

Для live-захвата можно использовать:

```text
dumpcap
```

или:

```text
tshark -i ...
```

---

# 5. Поддерживаемые платформы

## Обязательно

```text
macOS Apple Silicon
macOS Intel
```

## Желательно

```text
Linux x86_64
Linux ARM64
```

## Опционально

```text
Windows
```

---

# 6. Основные команды CLI

## 6.1. Проверка окружения

```bash
packetscope doctor
```

Проверяет:

- установлен ли `tshark`;
- установлен ли `dumpcap`;
- видны ли сетевые интерфейсы;
- есть ли права на захват;
- версия Python;
- версия PacketScope.

Пример вывода:

```text
PacketScope Doctor

tshark      OK   /opt/homebrew/bin/tshark
dumpcap     OK   /opt/homebrew/bin/dumpcap
interfaces  OK   en0, en5, lo0
permissions WARN live capture may require sudo
```

---

## 6.2. Список интерфейсов

```bash
packetscope interfaces
```

Пример вывода:

```text
Available interfaces

1  en0       Wi-Fi
2  en5       USB Ethernet
3  lo0       Loopback
4  any       All interfaces
```

---

## 6.3. Открыть PCAP/PCAPNG

```bash
packetscope open file.pcapng
```

Параметры:

```bash
packetscope open file.pcapng --host 192.168.1.4
packetscope open file.pcapng --filter "udp && ip.addr == 192.168.1.4"
packetscope open file.pcapng --limit 5000
```

---

## 6.4. Захват трафика

```bash
sudo packetscope capture --iface en0
```

С фильтром по устройству:

```bash
sudo packetscope capture --iface en0 --host 192.168.1.4
```

С указанием файла:

```bash
sudo packetscope capture --iface en0 --host 192.168.1.4 --out capture.pcapng
```

С ограничением по времени:

```bash
sudo packetscope capture --iface en0 --host 192.168.1.4 --duration 60
```

С BPF-фильтром:

```bash
sudo packetscope capture --iface en0 --bpf "host 192.168.1.4 and udp"
```

---

## 6.5. Быстрый анализ Telegram

```bash
packetscope telegram capture.pcapng --host 192.168.1.4
```

Утилита должна найти:

- STUN/TURN-пакеты;
- пакеты с `realm: telegram`;
- активные UDP-соединения;
- IP с большим количеством пакетов;
- кандидатов на Telegram relay.

Пример вывода:

```text
Telegram candidates

IP            Proto  Packets  Bytes    Evidence
91.108.9.6    STUN   94       38 KB    realm: telegram
91.108.9.42   UDP    1204     1.8 MB   active UDP relay
```

---

## 6.6. Top IP

```bash
packetscope top capture.pcapng --host 192.168.1.4
```

Показывает самые активные внешние IP:

```text
Top external IPs

IP              Direction  Proto  Packets  Bytes
91.108.9.42     both       UDP    1204     1.8 MB
91.108.9.6      both       STUN   94       38 KB
149.154.167.91  both       TCP    331      240 KB
```

---

## 6.7. STUN/TURN

```bash
packetscope stun capture.pcapng
```

Показывает только STUN/TURN-пакеты:

```text
STUN/TURN packets

No   Time     Source       Destination  Info
143  5.097    192.168.1.4  91.108.9.6   Binding Request
144  5.102    91.108.9.6   192.168.1.4  Binding Success Response
145  5.147    192.168.1.4  91.108.9.42  Allocate Request UDP realm: telegram
```

---

## 6.8. DNS

```bash
packetscope dns capture.pcapng
```

Показывает DNS-запросы:

```text
DNS queries

Time     Client       Query
1.421    192.168.1.4  api.telegram.org
1.982    192.168.1.4  gateway.icloud.com
```

---

## 6.9. TLS SNI

```bash
packetscope tls capture.pcapng
```

Показывает TLS Server Name Indication:

```text
TLS SNI

Time     Source       Destination     SNI
2.112    192.168.1.4  149.154.167.91  api.telegram.org
```

---

# 7. TUI-интерфейс

## 7.1. Главный экран

Главный экран должен состоять из:

```text
┌ Header ───────────────────────────────────────────────┐
│ file name, packet count, active filter                │
├ Packet table ─────────────────────────────────────────┤
│ No | Time | Source | Destination | Proto | Length | Info │
├ Details panel ────────────────────────────────────────┤
│ selected packet decoded details                       │
├ Footer ───────────────────────────────────────────────┤
│ hotkeys                                               │
└───────────────────────────────────────────────────────┘
```

## 7.2. Таблица пакетов

Колонки:

```text
No
Time
Source
Destination
Src Port
Dst Port
Protocol
Length
Info
```

Обязательные возможности:

- прокрутка вверх/вниз;
- поиск;
- фильтр;
- сортировка;
- выбор пакета;
- открытие деталей;
- копирование IP;
- копирование строки;
- экспорт видимых строк.

## 7.3. Панель деталей

При выборе пакета показывать:

```text
Frame
Ethernet
IP
TCP/UDP
DNS/TLS/STUN/HTTP where available
Raw Info
```

На первом этапе детали можно получать через `tshark -V`.

Пример:

```bash
tshark -r file.pcapng -Y "frame.number == 143" -V
```

## 7.4. Поиск

Глобальный поиск:

```text
/
```

Ищет по:

- Source;
- Destination;
- Protocol;
- Info;
- DNS name;
- SNI;
- STUN realm.

Пример поиска:

```text
telegram
```

## 7.5. Фильтры

Клавиша:

```text
F
```

Открывает строку фильтра.

Поддерживать синтаксис Wireshark display filters, например:

```text
ip.addr == 192.168.1.4
udp
stun
stun && frame contains "telegram"
ip.addr == 192.168.1.4 && udp
tls.handshake.extensions_server_name
dns
```

Фильтр передаётся напрямую в `tshark -Y`.

## 7.6. Горячие клавиши

```text
Q        выход
F        фильтр
/        поиск
Enter    детали пакета
T        top IP
S        STUN/TURN
D        DNS
L        TLS SNI
G        перейти к пакету
R        сбросить фильтр
E        экспорт
C        копировать выбранное значение
?        помощь
```

---

# 8. Аналитические экраны

## 8.1. Top Talkers

Экран показывает внешние IP, сгруппированные по объёму и пакетам.

Колонки:

```text
IP
Direction
Protocol
Packets
Bytes
First Seen
Last Seen
Evidence
```

Критерии:

- исключать локальные адреса;
- группировать входящий и исходящий трафик;
- показывать UDP/TCP отдельно;
- сортировка по Bytes и Packets.

## 8.2. Telegram Detector

Отдельный экран:

```text
Telegram Candidates
```

Признаки:

```text
STUN/TURN
realm contains telegram
UDP traffic
IP belongs to known Telegram ranges, if database exists
large packet count
traffic active during call window
```

Вывод:

```text
IP              Score  Proto  Packets  Bytes   Evidence
91.108.9.6      100    STUN   94       38 KB   realm: telegram
91.108.9.42     85     UDP    1204     1.8 MB  UDP relay after STUN
```

Score:

```text
100  есть realm: telegram
80   STUN/TURN + UDP поток
60   IP из диапазона Telegram
40   много UDP-пакетов
```

Важно: утилита должна писать, что это **кандидаты**, а не гарантированная классификация.

## 8.3. DNS Screen

Показывает:

```text
Client IP
Query
Response IPs
Count
```

## 8.4. TLS SNI Screen

Показывает:

```text
Source
Destination
SNI
Count
```

## 8.5. Export Screen

Экспорт:

```text
CSV
TXT
JSON
```

Команды:

```bash
packetscope export capture.pcapng --format csv --out result.csv
```

---

# 9. Live Capture TUI

## 9.1. Экран live-захвата

```text
┌ PacketScope Live Capture ─────────────────────────────┐
│ Interface: en0     Filter: host 192.168.1.4           │
│ Output: ~/Captures/2026-08-28_telegram-call.pcapng    │
├ Stats ────────────────────────────────────────────────┤
│ Duration: 00:01:22                                    │
│ Packets: 14,922                                       │
│ Size: 18.4 MB                                         │
│ Top protocol: UDP                                     │
├ Recent packets ───────────────────────────────────────┤
│ Time | Source | Destination | Proto | Info            │
└───────────────────────────────────────────────────────┘
[S] Stop and Analyze  [Q] Stop and Quit
```

## 9.2. Остановка захвата

При нажатии `S`:

1. остановить процесс `tshark`/`dumpcap`;
2. закрыть файл;
3. проверить, что файл создан;
4. открыть его в режиме анализа.

---

# 10. Работа с файлами

## 10.1. Поддерживаемые форматы

```text
.pcap
.pcapng
```

## 10.2. Автоматическая директория захватов

По умолчанию:

```text
~/PacketScope/Captures/
```

Имена файлов:

```text
capture_2026-08-28_14-30-22.pcapng
telegram_2026-08-28_14-30-22.pcapng
```

## 10.3. Настройки

Файл настроек:

```text
~/.config/packetscope/config.toml
```

Пример:

```toml
default_interface = "en0"
default_host = "192.168.1.4"
captures_dir = "~/PacketScope/Captures"
theme = "dark"
max_rows = 10000
```

---

# 11. Цветовая схема TUI

## 11.1. Общий стиль

Стиль:

```text
тёмный фон
акцентный голубой/синий
минималистичные рамки
выделение выбранной строки
цветовая маркировка протоколов
```

## 11.2. Цвета протоколов

```text
DNS     cyan
STUN    magenta
UDP     yellow
TCP     green
TLS     blue
HTTP    orange
ICMP    red
OTHER   gray
```

## 11.3. Важные подсветки

Подсвечивать:

```text
telegram
STUN
TURN
Allocate Request
Binding Request
Binding Success
XOR-RELAYED-ADDRESS
TLS SNI
DNS Query
```

---

# 12. Вызовы `tshark`

## 12.1. Получение таблицы пакетов

```bash
tshark -r file.pcapng \
  -T fields \
  -E separator="\t" \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e tcp.srcport \
  -e tcp.dstport \
  -e udp.srcport \
  -e udp.dstport \
  -e frame.protocols \
  -e _ws.col.Protocol \
  -e frame.len \
  -e _ws.col.Info
```

## 12.2. С фильтром

```bash
tshark -r file.pcapng \
  -Y 'ip.addr == 192.168.1.4 && udp' \
  -T fields \
  ...
```

## 12.3. Детали пакета

```bash
tshark -r file.pcapng -Y "frame.number == 143" -V
```

## 12.4. STUN Telegram

```bash
tshark -r file.pcapng \
  -Y 'stun && frame contains "telegram"' \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e _ws.col.Info
```

## 12.5. DNS

```bash
tshark -r file.pcapng \
  -Y dns \
  -T fields \
  -e frame.time_relative \
  -e ip.src \
  -e dns.qry.name \
  -e dns.a
```

## 12.6. TLS SNI

```bash
tshark -r file.pcapng \
  -Y tls.handshake.extensions_server_name \
  -T fields \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e tls.handshake.extensions_server_name
```

---

# 13. MVP

## MVP 1 — базовый анализ файла

Обязательные функции:

```text
open file.pcap / file.pcapng
таблица пакетов
колонка Info
фильтр через tshark -Y
поиск по таблице
детали выбранного пакета
выход
```

## MVP 2 — аналитика

Добавить:

```text
Top IP
UDP conversations
STUN/TURN screen
DNS screen
TLS SNI screen
Telegram candidates
export CSV
```

## MVP 3 — live capture

Добавить:

```text
capture from interface
host filter
save to pcapng
stop and analyze
live stats
```

## MVP 4 — удобство

Добавить:

```text
config file
history of captures
recent files
themes
copy to clipboard
```

---

# 14. Ограничения

Утилита не должна:

- расшифровывать HTTPS;
- обходить certificate pinning;
- подменять сертификаты;
- декодировать защищённый контент;
- обещать точное определение владельца IP без проверки;
- заменять Wireshark для сложной экспертизы.

Утилита должна честно показывать:

```text
Telegram candidates, not guaranteed Telegram ownership
```

---

# 15. Критерии готовности

## Версия 0.1

Готово, если:

- открывает `.pcap` и `.pcapng`;
- показывает таблицу пакетов;
- показывает колонку `Info`;
- применяет display-фильтр;
- показывает детали пакета;
- работает на macOS Apple Silicon.

## Версия 0.2

Готово, если:

- показывает Top IP;
- показывает STUN/TURN;
- находит `realm: telegram`;
- экспортирует результаты в CSV.

## Версия 0.3

Готово, если:

- умеет live-захват;
- умеет stop and analyze;
- сохраняет `.pcapng`;
- показывает live-статистику.

## Версия 1.0

Готово, если:

- стабильный TUI;
- работает с большими файлами;
- есть конфиг;
- есть нормальная обработка ошибок;
- есть README;
- есть установка через Homebrew или pipx.

---

# 16. Рекомендуемый план разработки

## Этап 1

Создать CLI-основу:

```text
packetscope doctor
packetscope interfaces
packetscope open
```

## Этап 2

Сделать TUI-таблицу:

```text
Textual App
PacketTable
FilterInput
DetailsPanel
Footer
```

## Этап 3

Добавить фильтры и поиск:

```text
Wireshark display filters
search in visible rows
reset filter
```

## Этап 4

Добавить аналитические экраны:

```text
Top IP
STUN
DNS
TLS
Telegram
```

## Этап 5

Добавить live capture:

```text
capture
stop
save
auto-open
```

## Этап 6

Упаковка:

```text
pipx install packetscope
brew tap / formula
README
screenshots
examples
```

---

# 17. Пример README-команд

```bash
# Проверка окружения
packetscope doctor

# Список интерфейсов
packetscope interfaces

# Открыть pcapng
packetscope open ~/Downloads/capture.pcapng

# Открыть с фильтром по MacBook
packetscope open ~/Downloads/capture.pcapng --filter "ip.addr == 192.168.1.4"

# Найти Telegram-звонки
packetscope telegram ~/Downloads/capture.pcapng --host 192.168.1.4

# Захватить трафик MacBook
sudo packetscope capture --iface en0 --host 192.168.1.4 --out telegram-call.pcapng

# Показать top IP
packetscope top telegram-call.pcapng --host 192.168.1.4
```

---

# 18. Итоговое требование

Нужно создать лёгкую терминальную утилиту с TUI, которая использует `tshark` как backend, но предоставляет более простой интерфейс для бытового анализа трафика:

```text
открыть pcap
отфильтровать
посмотреть Info
найти STUN/TURN
найти Telegram-кандидаты
увидеть top IP
собрать live-захват
остановить и сразу разобрать
```

Главный фокус: **удобство, скорость и понятность**, а не замена всех возможностей Wireshark.