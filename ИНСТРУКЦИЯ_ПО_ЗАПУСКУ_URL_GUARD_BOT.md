# Пошаговая инструкция по запуску URL Guard Bot

Эта инструкция подходит для проекта **URL Guard Bot v1.2.1**.

Бот получает ссылку в Telegram, выполняет техническую проверку URL и защищён от SSRF, переходов во внутренние сети, опасных редиректов и перегрузки.

---

## 1. Что потребуется

Перед запуском подготовьте:

1. Компьютер или сервер с доступом в интернет.
2. Python версии **3.11, 3.12 или 3.13**.
3. Telegram-аккаунт.
4. Токен Telegram-бота, полученный у **@BotFather**.
5. Распакованный архив проекта.

Для обычного запуска база данных, домен, SSL-сертификат и открытые входящие порты не требуются. Бот работает через Telegram long polling.

---

## 2. Получение токена Telegram-бота

1. Откройте Telegram.
2. Найдите официальный аккаунт **@BotFather**.
3. Отправьте команду:

```text
/newbot
```

4. Укажите отображаемое имя бота.
5. Укажите username. Он должен оканчиваться на `bot`, например:

```text
safe_url_guard_bot
```

6. BotFather отправит токен примерно такого формата:

```text
1234567890:AAExampleTokenDoNotUse
```

7. Сохраните токен. Он понадобится при настройке файла `.env`.

> Никому не отправляйте настоящий токен. Тот, кто получил токен, может управлять ботом. Если токен был опубликован, отзовите его через BotFather и создайте новый.

---

# Вариант A — запуск на Windows

## 3. Распаковка проекта

1. Распакуйте архив проекта в отдельную папку.
2. Рекомендуемый путь без кириллицы и сложных символов:

```text
C:\Bots\url_security_bot
```

3. Внутри папки должны находиться файлы:

```text
.env.example
requirements.txt
run.bat
url_guard_bot\
```

Если внутри распакованной папки находится ещё одна папка `url_security_bot`, откройте именно её.

---

## 4. Проверка Python

Откройте PowerShell в папке проекта.

Быстрый способ:

1. Откройте папку проекта в Проводнике.
2. Нажмите правой кнопкой мыши по свободному месту.
3. Выберите «Открыть в терминале».

Проверьте Python:

```powershell
py --version
```

или:

```powershell
python --version
```

Ожидаемый результат:

```text
Python 3.11.x
```

Подойдут также Python 3.12 и 3.13.

Если команда не найдена, установите Python и при установке включите параметр **Add Python to PATH**.

---

## 5. Создание виртуального окружения

В PowerShell, находясь в папке проекта, выполните:

```powershell
py -m venv .venv
```

Если команда `py` отсутствует, используйте:

```powershell
python -m venv .venv
```

Активируйте окружение:

```powershell
.\.venv\Scripts\Activate.ps1
```

После активации в начале строки терминала появится:

```text
(.venv)
```

### Если PowerShell запрещает активацию

Выполните:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Затем повторите:

```powershell
.\.venv\Scripts\Activate.ps1
```

Изменение действует только для текущего окна PowerShell.

---

## 6. Установка зависимостей

Обновите установщик пакетов:

```powershell
python -m pip install --upgrade pip
```

Установите зависимости проекта:

```powershell
python -m pip install -r requirements.txt
```

Дождитесь завершения без красных сообщений об ошибках.

Проверьте зависимости:

```powershell
python -m pip check
```

Ожидаемый результат:

```text
No broken requirements found.
```

---

## 7. Создание файла `.env`

Скопируйте пример конфигурации:

```powershell
Copy-Item .env.example .env
```

Откройте файл:

```powershell
notepad .env
```

Найдите строку:

```dotenv
BOT_TOKEN=1234567890:replace_with_real_bot_token
```

Замените значение после `=` на настоящий токен:

```dotenv
BOT_TOKEN=ВАШ_ТОКЕН_ОТ_BOTFATHER
```

Пример структуры файла:

```dotenv
BOT_TOKEN=1234567890:AAExampleTokenDoNotUse

RATE_LIMIT_REQUESTS=5
RATE_LIMIT_WINDOW_SECONDS=60
MAX_CONCURRENT_ANALYSES=12
UPDATE_CONCURRENCY_LIMIT=40

MAX_URL_LENGTH=2048
MAX_REDIRECTS=5
ANALYSIS_TIMEOUT=20
REQUEST_TIMEOUT=8
CONNECT_TIMEOUT=4
READ_TIMEOUT=5
CHECK_META_REFRESH=true
META_REFRESH_MAX_BYTES=2048
ALLOWED_HTTP_PORTS=80
ALLOWED_HTTPS_PORTS=443
```

Сохраните файл и закройте Блокнот.

Важно:

- не добавляйте кавычки вокруг токена;
- не ставьте пробелы до или после токена;
- файл должен называться именно `.env`, а не `.env.txt`;
- не публикуйте `.env` и не отправляйте его другим людям.

---

## 8. Первый запуск

Убедитесь, что виртуальное окружение активно и в строке присутствует `(.venv)`.

Запустите бота:

```powershell
python -m url_guard_bot
```

При успешном запуске терминал останется открытым, а в журнале появятся сообщения aiogram о начале polling.

Не закрывайте терминал, пока бот должен работать.

### Альтернативный запуск через `run.bat`

Сначала активируйте виртуальное окружение:

```powershell
.\.venv\Scripts\Activate.ps1
```

Затем выполните:

```powershell
.\run.bat
```

---

## 9. Проверка работы

1. Откройте Telegram.
2. Найдите бота по username, который указали в BotFather.
3. Нажмите «Запустить» или отправьте:

```text
/start
```

4. Отправьте тестовую ссылку:

```text
https://example.com
```

Бот должен вернуть результат анализа.

Также можно проверить защиту, отправив:

```text
http://127.0.0.1
```

Бот должен заблокировать ссылку как внутренний или неглобальный адрес и не обращаться к нему.

---

## 10. Остановка и повторный запуск

Для остановки нажмите в терминале:

```text
Ctrl+C
```

Для повторного запуска после перезагрузки компьютера:

```powershell
cd C:\Bots\url_security_bot
.\.venv\Scripts\Activate.ps1
python -m url_guard_bot
```

---

# Вариант B — запуск на Linux или VPS

## 11. Установка системных компонентов

Для Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip
```

Проверьте версию:

```bash
python3 --version
```

---

## 12. Подготовка проекта

Перейдите в папку проекта:

```bash
cd /путь/к/url_security_bot
```

Создайте окружение:

```bash
python3 -m venv .venv
```

Активируйте его:

```bash
source .venv/bin/activate
```

Установите зависимости:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
```

---

## 13. Настройка `.env` на Linux

Создайте файл из примера:

```bash
cp .env.example .env
```

Откройте его:

```bash
nano .env
```

Замените значение `BOT_TOKEN` на настоящий токен.

Сохранение в nano:

1. Нажмите `Ctrl+O`.
2. Нажмите `Enter`.
3. Нажмите `Ctrl+X`.

Ограничьте доступ к файлу:

```bash
chmod 600 .env
```

---

## 14. Запуск на Linux

```bash
python -m url_guard_bot
```

Либо:

```bash
chmod +x run.sh
./run.sh
```

Остановка:

```text
Ctrl+C
```

---

## 15. Автозапуск через systemd на VPS

Этот раздел необязателен. Он нужен, чтобы бот запускался автоматически после перезагрузки сервера.

Предположим, проект расположен здесь:

```text
/opt/url_security_bot
```

Узнайте имя текущего пользователя:

```bash
whoami
```

Создайте службу:

```bash
sudo nano /etc/systemd/system/url-guard-bot.service
```

Вставьте, заменив `YOUR_USER` и пути при необходимости:

```ini
[Unit]
Description=URL Guard Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_USER
WorkingDirectory=/opt/url_security_bot
ExecStart=/opt/url_security_bot/.venv/bin/python -m url_guard_bot
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
```

Примените настройки:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now url-guard-bot
```

Проверьте состояние:

```bash
sudo systemctl status url-guard-bot
```

Просмотр журнала:

```bash
sudo journalctl -u url-guard-bot -f
```

Перезапуск:

```bash
sudo systemctl restart url-guard-bot
```

Остановка:

```bash
sudo systemctl stop url-guard-bot
```

> Если проект находится в домашней папке, параметр `ProtectHome=true` может запретить службе доступ к нему. В таком случае перенесите проект в `/opt/url_security_bot` или аккуратно измените ограничение службы.

---

# Вариант C — запуск через Docker

## 16. Подготовка Docker

Установите Docker Desktop на Windows или Docker Engine с плагином Compose на Linux.

Проверьте команды:

```bash
docker --version
docker compose version
```

---

## 17. Настройка `.env` для Docker

В папке проекта создайте `.env`.

Windows PowerShell:

```powershell
Copy-Item .env.example .env
notepad .env
```

Linux:

```bash
cp .env.example .env
nano .env
```

Укажите настоящий `BOT_TOKEN`.

---

## 18. Сборка и запуск контейнера

В папке проекта выполните:

```bash
docker compose up -d --build
```

Проверьте состояние:

```bash
docker compose ps
```

Посмотрите журнал:

```bash
docker compose logs -f
```

Для выхода из просмотра журнала нажмите `Ctrl+C`. Контейнер продолжит работать.

Перезапуск:

```bash
docker compose restart
```

Остановка и удаление контейнера:

```bash
docker compose down
```

Полная пересборка после изменения кода:

```bash
docker compose down
docker compose up -d --build
```

---

# Дополнительные проверки

## 19. Запуск автоматических тестов

Для обычной работы тестовые зависимости не нужны. Для проверки проекта установите их отдельно.

Windows или Linux с активированным окружением:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Ожидаемый результат текущей версии:

```text
84 passed
```

Проверка синтаксиса:

```bash
python -m compileall -q url_guard_bot
```

Проверка линтером:

```bash
python -m ruff check .
python -m ruff format --check .
```

---

# Настройки безопасности и нагрузки

## 20. Основные параметры `.env`

### Ограничение запросов одного пользователя

```dotenv
RATE_LIMIT_REQUESTS=5
RATE_LIMIT_WINDOW_SECONDS=60
```

Один пользователь может выполнить до 5 проверок за 60 секунд.

### Общий лимит одновременных проверок

```dotenv
MAX_CONCURRENT_ANALYSES=12
UPDATE_CONCURRENCY_LIMIT=40
```

Не увеличивайте значения без необходимости, особенно на слабом VPS.

### Лимит редиректов и времени

```dotenv
MAX_REDIRECTS=5
ANALYSIS_TIMEOUT=20
REQUEST_TIMEOUT=8
CONNECT_TIMEOUT=4
READ_TIMEOUT=5
```

### Проверка HTML meta-refresh

```dotenv
CHECK_META_REFRESH=true
META_REFRESH_MAX_BYTES=2048
```

Для отключения:

```dotenv
CHECK_META_REFRESH=false
```

### Разрешённые исходящие порты

```dotenv
ALLOWED_HTTP_PORTS=80
ALLOWED_HTTPS_PORTS=443
```

Не добавляйте внутренние или нестандартные порты без понимания рисков SSRF.

---

# Частые ошибки

## 21. `BOT_TOKEN is not configured`

Причина: отсутствует `.env` или в нём нет токена.

Проверьте:

```powershell
Get-Content .env
```

или на Linux:

```bash
cat .env
```

Файл должен находиться в корне проекта рядом с `requirements.txt`.

Не публикуйте вывод команды, если в нём находится настоящий токен.

---

## 22. `TokenValidationError`

Причины:

- токен скопирован не полностью;
- вокруг токена добавлены кавычки;
- присутствуют лишние пробелы;
- токен был отозван;
- в `.env` оставлено тестовое значение.

Получите новый токен через BotFather и замените значение `BOT_TOKEN`.

---

## 23. `ModuleNotFoundError: No module named ...`

Причина: зависимости не установлены либо виртуальное окружение не активировано.

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

---

## 24. `No module named url_guard_bot`

Вы запускаете команду не из корня проекта.

Перед запуском перейдите в папку, где находятся `requirements.txt` и каталог `url_guard_bot`.

Проверка на Windows:

```powershell
Get-ChildItem
```

Проверка на Linux:

```bash
ls -la
```

---

## 25. Ошибка активации PowerShell

Выполните:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

---

## 26. `Conflict: terminated by other getUpdates request`

Одновременно запущены две копии одного бота.

Закройте лишнее окно, остановите старый процесс или выполните:

```bash
docker compose down
```

если предыдущая копия работает в Docker.

Один токен должен использоваться только одним polling-процессом.

---

## 27. Бот запущен, но не отвечает

Проверьте:

1. Терминал с ботом не закрыт.
2. В журнале нет ошибок.
3. Компьютер или VPS имеет доступ в интернет.
4. Токен относится к нужному боту.
5. Не запущена другая копия с тем же токеном.
6. Пользователь нажал «Запустить» в Telegram.
7. На сервере корректно работает DNS.

Для Docker:

```bash
docker compose logs --tail=100
```

Для systemd:

```bash
sudo journalctl -u url-guard-bot -n 100 --no-pager
```

---

## 28. Сайт получает результат «не удалось проверить»

Это не обязательно означает, что сайт вредоносный. Возможные причины:

- сайт не отвечает;
- соединение превышает таймаут;
- DNS временно недоступен;
- сервер блокирует автоматические запросы;
- TLS-сертификат некорректен;
- адрес использует запрещённый порт;
- адрес разрешается во внутренний или специальный IP.

Не отключайте SSRF-защиту ради проверки такого сайта.

---

# Обновление проекта

## 29. Безопасное обновление

1. Остановите бота.
2. Сохраните свой файл `.env` отдельно.
3. Распакуйте новую версию проекта в новую папку.
4. Скопируйте только `.env` в новую папку.
5. Создайте новое виртуальное окружение или обновите зависимости:

```bash
python -m pip install -r requirements.txt --upgrade
```

6. Выполните тесты.
7. Запустите новую версию.

Не заменяйте новые исходники старыми файлами `url_checker.py` или `handlers.py`.

---

# Минимальный набор команд для Windows

```powershell
cd C:\Bots\url_security_bot
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
python -m url_guard_bot
```

# Минимальный набор команд для Linux

```bash
cd /opt/url_security_bot
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
nano .env
chmod 600 .env
python -m url_guard_bot
```

# Минимальный набор команд для Docker

```bash
cp .env.example .env
# Укажите BOT_TOKEN в .env
docker compose up -d --build
docker compose logs -f
```

---

## Важное ограничение

URL Guard Bot выполняет техническую и эвристическую проверку. Он не является полноценным антивирусом и без внешних репутационных сервисов не гарантирует, что сайт безопасен.

Формулировка «явных признаков угрозы не обнаружено» означает только то, что текущая проверка не нашла известных технических признаков риска.

---

## Локальная база скам-ссылок

После запуска можно добавлять известные вредоносные ссылки в файл `scam_links.txt`, расположенный рядом с `.env`.

Примеры:

```text
bad-domain.com
https://example.com/fake-login
prefix:https://example.net/malware/
```

Сохраните файл. Бот увидит изменения автоматически — перезапуск не нужен. Подробное описание форматов находится в файле `ИНСТРУКЦИЯ_ПО_БАЗЕ_СКАМ_ССЫЛОК.md`.
