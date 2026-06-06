# Casebook AD CTF Service

`Casebook` — учебный сервис для формата Attack-Defense CTF. По легенде это внутренний журнал расследований инцидентов: пользователи регистрируются, создают кейсы и хранят в приватной заметке чувствительные данные. В CTF этой приватной заметкой является флаг формата `[A-Z0-9]{31}=`.

Сервис специально содержит уязвимости, но не содержит вредоносного кода, майнеров, fork bomb, удаления системных файлов, атак на внешние ресурсы или попыток выхода за пределы контейнера.

## Стек

- Python 3.12
- FastAPI
- SQLite
- Docker / docker-compose

## Порт

Сервис слушает порт `8080` внутри контейнера и публикуется как `8080:8080`.

## Запуск

```bash
docker compose up --build
```

Проверка:

```bash
curl http://127.0.0.1:8080/health
```

Остановка с сохранением данных:

```bash
docker compose down
```

Полное удаление данных:

```bash
docker compose down -v
```

## Бизнес-логика

1. Пользователь регистрируется через `/api/users/register`.
2. Пользователь получает bearer token.
3. Пользователь создаёт case через `/api/cases`.
4. Поле `secret_note` является приватным хранилищем флага.
5. Владелец получает свой флаг легитимно через `/api/cases/{case_id}` с bearer token.
6. Дополнительно есть механизм share-кодов и внутренний audit search.

## Основные эндпоинты

### Healthcheck

```http
GET /health
```

### Регистрация

```http
POST /api/users/register
Content-Type: application/json

{
  "username": "alice",
  "password": "strong-password"
}
```

Ответ содержит `token`.

### Логин

```http
POST /api/sessions/login
Content-Type: application/json

{
  "username": "alice",
  "password": "strong-password"
}
```

### Положить флаг

```http
POST /api/cases
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "incident-001",
  "category": "network",
  "public_summary": "short public text",
  "secret_note": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
```

### Получить ранее положенный флаг легитимно

```http
GET /api/cases/<case_id>
Authorization: Bearer <token>
```

## Чекер

Чекер находится в `checker/checker.py`.

Установка зависимостей (рекомендуется виртуальное окружение):

```bash
cd checker
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Команды:

```bash
python3 checker.py 127.0.0.1 8080 check
python3 checker.py 127.0.0.1 8080 put ABCDEFGHIJKLMNOPQRSTUVWXYZ12345=
python3 checker.py 127.0.0.1 8080 get '<flag_id>' ABCDEFGHIJKLMNOPQRSTUVWXYZ12345=
python3 checker.py 127.0.0.1 8080 get_flags
```

Чекер не выводит текст — результат передаётся через exit code. Чтобы увидеть его явно:

```bash
python3 checker.py 127.0.0.1 8080 check; echo "Exit code: $?"
```

Если `put` запустить без флага, чекер сам сгенерирует случайный флаг в формате `[A-Z0-9]{31}=`.

`put` печатает `flag_id` в stdout. `get` может принимать `flag_id` и ожидаемый флаг. Если аргументы не переданы, `get` берёт последнюю запись из локального файла `checker/checker_flags.json`.

Коды возврата:

- `101` — OK
- `102` — CORRUPT
- `103` — MUMBLE
- `104` — DOWN
- `110` — CHECK_FAILED

## Уязвимость 1: предсказуемые share-коды

В сервисе есть эндпоинт:

```http
GET /api/shared/{code}
```

Share-code создаётся из последовательного `case_id` и статической соли:

```python
md5(f"{case_id}:{SHARE_SALT}").hexdigest()[:10]
```

Проблема: код не привязан к владельцу, не содержит случайности и может быть сгенерирован атакующим, который знает исходный код сервиса. Так как `case_id` последовательный, атакующий перебирает id, вычисляет валидные share-коды и получает чужие `secret_note`.

PoC (запускать из корня проекта):

```bash
python3 -m venv exploits/.venv && source exploits/.venv/bin/activate
pip install -r exploits/requirements.txt
python3 exploits/exploit_share_code.py 127.0.0.1 8080 200
```

## Уязвимость 2: SQL Injection в audit search

Эндпоинт:

```http
GET /api/audit/search?category=network&needle=text
Authorization: Bearer <token>
```

Внутри используется небезопасная строковая интерполяция SQL:

```python
sql = f"SELECT ... FROM cases WHERE category = '{category}' AND title LIKE '%{needle}%'"
```

Проблема: параметр `category` попадает в SQL без параметризации. Атакующий создаёт обычный аккаунт, отправляет payload `network' OR 1=1 --` и получает строки чужих кейсов. Из-за отладочного поля `debug_preview` в ответ попадает `secret_note`.

PoC (запускать из корня проекта, окружение из предыдущего шага уже активно):

```bash
python3 exploits/exploit_search_sqli.py 127.0.0.1 8080
```