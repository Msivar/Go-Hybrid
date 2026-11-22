Standalone HookVault demonstration. This directory is independent of Hybrid and is not a Hybrid feature or an upstream contribution.

HookVault 1.0 — надёжный локальный приёмник вебхуков

Задача
Внешняя система повторяет уведомление после сетевого сбоя. Наивный обработчик
может дважды создать заказ или потерять событие при перезапуске. HookVault
сохраняет подписанный JSON в SQLite, отделяет получение от обработки и выдаёт
событие одному обработчику на ограниченное время.

Запуск за минуту
Нужен Python 3.10 или новее. Внешних пакетов нет.
  python demo.py
Демонстрация запускается только на 127.0.0.1, сама завершается и удаляет свою
временную базу. Она не выполняет платежи и не обращается к сторонним сервисам.

Проверка
  python -B -m unittest -v
Проверено: Windows, Python 3.12.14; 17 тестов проходят.
Тесты используют временные файлы и локальные HTTP-соединения.

Постоянный запуск (PowerShell)
  $env:HOOKVAULT_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
  python hookvault.py --db inbox.sqlite3 serve
Не передавайте этот секрет в чат или клиентский код браузера. Отправитель и
приёмник должны знать один секрет. При перезапуске используйте тот же секрет.

Приём событий
POST http://127.0.0.1:8787/hooks
Content-Type: application/json
X-Hook-Id: уникальный ID события, 1–128 ASCII-символов A-Z a-z 0-9 _ . : -
X-Hook-Timestamp: целое число секунд Unix; допустимое отклонение ±300 секунд
X-Hook-Signature: sha256=<hex HMAC-SHA256>

Подпись вычисляется над байтами:
  timestamp + ':' + длина event_id в байтах + ':' + event_id + ':' + raw_body
Первые три поля кодируются UTF-8. В длине используются десятичные ASCII-цифры.
Подписывайте ровно те байты JSON, которые отправляете. Готовая функция:
  from hookvault import signature
Лимит тела — 1 МиБ. Chunked encoding не поддерживается.

Ответы
201 created: новое событие сохранено.
200 duplicate: этот ID с теми же байтами уже сохранён.
409 conflict: ID занят другим телом, оригинал сохранён.
400: неправильные заголовки или JSON. 401: подпись/время.
413: превышен лимит. 415: неверный Content-Type. 503: недоступно хранилище.
GET /health возвращает только состояние сервиса, без содержимого событий.

Обработка из Python
  from hookvault import Inbox
  inbox = Inbox('inbox.sqlite3')
  event = inbox.claim(lease_seconds=60)
  if event is not None:
      # Выполните свою идемпотентную операцию с event['payload'].
      inbox.settle(event['id'], event['token'])
При ошибке:
  inbox.settle(event['id'], event['token'], error='CRM timeout', delay=30)
Если операция занимает больше времени аренды, задайте большую аренду заранее.
Истёкшая аренда не продлевается автоматически. Старый token не может подтвердить
событие после истечения аренды или передачи другому работнику.
После пяти неудачных попыток/просроченных аренд событие становится dead.

Командная строка
  python hookvault.py --db inbox.sqlite3 list
  python hookvault.py --db inbox.sqlite3 list --payload --limit 100
  python hookvault.py --db inbox.sqlite3 claim --lease 120
  python hookvault.py --db inbox.sqlite3 ack EVENT_ID TOKEN
  python hookvault.py --db inbox.sqlite3 retry EVENT_ID TOKEN --error "CRM timeout" --delay 30
Обычный list не показывает payload и token. claim возвращает token для обработки.

Практические границы
Это компонент для разработки интеграций. Подписи Stripe, ЮKassa и других
провайдеров отличаются: для них нужен отдельный адаптер.
HTTP-сервер предназначен для localhost/доверенной среды. Для публичного
развёртывания нужны TLS, reverse proxy с лимитами соединений, контроль размера
диска, права на базу и резервные копии. Встроенного шифрования базы нет.
Дедупликация при получении не даёт exactly-once для внешних бизнес-операций:
при сбое после записи в CRM, но до ack, обработка повторится. Передавайте ID
события в идемпотентный интерфейс CRM/платежей или используйте транзакционный
outbox. База, raw body и ID сохраняются без автоматического удаления.
Имеющиеся dead-события доступны через list --payload для диагностики; автоматического
повторного запуска dead-событий в этой версии нет.

Состав
hookvault.py — сервер, хранилище и CLI.
demo.py — полностью локальная демонстрация.
test_hookvault.py — HTTP, конкурентные и аварийные проверки.
LICENSE — MIT.
