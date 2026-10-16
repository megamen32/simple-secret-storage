# Форма секрета с первого вызова

Владелец17Oct: исправить повторные отказы вызова secret, общий простой маршрут
для всех агентов; без имени генерировать любое, не задавать вопросов об имени.
Это самостоятельная боковая сессия: UserIO/X-manager/секрет passtg не трогать.

RED: общий secret skill ошибочно обещает форму от readiness-only ask_secret;
pluginasksecret требует лишний вопрос об имени. Live ask_secret для отсутствующего
имени отказывает not ready вместо формы. Показанная клиентская ошибка соединения
реальна, но текущие3HTTPS пробы pswd и mcp успешны (401 безcredentials),
SSS не перезапускался с13Oct. Не приписывать transientnetwork неподтверждённую
первопричину. Stateful /mcp также отвергает неизвестный sessionID400.

Решение: существующий ask_secret возвращает безопасный pending/input_url либо
ready; optionalname сгенерирован сервером, request_id стабилизирует retry.
get_secret также optionalname. Стандартный SDK stateless JSON транспорт:
вся durablestate уже в Storage, старый sessionheader не мешает reconnect.
HTTP/stdio используют одну регистрацию; stdin-only consumer неизменён.
Общая короткая инструкция распространяется узко на secret/asksecret, без
изменения других навыков/MCP credentials и без чтения пользовательских секретов.

Приёмка: живой tools/call ask_secret без имени → рабочая форма /i/; повтор
с тем же именем/identity сохраняет URL; синтетический submit → ready безvalue;
рестарт изолированного сервера не ломает pending/клиент. Старые пользовательские
pendingmetadata/ключи/blob остаются. Минимальный restart толькоSSS после
scopedmain публикации; новые формы с пользовательскими значениями не заполнять.

Бюджет focused integration: expected10/max100с вместе с build, CPU2,
RAM768MiBsoft/1GiBhard, swap0/tasks128, временные данные128MiB; один workload.
Fresh MemAvailable перед запуском; сохранить >=16GiB hostreserve. Live service
доизменений~94MiB/11tasks; его действующие лимиты не повышать.

## Принято

SSS968a98c опубликован в origin/main и установлен17Oct02:06MSK кратким
restart толькоsss.service. Bundle8f6c764 опубликован в upstream/master;
pluginfd9df39 в origin/main. Scoped sync толькоsecret: Codex/Hermes/OpenCode/
ZCode, текущая migratedCodexskill и legacycommand. Чужие bundleWIP сохранены.

9focusedchecks PASS9.99с/пик224026624B; ownedcontainer удалён. Реальный
CodexMCP ask_secret({}) сразу pending савтоименем; repeat возвращаеттотжеURL.
Настоящий publicHTTPSGET inputURL=200/passwordfield; stdioruntime вернултотже
pending без identityregistration и безdownload/secretfetch. Синтетический
submit/ready и восстановление послеrestart проверены наisolatedstore.
Private receipt/logs: .tmp/20261017-form/{receipt,live-proof,skill-sync}.json.

Первопричина показанного transport send error сейчас не воспроизвелась:
успешные пробы не доказывают, что исчезла любая внешняя сетевая проблема.
Подтверждённые дефекты readiness-only/namequestion устранены; stateless SDK
также устраняет конкретный отказ от старого MCPsession послеrestart.
Никакие реальные secrets/пользовательские поля и соседние продукты не менялись.
