# go-ptrace

Инструмент для инъекции разделяемой библиотеки в чужой процесс. Утилита для дебага или мониторинга, которая по PID целевого процесса внедряет в него свою `.so` библиотеку.

## Как это работает

1. Подключается к целевому процессу через `ptrace(2)`, останавливая **все** LWP (T13)
2. Проверяет состояние цели (T31): не zombie, не уже трейсится, проверяет `kernel.yama.ptrace_scope`
3. Находит адрес `dlopen` в памяти процесса: парсит `/proc/<pid>/maps` для определения load base libc и извлекает смещение символа из ELF (T5)
4. Генерирует x86_64 shellcode (30 байт) для вызова `dlopen(path, RTLD_NOW)`
5. Выделяет **два** различных исполняемых региона через удалённый `mmap` (SYS_MMAP через syscall-gate, T1/T2)
6. Записывает путь к библиотеке и shellcode в выделенную память (T19)
7. Перехватывает `RIP`/`RDI` целевого процесса, устанавливая `ORIG_RAX = -1` для предотвращения syscall-restart пути ядра (T39)
8. Ждёт `int3` (SIGTRAP) и фиксирует RAX (handle)
9. Полностью восстанавливает снапшот регистров и байты syscall-gate (T7/T10)
10. Отключается (Detach), возвращая цель в нормальное состояние

## Сборка

```bash
# Собрать CLI
make build

# Собрать пример библиотеки
make example

# Запустить все тесты
make test
```

## Использование

```bash
# Собрать пример библиотеки
make example

# Запустить целевой процесс
sleep 100 &
PID=$!

# Внедрить библиотеку
./bin/go-ptrace --pid $PID --so examples/hooklib/hooklib.so

# Проверить что constructor вызван
cat /tmp/go-ptrace-hook.log
```

### Флаги

| Флаг | Описание | Обязательный |
|------|----------|:---:|
| `--pid <PID>` | PID целевого процесса | ✅ |
| `--so <path>` | Абсолютный путь к `.so` библиотеке | ✅ |
| `--dry-run` | Валидировать план без ptrace (T32) | |
| `--verbose`, `-v` | Выводить каждый этап инъекции в stderr (T32) | |
| `--timeout <dur>` | Лимит ожидания ptrace-события, напр. `5s` (T17) | |
| `--help`, `-h` | Показать справку | |

### Примеры

```bash
# Внедрить библиотеку в процесс с PID 1234
./bin/go-ptrace --pid 1234 --so /path/to/library.so

# Показать справку
./bin/go-ptrace --help

# Предварительная проверка (без ptrace)
./bin/go-ptrace --pid 1234 --so /path/to/library.so --dry-run

# С подробным логированием
./bin/go-ptrace --pid 1234 --so /path/to/library.so --verbose --timeout 5s
```

## Диагностика ошибок

Перед попыткой Attach трейсер проверяет состояние процесса (T31):

| Состояние | Сообщение | Решение |
|-----------|-----------|---------|
| Нет процесса | `does not exist` | Проверьте PID |
| Zombie | `is a zombie` | Процесс уже завершён |
| Уже трейсится | `already traced by pid N` | Остановите другой дебаггер |
| EPERM + yama | `ptrace_scope is N` | Запустите от root (`sudo`) или `sysctl kernel.yama.ptrace_scope=0` |

## Архитектура

```
cmd/cli/main.go         ← CLI (парсинг флагов, вызов injector)
cmd/cli/inject.go       ← инъекция на linux/amd64
cmd/cli/inject_other.go ← stub на других платформах

internal/injector/
  e2e.go                ← обёртки unix.Ptrace* (реальные syscall)
  tracer.go             ← Tracer interface + ptracer (логика ptrace)
  injector.go           ← InjectLibrary() — оркестрация: attach → mmap → poke → set regs → run → wait → detach
  shellcode.go          ← генерация x86_64 shellcode для dlopen (30 байт)
  syms.go               ← поиск символов в ELF (dlopen адрес)
```

**Ключевые механизмы:**

- **Syscall-gate** (T1): `syscall; int3` вставляется в существующий `r-xp` регион для вызова `mmap` в цели. Байты восстанавливаются при Detach (T10).
- **Восстановление состояния** (T7): трейсер снимает полный снапшот регистров в Attach и восстанавливает его после int3.
- **Блокировка тредa** (T27): `runtime.LockOSThread` в Attach; ptrace привязывает tracee к OS-потоку, поэтому все операции идут из той же горутины.
- **Конечное ожидание** (T17): `WNOHANG`-поллинг `Wait4` с таймаутом; защита от зависания при заклинившей инъекции.
- **Кроссплатформенная сборка**: build-теги `//go:build linux && amd64` на платформозависимых файлах.

## Тесты

```bash
make test
```

Включает ~80 юнит-тестов (mock-уровень) и 3 e2e-теста (реальная инъекция в `sleep`).

## Требования

- Linux x86_64 (build-теги `//go:build linux && amd64`)
- Go 1.26+
- gcc (для сборки примера `hooklib.so`)
- Права на `ptrace` (может потребоваться `sudo` или настройка `sysctl kernel.yama.ptrace_scope=0`)

## Лицензия

GPL v3
