# go-ptrace

Инструмент для инъекции разделяемой библиотеки в чужой процесс. Утилита для дебага или мониторинга, которая по PID целевого процесса внедряет в него свою `.so` библиотеку.

## Как это работает

1. Подключается к целевому процессу через `ptrace(2)`
2. Находит адрес `dlopen` в памяти процесса (парсит `/proc/<pid>/maps` и ELF-символы)
3. Генерирует x86_64 shellcode для вызова `dlopen(path, RTLD_NOW)`
4. Выделяет память в процессе через `PTRACE_POKEDATA`
5. Записывает shellcode и путь к библиотеке
6. Перезаписывает регистры `RIP` и `RDI`, запуская shellcode
7. Ждёт `SIGTRAP` (int3 в shellcode) и отключается

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
| `--so <path>` | Путь к `.so` библиотеке | ✅ |
| `--help`, `-h` | Показать справку | |

### Примеры

```bash
# Внедрить библиотеку в процесс с PID 1234
./bin/go-ptrace --pid 1234 --so /path/to/library.so

# Показать справку
./bin/go-ptrace --help
```

## Архитектура

```
cmd/cli/main.go          ← CLI (парсинг флагов, вызов injector)
internal/injector/
  e2e.go                 ← обёртки unix.Ptrace* (реальные syscall)
  tracer.go              ← Tracer interface + ptracer (логика ptrace)
  injector.go            ← Inject() — оркестрация: attach → mmap → poke → set regs → run → wait → detach
  shellcode.go           ← генерация x86_64 shellcode для dlopen
  syms.go                ← поиск символов в ELF (dlopen адрес)
```

## Тесты

```bash
make test
```

## Требования

- Linux x86_64
- Go 1.26+
- gcc (для сборки примера `hooklib.so`)
- Права на `ptrace` (может потребоваться `sudo` или настройка `sysctl kernel.yama.ptrace_scope=0`)

## Лицензия

GPL v3
