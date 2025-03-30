# Audio Service API

## Описание
FastAPI-приложение для работы с аудиофайлами и аутентификацией через Yandex. 
Файлы для запуск докер-контейнер находятся в архиве.  
https://drive.google.com/drive/folders/1kgOj6rfeVoD_8FSQH0uW55xb1ejh4nxK?usp=sharing

## Требования
- Docker 20.10+
- Docker Compose 2.0+

## Запуск
```bash
docker-compose up -d
```

## Доступные endpoint'ы
- `POST /audio` - загрузка аудиофайла
- `GET /audio_files` - список файлов пользователя
- `GET /auth/yandex` - авторизация через Yandex
- Полная документация API доступна после запуска:
  - Swagger: http://localhost:8000/docs
  - ReDoc: http://localhost:8000/redoc



# Для авторизации через яндекс:
- Получить ссылку по первому эндпоинту
- Ввести код во второй эндпоинт
- Ввести access_token в авторизации (справа сверху)