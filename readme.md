# FastAPI, refresh JWT, async SQLAlchemy, Alembic, Pytest

Данный проект является учебным портфолио для трудоустройства junior backend-разработчиком. 

Функционал, реализованный в проекте: 
- регистрация пользователя;
- подтверждение регистрации пользователя через email;
- запрос кода сброса пароля через email;
- аутентификация пользователя на основе access и refresh jwt токенов;
- logout через отзыв cookie; 
- авторизация пользователей на основе ролей.

Конфигурация проекта хранится в .yml файле. 
Имя файла конфигурации задаётся в переменной окружения "FastAPI_CONFIG_FILE". 
Загрузка конфигурации выполняется функцией parse_settings модуля app.api.core.config
Конфигурация загружается с валидацией через pydantic модель.
Приватные атрибуты имеют тип SecretStr для исключения случайного вывода содержимого в консоль.

Создание таблиц и первичное наполнение рабочей БД выполняется через alembic миграции.
Строка подключения к БД находится в параметре DB_ALCHEMY.

Репозиторий работы с базой данных (паттерн DAO) описывается абстрактным классом UserRepository.
От UserRepository наследуется AlchemyUserRepository, реализующий методы.

Большая часть эндпоинтов роутера user_router покрыта интеграционными тестами.
Тестирование выполняется с тестовой базой данных. 
Строка подключения к тестовой базе данных задаётся конфигурационным параметром DB_ALCHEMY_TEST.
При запуске тестирования фикстуры из модуля conftest выполняют подмену зависимостей
и подготовку тестовой базы данных через применение миграций alembic.
Для подготовки тестовых пользователей и данных для параметризованных тестов
запускается фикстура fixture_users (находится в файле с тестами test_users).
Класс отправки email не тестируется и глушится на время тестов.

Для подготовки проекта применены знания полученные при прохождении курсов:
- Телеграм-боты на Python: продвинутый уровень https://stepik.org/course/153850
- Быстрый старт в FastAPI Python https://stepik.org/course/179694

Применение библиотек fastapi_jwt_auth и fastapi_mail почерпнуто из репозитория 
https://github.com/wpcodevo/python_fastapi.git

Проект планирую дополнять (по крайней мере, до момента трудоустройства).
