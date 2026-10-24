

## Часть I. Исправление SQL-запросов

1. **Задание: Найти ошибки в SQL-запросах и исправить их.**
    
    1.1. Запрос:
    
    ```sql
    SELECT id, sum(creditlimit)
    FROM loans;
    ```
    
    **Ошибка:** Отсутствует `GROUP BY` для агрегатной функции `SUM`. Нужно группировать по полю `id`.
    
    **Исправленный запрос:**
    
    ```sql
    SELECT id, SUM(creditlimit)
    FROM loans
    GROUP BY id;
    ```
    
    1.2. Запрос:
    
    ```sql
    SELECT id, extract(year from dt) as dt_year
    FROM loans
    WHERE dt_year >= 2023;
    ```
    
    **Ошибка:** В условии `WHERE` используется алиас `dt_year`, который создается только после выполнения `SELECT`. Нужно использовать выражение напрямую.
    
    **Исправленный запрос:**
    
    ```sql
    SELECT id, EXTRACT(YEAR FROM dt) AS dt_year
    FROM loans
    WHERE EXTRACT(YEAR FROM dt) >= 2023;
    ```
    
    1.3. Запрос:
    
    ```sql
    SELECT id, sum(creditlimit)
    FROM loans
    ORDER BY id
    GROUP BY id;
    ```
    
    **Ошибка:** Нарушен порядок выполнения выражений `GROUP BY` и `ORDER BY`. Сначала должно выполняться `GROUP BY`, затем `ORDER BY`.
    
    **Исправленный запрос:**
    
    ```sql
    SELECT id, SUM(creditlimit)
    FROM loans
    GROUP BY id
    ORDER BY id;
    ```
    
2. **Вывод id, где программа кредитования не была 1 и не была 2:**
    
    Исходный запрос:
    
    ```sql
    SELECT id
    FROM loans
    WHERE program NOT IN (1, 2);
    ```
    
    **Проблема:** В таблице некоторые строки могут иметь `NULL` в колонке `program`, и запрос не учитывает `NULL`.
    
    **Исправленный запрос:**
    
    ```sql
    SELECT id
    FROM loans
    WHERE program IS NOT NULL AND program NOT IN (1, 2);
    ```
    

---

## Часть II. SQL-запросы для анализа данных

1. **Вывести ФИО клиентов с более чем одной активной картой:**
    
    Здесь нужно сделать JOIN между таблицами `personal_data` и `cards`, чтобы получить количество активных карт для каждого клиента и отфильтровать тех, у кого их более одной.
    
    **Запрос:**
    
    ```sql
    SELECT pd.name, pd.surname, pd.patronymic
    FROM personal_data pd
    JOIN cards c ON pd.id_per = c.id_per
    WHERE c.active = 1
    GROUP BY pd.name, pd.surname, pd.patronymic
    HAVING COUNT(c.id_cards) > 1;
    
    ```
    
2. **Вывести ФИО клиентов в возрасте от 30 до 60 лет, которые совершили более 100 операций в 2023 году:**
    
    Для этого нужно вычислить возраст клиентов и затем соединить данные с таблицей транзакций.
    
    **Запрос:**
    
    ```sql
    SELECT pd.name, pd.surname, pd.patronymic
    FROM personal_data pd
    JOIN cards c ON pd.id_per = c.id_per
    JOIN transactions t ON c.id_cards = t.id_cards
    WHERE EXTRACT(YEAR FROM AGE(pd.birthdate)) BETWEEN 30 AND 60
      AND EXTRACT(YEAR FROM t.operation_date) = 2023
    GROUP BY pd.name, pd.surname, pd.patronymic
    HAVING COUNT(t.id_transaction) > 100;
    
    ```
    
3. **Вывести суммарные поступления и медианную сумму снятий/покупок по каждому клиенту ежемесячно:**
    
    Для каждого месяца и года необходимо подсчитать поступления и медиану снятий. Медиану можно рассчитать через подзапрос или встроенную функцию, если СУБД поддерживает её.
    
    **Запрос:**
    
    ```sql
    WITH transactions_agg AS (
      SELECT c.id_per,
             DATE_TRUNC('month', t.operation_date) AS month_start,
             SUM(CASE WHEN t.operation = 1 THEN t.sum ELSE 0 END) AS total_incomes,
             PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY CASE WHEN t.operation = -1 THEN t.sum END) AS median_withdrawals
      FROM transactions t
      JOIN cards c ON t.id_cards = c.id_cards
      GROUP BY c.id_per, DATE_TRUNC('month', t.operation_date)
    )
    SELECT id_per, month_start, total_incomes, median_withdrawals
    FROM transactions_agg;
    
    ```
    
4. **Вывести ФИО клиентов, которые по картам с платёжной системой "МИР" суммарно сняли/купили более 10 000 за последние три месяца от 11.10.2023:**
    
    Сначала нужно отфильтровать транзакции по дате и платёжной системе, затем суммировать покупки и снять суммы для каждого клиента.
    
    **Запрос:**
    
    ```sql
    SELECT pd.name, pd.surname, pd.patronymic
    FROM personal_data pd
    JOIN cards c ON pd.id_per = c.id_per
    JOIN transactions t ON c.id_cards = t.id_cards
    WHERE c.payment_system = 'МИР'
      AND t.operation_date BETWEEN '2023-07-11' AND '2023-10-11'
      AND t.operation = -1
    GROUP BY pd.name, pd.surname, pd.patronymic
    HAVING SUM(t.sum) > 10000;
    
    ```
    

---

## Часть III. Задачи на Python

> Код в файле 3.ipynb
> 

### 1) Работа с файлами `file_1.xlsx` и `file_2.xlsx`:

- **Шаги решения:**
    1. Загрузка данных из файла `file_1.xlsx`, содержащего информацию о товарах, ценах и агрегации.
    2. Агрегация цен конкурентов для каждого товара на основе типа агрегации (среднее, медиана, минимум, максимум или по приоритету ранга).
    3. Применение условий на допустимое отклонение от старой цены (±20%) для формирования новой цены `new_price`.
    4. Сравнение результата с результатом разработчиков из файла `file_2.xlsx`.
    5. Проверка наличия расчётов для всех товаров и вывод результатов.
- **Выводы**:
    - Финальная цена для товаров была рассчитана на основе данных о ценах конкурентов, при этом для товаров без цен конкурентов использовалась базовая цена.
    - Расхождения с результатом разработчиков могут указывать на различия в обработке данных или использовании округления.

### 2) Работа с файлом `file_3.xlsx`:

- **Шаги решения:**
    1. Загрузка данных с информацией о месяцах, типах оплаты и проценте успешных оплат.
    2. Анализ стабильности различных типов оплаты по месяцам.
    3. Визуализация данных для нахождения наиболее стабильной системы платежей.
- **Выводы**:
    - Визуализация позволит увидеть тенденции изменения процентного успеха для каждого типа оплаты. Выявление наиболее стабильного и самого нестабильного способа оплаты.

---

### Часть IV. Построение модели для вторичного рынка

> Код в файле 4.ipynb
> 
- **Шаги решения:**
    1. Подготовка данных: загрузка и очистка, обработка пропусков, преобразование категориальных переменных в числовые.
    2. Выбор алгоритма машинного обучения (линейная регрессия, дерево решений и т.д.).
    3. Разделение данных на обучающую и тестовую выборки.
    4. Обучение модели на данных, подбор гиперпараметров и валидация модели.
    5. Прогнозирование цен для новых данных.
    6. Оценка модели на основе метрик (MAE, RMSE и т.д.).
- **Выводы**:
    - Модель машинного обучения успешно прогнозирует цены вторичного жилья в Кировском и Н-С районах. Улучшение модели возможно за счёт дополнительных данных и оптимизации гиперпараметров.

---
