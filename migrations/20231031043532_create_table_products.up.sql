CREATE TABLE Products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    stock INTEGER NOT NULL,
    price NUMERIC NOT NULL
);

-- Insert produk Avengers
INSERT INTO Products (name, stock, price) VALUES
    ('Avengers: Endgame Blu-ray', 50, 19.99),
    ('Avengers: Infinity War DVD', 30, 14.99),
    ('Avengers T-shirt', 100, 12.99);
