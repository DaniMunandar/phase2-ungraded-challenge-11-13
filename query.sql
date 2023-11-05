CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    deposit_amount NUMERIC NOT NULL
);

DROP TABLE IF EXISTS Users;

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


DROP TABLE IF EXISTS Products;

CREATE TABLE Transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES Users(id) NOT NULL,
    product_id INTEGER REFERENCES Products(id) NOT NULL,
    quantity INTEGER NOT NULL,
    total_amount NUMERIC NOT NULL
);

DROP TABLE IF EXISTS Transactions;

CREATE TABLE Store (
    id SERIAL PRIMARY KEY,
    nama_store VARCHAR(255) NOT NULL,
    alamat TEXT,
    longitude DOUBLE PRECISION,
    latitude DOUBLE PRECISION,
    rating DOUBLE PRECISION
);


INSERT INTO Store (nama_store, alamat, longitude, latitude, rating)
VALUES ('Avengers Store 1', 'Jl. Avengers No. 1', -74.006, 40.7128, 4.5);

INSERT INTO Store (nama_store, alamat, longitude, latitude, rating)
VALUES ('Avengers Store 2', 'Jl. Avengers No. 2', -73.987, 40.7537, 4.7);


DROP TABLE IF EXISTS Store;