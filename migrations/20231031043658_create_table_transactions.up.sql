CREATE TABLE Transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES Users(id) NOT NULL,
    product_id INTEGER REFERENCES Products(id) NOT NULL,
    quantity INTEGER NOT NULL,
    total_amount NUMERIC NOT NULL
);
