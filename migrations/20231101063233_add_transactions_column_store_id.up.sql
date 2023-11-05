ALTER TABLE Transactions
    ADD COLUMN IF NOT EXISTS store_id INT NOT NULL;

ALTER TABLE Transactions
    ADD CONSTRAINT fk_store_id FOREIGN KEY (store_id) REFERENCES Stores(id);