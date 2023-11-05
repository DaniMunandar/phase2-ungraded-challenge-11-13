CREATE TABLE Stores (
    id SERIAL PRIMARY KEY,
    nama_store VARCHAR(255) NOT NULL,
    alamat TEXT,
    longitude DOUBLE PRECISION,
    latitude DOUBLE PRECISION,
    rating DOUBLE PRECISION
);


INSERT INTO Stores (nama_store, alamat, longitude, latitude, rating)
VALUES ('Avengers Store 1', 'Jl. Avengers No. 1', -74.006, 40.7128, 4.5);

INSERT INTO Stores (nama_store, alamat, longitude, latitude, rating)
VALUES ('Avengers Store 2', 'Jl. Avengers No. 2', -73.987, 40.7537, 4.7);
