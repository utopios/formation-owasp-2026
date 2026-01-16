-- Données initiales pour VulnerableBank
-- ATTENTION: Données de test uniquement !

-- Création d'utilisateurs de test
INSERT INTO users (username, password, email, role, ssn, credit_card, balance, active) VALUES
('admin', 'admin123', 'admin@vulnerablebank.com', 'ADMIN', '123-45-6789', '4111-1111-1111-1111', 100000.00, true),
('john', 'password123', 'john@example.com', 'USER', '987-65-4321', '4222-2222-2222-2222', 5000.00, true),
('jane', 'jane2024', 'jane@example.com', 'USER', '456-78-9012', '4333-3333-3333-3333', 7500.00, true),
('bob', 'bob12345', 'bob@example.com', 'USER', '789-01-2345', '4444-4444-4444-4444', 2500.00, true),
('alice', 'alice2024', 'alice@example.com', 'USER', '234-56-7890', '4555-5555-5555-5555', 10000.00, true);

-- Transactions de test
INSERT INTO transactions (from_user_id, to_user_id, amount, description, timestamp, status) VALUES
(2, 3, 100.00, 'Remboursement déjeuner', CURRENT_TIMESTAMP, 'COMPLETED'),
(3, 2, 50.00, 'Part cinéma', CURRENT_TIMESTAMP, 'COMPLETED'),
(4, 5, 200.00, 'Cadeau anniversaire', CURRENT_TIMESTAMP, 'COMPLETED'),
(5, 2, 75.00, 'Remboursement concert', CURRENT_TIMESTAMP, 'COMPLETED');
