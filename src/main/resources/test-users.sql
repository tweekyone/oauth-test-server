INSERT INTO role (role_id, role)
VALUES (1, 'ROLE_ADMIN'),
       (2, 'ROLE_USER');

INSERT INTO users (user_id, role_id, name, password, is_enabled)
VALUES (1, 1, 'Admin', 'pass', true),
       (2, 2, 'User 1', 'pass', true),
       (3, 2, 'User_2', 'pass', true)