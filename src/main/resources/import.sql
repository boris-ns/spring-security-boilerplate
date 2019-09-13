INSERT INTO `authorities` (id, name) VALUES (1, 'ROLE_USER');
INSERT INTO `authorities` (id, name) VALUES (2, 'ROLE_ADMIN');

INSERT INTO `users` (id, email, enabled, first_name, last_name, last_password_reset_date, password, username) VALUES (1,'john@doe.com', true, 'John', 'Doe','2017-10-01 21:58:58', '$2a$04$Vbug2lwwJGrvUXTj6z7ff.97IzVBkrJ1XfApfGNl.Z695zqcnPYra', 'john.doe');
INSERT INTO `users` (id, email, enabled, first_name, last_name, last_password_reset_date, password, username) VALUES (2,'jane@doe.com', true, 'Jane', 'Doe','2017-09-01 22:40:00', '$2a$04$Vbug2lwwJGrvUXTj6z7ff.97IzVBkrJ1XfApfGNl.Z695zqcnPYra', 'jane.doe');

INSERT INTO `user_authority` (user_id, authority_id) VALUES (1, 1);
INSERT INTO `user_authority` (user_id, authority_id) VALUES (2, 2);