CREATE SEQUENCE role_id_seq START 1 INCREMENT 1;
CREATE SEQUENCE user_id_seq START 1 INCREMENT 1;

CREATE TABLE Role (
    role_id BIGINT NOT NULL ,
    role VARCHAR(10) NOT NULL ,
    PRIMARY KEY (role_id)
);

CREATE TABLE Users (
    user_id BIGINT NOT NULL ,
    role_id BIGINT NOT NULL ,
    name VARCHAR(100) NOT NULL ,
    password VARCHAR(20) NOT NULL ,
    is_enabled BOOLEAN NOT NULL ,
    PRIMARY KEY (user_id) ,
    CONSTRAINT fk_role FOREIGN KEY (role_id)
        REFERENCES Role(role_id)
);
