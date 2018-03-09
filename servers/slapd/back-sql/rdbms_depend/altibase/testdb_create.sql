CREATE TABLE persons (
	id int NOT NULL,
	name varchar(255) NOT NULL,
	surname varchar(255) NOT NULL,
	password varchar(64)
);

CREATE TABLE institutes (
	id int NOT NULL,
	name varchar(255)
);

CREATE TABLE documents (
	id int NOT NULL,
	title varchar(255) NOT NULL,
	abstract varchar(255)
);

CREATE TABLE authors_docs (
	pers_id int NOT NULL,
	doc_id int NOT NULL
);

CREATE TABLE phones (
	id int NOT NULL ,
	phone varchar(255) NOT NULL ,
	pers_id int NOT NULL 
);

CREATE TABLE referrals (
	id int NOT NULL,
	name varchar(255) NOT NULL,
	url varchar(255) NOT NULL
);

ALTER TABLE authors_docs  ADD 
	CONSTRAINT PK_authors_docs PRIMARY KEY  
	(
		pers_id,
		doc_id
	);

ALTER TABLE documents  ADD 
	CONSTRAINT PK_documents PRIMARY KEY  
	(
		id
	); 

ALTER TABLE institutes  ADD 
	CONSTRAINT PK_institutes PRIMARY KEY  
	(
		id
	);  


ALTER TABLE persons  ADD 
	CONSTRAINT PK_persons PRIMARY KEY  
	(
		id
	); 

ALTER TABLE phones  ADD 
	CONSTRAINT PK_phones PRIMARY KEY  
	(
		id
	); 

CREATE SEQUENCE person_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE document_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE institute_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE phone_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE referral_ids START WITH 1 INCREMENT BY 1;

