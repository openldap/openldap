-- mappings 

-- objectClass mappings: these may be viewed as structuralObjectClass, the ones that are used to decide how to build an entry
--	id		a unique number identifying the objectClass
--	name		the name of the objectClass; it MUST match the name of an objectClass that is loaded in slapd's schema
--	keytbl		the name of the table that is referenced for the primary key of an entry
--	keycol		the name of the column in "keytbl" that contains the primary key of an entry; the pair "keytbl.keycol" uniquely identifies an entry of objectClass "id"
--	create_proc	a procedure to create the entry
--	delete_proc	a procedure to delete the entry; it takes "keytbl.keycol" of the row to be deleted
--	expect_return	a bitmap that marks whether create_proc (1) and delete_proc (2) return a value or not
insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (1,'inetOrgPerson','persons','id','exec create_person(?)','exec delete_person(?)',1);

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (2,'document','documents','id','exec create_document(?)','exec delete_document(?)',1);

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (3,'organization','institutes','id','exec create_org(?)','exec delete_org(?)',1);

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (4,'referral','referrals','id','exec create_referral(?)','exec delete_referral(?)',1);

-- attributeType mappings: describe how an attributeType for a certain objectClass maps to the SQL data.
--	id		a unique number identifying the attribute	
--	oc_map_id	the value of "ldap_oc_mappings.id" that identifies the objectClass this attributeType is defined for
--	name		the name of the attributeType; it MUST match the name of an attributeType that is loaded in slapd's schema
--	sel_expr	the expression that is used to select this attribute (the "select <sel_expr> from ..." portion)
--	from_tbls	the expression that defines the table(s) this attribute is taken from (the "select ... from <from_tbls> where ..." portion)
--	join_where	the expression that defines the condition to select this attribute (the "select ... where <join_where> ..." portion)
--	add_proc	a procedure to insert the attribute; it takes the value of the attribute that is added, and the "keytbl.keycol" of the entry it is associated to
--	delete_proc	a procedure to delete the attribute; it takes the value of the attribute that is added, and the "keytbl.keycol" of the entry it is associated to
--	param_order	a mask that marks if the "keytbl.keycol" value comes before or after the value in add_proc (1) and delete_proc (2)
--	expect_return	a mask that marks whether add_proc (1) and delete_proc(2) are expected to return a value or not
insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (1,1,'cn','persons.name||'' ''||persons.surname','persons',NULL,
	NULL,NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (2,1,'telephoneNumber','phones.phone','persons,phones',
        'phones.pers_id=persons.id','exec add_phone(?,?)',
        'exec delete_phone(?,?)',0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (3,1,'givenName','persons.name','persons',NULL,'exec set_person_name(?,?)',
        NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (4,1,'sn','persons.surname','persons',NULL,'exec set_person_surname(?,?)',
        NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (5,1,'userPassword','persons.password','persons',
	'persons.password IS NOT NULL','exec set_person_password(?,?)',
        NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (6,1,'seeAlso','seeAlso.dn','ldap_entries seeAlso,documents,authors_docs,persons',
	'seeAlso.keyval=documents.id AND seeAlso.oc_map_id=2 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	NULL,NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (7,2,'description','documents.abstract','documents',NULL,'exec set_doc_abstract(?,?)',
	NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (8,2,'documentTitle','documents.title','documents',NULL,'exec set_doc_title(?,?)',NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (9,2,'documentAuthor','documentAuthor.dn','ldap_entries documentAuthor,documents,authors_docs,persons',
	'documentAuthor.keyval=persons.id AND documentAuthor.oc_map_id=1 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	'exec ?:=make_author_link(?,?)','exec ?:=del_author_link(?,?)',0,3);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (10,2,'documentIdentifier','''document ''||documents.id','documents',NULL,NULL,NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (11,3,'o','institutes.name','institutes',NULL,'exec set_org_name(?,?)',NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (12,3,'dc','lower(institutes.name)','institutes,ldap_entries dcObject,ldap_entry_objclasses auxObjectClass',
	'institutes.id=dcObject.keyval AND dcObject.oc_map_id=3 AND dcObject.id=auxObjectClass.entry_id AND auxObjectClass.oc_name=''dcObject''',
	NULL,NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (13,4,'ou','referrals.name','referrals',NULL,'exec set_ref_name(?,?)',NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (14,4,'ref','referrals.url','referrals',NULL,'exec set_ref_url(?,?)',NULL,0,0);

-- entries mapping: each entry must appear in this table, with a unique DN rooted at the database naming context
--	id		a unique number > 0 identifying the entry
--	dn		the DN of the entry, in "pretty" form
--	oc_map_id	the "ldap_oc_mappings.id" of the main objectClass of this entry (view it as the structuralObjectClass)
--	parent		the "ldap_entries.id" of the parent of this objectClass; 0 if it is the "suffix" of the database
--	keyval		the value of the "keytbl.keycol" defined for this objectClass
insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'dc=example,dc=com',3,0,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Mitya Kovalev,dc=example,dc=com',1,1,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Torvlobnor Puzdoy,dc=example,dc=com',1,1,2);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Akakiy Zinberstein,dc=example,dc=com',1,1,3);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'documentTitle=book1,dc=example,dc=com',2,1,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'documentTitle=book2,dc=example,dc=com',2,1,2);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'ou=Referral,dc=example,dc=com',4,1,1);

-- objectClass mapping: entries that have multiple objectClass instances are listed here with the objectClass name (view them as auxiliary objectClass)
--	entry_id	the "ldap_entries.id" of the entry this objectClass value must be added
--	oc_name		the name of the objectClass; it MUST match the name of an objectClass that is loaded in slapd's schema
insert into ldap_entry_objclasses (entry_id,oc_name) values (1,'dcObject');

insert into ldap_entry_objclasses (entry_id,oc_name) values (7,'extensibleObject');

-- procedures
-- these procedures are specific for this RDBMS and are used in mapping objectClass and attributeType creation/modify/deletion
CREATE OR REPLACE PROCEDURE create_person(keyval OUT INTEGER) AS
BEGIN
INSERT INTO persons (id,name,surname) VALUES (person_ids.nextval,' ',' ');
SELECT person_ids.currval INTO keyval FROM DUAL;
END;
/

CREATE OR REPLACE PROCEDURE delete_person(keyval IN INTEGER) AS
BEGIN
DELETE FROM phones WHERE pers_id=keyval;
DELETE FROM authors_docs WHERE pers_id=keyval;
DELETE FROM persons WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE create_org(keyval OUT INTEGER) AS
BEGIN
INSERT INTO institutes (id,name) VALUES (institute_ids.nextval,' ');
SELECT institute_ids.currval INTO keyval FROM DUAL;
END;
/

CREATE OR REPLACE PROCEDURE delete_org(keyval IN INTEGER) AS
BEGIN
DELETE FROM institutes WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE create_document(keyval OUT INTEGER) AS
BEGIN
INSERT INTO documents (id,title,abstract) VALUES (document_ids.nextval,' ',' ');
SELECT document_ids.currval INTO keyval FROM DUAL;
END;
/

CREATE OR REPLACE PROCEDURE delete_document (keyval IN INTEGER) AS
BEGIN
DELETE FROM authors_docs WHERE doc_id=keyval;
DELETE FROM documents WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE create_referral(keyval OUT INTEGER) AS
BEGIN
INSERT INTO referrals (id,name,url) VALUES (referral_ids.nextval,' ',' ');
SELECT referral_ids.currval INTO keyval FROM dual;
END;
/

CREATE OR REPLACE PROCEDURE delete_referral(keyval IN INTEGER) AS
BEGIN
DELETE FROM referrals WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE add_phone(pers_id IN INTEGER, phone IN varchar(255)) AS
BEGIN
INSERT INTO phones (id,pers_id,phone) VALUES (phone_ids.nextval,pers_id,phone);
END;
/

CREATE OR REPLACE PROCEDURE delete_phone(keyval IN INTEGER, phone IN varchar(255)) AS
BEGIN
DELETE FROM phones WHERE pers_id=keyval AND phone=phone;
END;
/

CREATE OR REPLACE PROCEDURE set_person_name(keyval IN INTEGER, new_name IN varchar(255)) AS
BEGIN
UPDATE persons SET name=new_name WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_person_surname(keyval IN INTEGER, new_surname IN varchar(255)) AS
BEGIN
UPDATE persons SET surname=new_surname WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_org_name(keyval IN INTEGER, new_name IN varchar(255)) AS
BEGIN
UPDATE institutes SET name=new_name WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_ref_name(keyval IN INTEGER, new_name IN varchar(255)) AS
BEGIN
UPDATE referrals SET name=new_name WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_ref_url(keyval IN INTEGER, new_url IN varchar(255)) AS
BEGIN
UPDATE referrals SET url=new_url WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_doc_title (keyval IN INTEGER, new_title IN varchar(255))  AS
BEGIN
UPDATE documents SET title=new_title WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_doc_abstract (keyval IN INTEGER, new_abstract IN varchar(255))  AS
BEGIN
UPDATE documents SET abstract=new_abstract WHERE id=keyval;
END;
/

CREATE OR REPLACE FUNCTION make_author_link (keyval IN INTEGER, author_dn IN varchar(255)) RETURN INTEGER AS
per_id INTEGER;
BEGIN
 SELECT keyval INTO per_id FROM ldap_entries 
     WHERE oc_map_id=1 AND upper(dn)=upper(author_dn);
 INSERT INTO authors_docs (doc_id,pers_id) VALUES (keyval,per_id);
 RETURN 0;
EXCEPTION
WHEN NO_DATA_FOUND THEN
 RETURN 1;
END;
/

CREATE OR REPLACE FUNCTION del_author_link (keyval IN INTEGER, author_dn IN varchar(255)) RETURN INTEGER AS
per_id INTEGER;
BEGIN
 SELECT keyval INTO per_id FROM ldap_entries
     WHERE oc_map_id=1 AND dn=author_dn;
 DELETE FROM authors_docs WHERE doc_id=keyval AND pers_id=per_id;
 RETURN 0;
EXCEPTION
WHEN NO_DATA_FOUND THEN
 RETURN 1;
END;
/

CREATE OR REPLACE FUNCTION make_doc_link (keyval IN INTEGER, doc_dn IN varchar(255)) RETURN INTEGER AS
docid INTEGER;
BEGIN
 SELECT keyval INTO docid FROM ldap_entries 
	   WHERE oc_map_id=2 AND upper(dn)=upper(doc_dn);
 INSERT INTO authors_docs (pers_id,doc_id) VALUES (keyval,docid);
 RETURN 0;
EXCEPTION
WHEN NO_DATA_FOUND THEN
 RETURN 1;
END;
/

CREATE OR REPLACE FUNCTION del_doc_link (keyval IN INTEGER, doc_dn IN varchar(255)) RETURN INTEGER AS
docid INTEGER;
BEGIN
 SELECT keyval INTO docid FROM ldap_entries 
	   	WHERE oc_map_id=2 AND dn=doc_dn;
 DELETE FROM authors_docs WHERE pers_id=keyval AND doc_id=docid;
 RETURN 0;
EXCEPTION
WHEN NO_DATA_FOUND THEN
 RETURN 1;
END;
/

