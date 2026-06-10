/* mtest_enc.c - memory-mapped database tester/toy with encryption */
/*
 * Copyright 2011-2021 Howard Chu, Symas Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the Symas
 * Dual-Use License.
 *
 * A copy of this license is available in the file LICENSE in the
 * source distribution.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "lmdb.h"

#define E(expr) CHECK((rc = (expr)) == MDB_SUCCESS, #expr)
#define RES(err, expr) ((rc = expr) == (err) || (CHECK(!rc, #expr), 0))
#define CHECK(test, msg) ((test) ? (void)0 : ((void)fprintf(stderr, \
	"%s:%d: %s: %s\n", __FILE__, __LINE__, msg, mdb_strerror(rc)), abort()))

MDB_crypto_funcs *cf;

#define MAX_VALUE_SIZE	65536
char valbuf[MAX_VALUE_SIZE];

/* For ITS#10520: this program creates a DB with records of various sizes,
 * to exercise handling of encrypted overflow pages. After creation, the
 * various dump/load/copy tools should be run to check for correct operation.
 */
int main(int argc,char * argv[])
{
	int i = 0, j = 0, rc;
	MDB_env *env;
	MDB_dbi dbi;
	MDB_val key, data;
	MDB_txn *txn;
	MDB_stat mst;
	int count;
	char sval[32] = "";
	char password[] = "This is my passphrase for now...";
	void *mlm;
	char *errmsg;
	MDB_crypto_funcs *mcf;

	srand(time(NULL));

	    count = 2400;
    
		E(mdb_env_create(&env));
		mlm = mdb_modload("./crypto.lm", NULL, &mcf, &errmsg);
		if (!mlm) {
			fprintf(stderr,"Failed to load crypto module: %s\n", errmsg);
			exit(1);
		}
		mdb_modsetup(env, mcf, password);
		E(mdb_env_set_maxreaders(env, 1));
		E(mdb_env_set_mapsize(env, 1073741824)); /* 1GB */
		E(mdb_env_open(env, "./testdb", 0 /*|MDB_NOSYNC*/, 0664));

		E(mdb_txn_begin(env, NULL, 0, &txn));
		E(mdb_dbi_open(txn, NULL, 0, &dbi));
   
		key.mv_size = 8;
		key.mv_data = sval;

		printf("Adding %d values\n", count);
	    for (i=0;i<count;i++) {	
			sprintf(sval, "%08x", rand());
			/* Set <data> in each iteration, since MDB_NOOVERWRITE may modify it */
			data.mv_size = rand() % MAX_VALUE_SIZE;
			data.mv_data = valbuf;
			sprintf(valbuf, "%d foo bar blah", (int)data.mv_size);
			if (RES(MDB_KEYEXIST, mdb_put(txn, dbi, &key, &data, MDB_NOOVERWRITE))) {
				j++;
				data.mv_size = sizeof(sval);
				data.mv_data = sval;
			}
			if (!(i % 100)) {
				E(mdb_txn_commit(txn));
				E(mdb_txn_begin(env, NULL, 0, &txn));
			}
	    }
		if (j) printf("%d duplicates skipped\n", j);
		E(mdb_txn_commit(txn));
		E(mdb_env_stat(env, &mst));

		mdb_dbi_close(env, dbi);
		mdb_env_close(env);
		mdb_modunload(mlm);

	return 0;
}
