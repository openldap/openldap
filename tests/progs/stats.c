#include "portable.h"

#include <lber.h>

#include <ac/time.h>

#include "lber_pvt.h"

#include "ldap.h"

#include <stdio.h>

#include "slapd-common.h"

/*
 * Compile-time constants
 */
#define SLAP_SYNC_SID_MAX	4095

#define	HAS_MONITOR	1
#define	HAS_BASE	2
#define	HAS_ENTRIES	4
#define	HAS_SREPL	8
#define HAS_ALL (HAS_MONITOR|HAS_BASE|HAS_ENTRIES|HAS_SREPL)


#define WAS_LATE	0x100
#define WAS_DOWN	0x200

#define	MONFILTER	"(objectClass=monitorOperation)"

/*
 * Forward declarations
 */
typedef struct ldap LDAP;

/*
 * Global variables
 */
static char *clearscreen = "\033[H\033[2J";
static struct berval base;
static int interval = 10;
static const char *default_monfilter = MONFILTER;


static void timestamp(const time_t *tt)
{
	struct tm *tm = gmtime(tt);
	printf("%d-%02d-%02d %02d:%02d:%02d",
		tm->tm_year + 1900, tm->tm_mon+1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

#if 0
static void deltat(const time_t *tt)
{
	struct tm *tm = gmtime(tt);
	if (tm->tm_mday-1)
		printf("%02d+", tm->tm_mday-1);
	printf("%02d:%02d:%02d",
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}
#endif

static void rotate_stats( server *sv, int numservers )
{
	if ( sv->flags & HAS_MONITOR )
		sv->c_prev = sv->c_curr;
	if ( sv->flags & HAS_BASE ) {
		int i;

		for (i=0; i<numservers; i++) {
			if ( sv->csn_curr.vals[i].bv_len ) {
				ber_bvreplace(&sv->csn_prev.vals[i],
					&sv->csn_curr.vals[i]);
				sv->csn_prev.tvs[i] = sv->csn_curr.tvs[i];
			} else {
				if ( sv->csn_prev.vals[i].bv_val )
					sv->csn_prev.vals[i].bv_val[0] = '\0';
			}
		}
	}
}

FILE *
init_stats( const char filename[], server *server ) {
	if( !filename ) {
		return NULL;
	}
	
	*server = (struct server) { .flags = HAS_ENTRIES };
				    
	return fopen(filename, "w");
}

void
update_stats( server *server, slap_op_t op,
	      unsigned long entries, unsigned long nop )
{
	gettimeofday(&server->c_curr.time, NULL);

	server->c_curr.entries = entries;
	server->c_curr.ops[op] = nop;
}

/*
 * Display statistics for the "server" (which may be a client).
 */
#define eprintf(...) fprintf (out, __VA_ARGS__)

void
display_stats( FILE *out, server *server ) {
	struct timeval tv;
	double rate, duration;
	long delta;
	struct timeval now = server->c_curr.time;
	size_t j;

	if( !out ) return; // no statistics requested
	assert(server);

	eprintf("\n%s\n", server->url? server->url : "" );
	eprintf("      ");

	if ( server->flags & HAS_ENTRIES )
		eprintf("  Entries  ");
	for ( j = 0; j<SLAP_OP_LAST; j++ )
		eprintf(" %9s ", opnames[j].display);
	eprintf("\n");
	eprintf("Num   ");
	if ( server->flags & HAS_ENTRIES )
		eprintf("%10lu ", server->c_curr.entries);
	for ( j = 0; j<SLAP_OP_LAST; j++ )
		eprintf("%10lu ", server->c_curr.ops[j]);
	eprintf("\n");
	eprintf("Num/s ");
	tv.tv_usec = now.tv_usec - server->c_prev.time.tv_usec;
	tv.tv_sec = now.tv_sec - server->c_prev.time.tv_sec;
	if ( tv.tv_usec < 0 ) {
		tv.tv_usec += 1000000;
		tv.tv_sec--;
	}
	duration = tv.tv_sec + (tv.tv_usec / (double)1000000);
	if ( server->flags & HAS_ENTRIES ) {
		delta = server->c_curr.entries - server->c_prev.entries;
		rate = delta / duration;
		eprintf("%10.2f ", rate);
	}
	for ( j = 0; j<SLAP_OP_LAST; j++ ) {
		delta = server->c_curr.ops[j] - server->c_prev.ops[j];
		rate = delta / duration;
		eprintf("%10.2f ", rate);
	}
	eprintf("\n");


	// Set previous to current.
	// If called again without update, delta will be zero. 
	server->c_prev = server->c_curr;
}

#if has_base_matters


	printf("\n%s", server->url );
	if ( server->flags & WAS_DOWN ) {
		printf(", down@");
		timestamp( &server->down );
	}
	if ( server->flags & WAS_LATE ) {
		printf(", late@");
		timestamp( &server->late );
	}
	printf("\n");


	if ( server->flags & HAS_BASE ) {
		for (j=0; j<numservers; j++) {
			/* skip empty CSNs */
			if (!server->csn_curr.vals[j].bv_len ||
			    !server->csn_curr.vals[j].bv_val[0])
				continue;
			printf("contextCSN: %s", server->csn_curr.vals[j].bv_val );
			if (ber_bvcmp(&server->csn_curr.vals[j],
				      &server->csn_prev.vals[j])) {
				/* a difference */
				if (server->times[j].idle) {
					server->times[j].idle = 0;
					server->times[j].active = 0;
					server->times[j].maxlag = 0;
					server->times[j].lag = 0;
				}
			active:
				if (!server->times[j].active)
					server->times[j].active = now_t;
				printf(" actv@");
				timestamp(&server->times[j].active);
			} else if ( server->times[j].lag || ( server->flags & WAS_LATE )) {
				goto active;
			} else {
				if (server->times[j].active && !server->times[j].idle)
					server->times[j].idle = now_t;
				if (server->times[j].active) {
					printf(" actv@");
					timestamp(&server->times[j].active);
					printf(", idle@");
					timestamp(&server->times[j].idle);
				} else {
					printf(" idle");
				}
			}
			if (server != servers + j) {
				if (ber_bvcmp(&server->csn_curr.vals[j],
					      &servers[j].csn_curr.vals[j])) {
					struct timeval delta;
					int ahead = 0;
					time_t deltatt;
					delta.tv_sec = servers[j].csn_curr.tvs[j].tv_sec -
						server->csn_curr.tvs[j].tv_sec;
					delta.tv_usec = servers[j].csn_curr.tvs[j].tv_usec -
						server->csn_curr.tvs[j].tv_usec;
					if (delta.tv_usec < 0) {
						delta.tv_usec += 1000000;
						delta.tv_sec--;
					}
					if (delta.tv_sec < 0) {
						delta.tv_sec = -delta.tv_sec;
						ahead = 1;
					}
					deltatt = delta.tv_sec;
					if (ahead)
						printf(", ahead ");
					else
						printf(", behind ");
					deltat( &deltatt );
					server->times[j].lag = deltatt;
					if (deltatt > server->times[j].maxlag)
						server->times[j].maxlag = deltatt;
				} else {
					server->times[j].lag = 0;
					printf(", sync'd");
				}
				if (server->times[j].maxlag) {
					printf(", max delta ");
					deltat( &server->times[j].maxlag );
				}
			}
			printf("\n");
		}
	}

void display( server *servers, int numservers, char *monfilter )
{
	int i, j;
	struct timeval now;
	time_t now_t;

	FILE *stats = fdopen(3, "w");

	gettimeofday(&now, NULL);
	now_t = now.tv_sec;
	printf("%s", clearscreen);
	timestamp(&now_t);
	printf("\n");

	for (i=0; i<numservers; i++) {
		display_stats(stats, servers + i, now);
		if ( !( servers[i].flags & WAS_LATE ))
			rotate_stats( servers + i, numservers );
	}
}
#endif




