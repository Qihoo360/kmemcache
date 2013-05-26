#include <linux/module.h>
#include <linux/string.h>
#include "config.h"
#include "mc_msg.h"

#define MSG_ENTRY(type, msg) (msg)

char* s2c_msg[MSG_MAX] __read_mostly = {
	MSG_ENTRY(MSG_SYS_CONNS,	"ERROR Too many open connections\r\n"),
	MSG_ENTRY(MSG_SYS_SHUT,		"ERROR: shutdown not enabled"),
	MSG_ENTRY(MSG_SYS_BUSY,		"BUSY currently processing reassign request"),
	MSG_ENTRY(MSG_SYS_BADCLS,	"BADCLASS invalid src or dst class id"),
	MSG_ENTRY(MSG_SYS_NOSPACE,	"NOSPARE source class has no spare pages"),
	MSG_ENTRY(MSG_SYS_SAMECLS,	"SAME src and dst class are identical"),
	MSG_ENTRY(MSG_SYS_VERSION,	PACKAGE_STRING),

	MSG_ENTRY(MSG_SER_OOM,		"SERVER_ERROR out of memory"),
	MSG_ENTRY(MSG_SER_OOM_STAT,	"SERVER_ERROR out of memory writing stats"),
	MSG_ENTRY(MSG_SER_OOM_RREQ,	"SERVER_ERROR out of memory reading request"),
	MSG_ENTRY(MSG_SER_OOM_WRES,	"SERVER_ERROR out of memory writing get response"),
	MSG_ENTRY(MSG_SER_OOM_PRES,	"SERVER_ERROR out of memory preparing response"),
	MSG_ENTRY(MSG_SER_OOM_SOBJ,	"SERVER_ERROR out of memory storing object"),
	MSG_ENTRY(MSG_SER_OOM_CAS,	"SERVER_ERROR out of memory making CAS suffix"),
	MSG_ENTRY(MSG_SER_MUL_PACK,	"SERVER_ERROR multi-packet request not supported"),
	MSG_ENTRY(MSG_SER_LAROBJ,	"SERVER_ERROR object too large for cache"),
	MSG_ENTRY(MSG_SER_STYPE,	"SERVER_ERROR Unhandled storage type."),
	MSG_ENTRY(MSG_SER_LNGOUT,	"SERVER_ERROR output line too long"),

	MSG_ENTRY(MSG_BIN_AUTHED,	"Authenticated"),
	MSG_ENTRY(MSG_BIN_OOM,		"Out of memory"),
	MSG_ENTRY(MSG_BIN_NCMD,		"Unknown command"),
	MSG_ENTRY(MSG_BIN_NFD,		"Not found"),
	MSG_ENTRY(MSG_BIN_NARG,		"Invalid arguments"),
	MSG_ENTRY(MSG_BIN_XKEY,		"Data exists for key."),
	MSG_ENTRY(MSG_BIN_LARG,		"Too large."),
	MSG_ENTRY(MSG_BIN_NNUM,		"Non-numeric server-side value for incr or decr"),
	MSG_ENTRY(MSG_BIN_NSTO,		"Not stored."),
	MSG_ENTRY(MSG_BIN_AUTH,		"Auth failure."),
	MSG_ENTRY(MSG_BIN_UHND,		"UNHANDLED ERROR"),
	MSG_ENTRY(MSG_BIN_UKNW,		"Unknown error"),

	MSG_ENTRY(MSG_TXT_OK,		"OK"),
	MSG_ENTRY(MSG_TXT_RESET,	"RESET"),
	MSG_ENTRY(MSG_TXT_ERROR,	"ERROR"),
	MSG_ENTRY(MSG_TXT_STORED,	"STORED"),
	MSG_ENTRY(MSG_TXT_EXISTS,	"EXISTS"),
	MSG_ENTRY(MSG_TXT_TOUCHED,	"TOUCHED"),
	MSG_ENTRY(MSG_TXT_DELETED,	"DELETED"),
	MSG_ENTRY(MSG_TXT_NFOUND,	"NOT_FOUND"),
	MSG_ENTRY(MSG_TXT_NSTORED,	"NOT_STORED"),

	MSG_ENTRY(MSG_TXT_BAD_CHUNK,	"CLIENT_ERROR bad data chunk"),
	MSG_ENTRY(MSG_TXT_BAD_CMDLIN,	"CLIENT_ERROR bad command line"),
	MSG_ENTRY(MSG_TXT_BAD_CMDFMT,	"CLIENT_ERROR bad command line format"),
	MSG_ENTRY(MSG_TXT_BAD_CMDUSG,	"CLIENT_ERROR bad command line format. Usage: delete <key> [noreply]"),
	MSG_ENTRY(MSG_TXT_ILL_SLAB,	"CLIENT_ERROR Illegal slab id"),
	MSG_ENTRY(MSG_TXT_ILL_TIME,	"CLIENT_ERROR invalid exptime argument"),
	MSG_ENTRY(MSG_TXT_ILL_NUM,	"CLIENT_ERROR invalid numeric delta argument"),
	MSG_ENTRY(MSG_TXT_USG_STAT,	"CLIENT_ERROR usage: stats detail on|off|dump"),
	MSG_ENTRY(MSG_TXT_CRE_VAL,	"CLIENT_ERROR cannot increment or decrement non-numeric value"),
	MSG_ENTRY(MSG_TXT_SLAB_DIS,	"CLIENT_ERROR slab reassignment disabled"),
};

u8 s2c_len[MSG_MAX] __read_mostly;

void msg_init(void)
{
	int i;

	for (i = 0; i < MSG_MAX; i++) {
		s2c_len[i] = strlen(s2c_msg[i]);
	}
}
