#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <time.h>

#include "vcl.h"
#include "vsa.h"
#include "vtim.h"
#include "vrt.h"
#include "cache/cache.h"

#include "vcc_if.h"

typedef VCL_BACKEND td_gwist_ttl(VRT_CTX, struct vmod_priv *priv, VCL_INT ttl);
typedef VCL_BACKEND td_gwist_backend(VRT_CTX, struct vmod_priv *,
		VCL_STRING, VCL_STRING);

static unsigned loadcnt = 0;

struct gwist_be {
	unsigned			magic;
#define GWIST_BE_MAGIC			0x6887bc23
	unsigned			refcnt;
	double				tod;
	char				*host;
	char				*port;
	int				af;
	struct director			*dir;
	VTAILQ_ENTRY(gwist_be)		list;
	pthread_cond_t                  cond;
};

struct gwist_ctx {
	unsigned			magic;
#define GWIST_CTX_MAGIC			0xcf2e5a2
	VCL_INT				ttl;
	struct lock			mtx;
	VTAILQ_HEAD(,gwist_be)		backends;
};

static struct VSC_C_lck *lck_gwist;

static void
free_backend(VRT_CTX, struct gwist_be *be) {
	AN(be->refcnt);
	be->refcnt--;
	if (be->refcnt)
		return;
	free(be->host);
	free(be->port);
	AZ(pthread_cond_destroy(&be->cond));
	if (be->dir)
		VRT_delete_backend(ctx, &be->dir);
}


int __match_proto__(vmod_event_f)
vmod_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	struct gwist_ctx *gctx;
	struct gwist_be *be, *tbe;
	ASSERT_CLI();
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(ctx->vcl);

	switch (e) {
		case VCL_EVENT_LOAD:
			AZ(priv->priv);
			CAST_OBJ(gctx, priv->priv, GWIST_CTX_MAGIC);
			if (loadcnt++ == 0)
				lck_gwist = Lck_CreateClass("gwist.director");

			AN(lck_gwist);
			AZ(gctx);
			ALLOC_OBJ(gctx, GWIST_CTX_MAGIC);
			VTAILQ_INIT(&gctx->backends);
			gctx->ttl = 10;
			Lck_New(&gctx->mtx, lck_gwist);
			priv->priv = gctx;
			break;
		case VCL_EVENT_DISCARD:
			CAST_OBJ_NOTNULL(gctx, priv->priv, GWIST_CTX_MAGIC);
			assert(loadcnt > 0);
			if (--loadcnt == 0)
				VSM_Free(lck_gwist);

			Lck_Delete(&gctx->mtx);
			VTAILQ_FOREACH_SAFE(be, &gctx->backends, list, tbe) {
				VTAILQ_REMOVE(&gctx->backends, be, list);
				free_backend(ctx, be);
			}
			CHECK_OBJ_NOTNULL(gctx, GWIST_CTX_MAGIC);
			FREE_OBJ(gctx);
			break;
		default:
			break;
	}

	return (0);
}

VCL_VOID __match_proto__(td_gwist_ttl)
vmod_ttl(VRT_CTX, struct vmod_priv *priv, VCL_INT ttl) {
	struct gwist_ctx *gctx;
	assert(ttl >= 0);
	CAST_OBJ_NOTNULL(gctx, priv->priv, GWIST_CTX_MAGIC);

	Lck_Lock(&gctx->mtx);
	gctx->ttl = ttl;
	Lck_Unlock(&gctx->mtx);
}

struct director *
bare_backend(VRT_CTX, const char *host, const char *port, int af) {
	struct vrt_backend vrt;
	struct addrinfo hints = { 0 };
	struct addrinfo *servinfo = NULL;
	struct suckaddr *vsa;
	char name[64 + 5 + 8]; /* host + port + gwist..\0 */

	int r = snprintf(name, sizeof name, "gwist.%s.%s", host, port);
	assert(r > 0);
	if (r > sizeof name)
		return (NULL);

	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hints, &servinfo))
		return (NULL);

	AN(servinfo);
	vsa = VSA_Malloc(servinfo->ai_addr, servinfo->ai_addrlen);
	AN(vsa);
	freeaddrinfo(servinfo);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);

	if (VSA_Get_Proto(vsa) == AF_INET) {
		vrt.ipv4_addr = host;
		vrt.ipv4_suckaddr = vsa;
	} else if (VSA_Get_Proto(vsa) == AF_INET6) {
		vrt.ipv6_addr = host;
		vrt.ipv6_suckaddr = vsa;
	} else {
		free(vsa);
		return (NULL);
	}

	vrt.vcl_name = name;
	vrt.hosthdr = host;
	vrt.port = port;

	return (VRT_new_backend(ctx, &vrt));
}

static VCL_BACKEND
backend(VRT_CTX,
		struct gwist_ctx *gctx,
		VCL_STRING host,
		VCL_STRING port,
		int af) {
	struct gwist_be *be, *tbe;
	struct director *_dir, *dir;
	int insert;

	/* if ttl is zero, and the cache is empty, we know we have to create a backend
	 * and we won't cache it, no need to lock. */
	if (!gctx->ttl && VTAILQ_EMPTY(&gctx->backends)) {
		_dir = dir = bare_backend(ctx, host, port, af);
		if (!_dir)
			VRT_delete_backend(ctx, &_dir);
		return (dir);
	}

	Lck_Lock(&gctx->mtx);

	insert = gctx->ttl > 0 ? 1 : 0;

	VTAILQ_FOREACH_SAFE(be, &gctx->backends, list, tbe) {
		if (be->tod > ctx->now) { // make room for the kids
			VTAILQ_REMOVE(&gctx->backends, be, list);
			free_backend(ctx, be);
		}
		if ((af == AF_UNSPEC || af == be->af) &&
				!strcmp(be->host, host) &&
				!strcmp(be->port, port)) {
			dir = be->dir;
			if (!dir) {
				be->refcnt++;
				Lck_CondWait(&be->cond, &gctx->mtx, 0);
				dir = be->dir;
				free_backend(ctx, be);
			}
			Lck_Unlock(&gctx->mtx);
			return (dir);
		}
	}

	/* no match found, so check if we should insert, just return a simple
	 * backend without wrapping it in a gwist_be */
	if (!insert) {
		Lck_Unlock(&gctx->mtx);
		_dir = dir = bare_backend(ctx, host, port, af);
		if (!_dir)
			VRT_delete_backend(ctx, &_dir);
		return (dir);
	}

	ALLOC_OBJ(be, GWIST_BE_MAGIC);
	be->tod = ctx->now + gctx->ttl;
	be->host = strdup(host);
	be->port = strdup(port);
	be->af = af;
	AZ(pthread_cond_init(&be->cond, NULL));
	be->refcnt = 1;
	VTAILQ_INSERT_TAIL(&gctx->backends, be, list);

	Lck_Unlock(&gctx->mtx);

	be->dir = bare_backend(ctx, host, port, af);

	Lck_Lock(&gctx->mtx);
	AZ(pthread_cond_signal(&be->cond));
	Lck_Unlock(&gctx->mtx);

	return (be->dir);
}

#define DECLARE_BE(NAME, AF)						\
	VCL_BACKEND __match_proto__(td_gwist_backend)			\
	NAME(VRT_CTX,							\
			struct vmod_priv *priv,				\
			VCL_STRING host,				\
			VCL_STRING port) {				\
		struct gwist_ctx *gctx;					\
		CAST_OBJ_NOTNULL(gctx, priv->priv, GWIST_CTX_MAGIC);	\
		return (backend(ctx, gctx, host, port, AF));		\
	}

DECLARE_BE(vmod_backend , AF_UNSPEC)
DECLARE_BE(vmod_backend4, AF_INET)
DECLARE_BE(vmod_backend6, AF_INET6)
