#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <vcl.h>
#include <vsa.h>
#include <vrt.h>
#include <cache/cache.h>

#include "vcc_if.h"

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
#define GWIST_CTX_MAGIC			0xcf26e5a2
	VCL_INT				ttl;
	struct lock			mtx;
	VTAILQ_HEAD(,gwist_be)		backends;
};

static unsigned loadcnt = 0;
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
	CAST_OBJ(gctx, priv->priv, GWIST_CTX_MAGIC);

	switch (e) {
		case VCL_EVENT_LOAD:
			AZ(gctx);
			if (loadcnt++ == 0)
				lck_gwist = Lck_CreateClass("gwist.director");

			AN(lck_gwist);
			ALLOC_OBJ(gctx, GWIST_CTX_MAGIC);
			VTAILQ_INIT(&gctx->backends);
			gctx->ttl = 10;
			Lck_New(&gctx->mtx, lck_gwist);
			priv->priv = gctx;
			break;
		case VCL_EVENT_DISCARD:
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
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CAST_OBJ_NOTNULL(gctx, priv->priv, GWIST_CTX_MAGIC);

	Lck_Lock(&gctx->mtx);
	gctx->ttl = ttl;
	Lck_Unlock(&gctx->mtx);
}

struct director *
bare_backend(VRT_CTX, const char *host, const char *port,
		const struct addrinfo *hints) {
	struct vrt_backend vrt;
	struct addrinfo *servinfo = NULL;
	struct suckaddr *vsa;
	char name[64 + 5 + 8]; /* host + port + gwist..\0 */
	int r;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(host);
	AN(port);
	AN(hints);

	r = snprintf(name, sizeof name, "gwist.%s.%s", host, port);
	assert(r > 0);
	if (r > sizeof name)
		return (NULL);

	if (getaddrinfo(host, port, hints, &servinfo))
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
backend(VRT_CTX, struct gwist_ctx *gctx,
		VCL_STRING host, VCL_STRING port,
		const struct addrinfo *hints) {
	struct gwist_be *be, *tbe;
	struct director *_dir, *dir;
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(gctx, GWIST_CTX_MAGIC);
	AN(host);
	AN(port);
	AN(hints);

	/* if ttl is zero, and the cache is empty, we know we have to create
	 * a backend and we won't cache it, no need to lock. (useless optim?)*/
	if (!gctx->ttl && VTAILQ_EMPTY(&gctx->backends)) {
		_dir = dir = bare_backend(ctx, host, port, hints);
		if (!_dir)
			VRT_delete_backend(ctx, &_dir);
		return (dir);
	}

	Lck_Lock(&gctx->mtx);

	VTAILQ_FOREACH_SAFE(be, &gctx->backends, list, tbe) {
		if (be->tod > ctx->now) { /* make room for the kids */
			VTAILQ_REMOVE(&gctx->backends, be, list);
			free_backend(ctx, be);
		}
		if ((hints->ai_family == AF_UNSPEC ||
					hints->ai_family == be->af) &&
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

	/* no match found, if inserting isn't required, just return a simple
	 * backend without wrapping it in a gwist_be */
	if (!gctx->ttl) {
		Lck_Unlock(&gctx->mtx);
		_dir = dir = bare_backend(ctx, host, port, hints);
		if (!_dir)
			VRT_delete_backend(ctx, &_dir);
		return (dir);
	}

	ALLOC_OBJ(be, GWIST_BE_MAGIC);
	be->tod = ctx->now + gctx->ttl;
	be->host = strdup(host);
	be->port = strdup(port);
	be->af = hints->ai_family;
	be->refcnt = 1;
	AZ(pthread_cond_init(&be->cond, NULL));
	VTAILQ_INSERT_TAIL(&gctx->backends, be, list);

	/* AI_NUMERICHOST avoids DNS resolution, no need to unlock/relock */
	if (hints->ai_flags & AI_NUMERICHOST)
		be->dir = bare_backend(ctx, host, port, hints);
	else {
		Lck_Unlock(&gctx->mtx);
		be->dir = bare_backend(ctx, host, port, hints);
		Lck_Lock(&gctx->mtx);
		AZ(pthread_cond_signal(&be->cond));
	}
	Lck_Unlock(&gctx->mtx);

	return (be->dir);
}

#define DECLARE_BE(NAME, AF, FLAGS)					\
	VCL_BACKEND __match_proto__(td_gwist_backend)			\
	NAME(VRT_CTX,  struct vmod_priv *priv,				\
			VCL_STRING host, VCL_STRING port) {		\
		struct addrinfo hints = { 0 };				\
		hints.ai_family = AF;					\
		hints.ai_socktype = SOCK_STREAM;			\
		hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | FLAGS;	\
		return (backend(ctx, (struct gwist_ctx *)priv->priv,	\
					host, port, &hints));	\
	}

DECLARE_BE(vmod_backend ,    AF_UNSPEC, 0)
DECLARE_BE(vmod_backend4,    AF_INET,	0)
DECLARE_BE(vmod_backend6,    AF_INET6,	0)
DECLARE_BE(vmod_backend_num, AF_UNSPEC, AI_NUMERICHOST)
