#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <vcl.h>
#include <vsa.h>
#include <vrt.h>
#include <cache/cache.h>

#include "vcc_if.h"

enum gwist_state {
	gwist_st_transient,
	gwist_st_resolving,
	gwist_st_cached,
	gwist_st_done,
};

struct gwist_be {
	unsigned			magic;
#define GWIST_BE_MAGIC			0x6887bc23
	unsigned			refcnt;
	enum gwist_state		state;
	double				tod;
	char				*host;
	char				*port;
	struct lock			*mtx;
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
release_backend_l(struct gwist_be *be, int lock) {
	CHECK_OBJ_NOTNULL(be, GWIST_BE_MAGIC);
	if (lock)
		Lck_Lock(be->mtx);
	assert(be->state == gwist_st_cached || be->state == gwist_st_transient);
	be->refcnt--;
	AN(be->refcnt);
	if (lock)
		Lck_Unlock(be->mtx);
}

static void
release_backend(void *ptr) {
	struct gwist_be *be;
	CAST_OBJ(be, ptr, GWIST_BE_MAGIC);
	release_backend_l(be, 1);
}

static void
free_backend(VRT_CTX, struct gwist_be *be) {
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(be, GWIST_BE_MAGIC);
	assert(be->refcnt == 1);
	free(be->host);
	free(be->port);
	AZ(pthread_cond_destroy(&be->cond));
	if (be->dir)
		VRT_delete_backend(ctx, &be->dir);
	free(be);
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

			VTAILQ_FOREACH_SAFE(be, &gctx->backends, list, tbe) {
				VTAILQ_REMOVE(&gctx->backends, be, list);
				free_backend(ctx, be);
			}
			Lck_Delete(&gctx->mtx);
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
backend(VRT_CTX, struct gwist_ctx *gctx, struct vmod_priv *priv,
		VCL_STRING host, VCL_STRING port,
		const struct addrinfo *hints) {
	struct gwist_be *be, *tbe;
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(gctx, GWIST_CTX_MAGIC);
	AN(hints);

	CAST_OBJ(be, priv->priv, GWIST_BE_MAGIC);

	Lck_Lock(&gctx->mtx);

	if (be)
		release_backend_l(be, 0);
	priv->free = release_backend;
	if (!host || !port) {
		Lck_Unlock(&gctx->mtx);
		return (NULL);
	}

	VTAILQ_FOREACH_SAFE(be, &gctx->backends, list, tbe) {
		CHECK_OBJ_NOTNULL(be, GWIST_BE_MAGIC);
		if (be->state  == gwist_st_cached && be->tod > ctx->now)
			be->state = gwist_st_done;
		if (be->refcnt == 1) {
			assert(be->refcnt == 1);
			VTAILQ_REMOVE(&gctx->backends, be, list);
			free_backend(ctx, be);
			continue;
		}
		if (be->state != gwist_st_cached ||
				be->state != gwist_st_resolving)
			continue;
		if ((hints->ai_family == AF_UNSPEC ||
					hints->ai_family == be->af) &&
				!strcmp(be->host, host) &&
				!strcmp(be->port, port)) {
			be->refcnt++;
			if (be->state == gwist_st_resolving)
				Lck_CondWait(&be->cond, &gctx->mtx, 0);
			assert(be->state == gwist_st_cached);
			Lck_Unlock(&gctx->mtx);
			priv->priv = be;
			return (be->dir);
		}
	}

	ALLOC_OBJ(be, GWIST_BE_MAGIC);
	priv->priv = be;
	be->tod = ctx->now + gctx->ttl;
	be->host = strdup(host);
	be->port = strdup(port);
	be->af = hints->ai_family;
	be->mtx = &gctx->mtx;
	be->refcnt = 2; /* PRIV_TASK + VTAILQ */
	be->state = gwist_st_resolving;
	AZ(pthread_cond_init(&be->cond, NULL));
	VTAILQ_INSERT_TAIL(&gctx->backends, be, list);

	if (gctx->ttl) {
		be->state = gwist_st_transient;
		be->tod = 0;
		Lck_Unlock(&gctx->mtx);
		be->dir = bare_backend(ctx, host, port, hints);
		return (be->dir);
	}

	/* AI_NUMERICHOST avoids DNS resolution, no need to unlock/relock */
	if (hints->ai_flags & AI_NUMERICHOST)
		be->dir = bare_backend(ctx, host, port, hints);
	else {
		Lck_Unlock(&gctx->mtx);
		be->dir = bare_backend(ctx, host, port, hints);
		Lck_Lock(&gctx->mtx);
		AZ(pthread_cond_signal(&be->cond));
	}
	be->state = gwist_st_cached;
	Lck_Unlock(&gctx->mtx);

	return (be->dir);
}

#define DECLARE_BE(NAME, AF, FLAGS)					\
	VCL_BACKEND __match_proto__(td_gwist_backend)			\
	NAME(VRT_CTX,  struct vmod_priv *vpriv, struct vmod_priv *tpriv,\
			VCL_STRING host, VCL_STRING port) {		\
		struct addrinfo hints = { 0 };				\
		hints.ai_family = AF;					\
		hints.ai_socktype = SOCK_STREAM;			\
		hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | FLAGS;	\
		return (backend(ctx, (struct gwist_ctx *)vpriv->priv,	\
					tpriv, host, port, &hints));	\
	}

DECLARE_BE(vmod_backend ,    AF_UNSPEC, 0)
DECLARE_BE(vmod_backend4,    AF_INET,	0)
DECLARE_BE(vmod_backend6,    AF_INET6,	0)
DECLARE_BE(vmod_backend_num, AF_UNSPEC, AI_NUMERICHOST)
