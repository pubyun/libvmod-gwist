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
	VTAILQ_ENTRY(gwist_be)	list;
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
	VRT_delete_backend(ctx, &be->dir);
}


int __match_proto__(vmod_event_f)
vmod_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
	struct gwist_ctx *gctx;
	struct gwist_be *be, *tbe;
	ASSERT_CLI();
	AN(ctx);
	AN(ctx->vcl);

	switch (e) {
		case VCL_EVENT_LOAD:
			AZ(priv->priv);
			CAST_OBJ(gctx, priv->priv, GWIST_CTX_MAGIC);
			if (loadcnt == 0) {
				lck_gwist = Lck_CreateClass("gwist.director");
			}
			AN(lck_gwist);
			loadcnt++;
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
			loadcnt--;
			if (loadcnt == 0) {
				VSM_Free(lck_gwist);
			}
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

VCL_VOID __match_proto__(td_gwist_backend)
vmod_ttl(VRT_CTX, struct vmod_priv *priv, VCL_INT ttl) {
	struct gwist_ctx *gctx;
	CAST_OBJ_NOTNULL(gctx, priv->priv, GWIST_CTX_MAGIC);

	Lck_Lock(&gctx->mtx);
	gctx->ttl = ttl;
	Lck_Unlock(&gctx->mtx);
}

VCL_BACKEND __match_proto__(td_gwist_backend)
backend(VRT_CTX,
		struct gwist_ctx *gctx,
		VCL_STRING host,
		VCL_STRING port,
		int af) {
	char *name;
	struct suckaddr *vsa;
	struct vrt_backend vrt;
	struct gwist_be *be, *tbe;
	struct addrinfo hints = { 0 };
	struct addrinfo *servinfo = NULL;
	struct director *dir;
	int insert;

	Lck_Lock(&gctx->mtx);

	insert = &gctx->ttl > 0 ? 1 : 0;

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

	ALLOC_OBJ(be, GWIST_BE_MAGIC);
	be->host = strdup(host);
	be->port = strdup(port);
	be->af = af;
	AZ(pthread_cond_init(&be->cond, NULL));
	be->refcnt++;

	if (insert)
		VTAILQ_INSERT_TAIL(&gctx->backends, be, list);
	Lck_Unlock(&gctx->mtx);

	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hints, &servinfo)) {
		VTAILQ_REMOVE(&gctx->backends, be, list);
		free_backend(ctx, be);
		Lck_Lock(&gctx->mtx);
		AZ(pthread_cond_signal(&be->cond));
		Lck_Unlock(&gctx->mtx);
		return (NULL);
	}

	AN(servinfo);

	vsa = VSA_Malloc(servinfo->ai_addr, servinfo->ai_addrlen);
	AN(vsa);

	INIT_OBJ(&vrt, VRT_BACKEND_MAGIC);

	if (VSA_Get_Proto(vsa) == AF_INET) {
		vrt.ipv4_addr = host;
		vrt.ipv4_suckaddr = vsa;
	} else if (VSA_Get_Proto(vsa) == AF_INET6) {
		vrt.ipv6_addr = host;
		vrt.ipv6_suckaddr = vsa;
	} else {
		freeaddrinfo(servinfo);
		VTAILQ_REMOVE(&gctx->backends, be, list);
		free_backend(ctx, be);
		Lck_Lock(&gctx->mtx);
		AZ(pthread_cond_signal(&be->cond));
		Lck_Unlock(&gctx->mtx);
		return (NULL);
	}


	// TODO: have a stack-allocated name
	name = malloc(strlen(host) + strlen(port) + 8);
	sprintf(name, "gwist.%s.%s", host, port);
	vrt.vcl_name = name;
	vrt.hosthdr = host;
	vrt.port = port;

	be->dir = VRT_new_backend(ctx, &vrt);

	free(name);
	freeaddrinfo(servinfo);

	if (insert) {
		be->tod = ctx->now + gctx->ttl;

		Lck_Lock(&gctx->mtx);
		AZ(pthread_cond_signal(&be->cond));
		Lck_Unlock(&gctx->mtx);
	} else
		be->tod = 0;

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
