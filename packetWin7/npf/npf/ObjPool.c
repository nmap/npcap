/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2020 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and may not be redistributed or incorporated   *
 * into other software without special permission from the Nmap Project.   *
 * We fund the Npcap project by selling a commercial license which allows  *
 * companies to redistribute Npcap with their products and also provides   *
 * for support, warranty, and indemnification rights.  For details on      *
 * obtaining such a license, please contact:                               *
 *                                                                         *
 * sales@nmap.com                                                          *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests.  However, we normally recommend that such  *
 * authors instead ask your users to download and install Npcap            *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  By sending these changes to the Nmap Project (including      *
 * through direct email or our mailing lists or submitting pull requests   *
 * through our source code repository), it is understood unless you        *
 * specify otherwise that you are offering the Nmap Project the            *
 * unlimited, non-exclusive right to reuse, modify, and relicence your     *
 * code contribution so that we may (but are not obligated to)             *
 * incorporate it into Npcap.  If you wish to specify special license      *
 * conditions or restrictions on your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 * This header summarizes a few important aspects of the Npcap license,    *
 * but is not a substitute for the full Npcap license agreement, which is  *
 * in the LICENSE file included with Npcap and also available at           *
 * https://github.com/nmap/npcap/blob/master/LICENSE.                      *
 *                                                                         *
 ***************************************************************************/
#include "ObjPool.h"
#include <ndis.h>

// TODO: Implement a way to shrink the pool occasionally?

/* Objects in the pool are retrieved and returned using this struct.
 * pObject is an uninitialized array of ulObjectSize bytes.
 */
typedef struct _NPF_OBJ_POOL_ELEM
{
	LIST_ENTRY ObjectsEntry;
	ULONG Refcount;
	UCHAR pObject[];
} NPF_OBJ_POOL_ELEM, *PNPF_OBJ_POOL_ELEM;

typedef struct _NPF_OBJ_SHELF
{
	LIST_ENTRY ShelfEntry;
	UCHAR pBuffer[];
} NPF_OBJ_SHELF, *PNPF_OBJ_SHELF;

typedef struct _NPF_OBJ_POOL
{
	LIST_ENTRY ShelfHead;
	KSPIN_LOCK ShelfLock;
	LIST_ENTRY ObjectsHead;
	KSPIN_LOCK ObjectsLock;
	NDIS_HANDLE NdisHandle;
	ULONG ulObjectSize;
	ULONG ulIncrement;
} NPF_OBJ_POOL;

#define NPF_OBJECT_POOL_TAG 'TPON'

#define NPF_OBJ_ELEM_ALLOC_SIZE(POOL) (sizeof(NPF_OBJ_POOL_ELEM) + (POOL)->ulObjectSize)
#define NPF_OBJ_SHELF_ALLOC_SIZE(POOL) ( sizeof(NPF_OBJ_SHELF) + NPF_OBJ_ELEM_ALLOC_SIZE(POOL) * (POOL)->ulIncrement)

BOOLEAN NPF_ExtendObjectShelf(PNPF_OBJ_POOL pPool)
{
	PNPF_OBJ_SHELF pShelf = NULL;
	PNPF_OBJ_POOL_ELEM pElem = NULL;
	ULONG i;

       	pShelf = (PNPF_OBJ_SHELF) NdisAllocateMemoryWithTagPriority(pPool->NdisHandle,
			NPF_OBJ_SHELF_ALLOC_SIZE(pPool),
		       	NPF_OBJECT_POOL_TAG,
			NormalPoolPriority);
	if (pShelf == NULL)
	{
		return FALSE;
	}
	RtlZeroMemory(pShelf, NPF_OBJ_SHELF_ALLOC_SIZE(pPool));

	ExInterlockedInsertTailList(&pPool->ShelfHead, &pShelf->ShelfEntry, &pPool->ShelfLock);

	// Buffer starts after the shelf itself
	for (i=0; i < pPool->ulIncrement; i++)
	{
		pElem = (PNPF_OBJ_POOL_ELEM) (pShelf->pBuffer + i * NPF_OBJ_ELEM_ALLOC_SIZE(pPool));
		ExInterlockedInsertTailList(&pPool->ObjectsHead, &pElem->ObjectsEntry, &pPool->ObjectsLock);
	}

	return TRUE;
}

PNPF_OBJ_POOL NPF_AllocateObjectPool(NDIS_HANDLE NdisHandle, ULONG ulObjectSize, ULONG ulIncrement)
{
	PNPF_OBJ_POOL pPool = NULL;
	PNPF_OBJ_SHELF pShelf = NULL;

	pPool = NdisAllocateMemoryWithTagPriority(NdisHandle,
			sizeof(NPF_OBJ_POOL),
		       	NPF_OBJECT_POOL_TAG,
			NormalPoolPriority);
	if (pPool == NULL)
	{
		return NULL;
	}

	InitializeListHead(&pPool->ShelfHead);
	KeInitializeSpinLock(&pPool->ShelfLock);
	InitializeListHead(&pPool->ObjectsHead);
	KeInitializeSpinLock(&pPool->ObjectsLock);

	pPool->NdisHandle = NdisHandle;
	pPool->ulObjectSize = ulObjectSize;
	pPool->ulIncrement = ulIncrement;

	return pPool;
}

PVOID NPF_ObjectPoolGet(PNPF_OBJ_POOL pPool)
{
	PNPF_OBJ_POOL_ELEM pElem = NULL;
	PLIST_ENTRY pEntry = ExInterlockedRemoveHeadList(&pPool->ObjectsHead, &pPool->ObjectsLock);
	if (pEntry == NULL)
	{
		if (!NPF_ExtendObjectShelf(pPool))
		{
			return NULL;
		}
		pEntry = ExInterlockedRemoveHeadList(&pPool->ObjectsHead, &pPool->ObjectsLock);
	}

	if (pEntry == NULL)
	{
		return NULL;
	}

	pElem = CONTAINING_RECORD(pEntry, NPF_OBJ_POOL_ELEM, ObjectsEntry);
	pElem->Refcount = 1;
	return pElem->pObject;
}

VOID NPF_FreeObjectPool(PNPF_OBJ_POOL pPool)
{
	PLIST_ENTRY pShelfEntry = NULL;

	while ((pShelfEntry = ExInterlockedRemoveHeadList(&pPool->ShelfHead, &pPool->ShelfLock)) != NULL)
	{
		NdisFreeMemory(
				CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry),
				NPF_OBJ_SHELF_ALLOC_SIZE(pPool),
				0);
	}
	NdisFreeMemory(pPool, sizeof(NPF_OBJ_POOL), 0);
}

VOID NPF_ObjectPoolReturn(PNPF_OBJ_POOL pPool, PVOID pObject, PNPF_OBJ_CLEANUP CleanupFunc)
{
	PNPF_OBJ_POOL_ELEM pElem = CONTAINING_RECORD(pObject, NPF_OBJ_POOL_ELEM, pObject);
	ULONG refcount = InterlockedDecrement(&pElem->Refcount);
	if (refcount == 0)
	{
		if (CleanupFunc)
		{
			CleanupFunc(pElem->pObject);
		}
		// Insert at the head instead of the tail, hoping the next Get will
		// avoid a cache miss.
		ExInterlockedInsertHeadList(&pPool->ObjectsHead, &pElem->ObjectsEntry, &pPool->ObjectsLock);
	}
}

VOID NPF_ReferenceObject(PVOID pObject)
{
	PNPF_OBJ_POOL_ELEM pElem = CONTAINING_RECORD(pObject, NPF_OBJ_POOL_ELEM, pObject);

	InterlockedIncrement(&pElem->Refcount);
}
