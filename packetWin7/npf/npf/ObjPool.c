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

typedef struct _NPF_OBJ_SHELF
{
	SINGLE_LIST_ENTRY ShelfEntry;
	PNPF_OBJ_POOL pPool;
	ULONG ulUsed;
	SINGLE_LIST_ENTRY UnusedHead;
	UCHAR pBuffer[];
} NPF_OBJ_SHELF, *PNPF_OBJ_SHELF;

/* Objects in the pool are retrieved and returned using this struct.
 * pObject is an uninitialized array of ulObjectSize bytes.
 */
typedef struct _NPF_OBJ_POOL_ELEM
{
	USHORT idxShelfOffset;
	SINGLE_LIST_ENTRY UnusedEntry;
	ULONG Refcount;
	UCHAR pObject[];
} NPF_OBJ_POOL_ELEM, *PNPF_OBJ_POOL_ELEM;

typedef struct _NPF_OBJ_POOL
{
	SINGLE_LIST_ENTRY EmptyShelfHead;
	SINGLE_LIST_ENTRY PartialShelfHead;
	NDIS_SPIN_LOCK ShelfLock;
	NDIS_HANDLE NdisHandle;
	ULONG ulObjectSize;
	ULONG ulIncrement;
} NPF_OBJ_POOL;

#define NPF_OBJECT_POOL_TAG 'TPON'

#define NPF_OBJ_ELEM_ALLOC_SIZE(POOL) (sizeof(NPF_OBJ_POOL_ELEM) + (POOL)->ulObjectSize)
#define NPF_OBJ_SHELF_ALLOC_SIZE(POOL) ( sizeof(NPF_OBJ_SHELF) + NPF_OBJ_ELEM_ALLOC_SIZE(POOL) * (POOL)->ulIncrement)
#define NPF_OBJ_ELEM_MAX_IDX(POOL) (NPF_OBJ_SHELF_ALLOC_SIZE(pPool) - sizeof(NPF_OBJ_SHELF))

_Ret_maybenull_
PNPF_OBJ_SHELF
NPF_NewObjectShelf(
		_In_ PNPF_OBJ_POOL pPool)
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
		return NULL;
	}
	RtlZeroMemory(pShelf, NPF_OBJ_SHELF_ALLOC_SIZE(pPool));
	pShelf->pPool = pPool;

	// Buffer starts after the shelf itself
	for (i=0; i < pPool->ulIncrement; i++)
	{
		pElem = (PNPF_OBJ_POOL_ELEM) (pShelf->pBuffer + i * NPF_OBJ_ELEM_ALLOC_SIZE(pPool));
		pElem->idxShelfOffset = (USHORT)((PUCHAR) pElem - (PUCHAR) (pShelf->pBuffer));
		PushEntryList(&pShelf->UnusedHead, &pElem->UnusedEntry);
	}

	return pShelf;
}

_Use_decl_annotations_
PNPF_OBJ_POOL NPF_AllocateObjectPool(NDIS_HANDLE NdisHandle, ULONG ulObjectSize, USHORT ulIncrement)
{
	PNPF_OBJ_POOL pPool = NULL;

	pPool = NdisAllocateMemoryWithTagPriority(NdisHandle,
			sizeof(NPF_OBJ_POOL),
		       	NPF_OBJECT_POOL_TAG,
			NormalPoolPriority);
	if (pPool == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(pPool, sizeof(NPF_OBJ_POOL));

	NdisAllocateSpinLock(&pPool->ShelfLock);

	pPool->NdisHandle = NdisHandle;
	pPool->ulObjectSize = ulObjectSize;
	pPool->ulIncrement = ulIncrement;

	return pPool;
}

_Use_decl_annotations_
PVOID NPF_ObjectPoolGet(PNPF_OBJ_POOL pPool)
{
	PNPF_OBJ_POOL_ELEM pElem = NULL;
	PSINGLE_LIST_ENTRY pEntry = NULL;
	PNPF_OBJ_SHELF pShelf = NULL;

	NdisAcquireSpinLock(&pPool->ShelfLock);
	// Get the first partial shelf
	pEntry = pPool->PartialShelfHead.Next;

	// If there are no partial shelves, get an empty one
	if (pEntry == NULL)
	{
		pEntry = pPool->EmptyShelfHead.Next;
		// If there are no empty shelves, allocate a new one
		if (pEntry == NULL)
		{
			pShelf = NPF_NewObjectShelf(pPool);
			// If we couldn't allocate one, bail.
			if (pShelf == NULL)
			{
				NdisReleaseSpinLock(&pPool->ShelfLock);
				return NULL;
			}
			pEntry = &pShelf->ShelfEntry;
		}
		// Now pEntry is an empty shelf. Move it to partials.
		PushEntryList(&pPool->PartialShelfHead, pEntry);
	}

	pShelf = CONTAINING_RECORD(pEntry, NPF_OBJ_SHELF, ShelfEntry);
	pShelf->ulUsed++;
	pEntry = PopEntryList(&pShelf->UnusedHead);
	if (pEntry == NULL)
	{
		// Should be impossible since all tracked shelves are partial or empty
		ASSERT(pEntry != NULL);
		NdisReleaseSpinLock(&pPool->ShelfLock);
		return NULL;
	}
	pElem = CONTAINING_RECORD(pEntry, NPF_OBJ_POOL_ELEM, UnusedEntry);

	// If there aren't any more unused slots on this shelf, unlink it
	if (pShelf->UnusedHead.Next == NULL)
	{
		// We always use the first partial shelf on the stack, so pop it off.
		// No need to keep track of it; Return operation will re-link
		// it into partials.
		PopEntryList(&pPool->PartialShelfHead);
	}

	NdisReleaseSpinLock(&pPool->ShelfLock);

	pElem->Refcount = 1;
	return pElem->pObject;
}

_Use_decl_annotations_
VOID NPF_FreeObjectPool(PNPF_OBJ_POOL pPool)
{
	PSINGLE_LIST_ENTRY pShelfEntry = NULL;

	NdisAcquireSpinLock(&pPool->ShelfLock);

	while ((pShelfEntry = PopEntryList(&pPool->PartialShelfHead)) != NULL)
	{
		NdisFreeMemory(
				CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry),
				NPF_OBJ_SHELF_ALLOC_SIZE(pPool),
				0);
	}
	while ((pShelfEntry = PopEntryList(&pPool->EmptyShelfHead)) != NULL)
	{
		NdisFreeMemory(
				CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry),
				NPF_OBJ_SHELF_ALLOC_SIZE(pPool),
				0);
	}
	NdisReleaseSpinLock(&pPool->ShelfLock);

	NdisFreeSpinLock(&pPool->ShelfLock);
	NdisFreeMemory(pPool, sizeof(NPF_OBJ_POOL), 0);
}

_Use_decl_annotations_
VOID NPF_ObjectPoolReturn(PVOID pObject, PNPF_OBJ_CLEANUP CleanupFunc)
{
	PNPF_OBJ_SHELF pShelf = NULL;
	PNPF_OBJ_POOL pPool = NULL;
	PNPF_OBJ_POOL_ELEM pElem = CONTAINING_RECORD(pObject, NPF_OBJ_POOL_ELEM, pObject);
	ULONG refcount = InterlockedDecrement(&pElem->Refcount);

	if (refcount == 0)
	{
		if (CleanupFunc)
		{
			CleanupFunc(pElem->pObject);
		}
		pShelf = CONTAINING_RECORD((PUCHAR) pElem - pElem->idxShelfOffset, NPF_OBJ_SHELF, pBuffer);
		pPool = pShelf->pPool;
		NdisAcquireSpinLock(&pPool->ShelfLock);

		refcount = InterlockedDecrement(&pShelf->ulUsed);
		if (refcount == 0)
		{
			// Empty shelf. Move it to the other list.
			PSINGLE_LIST_ENTRY pEntry = pPool->PartialShelfHead.Next;
			PSINGLE_LIST_ENTRY pPrev = &pPool->PartialShelfHead;
			while (pEntry)
			{
				if (pEntry == &pShelf->ShelfEntry)
				{
					// Found it. Unlink and stop looking.
					pPrev->Next = pEntry->Next;
					pEntry->Next = NULL;
					break;
				}
				pPrev = pEntry;
				pEntry = pPrev->Next;
			}

			PushEntryList(&pPool->EmptyShelfHead, &pShelf->ShelfEntry);
		}
		else if (refcount == pPool->ulIncrement - 1)
		{
			// This shelf was full and now it's partial. Link it in.
			PushEntryList(&pPool->PartialShelfHead, &pShelf->ShelfEntry);
		}

		PushEntryList(&pShelf->UnusedHead, &pElem->UnusedEntry);

		NdisReleaseSpinLock(&pPool->ShelfLock);
	}
}

_Use_decl_annotations_
VOID NPF_ReferenceObject(PVOID pObject)
{
	PNPF_OBJ_POOL_ELEM pElem = CONTAINING_RECORD(pObject, NPF_OBJ_POOL_ELEM, pObject);

	InterlockedIncrement(&pElem->Refcount);
}
