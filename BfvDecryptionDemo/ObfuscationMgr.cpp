#include "ObfuscationMgr.h"

_QWORD __fastcall sub_1416F51D0(_QWORD RCX )
{
	return RCX ^ (_QWORD)(0x598447EFD7A36912);
}
_QWORD __fastcall sub_1416F4410(_QWORD RCX, _QWORD RDX)
{
	//decrypting the function address to call:
	//RAX = ( *(_QWORD *)(RCX + 0xD8) ^ *(_QWORD *)(RCX + 0xF8) )
	//RCX = RDX
	//jmp RAX
	DWORD64 RAX = ( *(_QWORD *)(RCX + 0xD8) ^ *(_QWORD *)(RCX + 0xF8) );
	if (!ValidPointer(RAX)) return NULL;

	if ( RAX > 0x140000000 && RAX < 0x14FFFFFFF )
		return sub_1416F51D0( RDX );
	
	//just to make sure nobody gets confused this function is a window-API
	//https://msdn.microsoft.com/en-us/library/bb432242(v=vs.85).aspx
	return (_QWORD)DecodePointer( (void*)RDX );
}
 
fb::ClientPlayer* EncryptedPlayerMgr__GetPlayer( QWORD EncryptedPlayerMgr, int id )
{
	_QWORD XorValue1 = *(_QWORD *)(EncryptedPlayerMgr + 0x20) ^ *(_QWORD *)(EncryptedPlayerMgr + 8);
	_QWORD XorValue2 = sub_1416F4410( *(_QWORD *)(EncryptedPlayerMgr + 0x28),  // old code: = (XorValue1 ^ *(_QWORD *)(EncryptedPlayerMgr + 0x10));
									  *(_QWORD *)(EncryptedPlayerMgr + 0x10) );
	if (!ValidPointer(XorValue2)) return nullptr;
	_QWORD Player = XorValue1 ^ *(_QWORD *)( XorValue2 + 8 * id);
	return (fb::ClientPlayer*)Player;
}
fb::ClientPlayer* GetPlayerById( int id )
{
	fb::ClientGameContext* pClientGameContext = fb::ClientGameContext::GetInstance();
	if (!ValidPointer(pClientGameContext)) return nullptr;
	fb::ClientPlayerManager* pPlayerManager = pClientGameContext->m_clientPlayerManager;
	if (!ValidPointer(pPlayerManager)) return nullptr;
 
	_QWORD pObfuscationMgr = *(_QWORD*)OFFSET_ObfuscationMgr;
	if (!ValidPointer(pObfuscationMgr)) return nullptr;
 
	_QWORD PlayerListXorValue = *(_QWORD*)( (_QWORD)pPlayerManager + 0xF8 );
	_QWORD PlayerListKey = PlayerListXorValue ^ *(_QWORD *)(pObfuscationMgr + 0xE0 /*old: 0x70*/);
 
	hashtable<_QWORD>* table = (hashtable<_QWORD>*)(pObfuscationMgr + 8 + 8);
	hashtable_iterator<_QWORD> iterator = {0};
 
	hashtable_find(table, &iterator, PlayerListKey);
	if ( iterator.mpNode == table->mpBucketArray[table->mnBucketCount] )
		return nullptr;
	if (!ValidPointer(iterator.mpNode)) return nullptr;
	_QWORD EncryptedPlayerMgr = (_QWORD)iterator.mpNode->mValue.second;
	if (!ValidPointer(EncryptedPlayerMgr)) return nullptr;
 
	_DWORD MaxPlayerCount = *(_DWORD *)(EncryptedPlayerMgr + 0x18);
	if( MaxPlayerCount != 70u || MaxPlayerCount <= (unsigned int)(id) ) return nullptr;
 
	return EncryptedPlayerMgr__GetPlayer( EncryptedPlayerMgr, id );
}
 
fb::ClientPlayer* GetLocalPlayer( void )
{
	fb::ClientGameContext* pClientGameContext = fb::ClientGameContext::GetInstance();
	if (!ValidPointer(pClientGameContext)) return nullptr;
	fb::ClientPlayerManager* pPlayerManager = pClientGameContext->m_clientPlayerManager;
	if (!ValidPointer(pPlayerManager)) return nullptr;
 
	_QWORD pObfuscationMgr = *(_QWORD*)OFFSET_ObfuscationMgr;
	if (!ValidPointer(pObfuscationMgr)) return nullptr;
 
	_QWORD LocalPlayerListXorValue = *(_QWORD*)( (_QWORD)pPlayerManager + 0xF0 );
	_QWORD LocalPlayerListKey = LocalPlayerListXorValue ^ *(_QWORD *)(pObfuscationMgr + 0xE0 /*old: 0x70*/);
 
	hashtable<_QWORD>* table = (hashtable<_QWORD>*)(pObfuscationMgr + 8 + 8);
	hashtable_iterator<_QWORD> iterator = {0};
 
	hashtable_find(table, &iterator, LocalPlayerListKey);
	if ( iterator.mpNode == table->mpBucketArray[table->mnBucketCount] )
		return nullptr;
	if (!ValidPointer(iterator.mpNode)) return nullptr;

	_QWORD EncryptedPlayerMgr = (_QWORD)iterator.mpNode->mValue.second;
	if (!ValidPointer(EncryptedPlayerMgr)) return nullptr;
 
	_DWORD MaxPlayerCount = *(_DWORD *)(EncryptedPlayerMgr + 0x18);
	if( MaxPlayerCount != 1u ) return nullptr;
	
	return EncryptedPlayerMgr__GetPlayer( EncryptedPlayerMgr, 0 );
}

hashtable_iterator<_QWORD> *__fastcall hashtable_find(hashtable<_QWORD>* table, hashtable_iterator<_QWORD>* iterator, _QWORD key)
{  
	unsigned int mnBucketCount = table->mnBucketCount;

	//bfv
	unsigned int startCount = (_QWORD)(key) % (_QWORD)(mnBucketCount);
 
	//bf1
	//unsigned int startCount = (unsigned int)(key) % mnBucketCount;

	hash_node<_QWORD>* node = table->mpBucketArray[ startCount ];
 
	if ( ValidPointer(node) && node->mValue.first ) 
	{
		while ( key != node->mValue.first )
		{
			node = node->mpNext;
			if ( !node || !ValidPointer(node) 
				)
				goto LABEL_4;
		}
		iterator->mpNode = node;
		iterator->mpBucket = &table->mpBucketArray[ startCount ];
	}
	else
	{
LABEL_4:
		iterator->mpNode = table->mpBucketArray[ mnBucketCount ];
		iterator->mpBucket = &table->mpBucketArray[ mnBucketCount ];
	}
	return iterator;
}

void* DecryptPointer( DWORD64 EncryptedPtr, DWORD64 PointerKey )
{
	_QWORD pObfuscationMgr = *(_QWORD*)OFFSET_ObfuscationMgr;
	if (!ValidPointer(pObfuscationMgr))
		return nullptr;
 
	if ( !(EncryptedPtr & 0x8000000000000000) )
		return nullptr; //invalid ptr
 
	_QWORD hashtableKey = *(_QWORD *)(pObfuscationMgr + 0xE0 ) ^ PointerKey;
 
	hashtable<_QWORD>* table = (hashtable<_QWORD>*)( pObfuscationMgr + 0x78 );
	hashtable_iterator<_QWORD> iterator = {};
 
	hashtable_find( table, &iterator, hashtableKey );
	if ( iterator.mpNode == table->mpBucketArray[table->mnBucketCount] ) 
		return nullptr;
	if (!ValidPointer(iterator.mpNode))
		return nullptr;
	_QWORD EncryptionKey = NULL;
 
	_QWORD EncryptionKeyFnc = *(_QWORD *)(pObfuscationMgr + 0xE0 ) ^ *(_QWORD *)(pObfuscationMgr + 0x100);
	if ( EncryptionKeyFnc > 0x140000000 && EncryptionKeyFnc < 0x14FFFFFFF )
		EncryptionKey = sub_1416F51D0( (_QWORD)(iterator.mpNode->mValue.second) );
	else
		EncryptionKey = (_QWORD)DecodePointer( iterator.mpNode->mValue.second );
 
	EncryptionKey ^= (5 * EncryptionKey);
 
	_QWORD DecryptedPtr = NULL;
	BYTE* pDecryptedPtrBytes = (BYTE*)&DecryptedPtr;
	BYTE* pEncryptedPtrBytes = (BYTE*)&EncryptedPtr;
	BYTE* pKeyBytes = (BYTE*)&EncryptionKey;
 
	for (char i = 0; i < 7; i++)
	{
		pDecryptedPtrBytes[i] = ( pKeyBytes[i] * 0x3B ) ^ ( pEncryptedPtrBytes[i] + pKeyBytes[i] );
		EncryptionKey += 8;
	}
	pDecryptedPtrBytes[7] = pEncryptedPtrBytes[7];
 
	DecryptedPtr &= ~( 0x8000000000000000 ); //to exclude the check bit
 
	return (void*)DecryptedPtr;
}
