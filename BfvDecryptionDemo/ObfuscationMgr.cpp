#include "ObfuscationMgr.h"

//In case you don't want to Include the whole directx library
#if !defined(D3DX11_SDK_VERSION)
typedef struct D3D11_MAPPED_SUBRESOURCE
{
	void *pData;
	UINT RowPitch;
	UINT DepthPitch;
} 	D3D11_MAPPED_SUBRESOURCE;
typedef 
enum D3D11_MAP
{
	D3D11_MAP_READ	= 1,
	D3D11_MAP_WRITE	= 2,
	D3D11_MAP_READ_WRITE	= 3,
	D3D11_MAP_WRITE_DISCARD	= 4,
	D3D11_MAP_WRITE_NO_OVERWRITE	= 5
} D3D11_MAP;
struct ID3D11DeviceContext
{
	virtual void Function0(); //
	virtual void Function1(); //
	virtual void Function2(); //
	virtual void Function3(); //
	virtual void Function4(); //
	virtual void Function5(); //
	virtual void Function6(); //
	virtual void Function7(); //
	virtual void Function8(); //
	virtual void Function9(); //
	virtual void Function10(); //
	virtual void Function11(); //
	virtual void Function12(); //
	virtual void Function13(); //
	virtual HRESULT STDMETHODCALLTYPE Map( void *pResource, UINT Subresource, D3D11_MAP MapType, UINT MapFlags, D3D11_MAPPED_SUBRESOURCE *pMappedResource);
	virtual void STDMETHODCALLTYPE Unmap(  void *pResource, UINT Subresource);
};
struct ID3D11Buffer
{
};
#endif

struct ObfuscationMgr
{
	char _0x0000[224];
	__int64 m_E0; //0x00E0 
	char _0x00E8[16];
	__int64 m_DecryptionFunction; //0x00F8
	__int64 m_EncryptedBuffer; //0x0100  		//encrypted ID3D11Buffer*
	__int64 m_EncryptedDeviceContext; //0x0108 	//encrypted ID3D11DeviceContext*
	__int64 m_EncryptedDevice; //0x0110 		//encrypted ID3D11Device*
	__int64 m_D3d11; //0x0118 					//encrypted d3d11.dll
};

__int64 __fastcall PointerXorMultiplayer(__int64 ValueToXor /*RCX*/, __int64 EncryptedBuffer /*RDX*/, __int64 EncryptedDeviceContext /*R8*/ )
{
	__int64 XorD3D11 = 0x2CE4356EA77515AEui64;

	ID3D11DeviceContext* pDeviceContext = (ID3D11DeviceContext*)( EncryptedDeviceContext ^ XorD3D11 );
	ID3D11Buffer* pBuffer = (ID3D11Buffer*)( EncryptedBuffer ^ XorD3D11 );

	D3D11_MAPPED_SUBRESOURCE MappedSubResource = {0};

	HRESULT hResult = pDeviceContext->Map( pBuffer, NULL, D3D11_MAP_READ, NULL, &MappedSubResource );
	if ( !SUCCEEDED(hResult) || !MappedSubResource.pData )
		return ValueToXor;

	__int64 XorKey = *(__int64 *)MappedSubResource.pData;

	pDeviceContext->Unmap( pBuffer, NULL );

	return ValueToXor ^ XorKey;
}

__int64 __fastcall PointerXorSinglePlayer(__int64 RCX )
{
	return RCX ^ 0x598447EFD7A36912ui64;
}

//So its 2019 if you still use a shitty external in c# you can do the following:
//	Before you join any server make sure your external is running.
//	with this code the ObfuscationMgr will NEVER activate the multiplayer encryption!

//pattern: 49 89 E3 49 89 5B 08 49 89 6B 18 49 89 73 20 57 48 83 EC 40 45 31 C9
static BYTE* OFFSET_DecryptPointerMultiplayer = NULL; //0x147D03E00
static BYTE* OFFSET_DecryptPointerMultiplayerJmp = NULL; //0x1415DFB50
void BypassObfuscationMgr()
{
	 
	if ( OFFSET_DecryptPointerMultiplayer == NULL )
	{
		OFFSET_DecryptPointerMultiplayer = FindPattern( (BYTE*)0x140001000, ~0, (BYTE*)"\x49\x89\xE3\x49\x89\x5B\x08\x49\x89\x6B\x18\x49\x89\x73\x20\x57\x48\x83\xEC\x40\x45\x31\xC9","xxxxxxxxxxxxxxxxxxxxxxx");
		for (BYTE* p = (BYTE*)0x140001000; p ; p++)
		{
			if (p[0] != 0xE9) 
				continue;
			BYTE* Fnc = (BYTE*)ResolveRelativePtr( p + 1 );
			if ( Fnc != OFFSET_DecryptPointerMultiplayer )
				continue;
			
			OFFSET_DecryptPointerMultiplayerJmp = p;
			break;
		}
	}
	//place the singleplayer encryption code into the multiplayer encryption function:
	static bool g_bPatchFunction = true;
	if (g_bPatchFunction)
	{
		
		BYTE DecryptSinglePlayer[] = {
			0xC6, 0x44, 0x24, 0x08, 0x12,	//mov     byte ptr [rsp+arg_0], 12h
			0xC6, 0x44, 0x24, 0x09, 0x69,	//mov     byte ptr [rsp+arg_0+1], 69h
			0xC6, 0x44, 0x24, 0x0A, 0xA3,	//mov     byte ptr [rsp+arg_0+2], 0A3h
			0xC6, 0x44, 0x24, 0x0B, 0xD7,	//mov     byte ptr [rsp+arg_0+3], 0D7h
			0xC6, 0x44, 0x24, 0x0C, 0xEF,	//mov     byte ptr [rsp+arg_0+4], 0EFh
			0xC6, 0x44, 0x24, 0x0D, 0x47,	//mov     byte ptr [rsp+arg_0+5], 47h
			0xC6, 0x44, 0x24, 0x0E, 0x84,	//mov     byte ptr [rsp+arg_0+6], 84h
			0xC6, 0x44, 0x24, 0x0F, 0x59,	//mov     byte ptr [rsp+arg_0+7], 59h
			0x48, 0x8B, 0x44, 0x24, 0x08,	//mov     rax, [rsp+arg_0]
			0x48, 0x31, 0xC8,      			//xor     rax, rcx
			0xC3            				//retn
		};

		WriteProcessMemory( INVALID_HANDLE_VALUE, OFFSET_DecryptPointerMultiplayer, DecryptSinglePlayer, 49, NULL );
		g_bPatchFunction = false;
	}
	_QWORD pObfuscationMgr = *(_QWORD*)OFFSET_ObfuscationMgr;
	if (!ValidPointer(pObfuscationMgr)) return;

	//pObfuscationMgr->m_DecryptionFunction = (_QWORD)OFFSET_DecryptPointerMultiplayerJmp  ^ pObfuscationMgr->m_E0;
	*(_QWORD*)(pObfuscationMgr + 0x0F8 ) = (_QWORD)OFFSET_DecryptPointerMultiplayerJmp  ^ *(_QWORD*)(pObfuscationMgr + 0x0E0 );
}

_QWORD __fastcall PointerXor(_QWORD RCX, _QWORD RDX)
{
//original function code from sub_1415780F0
//RAX = ( *(_QWORD *)(RCX + 0xD8) ^ *(_QWORD *)(RCX + 0xF8) )
//RCX = RDX
//RDX = *(_QWORD *)(RCX + 0x100)
//R8  = *(_QWORD *)(RCX + 0x108)
//jmp RAX

	_QWORD pObfuscationMgr = RCX - 8;

	_QWORD EncryptedBuffer = *(_QWORD *)(pObfuscationMgr + 0x108 - 8);
	_QWORD EncryptedDeviceContext = *(_QWORD *)(pObfuscationMgr + 0x110 - 8);

	DWORD64 DecryptFunction = ( *(_QWORD *)(pObfuscationMgr + 0xE0) ^ *(_QWORD *)(pObfuscationMgr + 0x100 - 8) );
	
	//Index: 0 = singleplayer | 1 = MP
	static DWORD64 DecryptionFunctions[2] = {0,0};

	if ( DecryptionFunctions[0] != DecryptFunction &&
		 DecryptionFunctions[1] != DecryptFunction )
	{
		DWORD64 FncCodeAddress = (DWORD64)DecryptFunction;
		if (*(BYTE*)FncCodeAddress == 0xE9)
			FncCodeAddress = (DWORD64)ResolveRelativePtr( (void*)( FncCodeAddress + 1 ) );
		if ( *(WORD*)FncCodeAddress == 0x44C6 ) //Singleplayer
		{
			DecryptionFunctions[0] = DecryptFunction;
		}
		else
			DecryptionFunctions[1] = DecryptFunction;
	}

	bool IsMultiPlayerEncryption = DecryptionFunctions[1] == DecryptFunction;
	if ( IsMultiPlayerEncryption != true || EncryptedBuffer == NULL || EncryptedDeviceContext == NULL )
		return (_QWORD)PointerXorSinglePlayer( RDX );
	
	return (_QWORD)PointerXorMultiplayer( RDX, EncryptedBuffer, EncryptedDeviceContext );
}
 
fb::ClientPlayer* EncryptedPlayerMgr__GetPlayer( QWORD EncryptedPlayerMgr, int id )
{
	_QWORD XorValue1 = *(_QWORD *)(EncryptedPlayerMgr + 0x20) ^ *(_QWORD *)(EncryptedPlayerMgr + 8);
	_QWORD XorValue2 = PointerXor(    *(_QWORD *)(EncryptedPlayerMgr + 0x28),
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
	_QWORD PlayerListKey = PlayerListXorValue ^ *(_QWORD *)(pObfuscationMgr + 0xE0 );
 
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
	_QWORD LocalPlayerListKey = LocalPlayerListXorValue ^ *(_QWORD *)(pObfuscationMgr + 0xE0 );
 
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


	EncryptionKey = PointerXor( (_QWORD)pObfuscationMgr + 8, (_QWORD)(iterator.mpNode->mValue.second) );

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
