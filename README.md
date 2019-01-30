# BFV-Decryption

Starting in Battlefield 1 the game developer started to encrypt stuff.<br />
This demo project will show how player-list and pointer decryption can be done.<br />
This is based on information that I reverse engineered from the game.<br />
For decryption the game uses the so-called "DispDispReqMessage" message which also serves the purpose of "hiding" the actual decryption routines.<br />
The decryption can also be done from an external program that is running in a different process with this method.<br />

## Console output
![Demo pic](https://raw.githubusercontent.com/Speedi13/BFV-Decryption/master/ConsoleOutputScreenshot.png)
<br>
[ConsoleOutput.txt](https://github.com/Speedi13/BFV-Decryption/blob/master/ConsoleOutput.txt)

## Note for external cheats
So its 2019 if you still use a shitty external in c# you can do the following:<br />
&nbsp;&nbsp;	Before you join any server make sure your external is running.<br />
&nbsp;&nbsp;	You need to keep the UpdateTimer inside the ObfuscationMgr below 24000<br />
&nbsp;&nbsp;	then the ObfuscationMgr will NEVER activate the sophisticated multiplayer encryption!<br />
&nbsp;&nbsp;	For the singleplayer encryption look the function ``PointerXorSinglePlayer``<br />
```cpp
void TrickObfuscationMgr()
{
	_QWORD pObfuscationMgr = *(_QWORD*)OFFSET_ObfuscationMgr;
	if (!ValidPointer(pObfuscationMgr)) return;

	if ( *(__int64*)( pObfuscationMgr + 0x108 ) != NULL )
		MessageBox( NULL, "u noob! Run ur shit before joining a server!", NULL, 16 );

	//pObfuscationMgr->m_dwUpdateTimer = 0
	*(__int64*)( pObfuscationMgr + 0xF0 ) = 0ui64; 
}
```

## Player-list decryption code
```cpp
fb::ClientPlayer* GetPlayerById( int id )
{
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
fb::ClientPlayer* EncryptedPlayerMgr__GetPlayer( QWORD EncryptedPlayerMgr, int id )
{
	_QWORD XorValue1 = *(_QWORD *)(EncryptedPlayerMgr + 0x20) ^ *(_QWORD *)(EncryptedPlayerMgr + 8);
  
	_QWORD XorValue2 = PointerXor( *(_QWORD *)(EncryptedPlayerMgr + 0x28), *(_QWORD *)(EncryptedPlayerMgr + 0x10) );
  
	_QWORD Player = XorValue1 ^ *(_QWORD *)( XorValue2 + 8 * id);
  
	return (fb::ClientPlayer*)Player;
}
__int64 __fastcall PointerXorMultiplayer(__int64 ValueToXor /*RCX*/, __int64 EncryptedBuffer /*RDX*/, __int64 EncryptedDeviceContext /*R8*/ )
{
	__int64 XorD3D11 = 0xAB541E6F771275BCui64;

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
	return RCX ^ 0x598447EFD7A36912i64;
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

	_QWORD EncryptedBuffer = *(_QWORD *)(pObfuscationMgr + 0x108);
	_QWORD EncryptedDeviceContext = *(_QWORD *)(pObfuscationMgr + 0x110);

	DWORD64 DecryptFunction = ( *(_QWORD *)(pObfuscationMgr + 0xE0) ^ *(_QWORD *)(pObfuscationMgr + 0x100) );
	
	if ( *(bool*)(pObfuscationMgr + 0xEC) != true )
		return (_QWORD)PointerXorSinglePlayer( RDX );
	
	return (_QWORD)PointerXorMultiplayer( RDX, EncryptedBuffer, EncryptedDeviceContext );
}
```

## Pointer decryption code
The pointer key is usually the start address of the class that contains the encrypted pointer
```cpp
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
```
