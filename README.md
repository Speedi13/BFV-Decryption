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
  
	_QWORD XorValue2 = sub_1416F4410( *(_QWORD *)(EncryptedPlayerMgr + 0x28), *(_QWORD *)(EncryptedPlayerMgr + 0x10) );
  
	_QWORD Player = XorValue1 ^ *(_QWORD *)( XorValue2 + 8 * id);
  
	return (fb::ClientPlayer*)Player;
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
_QWORD __fastcall sub_1416F51D0(_QWORD RCX )
{
	return RCX ^ (_QWORD)(0x598447EFD7A36912);
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
```
