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
https://github.com/Speedi13/BFV-Decryption/blob/master/BfvDecryptionDemo/ObfuscationMgr.cpp

## Pointer decryption code
The pointer key is usually the start address of the class that contains the encrypted pointer
```cpp
void* DecryptPointer( DWORD64 EncryptedPtr, DWORD64 PointerKey )
{
	_QWORD pObfuscationMgr = (_QWORD)OFFSET_ObfuscationMgr;
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
