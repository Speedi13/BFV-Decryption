#pragma once
#include <Windows.h>

#define OFFSET_CLIENTGAMECONTEXT 0x1443FEC80
#define OFFSET_ObfuscationMgr 0x1440BBA90

#define ValidPointer( pointer ) ( pointer != NULL && (DWORD_PTR)pointer >= 0x10000 && (DWORD_PTR)pointer < 0x000F000000000000 /*&& some other checks*/ )

extern DWORD OFFSET_PredictedController;
void* DecryptPointer( DWORD64 EncryptedPtr, DWORD64 PointerKey );

namespace fb
{	

	template< class T >
	struct WeakToken
	{
		T* m_realptr; //its value is: realptr + 8
		DWORD32 m_refcount;
	};
	template< class T > 
	class WeakPtr
	{
	private:
		WeakToken<T>* m_ptr;
	public:
		T* GetData() // << the function in question
		{
			if (!ValidPointer( m_ptr ))
    				return NULL;

			if (!ValidPointer( &m_ptr->m_realptr ))
    				return NULL;
     
			T* ptr = m_ptr->m_realptr;
			if (!ValidPointer(ptr) )
    				return NULL;
     
			return (T*)((DWORD_PTR)(ptr) - 0x8);
		}
	};

	template< class T > class EncryptedPtr
	{
	public:
		DWORD64 m_encryptedPtr;
		DWORD64 m_pointerKey;

	public:
		T* GetPtr( )
		{
			return (T*)( DecryptPointer( this->m_encryptedPtr, (DWORD64)(this->m_pointerKey) ) );
		}
	};

	struct Vec4 { union {float v[4]; struct {float x;float y;float z;float w;}; }; };
	struct Matrix4x4 { union {Vec4 v[4]; float m[4][4]; struct {Vec4 right;Vec4 up;Vec4 forward;Vec4 trans;}; }; };
	typedef Matrix4x4 LinearTransform;

	class ClientPlayerManager
	{
	public:

	};

	class ClientGameContext
	{
	public:
		char _0x0000[0x20];
		ClientPlayerManager* m_playerManager; //0x0020 
		char _0x0028[0x40];
		ClientPlayerManager* m_clientPlayerManager; //0x0068 

		static ClientGameContext* GetInstance()
		{
			return *(ClientGameContext**)(OFFSET_CLIENTGAMECONTEXT);
		}
	};

	class ClientSoldierPrediction
	{
	public:
		void* vtable;
		void* m_characterPhyEntity; //0x0008 
		char _0x0010[128];
		Vec4 m_Position; //0x0090 
	};

	class ClientSoldierEntity
	{
	public:
		EncryptedPtr<ClientSoldierPrediction> GetPredictedController()
		{
			return *(EncryptedPtr<ClientSoldierPrediction>*)( (DWORD_PTR)this + OFFSET_PredictedController );
		};

		void GetTransform( LinearTransform* OutMatrix )
		{
			DWORD_PTR m_collection = *(DWORD_PTR *)( (DWORD_PTR)this  + 0x38);
			unsigned __int8 _9 = *(unsigned __int8 *)(m_collection + 9);
			unsigned __int8 _10 = *(unsigned __int8 *)(m_collection + 10);

			DWORD_PTR ComponentCollectionOffset = 0x20 * (_10 + (2 * _9) );

			*(LinearTransform *)OutMatrix = *(LinearTransform *)(m_collection + ComponentCollectionOffset + 0x10);
		}
	};

	class ClientPlayer
	{
	public:
		virtual ~ClientPlayer();
		virtual DWORD_PTR GetCharacterEntity(); //=> ClientSoldierEntity + 0x268 
		virtual DWORD_PTR GetCharacterUserData(); //=> PlayerCharacterUserData
		virtual class EntryComponent* GetEntryComponent();
		virtual bool InVehicle();
		virtual unsigned int getId();

		ClientSoldierEntity* GetSoldier()
		{
			DWORD_PTR* vtable = *(DWORD_PTR**)this;
			if ( (DWORD_PTR)vtable < 0x140000000 || (DWORD_PTR)vtable > 0x14FFFFFFF ) return nullptr;

			static DWORD SoldierOffset = NULL;
			if (SoldierOffset == NULL)
			{
				BYTE* fncGetCharacterEntity = (BYTE*)vtable[1]; 
				if ( (DWORD_PTR)fncGetCharacterEntity < 0x140000000 || (DWORD_PTR)fncGetCharacterEntity > 0x14FFFFFFF ) return nullptr;

				if (fncGetCharacterEntity[0] == 0xE9) //a jump, resolve it
				{
					__int32 Offset = *(__int32*)&fncGetCharacterEntity[1];
					fncGetCharacterEntity = &fncGetCharacterEntity[1] + Offset + sizeof(__int32);
				}
				SoldierOffset = *(DWORD*)&fncGetCharacterEntity[3]; //48 8B 81 38 1D 00 00	mov     rax, [rcx+1D38h]
			}
			WeakPtr<ClientSoldierEntity> m_soldier = *(WeakPtr<ClientSoldierEntity>*)( (DWORD_PTR)this + SoldierOffset ) ;

			return m_soldier.GetData();
		}

		char _0x0008[16];
		char* m_pName; //0x0018 
		char _0x0020[32];
		char szName[16]; //0x0040 
	};
};
