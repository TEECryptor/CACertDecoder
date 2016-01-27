#pragma once

template<typename T>
class MemoryBlock
{
public:
	MemoryBlock(void) : _ulSize(0), _ptr(0), _isAttached(false) {}
	MemoryBlock(ULONG ulSize)
		: _ulSize(ulSize)
		, _ptr(0)
		, _isAttached(false) {
			if (ulSize > 0)
			{
				_ptr = new T[ulSize];
				ZeroMemory(_ptr, sizeof(T) * ulSize);
			}
	}

	MemoryBlock(const MemoryBlock<T>& rhsMemoryBlock)
		: _ulSize(0)
		, _ptr(0)
		, _isAttached(false)

	{
		if (rhsMemoryBlock._ulSize == 0 || rhsMemoryBlock._ptr == NULL)
			return;

		_ptr = new T[rhsMemoryBlock._ulSize];
		if (_ptr == 0)
			return;
		_ulSize = rhsMemoryBlock._ulSize;
		memcpy_s(_ptr, sizeof(T) * _ulSize, rhsMemoryBlock._ptr, sizeof(T) * _ulSize);
	}

	virtual ~MemoryBlock(void) {
		if (_ptr != 0 && !_isAttached)
			delete[] _ptr;
		_ptr = 0;
	}

protected:
	ULONG _ulSize;
	T* _ptr;
	bool _isAttached;

public:
	// Get address of memory block
	T* GetPtr(void) const
	{
		return _ptr;
	}

	ULONG GetCapacity(void) const
	{
		return _ulSize;
	}

	void Empty()
	{
		if (_isAttached)
			Dettach();

		if (_ptr != 0)
		{
			delete[] _ptr;
			_ptr = 0;
		}

		_ulSize = 0;
	}

	BOOL Allocate(ULONG ulSize)
	{
		if (_isAttached)
			return FALSE;

		Empty();
		if (ulSize == 0)	// equal empty operation
			return TRUE;

		_ptr = new T[ulSize];
		if (_ptr != 0)
		{
			ZeroMemory(_ptr, sizeof(T) * ulSize);
			_ulSize = ulSize;
			return TRUE;
		}
		return FALSE;
	}

	virtual BOOL Reallocate(ULONG ulSize, bool keepOld = true)
	{
		if (_isAttached)
			return FALSE;

		if (ulSize > _ulSize)
		{
			T* ptr = new T[ulSize];
			if (ptr == 0) return FALSE;
			ZeroMemory(ptr, sizeof(T) * ulSize);
			if (keepOld && _ulSize > 0)
			{
				int copySize = (_ulSize < ulSize ? _ulSize : ulSize);
				memcpy_s(ptr, ulSize * sizeof(T), _ptr, copySize * sizeof(T));
			}

			if (_ptr != 0)
				delete[] _ptr;

			_ptr = ptr;
			_ulSize = ulSize;
		}
		else
		{
			if (!keepOld)
				ZeroMemory(_ptr, sizeof(T) * _ulSize);
		}

		return TRUE;
	}

	virtual BOOL Attach(T* p, ULONG ulSize)
	{
		if (_ptr)
			return FALSE;
		_ptr = p;
		_ulSize = ulSize;
		_isAttached = true;
		return TRUE;
	}

	virtual BOOL Dettach()
	{
		if (!_isAttached)
			return FALSE;
		_ptr = 0;
		_ulSize = 0;
		_isAttached = false;
		return TRUE;
	}

	HRESULT ToFile(HANDLE hFile) const
	{
		if (INVALID_HANDLE_VALUE == hFile)
			return E_HANDLE;

		DWORD dwWriten = 0;
		if (!WriteFile(hFile, &(_ulSize), sizeof(ULONG), &dwWriten, NULL))
		{
			return E_FAIL;
		}
		if (!WriteFile(hFile, _ptr, _ulSize * sizeof(T), &dwWriten, NULL))
		{
			return E_FAIL;
		}
		return S_OK;
	}

	HRESULT FromFile(HANDLE hFile)
	{
		if (INVALID_HANDLE_VALUE == hFile)
			return E_HANDLE;

		DWORD dwRead = 0;
		if (!ReadFile(hFile, &_ulSize, sizeof(ULONG), &dwRead, NULL))
			return E_FAIL;
		if (!Allocate(_ulSize) || _ptr == NULL)
			return E_OUTOFMEMORY;

		if (!ReadFile(hFile, _ptr, sizeof(T) * _ulSize, &dwRead, NULL))
			return E_FAIL;

		return S_OK;
	}

	MemoryBlock<T>& operator = (const MemoryBlock<T>& rhsBlock) throw()
	{
		if (rhsBlock._ulSize != 0 && rhsBlock._ptr != NULL)
		{
			_ptr = new T[rhsBlock._ulSize];
			if (_ptr != 0)
			{
				_ulSize = rhsBlock._ulSize;
				memcpy_s(_ptr, sizeof(T) * _ulSize, rhsBlock._ptr, sizeof(T) * _ulSize);
			}
		}
		return *this;
	}
protected:
	virtual void Assign(const MemoryBlock<T>& rhsBlock)
	{
		if (_isAttached)
			return;

		if (_ptr != rhsBlock._ptr)
		{
			Allocate(rhsBlock._ulSize);
			memcpy_s(_ptr, rhsBlock._ulSize * sizeof(T), rhsBlock._ptr, rhsBlock._ulSize * sizeof(T));
			_ulSize = rhsBlock._ulSize;
		}
	}
};

typedef MemoryBlock<BYTE> DataBlock;

class RingBuffer
{
public:
	RingBuffer(void)
		: pbRead(NULL)
		, pbWrite(NULL)
		, pbBegin(NULL)
		, pbEnd(NULL) {
	}
	~RingBuffer(void){}

private:
	DataBlock m_buffer;
	BYTE* pbRead;
	BYTE* pbWrite;
	BYTE* pbBegin;
	BYTE* pbEnd;

public:
	void SetCapacity(ULONG ulSize)
	{
		if (ulSize == 0)
		{
			m_buffer.Empty();
			pbRead = pbBegin = pbWrite = pbEnd = 0;
			return;
		}
		m_buffer.Allocate(ulSize + 1);	// keep empty for pbWrite;
		pbRead = pbBegin = m_buffer.GetPtr();
		pbWrite = pbRead;
		pbEnd = pbBegin + ulSize;
	}

	ULONG GetCapacity()
	{
		if (m_buffer.GetCapacity() == 0)
			return 0;
		return m_buffer.GetCapacity() - 1;
	}

	ULONG Write(const BYTE* pbData, ULONG cbData)
	{
		if (cbData > GetRemain())
			return 0;

		// block after pw
		ULONG ulBlock1 = pbEnd - pbWrite + 1;
		if (ulBlock1 > GetRemain())	// pbRead == m_buffer.GetPtr()
		{
			/* sketch map
			pbBegin											pbEnd
			©°©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©´
			©¦ + ©¦pw ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦pr+©¦ + ©¦
			©¸©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©¼
			*/
			memcpy_s(pbWrite, cbData, pbData, cbData);
			pbWrite += cbData;
		}
		else
		{
			/* sketch map
			pbBegin											pbEnd
			©°©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©´
			©¦   ©¦pr+©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦pw ©¦   ©¦
			©¸©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©¼
			*/
			if (cbData < ulBlock1)
			{
				memcpy_s(pbWrite, cbData, pbData, cbData);
				pbWrite += cbData;
			}
			else
			{
				memcpy_s(pbWrite, ulBlock1, pbData, ulBlock1);
				// 2nd block
				ULONG ulBlock2 = cbData - ulBlock1;
				if (ulBlock2)
					memcpy_s(m_buffer.GetPtr(), ulBlock2, pbData + ulBlock1, ulBlock2);
				pbWrite = m_buffer.GetPtr() + ulBlock2;
			}
		}
		return cbData;
	}

	ULONG Read(BYTE* pbData, ULONG cbData)
	{
		if (GetActualSize() == 0)
			return 0;

		ULONG ulRead = cbData;
		if (cbData > GetActualSize())
		{
			ulRead = GetActualSize();
		}

		if (pbWrite > pbRead)
		{
			/* sketch map
			low												heigh
			©°©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©´
			©¦   ©¦pr+©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦ + ©¦pw ©¦   ©¦
			©¸©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©¼
			*/
			memcpy_s(pbData, ulRead, pbRead, ulRead);
			pbRead += ulRead;
		}
		else
		{
			/* sketch map
			pbBegin											pbEnd
			©°©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©Ð©¤©´
			©¦ + ©¦pw ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦   ©¦pr+©¦ + ©¦
			©¸©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©Ø©¤©¼
			*/
			ULONG ulBlock1 = pbEnd - pbRead + 1;
			if (ulBlock1 > ulRead)
			{
				memcpy_s(pbData, ulRead, pbRead, ulRead);
				pbRead += ulRead;
			}
			else
			{
				memcpy_s(pbData, ulBlock1, pbRead, ulBlock1);
				ULONG ulBlock2 = ulRead - ulBlock1;
				if (ulBlock2)
					memcpy_s(pbData + ulBlock1, ulBlock2, pbBegin, ulBlock2);
				pbRead = pbBegin + ulBlock2;
			}
		}
		return ulRead;
	}

	ULONG GetActualSize()
	{
		if (pbRead <= pbWrite)
			return pbWrite - pbRead;
		else
			return pbWrite + m_buffer.GetCapacity() - pbRead;
	}

	ULONG GetRemain()
	{
		return GetCapacity() - GetActualSize();
	}
};
