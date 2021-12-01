bool SetHideMachineSIMBIOS()
	{
#define WMI_PATH L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\"

		bool Status = false;
		bool HideMachineFound = false;

		UNICODE_STRING DestinationString;
		OBJECT_ATTRIBUTES ObjectAttributes;
		ULONG ResultLength;
		void* KeyHandle;

		RtlInitUnicodeString(&DestinationString, TEXT(WMI_PATH "Restrictions"));

		InitializeObjectAttributes(&ObjectAttributes, &DestinationString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		if (!NT_SUCCESS(ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes))) //Failed to find "Restrictions" so attempt to create it.
		{
			if (!NT_SUCCESS(ZwCreateKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes, NULL, NULL, REG_OPTION_NON_VOLATILE, &ResultLength)))
			{
				return Status;
			}
		}

		RtlInitUnicodeString(&DestinationString, L"HideMachine");

		if (NT_SUCCESS(ZwQueryValueKey(KeyHandle, &DestinationString, KeyValuePartialInformation, NULL, NULL, &ResultLength)))
		{
			return Status;
		}

		PKEY_VALUE_FULL_INFORMATION KeyInfoPool = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePool(NonPagedPool, ResultLength);
		if (!KeyInfoPool)
		{
			return Status;
		}

		if (NT_SUCCESS(ZwQueryValueKey(KeyHandle, &DestinationString, KeyValuePartialInformation, KeyInfoPool, ResultLength, &ResultLength)))
		{
			HideMachineFound = true;
		}

		if (HideMachineFound)
		{
			//Check if HideMachine is set properly!
			if (KeyInfoPool->Type != REG_DWORD || KeyInfoPool->DataOffset != 4 || KeyInfoPool->DataLength != 1)
			{
				if (!NT_SUCCESS(ZwDeleteValueKey(KeyHandle, &DestinationString)))
				{
					return Status;
				}

				HideMachineFound = false;
			}
		}

		ExFreePool(KeyInfoPool);

		if (!HideMachineFound)
		{
			PULONG HideMachinePool = (PULONG)ExAllocatePool(NonPagedPool, sizeof(ULONG));
			if (HideMachinePool)
			{
				*HideMachinePool = 1;

				//Activate HideMachine
				if (NT_SUCCESS(ZwSetValueKey(KeyHandle, &DestinationString, NULL, REG_DWORD, HideMachinePool, sizeof(ULONG))))
				{
					Status = true;
				}

				ExFreePool(HideMachinePool);
			}
		}

		if (KeyHandle)
		{
			ZwClose(KeyHandle);
		}

		return Status;
	}
