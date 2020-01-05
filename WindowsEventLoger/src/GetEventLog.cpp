#include "GetEventLog.h"
#include "strsafe.h"
#include <sddl.h>
#include <string>
#include <stdio.h>
#include <locale>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wevtapi.lib")

#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call
//登录日志审计参考：https://www.secpulse.com/archives/106858.html
// Event Log 条件筛选器，这里筛选条件为：安全通道：（Security）,登录类型及说明如下
// 事件ID: 说明
// 4720	创建用户
// 4624	登录成功
// 4625	登录失败
// 4634	注销成功
// 4647	用户启动的注销
// 4672	使用超级用户（如管理员）进行登录
//-------------------------------------
// 登录类型	描述  	                说明
// 2	c（Interactive）         	用户在本地进行登录。
// 7	解锁（Unlock）	            屏保解锁。
// 10	远程交互（RemoteInteractive）	通过终端服务、远程桌面或远程协助访问计算机。

#define EVENT_FILTER \
    L"<QueryList>" \
    L"  <Query Path='Security'>" \
    L"    <Select> "\
	L"		Event/System[EventID=4620 or EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4672] and"\
	L"      Event/EventData[Data[@Name='LogonType']=2 or Data[@Name='LogonType']=7 or Data[@Name='LogonType']=10]"\
    L"    </Select>" \
    L"  </Query>" \
    L"</QueryList>"

void GetEventLog::GetSpecifyEvents(const std::wstring& event_channel /*= L""*/)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hResults = NULL;

	hResults = EvtQuery(NULL, NULL, EVENT_FILTER, EvtQueryChannelPath | EvtQueryReverseDirection);
	if (NULL == hResults)
	{
		status = GetLastError();

		if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
			wprintf(L"The channel was not found.\n");
		else if (ERROR_EVT_INVALID_QUERY == status)
			// You can call the EvtGetExtendedStatus function to try to get 
			// additional information as to what is wrong with the query.
			wprintf(L"The query is not valid.\n");
		else
			wprintf(L"EvtQuery failed with %lu.\n", status);

		goto cleanup;
	}

	PrintResults(hResults);

cleanup:

	if (hResults)
		EvtClose(hResults);
}

DWORD GetEventLog::PrintResults(EVT_HANDLE hResults)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hEvents[ARRAY_SIZE];
	DWORD dwReturned = 0;

	while (true)
	{
		// Get a block of events from the result set.
		if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
		{
			if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
			{
				wprintf(L"EvtNext failed with %lu\n", status);
			}
			goto cleanup;
		}

		// For each event, call the PrintEvent function which renders the
		// event for display. PrintEvent is shown in RenderingEvents.
		for (DWORD i = 0; i < dwReturned; i++)
		{
			PrintEvent(hEvents[i]);
			//writeNextRecord(hEvents[i]);
			if (ERROR_SUCCESS == (status = PrintEventValues(hEvents[i])))
				//if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i])))
			{
				EvtClose(hEvents[i]);
				hEvents[i] = NULL;
			}
			else
			{
				goto cleanup;
			}
		}
	}

cleanup:

	for (DWORD i = 0; i < dwReturned; i++)
	{
		if (NULL != hEvents[i])
			EvtClose(hEvents[i]);
	}

	return status;
}

DWORD GetEventLog::PrintEvent(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = NULL;

	// The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)malloc(dwBufferSize);
			if (pRenderedContent)
			{
				EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
			}
			else
			{
				wprintf(L"malloc failed\n");
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", GetLastError());
			goto cleanup;
		}
	}

	wprintf(L"\n\n%s", pRenderedContent);

cleanup:

	if (pRenderedContent)
		free(pRenderedContent);

	return status;
}

DWORD GetEventLog::PrintEventValues(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	EVT_HANDLE hContext = NULL;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	PEVT_VARIANT pRenderedValues = NULL;
	LPCWSTR ppValues[] = {
		L"Event/System/EventID",
		L"Event/System/TimeCreated/@SystemTime",
		L"Event/System/Computer",
		L"Event/EventData/Data[@Name='LogonType']",
		L"Event/EventData/Data[@Name='ProcessName']",
		L"Event/EventData/Data[@Name='IpAddress']",
		L"Event/EventData/Data[@Name='IpPort']",
	};
	DWORD count = sizeof(ppValues) / sizeof(LPWSTR);

	// Identify the components of the event that you want to render. In this case,
	// render the provider's name and channel from the system section of the event.
	// To get user data from the event, you can specify an expression such as
	// L"Event/EventData/Data[@Name=\"<data name goes here>\"]". 
	//  list all the components of the event use blow way
	//  //Renders event system properties
	// 	EVT_HANDLE renderContext = EvtCreateRenderContext(NULL, 0, EvtRenderContextSystem);
	// 	//Renders event user properties
	// 	EVT_HANDLE renderUserContext = EvtCreateRenderContext(NULL, 0, EvtRenderContextUser);

	do 
	{
		hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
		if (NULL == hContext)
		{
			wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
			break;
		}

		// The function returns an array of variant values for each element or attribute that
		// you want to retrieve from the event. The values are returned in the same order as 
		// you requested them.
		if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
		{
			if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
			{
				dwBufferSize = dwBufferUsed;
				pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
				if (pRenderedValues)
				{
					EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
				}
				else
				{
					wprintf(L"malloc failed\n");
					status = ERROR_OUTOFMEMORY;
					break;
				}
			}

			if (ERROR_SUCCESS != (status = GetLastError()))
			{
				wprintf(L"EvtRender failed with %d\n", GetLastError());
				break;
			}
		}

		wchar_t creationTime[500];
		DWORD creationTimeSize = sizeof(creationTime);

		//creation time	
		GetCreationTime(creationTime, creationTimeSize, 1, pRenderedValues, dwPropertyCount);
		wprintf(L"\nEventID: %6hu\n", (pRenderedValues[0].Type == EvtVarTypeNull) ? 0 : pRenderedValues[0].Int16Val);
		wprintf(L"TimeCreated: %s\n", creationTime);
		wprintf(L"Computer: %s\n", (EvtVarTypeNull == pRenderedValues[2].Type) ? L"" : pRenderedValues[2].StringVal);
		wprintf(L"LogonType: %d\n", (EvtVarTypeNull == pRenderedValues[3].Type) ? 0 : pRenderedValues[3].Int16Val);
		wprintf(L"ProcessName: %s\n", (EvtVarTypeNull == pRenderedValues[4].Type) ? L"" : pRenderedValues[4].StringVal);
		wprintf(L"IpAddress: %s\n", (EvtVarTypeNull == pRenderedValues[5].Type) ? L"" : pRenderedValues[5].StringVal);
		wprintf(L"IpPort: %s\n", (EvtVarTypeNull == pRenderedValues[6].Type) ? L"" : pRenderedValues[6].StringVal);

	} while (false);

	if (hContext)
		EvtClose(hContext);

	if (pRenderedValues)
		free(pRenderedValues);

	return status;
}

void GetEventLog::GetCreationTime(LPWSTR creationTime, DWORD creationTimeSize, DWORD serialNumber, PEVT_VARIANT valArray, DWORD sysPropertyCount)
{
	FILETIME FileTime, LocalFileTime;
	__int64 lgTemp;
	lgTemp = valArray[serialNumber].FileTimeVal;
	FileTime.dwLowDateTime = (DWORD)lgTemp;
	FileTime.dwHighDateTime = (DWORD)(lgTemp >> 32);

	SYSTEMTIME SysTime;
	FileTimeToLocalFileTime(&FileTime, &LocalFileTime);
	FileTimeToSystemTime(&LocalFileTime, &SysTime);
	StringCchPrintfW(creationTime, creationTimeSize, L"%02d/%02d/%02d %02d:%02d:%02d.%06d",
		SysTime.wMonth,
		SysTime.wDay,
		SysTime.wYear,
		SysTime.wHour,
		SysTime.wMinute,
		SysTime.wSecond,
		SysTime.wMilliseconds);
}

