#pragma once
#include <windows.h>
#include <string>
#include <winevt.h>
//参考链接：https://docs.microsoft.com/zh-cn/windows/win32/wes/using-windows-event-log

class GetEventLog
{
public:
	//枚举所有指定的日志(XML 字符串作为筛选器)
	void GetSpecifyEvents(const std::wstring& event_channel = L"");
	// Enumerate all the events in the result set.
	DWORD PrintResults(EVT_HANDLE hResults);

private:
	//打印原始XML格式的事件信息
	DWORD PrintEvent(EVT_HANDLE hEvent);
	DWORD PrintEventValues(EVT_HANDLE hEvent);
	void GetCreationTime(LPWSTR creationTime, DWORD creationTimeSize, DWORD serialNumber, PEVT_VARIANT valArray, DWORD sysPropertyCount);

};

