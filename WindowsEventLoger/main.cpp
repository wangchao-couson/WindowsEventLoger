#include "GetEventLog.h"
#include <windows.h>
#include <locale>


void main()
{
	std::unique_ptr<GetEventLog> pGetEventLog(new GetEventLog);
	pGetEventLog->GetSpecifyEvents();
	
	system("pause");
}