# WindowsEventloger 

这是一个简单的Demo，用以打印出指定筛选条件的日志信息，本工程已经在win10 64位、VS2019 测试通过，有关系统日志参考：https://docs.microsoft.com/zh-cn/windows/win32/wes/windows-event-log

本例以安全登录审计相关事件为例，简单实现，过滤条件如下：
//登录日志审计参考：https://www.secpulse.com/archives/106858.html
```
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
```
	




