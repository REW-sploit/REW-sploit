"""

Define the constants for Donut code support

Donut: https://github.com/TheWover/donut

"""

#
# This is the list of API used by the donut stub. They may change, these come
# from version 0.9.3 and they are located in "donut.c" file under
#
#     static API_IMPORT api_imports[]=
#

donut_api_imports = [
    b'LoadLibraryA',
    b'GetProcAddress',
    b'GetModuleHandleA',
    b'VirtualAlloc',
    b'VirtualFree',
    b'VirtualQuery',
    b'VirtualProtect',
    b'Sleep',
    b'MultiByteToWideChar',
    b'GetUserDefaultLCID',
    b'WaitForSingleObject',
    b'CreateThread',
    b'GetThreadContext',
    b'GetCurrentThread',
    b'GetCommandLineA',
    b'GetCommandLineW',
    b'CommandLineToArgvW',
    b'SafeArrayCreate',
    b'SafeArrayCreateVector',
    b'SafeArrayPutElement',
    b'SafeArrayDestroy',
    b'SafeArrayGetLBound',
    b'SafeArrayGetUBound',
    b'SysAllocString',
    b'SysFreeString',
    b'LoadTypeLib',
    b'InternetCrackUrlA',
    b'InternetOpenA',
    b'InternetConnectA',
    b'InternetSetOptionA',
    b'InternetReadFile',
    b'InternetCloseHandle',
    b'HttpOpenRequestA',
    b'HttpSendRequestA',
    b'HttpQueryInfoA',
    b'CorBindToRuntime',
    b'CLRCreateInstance',
    b'CoInitializeEx',
    b'CoCreateInstance',
    b'CoUninitialize',
    b'RtlEqualUnicodeString',
    b'RtlEqualString',
    b'RtlUnicodeStringToAnsiString',
    b'RtlInitUnicodeString',
    b'RtlExitUserThread',
    b'RtlExitUserProcess',
    b'RtlCreateUnicodeString',
    b'RtlGetCompressionWorkSpaceSize',
    b'RtlDecompressBuffer',
    b'NtContinue',
    b'AddVectoredExceptionHandler',
    b'RemoveVectoredExceptionHandler'
]
