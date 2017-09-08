# trusty_app_demo
这是一个基于android trusty方案的应用demo程序，用于示例CA/TA之间如何基于trusty ipc接口进行通信。

主要模拟的应用点如下：
1. CA/TA之间通信的api使用。
2. trusty storage接口的使用

如何运行：
1.android侧编译，将CA目录下的代码文件编译出可执行文件。该程序用于启用一个linux进程，并通过trusty CA侧ipc接口向TA发送读写命令。
2.TEE app编译，将TA目录下的文件拷贝到trusty编译环境中，编译出tos镜像文件。
3.将1中编译出来的可执行文件push到system/bin下，并赋予可执行权限；将2中编译出来的镜像文件down到手机中。
4.进入adb shell，在其中执行trusty_test；查看打印出来的log信息。