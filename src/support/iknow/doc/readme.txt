
/*
	iknow_print()增加level, module参数, 像MESA_runtime_log一样, 
	方便控制日志等级和分模块处理.

	日志显示分为等级和模块分类, 
	首次登陆时, 默认显示所有等级和所有模块, 可通过set level, set module 设置.
	

	命令使用树结构索引, 方便使用table键帮助提示,

	注册命令时不分级别, 靠'空格'或'tab'分割, 理论上可以无限长, 即数的层次无限深;
	如果已有同名命令, 即命令终结在同一个叶子节点, 返回失败.
	也不允许一个命令是另一个命令的子集情况.

	如: "show http url detail", "show http url", 如果都做为两个独立命令, 是不允许的!
	
	
	如果命令有参数, 那么后续的所有字符都作为参数传给cb.
	例命令: set module http on
			自动识别为命令:"set module http"
	 		"on"做为参数, 

	多条命令之间用';'分割, 可以一次性执行多条命令:
	show http bps; show http pps; show http url num...


	命令后跟'!'表示命令结束后, TCP连接也立即关闭, 方便管道重定向, 如:
	iknow -i 127.0.0.1 -p 14723 show bps! > xxx.log
	基于密码验证方式:
	iknow -i 127.0.0.1 -p 14723 -k 123456 show bps! > xxx.log

	命令未输完时, 按tab键, 自动查询已输入的字母开头所有的命令;
	命令已输完且有空格, 按tab键, 自动查询本命令下一级可用命令或参数, 或者提示无此命令.


	打开全局刷屏后, 
	终端的ctrl+c 信号被捕获, 表示全局刷屏时停止, 不再表示退出终端的意思, 只能靠exit退出.
	在信号处理函数中, 自动发送off命令给服务器端.
	也可以手动输入"off", 关闭全局打印开关.

	关于帮助信息:
	module ?
	即可以直接输入模块名, 如http,
	也可以输入下一级命令, add, del等.
	显示成这样:
	#module ?
	args:
		xxx	set this module name
	sub cmd:
		add	add module name
		del	del module name

*/

