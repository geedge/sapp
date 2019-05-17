/* 
 Name        : Iknow
 Author      : lijia@nismail.iie.ac.cn
 Date        : 2014-07-23
 Copyright   : All right reserved by Institute of Engineer,Chinese Academic of Science 2014~2018

 V0.1 20140723 lijia 有此想法, 需求分析, 设想大概功能，初步设计; 
 V0.2 20150620 lijia 初步实现各项基本功能, 内部测试;
 V0.3 20150916 lijia 发布可实际使用的第一个版本;
 V0.4 20150921 lijia 注册回调函数接口增加自定义参数功能, 便于调用者识别控制回调函数.
 V0.5 20160510 lijia 绑定本地端口时如果失败, 则继续重试下一个, 防止多个进程同时运行时经常出现绑定错误.
 */
