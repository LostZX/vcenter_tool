# vcenter tools
哥斯拉 vcenter后渗透插件

暂时支持支Linux，因为没windows测试环境，也没碰见过vc是windows的

## ldap添加用户

可能会出现密码强度问题，重新加一遍就行了

ldap_add: Constraint violation (19)
additional info: Password strength check

参考 https://github.com/3gstudent/Homework-of-Python/blob/master/vCenterLDAP_Manage.py

修复一个bug 如果密码中有反引号在webshell命令行模式下会报错 

![ldap.png](img%2Fldap.png)

## esxi解密

https://github.com/shmilylty/vhost_password_decrypt


![esxi.png](img%2Fesxi.png)

## saml登录

先放着，有空看下咋提取证书的

https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/

