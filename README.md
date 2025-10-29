# PaloAlto_XDR_List_Import

本脚本用于将 PaloAlto XDR 列表导入到 PaloAlto firewall 中。
## 使用方法
运行Python脚本，会弹出GUI界面，根据界面填入相关信息
![alt text](image\Dashboard.png)

1. API对接
    1.1. 生成API权限
    前往XDR控制台，依次点击：
    Settings -> API Keys -> + New Key
    ![alt text](image\Export-Hashlist.png)
    API权限：Advanced -> 需要Edit Allow / Block List 权限

    1.2. 填写API信息
    在GUI界面，填入XDR控制台生成的API Key。添加完后可以选择位置保存API文件供下次使用，文件采用Fernet加密。

2. 导入Allow/Block List 
    2.1. 从平台A迁移到平台B 可以直接前往XDR控制台Export to File
    XDR：Incident Response -> Response -> Action Center -> Allow / Block List
    XSIAM: Investigation & Response -> Response -> Action Center -> Allow / Block List
    ![alt text](image\GEN-API.png)

    2.2. 手动生成tsv文件
    Hash	Status	Comment	Incident ID
    <Hash>	<Enable/Dsiable>	<Comment>	<未开发/未使用>

3. 上传至XDR
    点击“上传到XDR”会出现二次确认，确定上传到Allow List / Block List后就会自动上传。
    任务栏底部会有上传进度

4. 确认结果
    日志文件默认保存在C:\ProgramData\XDR_List_Import\log\
