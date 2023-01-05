# 一个代理小工具
## 简介
一个自定义代理工具，可以根据要求修改请求和响应中的字段，也可以根据要求保存一些请求和响应包。（后续还想加一些功能，做的更完善一点）

## 说明
### 使用方法：
`xproxy.exe [-listen :8082] [-config config.yaml]`

### 配置文件说明
具体`config.yaml`配置项有空再写

## 参考项目
- 代理部分参考[https://github.com/ouqiang/goproxy](https://github.com/ouqiang/goproxy)
- 带通配符的字符串匹配参考[https://blog.csdn.net/weixin_39678570/article/details/123114159](https://blog.csdn.net/weixin_39678570/article/details/123114159)
- 子网掩码的ip段匹配参考[https://blog.csdn.net/insist100/article/details/90475424](https://blog.csdn.net/insist100/article/details/90475424)
- 配置文件部分参考`xray`

## feature（可能不做了）
- [ ] 做一些简单的越权数据包重放，保存返回结果用于判断是否存在越权
- [ ] 支持`xray`的`poc`
- [ ] 参考`burpsuite`加个`web`页面支持手动修改请求和响应包
- [ ] 支持`websocket`
- [ ] 其他想到了再补充