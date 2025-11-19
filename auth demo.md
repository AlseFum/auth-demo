## 意图

这个demo用于在透明管道中输送内容，并通过多个密码-内容对的形式存储简单的权限信息。

不适用于高速收发的场合

## 核心API形式：

基本就两种，

1. 请求公钥，每个IP限量。这里不需要加密。

```plain
{cmd:"request_public_key"}
```
返回
```plain
{
  pubkey_id:"..."
  value:"..."
}
```
1. 一般请求，差不多都这个形式，但需要使用之前请求的公钥加密

```plain
{
  encrypted:  
  {
    account:"..."
    cmd:"..."
    shortpwd:"..."
    content:"..."
    timestamp:"..."
  }
  pubkey_id:"..."
}
```
返回
```plain
{
  status:...
  value:"..."
}
```
其中的value是用shortpwd对称加密过的，shortpwd明文加密，但毕竟被不对称加密过了，所以毕竟安全。shortpwd会经常更换。同时，使用timestamp防止重放攻击。
shortpwd必须在三分钟内expire

### 注册

cmd="reg"

content=[pwd,nickname]

nickname是不是真有必要我不好说

### 获取

cmd="get"

content=[pwd,(preprocessor)]

preprocessor我不知道能具体怎么整

### 更改

cmd="set"

content=[accountpwd,pwd,content]

content为""就是删除

accountpwd用于控制能不能在accoutn名下写内容

内容会先生成唯一对称key加密一回，再使用内部公私钥加密，这样更换使用的公私钥时，内容并不会直接在内存中出现。

### #关于password

password在服务器解析出来之后，会使用16位盐进行慢哈希。

校验时加上盐进行对比。

### #关于密钥轮换

密钥只存在服务器内部，每个都会有id和热度统计，高热度的会进入轮换名单，所有使用它的内容经过更换之后，删除这个密钥。

### #更新

现在客户端用公钥加密一次就够了

服务器内部使用慢hash


