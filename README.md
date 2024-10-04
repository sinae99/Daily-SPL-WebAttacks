# Daily-SPL-WebAttacks
Some Splunk queries that might be useful for SOC daily routine 

spl queries to detect almost every form of these attacks :

XSS , SQLI , DirectoryTraversal


--------------------------------------------------------------------------------------------------------------------------------------------------------

### XSS
```
index="your index name" 
http_user_agent IN ("%3C", "%3E", "%27", "%23", "%4F", "%22", "%3B", "%25", "*<script>*", "+","!", "[", "]", "*script*", "*javascript:*", "'", "*‘*" ,"<*>" ,"&#" , "%3C" , "&lt", "\\x3c", "*&#X0*", "*onfocus*" ,"*onload*", "\\u003c" , "\\00" ,"*onerror*" ,"*alert*", "*al\145rt*", "*al\x65rt*", "*al\u0065rt*" , "&lt", "&lt;", "*top[*", "*%3cscript*", "*%3ealert*" , "*toString*", "\x3c" , "\x3C", "\u003c" ,"\u003C", "&LT;" ,"&#60" )
OR
 httpRequest.requestUrl IN("%3C" ,"%3E", "%27" ,"*alert*", "%23" ,"%4F" ,"%22", "%3B", "%25", "<script>", "+", "!", "[", "]" ,"*script*" ,"*javascript:*", "'" ,"*‘*" , "<*>" ,"&#" , "%3C", "&lt" , "\\x3c", "*&#X0*", "\\u003c", "\\00", "*onerror*" ,"*alert*", "*al\145rt*" ,"*al\x65rt*", "*al\u0065rt*" , "*onfocus*" ,"*onload*", "&lt", "&lt;" ,"*top[*" ,"*toString*", "\x3c" ,"*%3cscript*", "*%3ealert*", "\x3C" ,"\u003c", "\u003C", "&LT", "&LT;" ,"&#60" )
 OR
 http_referrer IN("%3C", "%3E" ,"%27", "%23", "%4F" ,"%22" , "%3B", "%25" , "<script>" , "+", "!" ,"[", "]", "*script*", "*javascript:*", "'", "*‘*" ,"<*>", "&#" , "%3C" , "&lt" , "\\x3c", "*alert*" ,"*&#X0*", "*onfocus*", "*onload*" ,"\\u003c", "\\00" ,"*onerror*", "*alert*", "*al\145rt*", "*al\x65rt*", "*al\u0065rt*", "&lt", "&lt;" ,"*top[*" ,"*%3cscript*", "*%3ealert*", "*toString*", "\x3c" , "\x3C", "\u003c", "\u003C" ,"&LT" ,"&LT;", "&#60" ) 
 OR 
url IN("%3C", "%3E" ,"%27", "%23", "%4F" ,"%22" , "%3B", "%25" , "<script>" , "+", "!" ,"[", "]", "*script*", "*javascript:*", "'", "*‘*" ,"<*>", "&#" , "%3C" , "&lt" , "\\x3c", "*alert*" ,"*&#X0*", "*onfocus*", "*onload*" ,"\\u003c" , "\\00" ,"*onerror*", "*alert*", "*al\145rt*", "*al\x65rt*", "*al\u0065rt*", "&lt", "&lt;" ,"*top[*" ,"*%3cscript*", "*%3ealert*", "*toString*", "\x3c" , "\x3C", "\u003c", "\u003C" ,"&LT" ,"&LT;", "&#60" )

 | stats count by src , dest , http_referrer , http_url , http_user_agent , http_method

```

--------------------------------------------------------------------------------------------------------------------------------------------------------

### SQL injection

```
index="your index name"
http_user_agent IN ("*%27*" , "*%27%27*" , "*%27 %27*", "*%22*" ,"*'*" , "*%3B*" , "*%25*" , "*$$*" ,"*sleep*" , "*action=xp_cmdshell*" ,"*select *" , "*union *" , "*concat*" , *union* , "*ascii*" , "*se//lect*" "*ion+se*")
 OR 
 httpRequest.requestUrl IN("*%27*" , "*%27%27*" , "*%27 %27*", "*%22*" ,"*'*" , "*%3B*" , "*%25*" , "*$$*" ,"*sleep*" , "*action=xp_cmdshell*" ,"*select *" , "*union *" , "*concat*" , *union* , "*ascii*" , "*se//lect*" "*ion+se*")
 OR 
 http_referrer IN("*%27*" , "*%27%27*" , "*%27 %27*", "*%22*" ,"*'*" , "*%3B*" , "*%25*" , "*$$*" ,"*sleep*" , "*action=xp_cmdshell*" ,"*select *" , "*union *" , "*concat*" , *union* , "*ascii*" , "*se//lect*" "*ion+se*")
 OR 
 url IN("*%27*" , "*%27%27*" , "*%27 %27*", "*%22*" ,"*'*" , "*%3B*" , "*%25*" , "*$$*" ,"*sleep*" , "*action=xp_cmdshell*" ,"*select *" , "*union *" , "*concat*" , *union* , "*ascii*" , "*se//lect*" "*ion+se*")

 | stats count by src , dest , http_referrer , http_url , http_user_agent , http_method
```
--------------------------------------------------------------------------------------------------------------------------------------------------------

### Directory Traversal

```
index="your index name"
http_user_agent IN ( "*%..\*" , "*..*", "*%2e%2e%2f*" ,"*%uff0e*" , "*%u2216*" , "*%u2215*" , "%c0%2e" ,"*%e0%40%ae*" , "*%c0ae*" ,"%c0%5c*" , "*%c0%80%5c*" , "*..;/*" , "*%252e*" , "*%255c*" , "*///*" , "*\\\*" , "*proc*" , "*var*" , "*%2e*" , "*..%5c*" , "*..%u2215*" , "*%uff0e*" , "*..%uEFC8*" , "*..%uF025*" , "%uff0e*" ,"*..0x2f*" , "*..0x5c*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*.\.*" , "*htaccess*" , "*..%c1%8s*" ,"*..%c1%af*" , "*/\..%2f*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*./.*")
 OR 
 httpRequest.requestUrl IN( "*%..\*" , "*..*", "*%2e%2e%2f*" ,"*%uff0e*" , "*%u2216*" , "*%u2215*" , "%c0%2e" ,"*%e0%40%ae*" , "*%c0ae*" ,"%c0%5c*" , "*%c0%80%5c*" , "*..;/*" , "*%252e*" , "*%255c*" , "*///*" , "*\\\*" , "*proc*" , "*var*" , "*%2e*" , "*..%5c*" , "*..%u2215*" , "*%uff0e*" , "*..%uEFC8*" , "*..%uF025*" , "%uff0e*" ,"*..0x2f*" , "*..0x5c*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*.\.*" , "*htaccess*" , "*..%c1%8s*" ,"*..%c1%af*" , "*/\..%2*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*./.*")
 OR
 http_referrer IN( "*%..\*" , "*..*", "*%2e%2e%2f*" ,"*%uff0e*" , "*%u2216*" , "*%u2215*" , "%c0%2e" ,"*%e0%40%ae*" , "*%c0ae*" ,"%c0%5c*" , "*%c0%80%5c*" , "*..;/*" , "*%252e*" , "*%255c*" , "*///*" , "*\\\*" , "*proc*" , "*var*" , "*%2e*" , "*..%5c*" , "*..%u2215*" , "*%uff0e*" , "*..%uEFC8*" , "*..%uF025*" , "%uff0e*" ,"*..0x2f*" , "*..0x5c*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*.\.*" , "*htaccess*" , "*..%c1%8s*" ,"*..%c1%af*" , "*/\..%2f*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*./.*")
 OR
 url IN( "*%..\*" , "*..*", "*%2e%2e%2f*" ,"*%uff0e*" , "*%u2216*" , "*%u2215*" , "%c0%2e" ,"*%e0%40%ae*" , "*%c0ae*" ,"%c0%5c*" , "*%c0%80%5c*" , "*..;/*" , "*%252e*" , "*%255c*" , "*///*" , "*\\\*" , "*proc*" , "*var*" , "*%2e*" , "*..%5c*" ,, "*..%u2215*" , "*%uff0e*" , "*..%uEFC8*" , "*..%uF025*" , "%uff0e*" ,"*..0x2f*" , "*..0x5c*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*.\.*" , "*htaccess*" , "*..%c1%8s*" ,"*..%c1%af*" , "*/\..%2f*" ,"*0x2e0*" , "*..%c0%2f*" , "*..;/*" , "*%252e*" , "*%255c*" , "*./.*")

 | stats count by src , dest , http_referrer , http_url , http_user_agent , http_method

```
dont forget to tune these queries based on your company


thanks to  my dear teacher [Sina Mohebi](www.sinamohebi.com)



