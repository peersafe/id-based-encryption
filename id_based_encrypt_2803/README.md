------------------全局操作--------------------  
生成域名test.com的master公钥和keystore  
java -jar ibc.jar setup -security 128 -mpk ./test.mpk -keystorage ./test.keystore -domain test.com -password 123456  

---------------test1发送给test2---------------  
生成test1@test.com的私钥和签名文件  
java -jar ibc.jar keyextract -keystorage ./test.keystore -domain test.com -password 123456 -sk ./test1.sk -sks ./test1.sks -id  test1@test.com  

加密文件  
java -jar ibc.jar encrypt -to test2@test.com -mpk ./test.mpk -sks ./test1.sks  -in ./plain.txt -out ./encrypt.txt  

---------------test2解密test1发过来的文件---------------  
生成test2@test.com的私钥和签名文件  
java -jar ibc.jar keyextract -keystorage ./test.keystore -domain test.com -password 123456 -sk ./test2.sk -sks ./test2.sks -id test2@test.com  

解密文件  
java -jar ibc.jar decrypt -sk ./test2.sk  -in ./encrypt.txt -out ./plain.txt -to test2@test.com -from test1@test.com -mpk test.mpk  
