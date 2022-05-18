# Seccomp

## Build and load docker to EC2

```
docker build . -t seccomp && docker save seccomp | gzip | ssh ec2-user@54.174.92.239 docker load
```

## Run on EC2

```
nitro-cli terminate-enclave --all
nitro-cli build-enclave --docker-uri seccomp --output-file seccomp.eif
nitro-cli run-enclave --eif-path seccomp.eif --cpu-count 2 --memory 2000 --debug-mode --attach-console
```

Output:

```
hello world!
seccomp enabled
opening test.txt
[    0.324635] audit: type=1326 audit(1652889593.379:2): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=kernel pid=594 comm="seccomp" exe="/seccomp" sig=31 arch=c000003e syscall=257 compat=0 ip=0x7facd9d37be7 code=0x0
child exited by signal
```
