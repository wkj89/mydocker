```docker pull busybox
docker export -o rootfs.tar $(docker run -d busybox top -b)
注意  rootf要放在本项目里面
mkdir rootfs && tar -xf rootfs.tar -C rootfs/
```
