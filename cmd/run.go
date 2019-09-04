/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"math/rand"
	"mydocker/cgroups"
	"mydocker/cgroups/subsystems"
)

var (
	endpoint, mem, containerName string
	command                      []string
	initCommand, term            bool
	runUser                      int
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "A brief description of your command",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		if initCommand == true {
			log.Printf("child pid is %d \n", os.Getpid())

			//args[0] 是endpoit 1是mount的overlay挂在地址，2: 是cmd参数列表
			//rootfs := filepath.Join(pwd, "rootfs")
			if err := pivotRoot(args[1]); err != nil {
				log.Fatalf("Error running pivot_root - %s\n", err)
			}
			log.Printf("change rootfs sucess")

			err := syscall.Sethostname([]byte("mydocker"))
			if err != nil {
				log.Println("err when change hostname")
			}

			log.Printf("endpoint is %s , cmd list is %+v ", args[0], args[2:])
			endpoint := args[0]
			endpointPath, err := exec.LookPath(endpoint)
			log.Printf("endpoint path is %s", endpointPath)
			if err != nil {
				log.Fatalf("no such endpoint file  %s \n", endpoint)
			}
			err = syscall.Exec(endpointPath, append([]string{endpointPath}, args[2:]...), os.Environ())
			if err != nil {
				log.Printf("err when exec user's cmd ,err %s ", err.Error())
			}

		} else {
			pid := os.Getpid()
			log.Printf("father pid is %d \n", pid)
			if containerName == "" {
				containerID := randStringBytes(10)

				containerName = containerID
			}
			log.Printf("containerName is %s", containerName)

			CreateWriteLayer(containerName)
			CreateMountPoint(containerName)
			pwd, _ := os.Getwd()
			mntDir := filepath.Join(pwd, "mnt", containerName)

			cmd := exec.Command("/proc/self/exe", append([]string{"run", "--init", endpoint, mntDir}, command...)...)
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS
			//Credential holds user and group identities to be assumed by a child process started by StartProcess.
			//cmd.SysProcAttr.Credential = &syscall.Credential{
			//	Uid: 31,
			//	Gid: 31,
			//}
			//  新内核已经不使用这个https://github.com/xianlubird/mydocker/issues/3
			curuser, _ := user.Current()

			uid, _ := strconv.Atoi(curuser.Uid)

			gid, _ := strconv.Atoi(curuser.Gid)
			//if runUser != 0 {
			//	uid, gid = runUser, runUser
			//}
			cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}}
			cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: gid, Size: 1}}
			if term == true {
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
			}

			if err := cmd.Start(); err != nil {
				log.Fatalf("ERROR when exec myself to init docker %s", err)
			}
			cgroupManager := cgroups.NewCgroupManager(containerName)
			//defer cgroupManager.Destroy() //如果进程还存在会无法删除对应的cgroup，提示权限不足
			res := subsystems.ResourceConfig{MemoryLimit: mem}
			cgroupManager.Set(&res)
			log.Printf("child's pid is %d", cmd.Process.Pid)

			cgroupManager.Apply(cmd.Process.Pid)
			if term == true {
				cmd.Wait()

			}
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringVarP(&endpoint, "endpoint", "e", "", "endpoint like /bin/ls")
	runCmd.Flags().StringVar(&mem, "mem", "", "memery in bytes")
	runCmd.Flags().IntVar(&runUser, "user", 0, "run as user")
	runCmd.Flags().StringVarP(&containerName, "name", "n", "", "container name")

	runCmd.Flags().StringSliceVarP(&command, "command", "c", []string{}, `cmd like "/"`)
	runCmd.Flags().BoolVar(&initCommand, "init", false, "should NOT USE by user")
	runCmd.Flags().BoolVarP(&term, "term", "t", true, "should offer term or not")

}

func pivotRoot(root string) error {
	defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV

	source := "proc"
	target := filepath.Join(root, "/proc")
	fstype := "proc"

	mountErr := syscall.Mount(source, target, fstype, uintptr(defaultMountFlags), "")
	if mountErr != nil {
		log.Printf("mount err %s", mountErr)
	}

	// "new_root and put_old must not be on the same filesystem as the current root"
	if err := syscall.Mount(root, root, "bind", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("Mount rootfs to itself error: %v", err)
	}
	//// create rootfs/.pivot_root as path for old_root
	pivotDir := filepath.Join(root, ".pivot_root")
	if _, err := os.Stat(pivotDir); os.IsNotExist(err) {
		if err := os.Mkdir(pivotDir, 0777); err != nil {
			return err
		}
	}
	//
	//// pivot_root to rootfs, now old_root is mounted in rootfs/.pivot_root
	//// mounts from it still can be seen in `mount`
	if err := syscall.PivotRoot(root, pivotDir); err != nil {
		return err
	}

	//defaultMountFlags := syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV
	//mountErr := syscall.Mount("proc", "/proc","proc", uintptr(defaultMountFlags), "")
	// 网上教程写的是"proc", "/proc","proc"，如果这样写的话，mount proc只能放在这里，因为mount的是宿主机的proc目录，
	// 现在还没有umount 宿主机的根目录，所以可以mount，放在后面就会err 或者使用上面的写法
	//if mountErr != nil {
	//	log.Printf("mount err %s", mountErr)
	//}

	// change working directory to /
	// it is recommendation from man-page
	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / %v", err)
	}
	// path to pivot root now changed, update
	pivotDir = filepath.Join("/", ".pivot_root")
	// umount rootfs/.pivot_root(which is now /.pivot_root) with all submounts
	// now we have only mounts that we mounted ourselves in `mount`
	if err := syscall.Unmount(pivotDir, syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount pivot_root dir %v", err)
	}

	// remove temporary directory
	//return os.Remove(pivotDir)
	return nil
}

func cleanMntDir(containerName string) {
	pwd, _ := os.Getwd()

	mntURL := filepath.Join(pwd, "mnt", containerName)

	if err := syscall.Unmount(mntURL, syscall.MNT_DETACH); err != nil {
		log.Printf("unmount pivot_root dir %v", err)
	}
	writeURL := filepath.Join(pwd, "write", containerName)
	os.RemoveAll(writeURL)
	os.RemoveAll(mntURL)
	workURL := filepath.Join(pwd, "work", containerName)
	os.RemoveAll(workURL)

}

func randStringBytes(n int) string {
	letterBytes := "1234567890"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func CreateWriteLayer(containerName string) {
	pwd, _ := os.Getwd()
	writeURL := filepath.Join(pwd, "write", containerName)
	if err := os.MkdirAll(writeURL, 0777); err != nil {
		log.Fatalf("Mkdir write layer dir %s error. %v", writeURL, err)
	}
}

func CreateMountPoint(containerName string) error {
	pwd, _ := os.Getwd()

	tmpWriteLayer := filepath.Join(pwd, "write", containerName)
	mntUrl := filepath.Join(pwd, "mnt", containerName)

	workUrl := filepath.Join(pwd, "work", containerName)
	if err := os.MkdirAll(workUrl, 0777); err != nil {
		log.Fatalf("workUrl write layer dir %s error. %v", workUrl, err)
	}

	if err := os.MkdirAll(mntUrl, 0777); err != nil {
		//创建联合挂载点
		log.Fatalf("Mkdir mountpoint dir %s error. %v", mntUrl, err)
		return err
	}
	tmpImageLocation := filepath.Join(pwd, "rootfs")
	//https://blog.csdn.net/TSZ0000/article/details/83863504
	//userV:= filepath.Join(pwd, "userV")
	// 不支持多层lowerdir  upperdir https://stackoverflow.com/questions/31044982/how-to-use-multiple-lower-layers-in-overlayfs
	option := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", tmpImageLocation, tmpWriteLayer, workUrl)
	log.Printf("option is %s", option)
	//如果提示未知的filesystem看内核是否支持overlay，支持的话加载overlay模块
	//modinfo overlay
	//modprobe overlay

	_, err := exec.Command("mount", "-t", "overlay", "overlay", "-o", option, mntUrl).CombinedOutput()
	if err != nil {
		log.Fatalf("Run command for creating mount point failed %v", err)
		return err
	}
	return nil
}
