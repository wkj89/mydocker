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

	"github.com/spf13/cobra"
	"syscall"
	"mydocker/cgroups"
)

var containerPid int

// removeCmd represents the remove command
var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "remove container by name",

	Run: func(cmd *cobra.Command, args []string) {
		remove(containerName)
	},
}

func remove(containerName string) {
	cleanMntDir(containerName)
	syscall.Kill(containerPid,syscall.SIGKILL)
	cgroupManager := cgroups.NewCgroupManager(containerName)
	cgroupManager.Destroy()
}

func init() {
	rootCmd.AddCommand(removeCmd)
	removeCmd.Flags().StringVarP(&containerName, "name",  "n","", "container id to remove")
	removeCmd.Flags().IntVarP(&containerPid, "pid", "p", 0, "containerPid")

}
