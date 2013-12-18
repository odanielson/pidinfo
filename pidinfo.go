// Package pidinfo implements various functions related to PID:s and
// processes.
package pidinfo

import (
    "os"
    "io/ioutil"
    "fmt"
    "strconv"
)

// ProcessInfo contains meta information for a process.
type ProcessInfo struct {
    Pid int
    Cmd string
    Args []string
}

// LookupProcess returns a ProcessInfo reference for process given by pid.
func LookupProcess(pid int) *ProcessInfo {
    var info ProcessInfo
    info.Pid = pid

    var cmdPath string = fmt.Sprintf("/proc/%d/comm", pid)
    if cmd, err := ioutil.ReadFile(cmdPath); err == nil {
        info.Cmd = string(cmd)
    }
    return &info
}

// FindProcessForInode returns a ProcessInfo reference for the process that
// owns the given inode.
func FindProcessForInode(inode int) *ProcessInfo {
    return scanProcessesForInode(inode);
}

func scanProcessForInode(inode, pid int) bool {
    var inodePattern = fmt.Sprintf("socket:[%d]", inode)
    var path = fmt.Sprintf("/proc/%d/fd/", pid);
    if fds, err := ioutil.ReadDir(path); err == nil {
        for _, value := range(fds) {
            if link, err := os.Readlink(path + value.Name()); err == nil {
                if (link==inodePattern) {
                    return true;
                }
            }
        }
    }
    return false;
}

func scanProcessesForInode(inode int) *ProcessInfo {
    if processes, err := ioutil.ReadDir("/proc"); err == nil {
        for _, value := range(processes) {
            if pid, err := strconv.Atoi(value.Name()); err == nil {
                if scanProcessForInode(inode, pid) {
                    fmt.Printf("inode found in pid %d\n", pid);
                    return LookupProcess(pid);
                }
            }
        }
    }
    return nil
}
