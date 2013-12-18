
package pidinfo

import (
    "os"
    "io/ioutil"
    "fmt"
    "strconv"
)

type ProcessInfo struct {
    Pid int
    Cmd string
    Args []string
}

func lookupProcess(pid int) ProcessInfo {
    var info ProcessInfo
    info.Pid = pid

    var cmdPath string = fmt.Sprintf("/proc/%d/comm", pid)
    if cmd, err := ioutil.ReadFile(cmdPath); err == nil {
        info.Cmd = string(cmd)
    }
    return info
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

func ScanProcessesForInode(inode int) *ProcessInfo {
    if processes, err := ioutil.ReadDir("/proc"); err == nil {
        for _, value := range(processes) {
            if pid, err := strconv.Atoi(value.Name()); err == nil {
                if scanProcessForInode(inode, pid) {
                    fmt.Printf("inode found in pid %d\n", pid);
                    var processInfo = lookupProcess(pid);
                    return &processInfo
                }
            }
        }
    }
    return nil
}
