
package pidinfo

import (
    "os"
    "io/ioutil"
    "flag"
    "fmt"
    "bytes"
    "bufio"
    "strconv"
    "net"
)

type Conn struct {
    src net.IP
    src_port int
    dst net.IP
    dst_port int
}

type ProcessInfo struct {
    pid int
    cmd string
    args []string
}

type ConnInfo struct {
    conn Conn
    inode int
    processInfo ProcessInfo
}

func (a *Conn) match(b *Conn) bool {
    if (a.src.Equal(b.src) &&
        a.dst.Equal(b.dst) &&
        a.src_port == b.src_port &&
        a.dst_port == b.dst_port) {
        return true;
    }
    return false;
}

func lookupProcess(pid int) ProcessInfo {
    var info ProcessInfo
    info.pid = pid

    var cmdPath string = fmt.Sprintf("/proc/%d/comm", pid)
    if cmd, err := ioutil.ReadFile(cmdPath); err == nil {
        info.cmd = string(cmd)
    }
    return info
}

func parseLine(line string) ConnInfo {
    var entry ConnInfo
    var src, src_port, dst, dst_port, index, garbage, inode int

    //                 sl  local remo  st tx_q  rq_q  re ui ti ino
    fmt.Sscanf(line, " %d: %X:%X %X:%X %X %X:%X %X:%X %X %d %d %d",
        &index, &src, &src_port, &dst, &dst_port,
        &garbage, &garbage, &garbage, &garbage,
        &garbage, &garbage, &garbage, &garbage,
        &inode);

    entry.conn.src = []byte { byte(src & 0xff), byte(src >> 8 & 0xff),
        byte(src >> 16 & 0xff), byte(src >> 24 & 0xff) }
    entry.conn.src_port = src_port;

    entry.conn.dst = []byte { byte(dst & 0xff), byte(dst >> 8 & 0xff),
        byte(dst >> 16 & 0xff), byte(dst >> 24 & 0xff) }
    entry.conn.dst_port = dst_port;
    entry.inode = inode
    return entry
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
                    var processInfo = lookupProcess(pid);
                    return &processInfo
                }
            }
        }
    }
    return nil
}

func lookupTcpConnection(a_conn Conn) int {
    if data, err := ioutil.ReadFile("/proc/net/tcp"); err == nil {
        reader := bytes.NewReader(data)
        scanner := bufio.NewScanner(reader)
        for scanner.Scan() {
            entry := parseLine(scanner.Text())
            if (entry.conn.match(&a_conn)) {
                var info = scanProcessesForInode(entry.inode);
                fmt.Printf("Found in cmd %s (pid = %d)\n", info.cmd,
                    info.pid);
                return entry.inode
            }
        }
    }
    return -1;

}

func printConn(conn Conn) {
    fmt.Printf("%s:%d -> %s:%d\n", conn.src, conn.src_port, conn.dst,
        conn.dst_port);
}

func parseConn(a_src string, a_dst string) Conn {
    var c Conn;
    var src, port string;
    var err error;
    if src, port, err = net.SplitHostPort(a_src); err == nil {
        c.src = net.ParseIP(src);
        c.src_port, err = strconv.Atoi(port);
    }
    if src, port, err = net.SplitHostPort(a_dst); err == nil {
        c.dst = net.ParseIP(src);
        c.dst_port, err = strconv.Atoi(port);
    }
    return c;
}

func main() {
    flag.Parse()
    var src = flag.Arg(0);
    var dst = flag.Arg(1);

    fmt.Printf("Looking up connection %s -> %s\n", src, dst);
    conn := parseConn(src, dst);

    lookupTcpConnection(conn);
}
