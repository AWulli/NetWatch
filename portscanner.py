import socket
from dataclasses import dataclass 
from functools import lru_cache
from ipaddress import ip_address

import psutil
from ipwhois import IPWhois 

@dataclass(slots=True)
class SocketData:
    protocol: str 
    local_ip: str 
    local_port: int 
    remote_ip: str | None  
    remote_port: int | None 
    status: str 
    role: str 
    pid: int | None 
    process: str | None 


class PortScanner:
    def __init__(self):
        self.socketinfos: list[SocketData] = self.scan_sockets()
    

    def scan_sockets(self) -> list[SocketData]:
        results: list[SocketData] = []
        process_cache: dict[int, str | None] = {}

        for connection in psutil.net_connections(kind="inet"):
            protocol = ("TCP" if connection.type == socket.SOCK_STREAM else "UDP")
            
            local_ip = connection.laddr.ip if connection.laddr else ""
            local_port = connection.laddr.port if connection.laddr else 0
            
            remote_ip = connection.raddr.ip if connection.raddr else None 
            remote_port = connection.raddr.port if connection.raddr else None 

            if protocol == "TCP" and connection.status == psutil.CONN_LISTEN:
                role = "LISTEN"
            elif protocol == "UDP" and not connection.raddr:
                role = "BOUND"
            elif connection.raddr:
                role = "CONNECTED"
            else:
                role = connection.status 
            
            if connection.pid is not None:
                process_cache.setdefault(connection.pid, self.get_process_name(connection.pid),)
                results.append(
                    SocketData(
                        protocol = protocol,
                        local_ip = local_ip,
                        local_port = local_port,
                        remote_ip = remote_ip,
                        remote_port = remote_port,
                        status = connection.status,
                        role = role,
                        pid = connection.pid,
                        process = process_cache.get(connection.pid),
                    )
                )
        return results

    def  get_process_name(self, pid: int | None) -> str | None:
        if pid is None:
            return None
        
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    
if __name__ == "__main__":
    portscanner = PortScanner()
    print(portscanner.socketinfos)

