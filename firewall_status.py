import subprocess as sp 



class Firewall:
    def __init__(self):
        self.cmd = "ufw status verbose"
    
    def get_status_verbose(self) -> str:
        process = sp.run([self.cmd], text=True, shell=True, capture_output=True)
        output = process.stdout.strip() or process.stderr.strip()
        return output 
    
    