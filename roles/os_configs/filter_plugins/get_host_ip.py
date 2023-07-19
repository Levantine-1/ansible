# filter_plugins/get_host_ip.py

class FilterModule(object):
    def filters(self):
        return {
            'get_host_ip': self.get_host_ip
        }

    def get_host_ip(self, content, hostname):
        lines = content.splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[-1] == hostname:
                return parts[0]
        return None
