"""Apply native engine limits in a fresh child, avoiding preexec_fn in Qt threads."""
import os
import resource
import sys

if __name__ == '__main__':
    memory, cpu = int(sys.argv[1]), int(sys.argv[2])
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execvpe(sys.argv[3], sys.argv[3:], os.environ)
