# /bin/python
""" System call helper script.
Python script that takes in a list of system calls and compares to the
list of allowed system calls from cape jail. 

**Usage**
provide a `<list>` object in the following format and run `python run compare.py`

>>> with open('list', encoding="utf-8") as f:
...     read_data = f.read()
...     print(read_data)
access
arch_prctl
brk
clock_gettime
clone
close
dup
"""

l = []
with open('list', 'r') as f:
    for line in f:
        l.append("SCMP_SYS(" + line.strip() + ")")

with open('seccomp.c', 'r') as f:
    file = f.read()

for i in l:
    if file.find(i) == -1:
        print(i)