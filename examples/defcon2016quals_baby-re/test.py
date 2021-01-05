#!/usr/bin/env python2
# _*_ coding:UTF-8 _*_
import angr


def main():
    project = angr.Project('./test.exe',load_options={'auto_load_libs':False})
    @project.hook(0x411730)
    def print_flag(state):
        print("FLAG SHOULD BE:", state.posix.dumps(0))
        project.terminate_execution()
    project.execute()


if __name__ =='__main__':
    print(repr(main()))
