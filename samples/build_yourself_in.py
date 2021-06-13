# This is not the original source of build yourself in! I made this for demonstration purposes.

import sys

def main():
    print(sys.version)
    for i in range(2):
        try:
            print(">>>", end=" ")
            text = input()
            if '"' in text or "'" in text:
                print("No quotes allowed!")
                return
            exec(text, {'__builtins__': None, 'print':print})
        except Exception as e:
            print(e)

main()
