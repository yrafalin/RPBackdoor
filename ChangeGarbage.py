#!/usr/bin/env python3
#FOR PYTHON 3
import sys, os, tempfile, random


def main(arguments):
    print(sys.argv)
    with tempfile.TemporaryFile(mode='w+') as temp_program:
        with open(sys.argv[2] if sys.argv[1] == 'open' else sys.argv[1], 'r') as orig_program:
            to_write = orig_program.read()
            if 'GARBAGE = ' in to_write:
                to_write = to_write[:to_write.index('GARBAGE = ') + 10] + str(random.randint(10000000, 99999999)) + to_write[to_write.index('GARBAGE = ') + 18:]
            temp_program.write(to_write)
        temp_program.seek(0)
        with open(sys.argv[2] if sys.argv[1] == 'open' else sys.argv[1], 'w') as orig_program:
            orig_program.write(temp_program.read())
    if sys.argv[1] == 'open':
        os.system('python3 ' + ' '.join(sys.argv[2:]))

if __name__ == '__main__':
    main(sys.argv)
