import sys

def main(file_name):
    with open(file_name, 'r') as compiled_file:
        exec(compile(compiled_file.read(), filename='<ast>' mode='exec'))

if __name__ == '__main__':
    main(sys.argv[1])
