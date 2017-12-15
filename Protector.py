import ast, sys

def main(file_name):
    with open('./{}'.format(file_name), 'r') as python_file:
        print('{} opened...'.format(file_name))
        with open('./Compiled{}'.format(file_name), 'w') as new_file:
            print('Compiled{} created...'.format(file_name))
            print('{} being read from...'.format(file_name))
            new_file.write(ast.dump(ast.parse(python_file.read())))
            print('Compiled{} being written to...'.format(file_name))
    print('{} closed...'.format(file_name))
    print('Compiled{} closed...'.format(file_name))


if __name__ == '__main__':
    main(sys.argv[1])
