#!/usr/bin/env python3
#FOR PYTHON 3
import ast, sys, astor, random, string

class transformer(ast.NodeTransformer):
    def __init__(self):
        self.var_names = {}
    def visit_Name(self, node):
        print(node.id)
        if node.id[:2] == '__':
            return node
        if node.id in self.var_names:
            return ast.Name(id=self.var_names[node.id], ctx=node.ctx)
        else:
            self.var_names[node.id] = ''.join(random.choices(string.ascii_letters, k=8))
            return ast.Name(id=self.var_names[node.id], ctx=node.ctx)
    def visit_arg(self, node):
        if node.arg[:2] == '__':
            return node
        if node.arg in self.var_names:
            return ast.arg(arg=self.var_names[node.arg], annotation=node.annotation)
        else:
            self.var_names[node.arg] = ''.join(random.choices(string.ascii_letters, k=8))
            return ast.arg(arg=self.var_names[node.arg], annotation=node.annotation)
    def visit_Import(self, node):
        for module in node.names:
            print('module', module.name)
            self.var_names[module.name] = module.name
        return node
    def visit_Call(self, node):
        try:
            self.var_names[node.func.id] = node.func.id
        except:
            pass
        return node
    def visit_Assign(self, node):
        try:
            print(node.value.func.value)
            print(node.targets.id)
            self.var_names[node.targets.id] = node.targets.id
            return node
        except:
            return node


def main(file_to_change):
    with open(file_to_change, 'r') as orig_program:
        node = ast.parse(orig_program.read())
    print(ast.dump(node))
    to_write = astor.to_source(transformer().visit(node))
    print(ast.dump(node))
    print(to_write)
    with open((file_to_change[:-3]) + 'HashProtected.py', 'w') as new_program:
        new_program.write('#!/usr/bin/env python3\n')
        new_program.write(to_write)
    print('Done')

if __name__ == '__main__':
    main(sys.argv[1])
