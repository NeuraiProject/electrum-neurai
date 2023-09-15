from electrum.boolean_ast_tree import parse_boolean_equation

if __name__ == '__main__':

    var_mapping = {
        'A': True,
        'B': False,
    }
    for var in [
        'A',
        'A|B',
        '!(A&B)',
        '(!B&A)',
        '(A&B&B&A)|A|B',
        '!(\n(A&B ) \t | (B&A)|!(A|B))',
        'A|B&B',
        '!((A|B)&B)',
        '!(!B&!A|A&B)',
        'true&A',
        'A&true',
        'B|true',
        'true|B',
        #'B'
    ]:
        node = parse_boolean_equation(var)
        #print(node)
        assert node.evaluate(var_mapping), var
