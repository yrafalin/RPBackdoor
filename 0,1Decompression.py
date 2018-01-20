#!/usr/bin/env python3
# FOR PYTHON 3
import sys

#def previous_delimiters(prior_text, delimiter):  # I thought this could be helpful in decoding the index
#    delimiter_previously = 0
#    for letter in prior_text:
#        if letter == delimiter:
#            delimiter_previously += 1
#    return delimiter_previously


def main(to_decompress=sys.argv[1]):
    '''Main function. Uses formatted index to decompress to_decompress.

    Args:
        to_decompress - default is sys.argv[1], path of file compressed using
        the accompanying compression algorithm'''

    with open(to_decompress, 'r') as main_file:
        file_contents = main_file.read()  # Using sys.argv[1] as the file to use

    delimiter = file_contents[0]
    unsearched = file_contents[1:]

    dict_of_assigned = {}

    while True:  # Unknown number of words defined
        if unsearched[0] == delimiter:  # There are 2 delimiters after the final definition
            file_body = unsearched[1:]
            break

        letter = unsearched[:unsearched.index(delimiter)]
        unsearched = unsearched[unsearched.index(delimiter) + 1:]
        word = unsearched[:unsearched.index(delimiter)]
        unsearched = unsearched[unsearched.index(delimiter) + 1:]
        dict_of_assigned[letter] = word

    new_file_body = ''

    for letter in file_body:
        if letter in dict_of_assigned:
            put_back = dict_of_assigned[letter]
        else:
            put_back = letter
        new_file_body += put_back

    with open(to_decompress[:to_decompress.rindex('Compressed')] + 'Dec' + to_decompress[to_decompress.rindex('ompressed'):], 'w') as new_file:
        new_file.write(new_file_body)

if __name__ == '__main__':
    main()
