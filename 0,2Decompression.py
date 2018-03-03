#!/usr/bin/env python3
# FOR PYTHON 3
import sys, json

__version__ = '0.3'
__author__ = 'Yoav Rafalin'

#def previous_delimiters(prior_text, delimiter):  # I thought this could be helpful in decoding the index
#    delimiter_previously = 0
#    for letter in prior_text:
#        if letter == delimiter:
#            delimiter_previously += 1
#    return delimiter_previously


def main(to_decompress):
    '''Main function. Uses formatted index to decompress to_decompress.

    Args:
        to_decompress - path of file compressed using the accompanying
        compression algorithm'''

    try:
        with open(to_decompress, 'r') as main_file:
            file_contents = json.load(main_file)
    except:
        print('That file could not be read. Make sure it exists, and then run the program again.')
        raise SystemExit

    try:
        dict_of_assigned = file_contents['i']  # index/info
        file_body = file_contents['b']  # body
        new_file_body = ''

        for letter in file_body:
            if letter in dict_of_assigned:
                put_back = dict_of_assigned[letter]
            else:
                put_back = letter
            new_file_body += put_back

        return new_file_body
    except:
        print('There was a problem analyzing the file and/or decompressing it. Please make sure the file was compressed by the accompanying compression algorithm, and run the program again.')
        raise SystemExit

if __name__ == '__main__':
    try:
        load = sys.argv[1]
    except:
        print('You did not place the file as the second argument. Please do so, and run the program again.')
        raise SystemExit

    try:
        with open(load[:load.rindex('Compressed.')] + 'Dec' + load[load.rindex('ompressed.'):], 'w') as new_file:
            new_file.write(main(load))
    except:
        print('There was a problem writing the decompressed file into a new file. Check if the program is running correctly, and then run it again.')
        raise SystemExit
