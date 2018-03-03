#!/usr/bin/env python3
# FOR PYTHON 3
import sys, copy, json, multiprocessing, functools

__version__ = '0.3'
__author__ = 'Yoav Rafalin'

def remove_local_overlaps(positions, length):
    '''Removes overlaps in positions. Goes through list, and for every position,
    goes through again, and gets rid of the positions that are less than the
    position + its length, and larger than position.

    Args:
        positions - list of integers representing positions in the text
        length - integer, length of word
    Output:
        positions - list of integers, with no positions that are within length of every initial position'''
    positions_copy = positions
    for starting_letter in positions:
        for other_letter in positions[positions.index(starting_letter) + 1:]:
            if other_letter <= (starting_letter + length) and other_letter >= starting_letter:
                positions.remove(other_letter)
    return positions


def arrange_by_savings(repetitions_format_dict):
    '''Arranges repetitions by savings. Loops through repetitions_format_dict,
    a dictionary with lists of positions in the file to be compressed,
    corresponding to where the word is found. Each word is assessed for how
    many bytes it saves. The word and the amount of bytes it saves are added to
    corresponding_number_of_bytes as a pair.

    Args:
        repetitions_format_dict - dictionary with lists of positions in the
        file to be compressed, corresponding to where the word is found
    Output:
        corresponding_number_of_bytes - dictionary with words from repetitions_format_dict
        as keys, and the amount of bytes they save as values
        order_of_savings - list of keys/words in corresponding_number_of_bytes,
        ordered in the number of bytes they save, from most to least'''
    corresponding_number_of_bytes = {}  # Plug the word in to find how many bytes replacing it will save
    order_of_savings = []

    for word in repetitions_format_dict:
        amount_saved = (len(repetitions_format_dict[word]) - 1) * (len(word) - 1) - 2  # Because the words there are being removed
        # After it is removed, it is replaced with a corresponding byte, and the defining requires a byte, and the word itself

        corresponding_number_of_bytes[word] = amount_saved
        order_of_savings.append(word)

    return corresponding_number_of_bytes, sorted(order_of_savings, key=lambda x: corresponding_number_of_bytes[x], reverse=True)


def identify_negatives(number_dict):
    '''Finds negative numbers in number_dict. Loops through number_dict, adding
    the key to the number to a dictionary that is returned at the end if the
    number is negative.

    Args:
        number_dict - a dictionary with integer values
    Output:
        negatives_in_dict - a list with all of the keys to negative values in number_dict'''
    negatives_in_dict = []
    for word in number_dict:
        if number_dict[word] < 1:
            negatives_in_dict.append(word)
    return negatives_in_dict


def assign_index(leftover_file, unedited_file, repetitions):
    dict_of_assigned = {}  # For each word and the letter assigned to it
    cycle = 0

    leftover_file = list(set(leftover_file))  # set() gets rid of repeats
    leftover_values = []

    for letter in leftover_file:
        leftover_values.append(ord(letter))

    while cycle in leftover_values:
        cycle += 1
    delimiter = chr(cycle)  # The value that will seperate the defined fom the definition in the document
    cycle += 1

    for word in repetitions:
        while cycle in leftover_values:
            cycle += 1
        dict_of_assigned[word] = chr(cycle)
        cycle += 1

    file_body = list(unedited_file)  # This is what I will paste into the file after defining everything
    for word in repetitions:
        for starting_letter in repetitions[word]:
            start = 0
            for num in range(starting_letter, starting_letter + len(word)):
                if start == 0:
                    file_body[num] = dict_of_assigned[word]  # I make the first letter of the word the letter it is assigned...
                    start += 1
                else:
                    file_body[num] = delimiter  # And the others the delimiter...

    for _ in range(file_body.count(delimiter)):
        file_body.remove(delimiter)  # So I can remove all the parts I don't need, but still while placing the letters, their positions are the same

    return dict_of_assigned, file_body


def find_words(letter_info):
    starting_letter = letter_info[0]
    #print(starting_letter)
    uncompressed = letter_info[1]  # a.k.a. "file_contents"
    dict_of_possibilities = {}

    for other_letter in range(starting_letter - 1):  # It is starting_letter - 1 again because im looking for chunks that are at least 2 long# I start looking for repeats, starting with half the length and going down to 2
        length = 0
        current_word = ''

        while length + other_letter < starting_letter and starting_letter + length < len(uncompressed):

            if uncompressed[other_letter + length] == uncompressed[starting_letter + length]:
                current_word += uncompressed[starting_letter + length]
            else:
                break

            if length > 0:
                try:
                    if (other_letter in dict_of_possibilities[length + 1][current_word]) and (starting_letter in dict_of_possibilities[length + 1][current_word]):
                        to_add = []
                    if other_letter in dict_of_possibilities[length + 1][current_word]:
                        to_add = [starting_letter]
                    elif starting_letter in dict_of_possibilities[length + 1][current_word]:
                        to_add = [other_letter]
                    else:
                        to_add = [starting_letter, other_letter]
                except:
                    to_add = [starting_letter, other_letter]

                try:
                    dict_of_possibilities[current_word].extend(to_add)
                except:
                    dict_of_possibilities[current_word] = to_add

            length += 1
    #print(starting_letter, len(uncompressed), uncompressed[starting_letter], dict_of_possibilities)

    return dict_of_possibilities


def remove_all_overlaps(info_tuple, mini_dict):
    dict_of_repetitions = info_tuple[0]
    taken_spots = info_tuple[1]
    length = len([x for x in mini_dict][0])
    length_possibilities = mini_dict

    for word in length_possibilities:
        dict_of_repetitions[word] = remove_local_overlaps(length_possibilities[word], length)
        # Removing the overlapping spots (taking the string 'dadad' as an example: the last d in 'dad' is overlapped by the first d in 'dad')
        possibilities_copy = copy.deepcopy(length_possibilities[word])
        for starting_letter in possibilities_copy:
            for num in range(starting_letter, starting_letter + length):
                if num in taken_spots:
                    length_possibilities[word].remove(starting_letter)
                    break
                #else:
                #    taken_spots.extend(range(starting_letter, starting_letter + length))  # Updating taken spots

        if len(length_possibilities[word]) > 1:

            for starting_letter in length_possibilities[word]:
                taken_spots.extend(range(starting_letter, starting_letter + length))# + 1))  # Updating taken spots

            print('Found a repeat: ', "'" + word + "'")

            if word in dict_of_repetitions.values():
                for starting_letter in length_possibilities[word]:
                    if not starting_letter in dict_of_repetitions[word]:
                        dict_of_repetitions[word].append(starting_letter)
            else:
                dict_of_repetitions[word] = length_possibilities[word]  # Updating dict_of_repetitions
        else:
            del dict_of_repetitions[word]

    return (dict_of_repetitions, taken_spots)


def map_output_to_dict(previous_dict, map_output):
    new_dict = previous_dict
    for mini_dict in map_output:
        length = len(mini_dict)
        if length in new_dict:
            if mini_dict in new_dict[length]:
                for starting_letter in map_output[mini_dict]:
                    if starting_letter not in new_dict[length][mini_dict]:
                        new_dict[length][mini_dict].append(starting_letter)
            else:
                new_dict[length][mini_dict] = map_output[mini_dict]
        else:
            new_dict[length] = {mini_dict: map_output[mini_dict]}
    return new_dict


class search_word_iterator:
    def __init__(self, text):
        self.text = text
        self.index = 0
        self.length = len(text) - 1

    def __iter__(self):
        return self

    def __next__(self):
        if self.length == self.index:
            raise StopIteration
        result = self.index
        self.index += 1
        return (result, self.text)


# class overlap_removal_iterator:
#     def __init__(self, info_dict):
#         self.dict = info_dict
#         self.index = 0
#         self.list = sorted(info_dict, reverse=True)
#
#     def __iter__(self):
#         return self
#
#     def __next__(self):
#         try:
#             result = self.list[self.index]
#         except IndexError:
#             return StopIteration
#         self.index += 1
#         return (result, self.dict[result])


def main(to_compress=sys.argv[1]):
    '''Main function. Looks for repetitions in to_compress, and formats a new
    document. Look at comments for more info on formatting.

    Args:
        to_compress - default is sys.argv[1], path of a readable file'''

    try:
        with open(to_compress, 'r') as main_file:
            file_contents = main_file.read()  # Using sys.argv[1] as the file to use
    except:
        print('Please put in a file path as the second argument.')

    dict_of_repetitions = {}  # The dictionary where there is a word, corresponding to the position in file_contents
    taken_spots = []  # A list where I put ranges of all of the positions that repeat, along with the space they take up

    leftover_file_contents = list(file_contents)  # The data which has not been repeated gets leftover here

    print('search_word_iterator', search_word_iterator(file_contents))

    with multiprocessing.Pool() as map_pool:
        map_output = map_pool.map(find_words, search_word_iterator(file_contents))
    dict_of_possibilities = functools.reduce(map_output_to_dict, map_output)  # Same format as dict_of_repetitions, but for all chunks of length, and accumilating positions

    # dict_of_possibilities = {}
    # for mini_possibility_dict in list_of_possibilities:
    #     for key, value in mini_possibility_dict.items():
    #         try:
    #             dict_of_possibilities[key].append(value)
    #         except:
    #             dict_of_possibilities[key] = value

    print ('DICT OF POSS, POSITIN 1', dict_of_possibilities)

    #removal_iterator = overlap_removal_iterator(dict_of_possibilities)
    removal_iterator = [dict_of_possibilities[x] for x in sorted(dict_of_possibilities, reverse=True)]
    unoverlapped = functools.reduce(remove_all_overlaps, removal_iterator, ({}, []))  # After I've found the all the words...
    dict_of_repetitions, taken_spots = unoverlapped[0], unoverlapped[1]

    print('Done looking')
    print ('DICT OF re, POSITIN 2', dict_of_repetitions)
    print('SORTED TAKEN SPOTS', sorted(taken_spots))

    corresponding_number_of_bytes, order_of_savings = arrange_by_savings(dict_of_repetitions)  # Finding which words are not worth the hassle

    negative_savings = identify_negatives(corresponding_number_of_bytes)

    for word in negative_savings:
        for starting_letter in dict_of_repetitions[word]:
            for num in range(starting_letter, starting_letter + len(word) - 1):
                taken_spots.remove(num)  # The program should be able to reanalyze the chunk
        del dict_of_repetitions[word]

    for spot in sorted(taken_spots, reverse=True):  # Removing taken spots from leftover_file_contents to find the leftovers
        del leftover_file_contents[spot]

    # Now onto building the compressed document
    print('Now building document')

    with open(to_compress[:to_compress.rindex('.')] + 'Compressed' + to_compress[to_compress.rindex('.'):], 'w') as new_file:
        dict_of_assigned, file_body = assign_index(leftover_file_contents, file_contents, dict_of_repetitions)
        print(dict_of_assigned.values())
        print(dict_of_assigned.keys())
        json.dump({'i': dict(zip(dict_of_assigned.values(), dict_of_assigned.keys())), 'b': ''.join(file_body)}, new_file)


if __name__ == '__main__':
    main()
