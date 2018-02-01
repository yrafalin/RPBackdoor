#!/usr/bin/env python3
# FOR PYTHON 3
import sys

def remove_overlaps(positions, length):
    '''Removes overlaps in positions. Goes through list, and for every position,
    goes through again, and gets rid of the positions that are less than the
    position + its length, and larger than position.

    Args:
        positions - list of integers representing positions in the text
        length - integer, length of word to be assessed for
    Output:
        positions - list of integers, with no positions that are within length of every initial position'''
    for starting_letter in positions:
        for other_letter in positions:
            if other_letter > starting_letter:
                if other_letter <= (starting_letter + length) and other_letter > starting_letter:
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
        #order_of_savings.append(word)

    return corresponding_number_of_bytes, sorted(repetitions_format_dict, key=lambda x: corresponding_number_of_bytes[x], reverse=True)


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


def find_length_multiplier(opened_file):
    '''Finds the optimal length to start looking for repeats. It starts with a
    length_multiplier of 1/8. The length_multiplier times the length of
    opened_file is how long of words the function starts looking for. It runs
    through the opened_file similar to how is done in the main function, but
    stops when a repetition is found. The length_multiplier is then multplied
    by 2, and the process continues. If no repetition is found,
    length_multiplier is divided by 2. If ever the length_multiplier is
    repeated, if the previous length_multiplier was smaller, length_multiplier
    returns as is, but if otherwise, it returns doubled.

    Args:
        opened_file - the file to be compressed
    Output:
        length_multiplier - multiplied by the length of the file, that is a
        good length to start with when looking for repetitions'''
    prior_length_m = []  # After a length has been repeated, the function is exited
    first_time = True
    larger = False
    while True:
        if first_time == True:
            first_time = False
            length_multiplier = 1/8
        elif larger == True:
            length_multiplier *= 2
        elif larger == False:
            length_multiplier /= 2

        print('length multiplier ', length_multiplier)

        if length_multiplier in prior_length_m or length_multiplier < 1/1024:
            return (length_multiplier if larger == True else length_multiplier * 2)
        else:
            prior_length_m.append(length_multiplier)

        dict_of_possibilities = {}
        length = round(len(opened_file) * length_multiplier)
        larger = False
        for starting_letter in range(len(opened_file) - length):

            current_word = opened_file[starting_letter:starting_letter + length]

            if starting_letter + (length * 2) > len(opened_file) and current_word not in dict_of_possibilities:
                break

            if current_word in dict_of_possibilities:
                dict_of_possibilities[current_word].append(starting_letter)
                dict_of_possibilities[current_word] = remove_overlaps(dict_of_possibilities[current_word], length)
                if len(dict_of_possibilities[current_word]) > 1:
                    larger = True
                    break
            else:
                dict_of_possibilities[current_word] = [starting_letter]


def main(to_compress=sys.argv[1]):
    '''Main function. Looks for repetitions in to_compress, and formats a new
    document. Look at comments for more info on formatting.

    Args:
        to_compress - default is sys.argv[1], path of a readable file'''

    with open(to_compress, 'r') as main_file:
        file_contents = main_file.read()  # Using sys.argv[1] as the file to use

    dict_of_repetitions = {}  # The dictionary where there is a word, corresponding to the position in file_contents

    taken_spots = []  # A list where I put ranges of all of the positions that repeat, along with the space they take up

    forbidden_words = []

    start_length_multiplier = find_length_multiplier(file_contents)
    print('Length multiplier is ', start_length_multiplier)

    repetition = 1

    while True:
        leftover_file_contents = list(file_contents)  # The data which has not been repeated gets leftover here

        for length in range(2, round(len(file_contents) * start_length_multiplier))[::-1]:  # I start looking for repeats, starting with half the length and going down to 2
            dict_of_possibilities = {}  # Same format as dict_of_repetitions, but for all chunks of length, and accumilating positions

            print('Looking for length ', length)

            for starting_letter in range(len(file_contents) - length):  # It is file_contents - length because I can't have a chunk that is 10 long, if I am at the fifth from the end

                current_word = file_contents[starting_letter:starting_letter + length]

                #if starting_letter + (length * 2) > len(file_contents) and current_word not in dict_of_possibilities:
                #    break

                if current_word in forbidden_words:
                    continue

                continue_for = False
                for num in range(starting_letter, starting_letter + length):   # Check the spot against what has been taken
                    if num in taken_spots:
                        continue_for = True  # Can't do continue in here because it wont do anything
                if continue_for == True:
                    continue

                if current_word in dict_of_possibilities:  # If the word is in the dict (meaning it's been repeated), I don't want to make a new spot for it
                    dict_of_possibilities[current_word].append(starting_letter)
                else:  # Making a new spot for it
                    dict_of_possibilities[current_word] = [starting_letter]

            for word in dict_of_possibilities:  # After I've found the all the words...

                dict_of_possibilities[word] = remove_overlaps(dict_of_possibilities[word], length)
                # Removing the overlapping spots (taking the string 'dadad' as an example: the last d in 'dad' is overlapped by the first d in 'dad')

                # for starting_letter in dict_of_possibilities[word]:
                #     for num in range(starting_letter, starting_letter + length):
                #         if num in taken_spots:
                #             dict_of_possibilities[word].remove(starting_letter)
                #             break

                print('Found a repeat: ', word)
                print ('DICT OF poss, POSITIN 2', dict_of_possibilities)
                first_time = []
                cycle = 0
                for starting_letter in dict_of_possibilities[word]:
                    do_extend = True
                    to_loop = range(starting_letter, starting_letter + length)
                    if cycle == 1:
                        to_loop = [to_loop] + [first_time]
                    for num in to_loop:
                        if num in taken_spots:
                            if do_extend:
                                dict_of_possibilities[word].remove(starting_letter)
                            do_extend = False
                            break

                    if do_extend:
                        if cycle == 0:
                            first_time = range(starting_letter, starting_letter + length)
                        elif cycle == 1:
                            taken_spots.extend(range(starting_letter, starting_letter + length))
                            taken_spots.extend(first_time)
                        else:
                            taken_spots.extend(range(starting_letter, starting_letter + length))  # Updating taken_spots
                        cycle += 1
                    print('extending taken spots from ', starting_letter)
                    #

                if len(dict_of_possibilities[word]) > 1:  # Meaning it has repeats
                    try:
                        dict_of_repetitions[word].extend(dict_of_possibilities[word])
                    except:
                        dict_of_repetitions[word] = dict_of_possibilities[word]  # Updating dict_of_repetitions

        print('Done looking this cycle')
        print ('DICT OF repetitions, POSITIN 2', dict_of_repetitions)
        print('SORTED TAKEN SPOTS', sorted(taken_spots))

        print('taken', len(taken_spots))
        print(taken_spots)
        print('leftover', len(leftover_file_contents))
        print(leftover_file_contents)
        for spot in sorted(taken_spots)[::-1]:  # Removing taken spots from leftover_file_contents to find the leftovers
            print(spot)
            del leftover_file_contents[spot]

        leftover_file_contents = list(set(leftover_file_contents))  # set() gets rid of repeats
        leftover_contents_values = []

        for letter in leftover_file_contents:
            leftover_contents_values.append(ord(letter))

        corresponding_number_of_bytes, order_of_savings = arrange_by_savings(dict_of_repetitions)  # Finding which words are not worth the hassle

        #if len(identify_negatives(corresponding_number_of_bytes)) < 1:  # The loop gets repeated because the negatives are taken out
        #    break
        #else:
        #    negative_savings = identify_negatives(corresponding_number_of_bytes)

        #forbidden_words.extend(negative_savings)  # To stop the program from repeating because it doesn't remember to ignore the bad ones

        #for word in negative_savings:
        #    print ('word ', word)
        #    print('Value ', dict_of_repetitions[word])
        #    for starting_letter in dict_of_repetitions[word]:
        #        for num in range(starting_letter, starting_letter + len(word) - 1):
        #            print('num', num)
        #            print('taken', taken_spots)
        #            print('True?', True if num in taken_spots else False)
        #            taken_spots.remove(num)  # The program should be able to reanalyze the chunk
        #    del dict_of_repetitions[word]

        print('Done with cycle ', repetition)
        break
        repetition += 1

    # Now onto building the compressed document
    print('Now building document')

    dict_of_assigned = {}  # For each word and the letter assigned to it

    cycle = 0
    while cycle in leftover_contents_values:
        cycle += 1
    delimiter = chr(cycle)  # The value that will seperate the defined fom the definition in the document
    cycle += 1

    for word in order_of_savings:
        while cycle in leftover_contents_values:
            cycle += 1
        dict_of_assigned[word] = chr(cycle)
        cycle += 1

    file_body = list(file_contents)  # This is what I will paste into the file after defining everything
    for word in dict_of_repetitions:
        for starting_letter in dict_of_repetitions[word]:
            start = 0
            for num in range(starting_letter, starting_letter + len(word)):
                if start == 0:
                    file_body[num] = dict_of_assigned[word]  # I make the first letter of the word the letter it is assigned...
                    start += 1
                else:
                    file_body[num] = delimiter  # And the others the delimiter...

    while True:
        try:
            file_body.remove(delimiter)  # So I can remove all the parts I don't need, but still while placing the letters, their positions are the same
        except:
            break

    with open(to_compress[:to_compress.rindex('.')] + 'Compressed' + to_compress[to_compress.rindex('.'):], 'w') as new_file:
        new_file.write(delimiter)  # The first byte will signal what the delimiter is
        for word in dict_of_assigned:
            new_file.write(dict_of_assigned[word] + delimiter + word + delimiter)
        new_file.write(delimiter)  # 2 delimiters will signal the beginning of the body of the data
        new_file.write(''.join(file_body))


if __name__ == '__main__':
    main()
