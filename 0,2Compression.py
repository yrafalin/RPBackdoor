#!/usr/bin/env python3
# FOR PYTHON 3
import sys, copy

def remove_overlaps(positions, length):
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
    corresponding_number_of_bytes = {}  # Plug the word in to find how many bytes replacing it will save
    order_of_savings = []

    for word in repetitions_format_dict:
        amount_saved = (len(repetitions_format_dict[word]) - 1) * (len(word) - 1) - 2  # Because the words there are being removed
        # After it is removed, it is replaced with a corresponding byte, and the defining requires a byte, and the word itself

        corresponding_number_of_bytes[word] = amount_saved
        order_of_savings.append(word)

    return corresponding_number_of_bytes, sorted(order_of_savings, key=lambda x: corresponding_number_of_bytes[x], reverse=True)


def identify_negatives(number_dict):
    negatives_in_dict = []
    for word in number_dict:
        if number_dict[word] < 1:
            negatives_in_dict.append(word)
    return negatives_in_dict


def main(to_compress=sys.argv[1]):
    '''Main function'''

    with open(to_compress, 'r') as main_file:
        file_contents = main_file.read()  # Using sys.argv[1] as the file to use

    dict_of_repetitions = {}  # The dictionary where there is a word, corresponding to the position in file_contents
    tcount = 1
    taken_spots = []  # A list where I put ranges of all of the positions that repeat, along with the space they take up

    forbidden_words = []

    repetition = 1

    while True:
        leftover_file_contents = list(file_contents)  # The data which has not been repeated gets leftover here

        dict_of_possibilities = {}  # Same format as dict_of_repetitions, but for all chunks of length, and accumilating positions

        for starting_letter in range(len(file_contents) - 1):  # It is file_contents - 1 because I'm not looking for chunks of length 1
            print('Starting_letter: ', starting_letter)
            '''if repetition != 1:
                continue_for = False
                for num in range(starting_letter, starting_letter + length):   # Check the spot against what has been taken is case of another cycle
                    if num in taken_spots:
                        continue_for = True  # Can't do continue in here because it wont do anything
                if continue_for == True:
                    continue'''

            for other_letter in range(starting_letter - 1):  # It is starting_letter - 1 again because im looking for chunks that are at least 2 long# I start looking for repeats, starting with half the length and going down to 2
                length = 0
                current_word = ''
                #print('Other_letter: ', other_letter)

                while length + other_letter < starting_letter and starting_letter + length < len(file_contents):

                    if file_contents[other_letter + length] == file_contents[starting_letter + length]:
                        current_word += file_contents[starting_letter + length]
                        print('Current_word: ', current_word)
                    else:
                        break

                    if current_word in forbidden_words:
                        continue

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
                            dict_of_possibilities[length + 1][current_word].extend(to_add)
                        except:
                            try:
                                dict_of_possibilities[length + 1][current_word] = to_add
                            except:
                                dict_of_possibilities[length + 1] = {current_word: to_add}

                    length += 1
        print ('DICT OF POSS, POSITIN 1', dict_of_possibilities)

        for length in sorted(dict_of_possibilities, reverse=True):  # After I've found the all the words...
            #print('-----tart of loop fpr length' , dict_of_possibilities[length])
            for word in dict_of_possibilities[length]:
                #print('before overlaps dict_of_possibilities', dict_of_possibilities[length][word])
                dict_of_possibilities[length][word] = remove_overlaps(dict_of_possibilities[length][word], length)
                # Removing the overlapping spots (taking the string 'dadad' as an example: the last d in 'dad' is overlapped by the first d in 'dad')
                #print ('---start of loop fpr word -- length ', length, 'word', word)
                #print(' before dict_of_possibilities', dict_of_possibilities[length][word])
                possibilities_copy = copy.deepcopy(dict_of_possibilities[length][word])
                for starting_letter in possibilities_copy:
                    #print('starting letter', starting_letter, possibilities_copy)
                    for num in range(starting_letter, starting_letter + length):
                        #print('checkig ', num)
                        if num in taken_spots:
                            dict_of_possibilities[length][word].remove(starting_letter)
                            #print('removing ', length, word, starting_letter)
                            break
                        #else:
                        #    taken_spots.extend(range(starting_letter, starting_letter + length))  # Updating taken spots

                #print('after dict_of_possibilities', dict_of_possibilities[length][word])

                if len(dict_of_possibilities[length][word]) > 1:

                    for starting_letter in dict_of_possibilities[length][word]:
                        #print('--starting_letter--', starting_letter)
                        taken_spots.extend(range(starting_letter, starting_letter + length))# + 1))  # Updating taken spots
                        #print(taken_spots)
                        #if word == 't  ':
                        #    if tcount == 2:
                        #        print(range(starting_letter, starting_letter + length))
                        #        #raise SystemExit
                        #    tcount += 1
                        #print('--new taken_spots--', taken_spots)

                    print('Found a repeat: ', "'" + word + "'")

                    try:
                        dict_of_repetitions[word].extend(dict_of_possibilities[length][word])
                    except:
                        dict_of_repetitions[word] = dict_of_possibilities[length][word]  # Updating dict_of_repetitions
                    #print('dict_of_repetitions now', dict_of_repetitions)

        print('Done looking this cycle')
        print ('DICT OF re, POSITIN 2', dict_of_repetitions)
        print('SORTED TAKEN SPOTS', sorted(taken_spots))

        for spot in sorted(taken_spots, reverse=True):  # Removing taken spots from leftover_file_contents to find the leftovers
            #print('spot:', spot)
            print(len(leftover_file_contents))
            del leftover_file_contents[spot]# - 1]

        leftover_file_contents = list(set(leftover_file_contents))  # set() gets rid of repeats
        leftover_contents_values = []

        for letter in leftover_file_contents:
            leftover_contents_values.append(ord(letter))

        print('Identifying negatives')

        corresponding_number_of_bytes, order_of_savings = arrange_by_savings(dict_of_repetitions)  # Finding which words are not worth the hassle

        if len(identify_negatives(corresponding_number_of_bytes)) < 1:  # The loop gets repeated because the negatives are taken out
            break
        else:
            negative_savings = identify_negatives(corresponding_number_of_bytes)

        forbidden_words.extend(negative_savings)  # To stop the program from repeating because it doesn't remember to ignore the bad ones

        for word in negative_savings:
            for starting_letter in dict_of_repetitions[word]:
                for num in range(starting_letter, starting_letter + len(word) - 1):
                    #print('taken_spots', sorted(taken_spots))
                    #print('word', ':' + word + ':', len(word))
                    #print('starting_letter', starting_letter)
                    #print('num', num)
                    taken_spots.remove(num)  # The program should be able to reanalyze the chunk
            del dict_of_repetitions[word]

        print('Done with cycle ', repetition)
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
