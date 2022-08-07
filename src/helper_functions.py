import sys
import linecache
import configargparse
import random
import re
import copy

def _parse_url(url):
    """ This function extracts 
        components from a given URL.
    """
    authority = url.split('/')[2]
    uri = '/'.join(url.split('/')[3:])
    scheme = url.split('/')[0]

    if ':' not in authority:
        host = authority
        if scheme == 'https:':
            port = 443
        else:
            port = 80
    else:
        host, port = authority.split(':')

    return host, port, authority, uri

def _print_exception(extra_details=[]):
    """ This function prints exception details
        including the line number where the exception
        is raised, which is helpful in most cases.
    """
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print('EXCEPTION IN ({}, LINE {} "{}"): {}, {}'.format(filename, lineno, line.strip(), exc_obj, extra_details), file=sys.stderr)

def _parse_args(): 
    """ This function is for parsing the command
        line arguments fed into the script.
    """
    parser = configargparse.ArgParser(description='Frameshifter: Grammar-based HTTP/2 fuzzer with mutation ability')

    parser.add('-c', dest="config", required=True, help='config file path')
    parser.add('-i', action="store_true", dest="individual_mode", help="Turns the individual mode on where the fuzzer is run only for specified seeds.")
    parser.add('-s', dest="seed", type=int, help="Only needed for individual mode. Seed parameter for random number generator.")
    parser.add('-v', action="store_true", dest="verbose", help="Only needed for individual mode. Adds verbosity.")
    parser.add('-o', dest="outfilename", help = "Only needed for individual mode. File to write output.")
    parser.add('-f', dest="seedfile", help = "Only needed for individual mode. Input file containing seeds.")
    parser.add('-t', action="store_true", dest="testing_mode", help="Turns the testing mode on where the fuzzer generates and mutates inputs, but not delivers them.")

    args = parser.parse_args()
    #print(type(args))
    #print(args)

    return args

def random_choose_with_options(possible_expansions):
    possible_expansions_copy = copy.deepcopy(possible_expansions)
    probabilities = [0]*len(possible_expansions_copy)
    for index, expansion in enumerate(possible_expansions_copy):
        if "prob=" in expansion:
            probability = re.findall('(?<=prob=)[0-9.]+',expansion)[0]
            probabilities[index] = float(probability)

    probabilities = [(1-sum(probabilities))/probabilities.count(0) if elem == 0 else elem for elem in probabilities]

    chosen_expansion = random.choices(possible_expansions_copy, weights=probabilities)[0]
    # '(<headers-frame-1><data-frame-1>, opts(prob=0.9))'
    # for cases where symbol looks like above, trimming is needed
    if ', opts' in chosen_expansion:
        chosen_expansion = chosen_expansion.split(', opts')[0][1:]

    return chosen_expansion
