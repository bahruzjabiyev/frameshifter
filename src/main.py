import random
import re
import copy
import socket
import threading
from multiprocessing import Process, Queue
import time
import json
from h2client import H2Client

from input_tree_node import Node
from input_tree import InputTree
from input_tree_mutator import Mutator
from helper_functions import _print_exception, _parse_args, _parse_url

class Fuzzer:

    #def __init__(self, verbose, seed, outfilename, seedfile, testing_mode):
    def __init__(self, args):
        self.read_config(args.config)

        self.verbose = args.verbose
        self.seed = args.seed
        self.outfilename = args.outfilename
        self.seedfile = args.seedfile
        self.testing_mode = args.testing_mode

        self.lock = threading.Lock()

    def read_config(self, configfile):
        config_content = open(configfile).read().replace('config.', 'self.')
        exec(config_content)
        if False in [item in self.__dict__ for item in ["urls", "host_headers", "grammar", "min_num_tree_mutations", "max_num_tree_mutations", "min_num_string_mutations", "max_num_string_mutations", "symbol_mutation_types"]]:
            print("Please make sure that the configuration is complete.")
            exit()

        #self.entry_hosts = {self.entry_urls[i]:self.entry_host_headers[i] for i in range(len(self.entry_urls))}
        self.hosts = {self.urls[i]:self.host_headers[i] for i in range(len(self.urls))}

    def h2_send_fuzzy_data(self, inputdata, list_responses):
        try:
            sequence = inputdata.tree_to_sequence()
            h2_client = H2Client(self.verbose)
            if inputdata.string_mutated:
                response = h2_client.send(inputdata.host, int(inputdata.port), inputdata.host_header, inputdata.seed, sequence)  
            else:
                response = b'input not sent, because not string mutated'

            with self.lock:
                list_responses.append(response)

        except Exception as e:
            #raise(e)
            _print_exception([inputdata.host_header, inputdata.seed])

    def get_responses(self, seed, request):
        threads = []
        list_responses = []
        for url in self.urls:
            request.seed = seed
            request.url = url
            request.host_header = self.hosts[url]

            request_copy = copy.deepcopy(request)
            thread = threading.Thread(target=self.h2_send_fuzzy_data, args=(request_copy, list_responses))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(5)

        return list_responses

    def blackbox_fuzz_parallel_batch(self):
        for j in range(0, 1):
            num_procs = 128
            batch_size = 1000
            seeds_splitted = [[j*batch_size + i for i in list(range(i, batch_size, num_procs))] for i in range(num_procs)]
            quot = Queue()
            processes = [Process(target=self.run, args=(seeds_splitted[i], quot)) for i in range(num_procs)]
            responses_list = []

            for i, proc in enumerate(processes):
                proc.start()

            result = [quot.get() for p in processes]

            for i, proc in enumerate(processes):
                proc.join()

            result = json.dumps({"seeds": {k: v for d in result for k, v in d.items()}})

            with open("batch{}.out".format(j), 'w') as outfile:
                outfile.write(result)

    def blackbox_fuzz_individual(self, filename=None, seeds=[None]):
        if seeds == [None]:
            with open(filename, 'r') as _file:
                seeds = [int(line.strip()) for line in _file.readlines()]

        num_procs = 128 
        seeds_splitted = [[seeds[i] for i in list(range(i, len(seeds), num_procs))] for i in range(num_procs)]
        quot = Queue()
        processes = [Process(target=self.run_individual, args=(seeds_splitted[i], quot)) for i in range(num_procs)]
        responses_list = []

        for i, proc in enumerate(processes):
            proc.start()

        result = [quot.get() for p in processes]

        for i, proc in enumerate(processes):
            proc.join()

        json_result = json.dumps({"seeds": {k: v for d in result for k, v in d.items()}})

        if self.outfilename is None:
            print(json_result)
            print("\n")
        else:
            with open(self.outfilename, 'w') as outfile:
                outfile.write(json_result)

        #print([item for item in result if item][0][210])
        d = [item for item in result if item][0]
        print("input is: {}".format(d[list(d.keys())[0]]['input']))
        #print(type([item for item in result if item][0]))
        return result
        #return d[list(d.keys())[0]]['input']

    def run(self, seeds, _queue):
        responses_list = {}
        for seed in seeds:
            base_input = InputTree(self.grammar, seed, "http://hostname/uri", False)
            base_input.build_tree(base_input.root)

            mutator = Mutator(self.symbol_mutation_types, self.string_mutators, self.tree_mutators, self.char_pool, self.symbol_pool, base_input, seed, self.min_num_tree_mutations, self.max_num_tree_mutations, self.min_num_string_mutations, self.max_num_string_mutations, self.verbose)
            mutator.mutate_input()
            if self.testing_mode:
                responses = []
            else:
                responses = self.get_responses(seed, base_input)

            responses_list[seed] = {}
            responses_list[seed]["input"] = base_input.tree_to_humanreadable_sequence()
            responses_list[seed]["mutations"] = mutator.mutation_messages
            responses_list[seed]["responses"] = [response.decode() for response in responses]

        _queue.put(responses_list)

    def run_individual(self, seeds, _queue):
        responses_list = {}
        for seed in seeds:
            base_input = InputTree(self.grammar, seed, "http://hostname/uri", False)
            base_input.build_tree(base_input.root)

            mutator = Mutator(self.symbol_mutation_types, self.string_mutators, self.tree_mutators, self.char_pool, self.symbol_pool, base_input, seed, self.min_num_tree_mutations, self.max_num_tree_mutations, self.min_num_string_mutations, self.max_num_string_mutations, self.verbose)
            mutator.mutate_input()
            if self.testing_mode:
                responses = []
            else:
                responses = self.get_responses(seed, base_input)

            responses_list[seed] = {}
            responses_list[seed]["input"] = base_input.tree_to_humanreadable_sequence()
            responses_list[seed]["mutations"] = mutator.mutation_messages
            responses_list[seed]["responses"] = [response.decode() for response in responses]

        _queue.put(responses_list)

if __name__ == '__main__':
    args = _parse_args()
    start = time.time()

    fuzzer = Fuzzer(args)
    if args.individual_mode:
        fuzzer.blackbox_fuzz_individual(fuzzer.seedfile, [fuzzer.seed])
    else:
        fuzzer.blackbox_fuzz_parallel_batch()
    
    print(time.time() - start)
