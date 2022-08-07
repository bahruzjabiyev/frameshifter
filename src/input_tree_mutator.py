import random
from input_tree_node import Node
from helper_functions import _print_exception, random_choose_with_options

class Mutator:

    mutation_types = {0, # tree mutations
                     1} # string mutations

    def __init__(self, symbol_mutation_types, string_mutators, tree_mutators, char_pool, symbol_pool, _input, seed=0, min_num_tree_mutations=1, max_num_tree_mutations=4, min_num_string_mutations=1, max_num_string_mutations=4, verbose=False):
        self.input = _input
        random.seed(seed)
        self.min_num_string_mutations = min_num_string_mutations
        self.max_num_string_mutations = max_num_string_mutations
        self.min_num_tree_mutations = min_num_tree_mutations
        self.max_num_tree_mutations = max_num_tree_mutations
        self.verbose = verbose
        self.mutation_messages = []
        self.symbol_mutation_types = symbol_mutation_types
        self.symbol_pool = symbol_pool
        self.char_pool = char_pool
        self.string_mutators = string_mutators
        self.tree_mutators = tree_mutators

    def mutate_input(self, source_of_mutations = []):
        try:
            if source_of_mutations == []:
                num_done_mutations = 0
                num_tree_mutations = random.randint(self.min_num_tree_mutations, self.max_num_tree_mutations)

                while num_done_mutations < num_tree_mutations:
                    node_to_mutate_pool = [node for node in self.input.nonterminal_node_list.values() if node.symbol in self.symbol_mutation_types and self.symbol_mutation_types[node.symbol] == 0]
                    if not node_to_mutate_pool:
                        break
                    node_to_mutate = random.choice(node_to_mutate_pool)
                    chosen_mutator = random_choose_with_options(self.tree_mutators)
                    self.__getattribute__(chosen_mutator)(node_to_mutate, self.verbose)
                    num_done_mutations += 1

                num_done_mutations = 0
                num_string_mutations = random.randint(self.min_num_string_mutations, self.max_num_string_mutations)
                string_mutation_happens = True

                while num_done_mutations < num_string_mutations:
                    node_to_mutate_pool = [node for node in self.input.nonterminal_node_list.values() if node.symbol in self.symbol_mutation_types and self.symbol_mutation_types[node.symbol] == 1]
                    if not node_to_mutate_pool:
                        string_mutation_happens = False
                        break
                    node_to_mutate = random.choice(node_to_mutate_pool)
                    chosen_mutator = random_choose_with_options(self.string_mutators)
                    self.__getattribute__(chosen_mutator)(node_to_mutate, self.verbose)
                    num_done_mutations += 1

                if string_mutation_happens:
                    self.input.string_mutated = True

            else:
                for mutation in source_of_mutations:
                    random.setstate(mutation[2])
                    if mutation[1].id not in self.input.nonterminal_node_list:
                        raise Exception("KeyNotFound: {}".format(mutation[1].id))
                    self.__getattribute__(mutation[0])(self.input.nonterminal_node_list[mutation[1].id], False)

        except Exception as exception: 
            _print_exception() 
            raise(exception)

    def remove_random_character(self, node, verbose=False):
        """Remove a character at a random position"""
        s = node.children[0].symbol
        if s:
            pos = random.randint(0, len(s) - 1)
            if verbose:
                print("Removing character {} at pos {} of {}.".format(repr(s[pos]), pos, node.id))
            else:
                self.mutation_messages.append("Removing character {} at pos {} of {}.".format(repr(s[pos]), pos, node.id)) 

            node.children[0].symbol = s[:pos] + s[pos+1:]

    def insert_random_character(self, node, verbose=False):
        """Insert a random character at a random position"""
        s = node.children[0].symbol
        if s:
            pos = random.randint(0, len(s))
            random_character = random.choice(self.char_pool)
            if verbose:
                print("Inserting character {} at pos {} of {}.".format(repr(random_character), pos, node.id))
            else:
                self.mutation_messages.append("Inserting character {} at pos {} of {}.".format(repr(random_character), pos, node.id))

            node.children[0].symbol = s[:pos] + random_character + s[pos:]

    def insert_random_character_at_edges(self, node, verbose=False):
        """Insert a random character at the either edge"""
        s = node.children[0].symbol
        if s:
            pos = random.choice([0, len(s)])
            random_character = random.choice(self.char_pool)
            if verbose:
                print("Inserting character {} at pos {} of {}.".format(repr(random_character), pos, node.id))
            else:
                self.mutation_messages.append("Inserting character {} at pos {} of {}.".format(repr(random_character), pos, node.id))

            node.children[0].symbol = s[:pos] + random_character + s[pos:]

    def replace_random_character(self, node, verbose=False):
        """Replace a character at a random position with a random character"""
        s = node.children[0].symbol
        if s:
            pos = random.randint(0, len(s) - 1)
            random_character = random.choice(self.char_pool)
            if verbose:
                print("Replacing character {} at pos {} with {}.".format(repr(node.id), pos, repr(random_character)))
            else:
                self.mutation_messages.append("Replacing character {} at pos {} with {}.".format(repr(node.id), pos, repr(random_character)))

            node.children[0].symbol = s[:pos] + random_character + s[pos+1:]

    def remove_random_subtree(self, node, verbose=False):
        """Remove a subtree at a random position under a given node"""
        if node.children:
            pos = random.randint(0, len(node.children) - 1)
            if verbose:
                print("Removing subtree {} under {}.".format(repr(node.children[pos].symbol), repr(node.id)))
            else:
                self.mutation_messages.append("Removing subtree {} under {}.".format(repr(node.children[pos].symbol), repr(node.id)))

            # Remove the node and its children also from the node list
            self.input.remove_subtree_from_nodelist(node.children[pos])

            node.children = node.children[:pos] + node.children[pos+1:]

    def replace_random_subtree(self, node, verbose=False):
        """Update a subtree at a random position under a given node 
          with a subtree expanded from a symbol chosen randomly 
          from the list of symbols"""
        if node.children:
            pos = random.randint(0, len(node.children) - 1)
            random_symbol = random.choice(self.symbol_pool)
            random_subtree = self.input.build_tree(Node(random_symbol))
            if verbose:
                print("Replacing subtree {} under {} with {}.".format(repr(node.children[pos].symbol), repr(node.id), repr(random_symbol)))
            else:
                self.mutation_messages.append("Replacing subtree {} under {} with {}.".format(repr(node.children[pos].symbol), repr(node.id), repr(random_symbol)))
          
            # Remove the node and its children also from the node list
            self.input.remove_subtree_from_nodelist(node.children[pos])

            node.children = node.children[:pos] + [random_subtree] + node.children[pos+1:]

    def insert_random_subtree(self, node, verbose=False):
        """Insert a subtree at a random position under a given node;
          inserted subtree is expanded from a symbol chosen randomly 
          from the list of symbols"""
        if node.children:
            pos = random.randint(0, len(node.children) - 1)
            random_symbol = random_choose_with_options(self.symbol_pool)
            random_subtree = self.input.build_tree(Node(random_symbol))
            if verbose:
                print("Inserting subtree {} at pos {} of {}.".format(repr(random_symbol), pos, repr(node.id)))
            else:
                self.mutation_messages.append("Inserting subtree {} at pos {} of {}.".format(repr(random_symbol), pos, repr(node.id)))

            node.children = node.children[:pos] + [random_subtree] + node.children[pos:]
