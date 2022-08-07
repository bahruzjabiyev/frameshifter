from input_tree_node import Node
from helper_functions import _parse_url
from helper_functions import _print_exception, random_choose_with_options
import random
from collections import deque
import re
#import http2 as h2
import scapy.contrib.http2 as h2

class InputTree:

    def __init__(self, grammar, seed, url, verbose):
        """ Constructs a request object.
            
        Args:
          grammar: input grammar for describing the structure
          seed: a value based on which random number is
            generated. It is used for reproducability.

          url: address of the target endpoint
          verbose: a parameter to decide whether messages
            should be displayed.

        Returns:
          the constructed object
        """
        self.nonterminal_node_list = {}
        Node.symbol_counts = {}
        self.root = Node('<start>')
        self.grammar = grammar
        self.seed = seed
        random.seed(seed)
        self.url = url
        self.verbose = verbose
        self.host_header = None
        self.sequence = []
        self.string_mutated = False

    def build_tree(self, start_node):
        self.nonterminal_node_list[start_node.id] = start_node

        node_queue = deque([start_node])
        while node_queue:
            current_node = node_queue.pop()

            possible_expansions = self.grammar[current_node.symbol]
            chosen_expansion = random_choose_with_options(possible_expansions)

            for symbol in re.split(Node.RE_NONTERMINAL, chosen_expansion):
                if len(symbol) > 0:
                    new_node = Node(symbol)
                    current_node.children.append(new_node)

                    if not new_node.is_terminal:
                        node_queue.appendleft(new_node)
                        self.nonterminal_node_list[new_node.id] = new_node

        return start_node

    def remove_subtree_from_nodelist(self, start_node):
        """ This function updates the node_list dictionary
            when a node (and as a result its children) are removed.
        """
        if not start_node.is_terminal:
            self.nonterminal_node_list.pop(start_node.id)
            for child in start_node.children:
                self.remove_subtree_from_nodelist(child)

    def tree_to_sequence(self):
        self.frame_literals = {}
        self.host, self.port, self.authority, self.uri = _parse_url(self.url)
        if self.host_header is None:
            self.host_header = self.authority

        self.expand_node(self.root)
        return self.sequence

    def tree_to_humanreadable_sequence(self):
        frames = self.tree_to_sequence()
        return self.frame_literals 

    def extract_headers(self, node, headers_lst, node_id):
        is_header_node = False
        if len(node.children) == 2:
            if node.children[0].symbol.endswith('-header-name>') and node.children[1].symbol.endswith('-header-value>'):
                is_header_node = True
                header_name = node.children[0].children[0].symbol
                header_value = node.children[1].children[0].symbol
            elif node.children[0].symbol.endswith('-header-value>') and node.children[1].symbol.endswith('-header-name>'): 
                is_header_node = True
                header_value = node.children[0].children[0].symbol
                header_name = node.children[1].children[0].symbol

            if is_header_node:
                if node.symbol.endswith('authority-header>'):
                    header_value = header_value.replace('_HOST_', self.host_header)
                if node.symbol.endswith('path-header>'):
                    header_value = header_value.replace('_REQID_', str(self.seed))

                headers_lst.append(h2.HPackLitHdrFldWithoutIndexing(
                    hdr_name=h2.HPackHdrString(data=h2.HPackLiteralString(header_name)),
                    hdr_value=h2.HPackHdrString(data=h2.HPackLiteralString(header_value))
                ))
                self.frame_literals[node_id][header_name] = header_value

        if not is_header_node:
            for child_node in node.children:
                self.extract_headers(child_node, headers_lst, node_id)

    def build_frame(self, node, frame_type):
        try:
    
            def find_node(nodes, section_name):
                for node in nodes:
                    if node.symbol.endswith(section_name + '>'):
                        return node
    
            self.frame_literals[node.id] = {} 
            if frame_type == 'headers' or frame_type == 'padded-headers' or frame_type == 'priority-headers' or frame_type == 'continuation' or frame_type == 'push-promise':
                headers_lst = []
                header_block_node = find_node(node.children, 'header-block')
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
                self.extract_headers(header_block_node, headers_lst, node.id)

                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()

                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                id_value = int(stream_id_node.children[0].symbol)

                if frame_type == 'continuation':
                    return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2ContinuationFrame(hdrs=headers_lst)
                elif frame_type == 'push-promise':
                    promised_id_node = find_node(node.children, 'promised-id')
                    promised_id_value = promised_id_node.children[0].symbol
                    self.frame_literals[node.id]["promised-stream-id"] = promised_id_value
                    return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2PushPromiseFrame(stream_id=int(promised_id_value), hdrs=headers_lst)
                elif frame_type == 'padded-headers':
                    padding_node = find_node(node.children, 'padding')
                    padding_payload = padding_node.children[0].symbol
                    self.frame_literals[node.id]["padding"] = padding_payload
                    return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2PaddedHeadersFrame(hdrs=headers_lst, padding=padding_payload.encode())
                elif frame_type == 'priority-headers':
                    exclusive_node = find_node(node.children, 'exclusive')
                    dependency_node = find_node(node.children, 'dependency')
                    weight_node = find_node(node.children, 'weight')

                    exclusive_value = exclusive_node.children[0].symbol
                    dependency_value = dependency_node.children[0].symbol
                    weight_value = weight_node.children[0].symbol

                    self.frame_literals[node.id]["exclusive"] = exclusive_value
                    self.frame_literals[node.id]["dependency"] = dependency_value
                    self.frame_literals[node.id]["weight"] = weight_value
                    return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2PriorityHeadersFrame(exclusive=int(exclusive_value), stream_dependency = int(dependency_value), weight = int(weight_value), hdrs=headers_lst)
                else:
                    return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2HeadersFrame(hdrs=headers_lst)
    
            elif frame_type == 'data' or frame_type == 'padded-data':
                data_node = find_node(node.children, 'data')
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
    
                payload = data_node.children[0].symbol
                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()
                id_value = int(stream_id_node.children[0].symbol)

                self.frame_literals[node.id]["data"] = payload
                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                if frame_type == 'padded-data':
                    padding_node = find_node(node.children, 'padding')
                    padding_payload = padding_node.children[0].symbol
                    self.frame_literals[node.id]["padding"] = padding_payload
                    return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2PaddedDataFrame(data=payload, padding=padding_payload.encode())
                else:
                    return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2DataFrame(data=payload)

            elif frame_type == 'priority':
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
                exclusive_node = find_node(node.children, 'exclusive')
                dependency_node = find_node(node.children, 'dependency')
                weight_node = find_node(node.children, 'weight')

                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()
                id_value = int(stream_id_node.children[0].symbol)
                exclusive_value = exclusive_node.children[0].symbol
                dependency_value = dependency_node.children[0].symbol
                weight_value = weight_node.children[0].symbol

                self.frame_literals[node.id]["exclusive"] = exclusive_value
                self.frame_literals[node.id]["dependency"] = dependency_value
                self.frame_literals[node.id]["weight"] = weight_value
                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2PriorityFrame(exclusive = int(exclusive_value), stream_dependency = int(dependency_value), weight = int(weight_value))

            elif frame_type == 'reset':
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
                error_node = find_node(node.children, 'error')

                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()
                id_value = int(stream_id_node.children[0].symbol)
                error_value = error_node.children[0].symbol

                self.frame_literals[node.id]["error"] = h2.H2ErrorCodes.literal[int(error_value)]
                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2ResetFrame(error = int(error_value))

            elif frame_type == 'settings':
                settings_lst = []
                settings_node = find_node(node.children, 'settings')
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
   
                for child in settings_node.children:
                    setting_id_symbol = child.symbol.replace('>', '-id>')
                    setting_value_symbol = child.symbol.replace('>', '-value>')
    
                    for grandchild in child.children:
                        if grandchild.symbol == setting_id_symbol:
                            setting_id = grandchild.children[0].symbol
                        elif grandchild.symbol == setting_value_symbol:
                            setting_value = grandchild.children[0].symbol
    
                    settings_lst.append(h2.H2Setting(
                        id=int(setting_id),
                        value=int(setting_value),
                    ))

                    self.frame_literals[node.id][setting_id] = setting_value
    
                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()

                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                id_value = int(stream_id_node.children[0].symbol)
                p = h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2SettingsFrame(settings=settings_lst)
                return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2SettingsFrame(settings=settings_lst)

            elif frame_type == 'ping':
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
                opaque_node = find_node(node.children, 'opaque')

                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()
                id_value = int(stream_id_node.children[0].symbol)
                opaque_value = opaque_node.children[0].symbol

                self.frame_literals[node.id]["opaque"] = opaque_value
                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2PingFrame(opaque = int(opaque_value))

            elif frame_type == 'goaway':
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
                last_stream_id_node = find_node(node.children, 'last-id')
                error_node = find_node(node.children, 'error')
                additional_data_node = find_node(node.children, 'additional-data')

                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()
                id_value = int(stream_id_node.children[0].symbol)
                last_stream_id_value = last_stream_id_node.children[0].symbol
                error_value = error_node.children[0].symbol
                additional_data_value = additional_data_node.children[0].symbol

                self.frame_literals[node.id]["last_stream_id"] = last_stream_id_value
                self.frame_literals[node.id]["error"] = h2.H2ErrorCodes.literal[int(error_value)]
                self.frame_literals[node.id]["additional_data"] = additional_data_value
                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2GoAwayFrame(last_stream_id = int(last_stream_id_value), error = int(error_value), additional_data=additional_data_value.encode())

            elif frame_type == 'window-update':
                flags_node = find_node(node.children, 'flags')
                stream_id_node = find_node(node.children, 'stream-id')
                window_size_node = find_node(node.children, '-size')

                if flags_node.children[0].symbol != 'NONE':
                    flag_values = set(flags_node.children[0].symbol.split(';'))
                else:
                    flag_values = set()
                id_value = int(stream_id_node.children[0].symbol)
                window_size_value = window_size_node.children[0].symbol

                self.frame_literals[node.id]["window_size"] = window_size_value
                self.frame_literals[node.id]["flags"] = sorted(flag_values, reverse=True)
                return h2.H2Frame(flags = flag_values, stream_id = id_value)/h2.H2WindowUpdateFrame(win_size_incr = int(window_size_value))

        except Exception as e:
            raise(e)
            _print_exception(["node.symbol="+node.symbol])


    def expand_node(self, node):
        if node.symbol.startswith('<headers-frame'):
            self.sequence.append(self.build_frame(node, frame_type='headers'))
        elif node.symbol.startswith('<padded-headers-frame'):
            self.sequence.append(self.build_frame(node, frame_type='padded-headers'))
        elif node.symbol.startswith('<priority-headers-frame'):
            self.sequence.append(self.build_frame(node, frame_type='priority-headers'))
        elif node.symbol.startswith('<data-frame'):
            self.sequence.append(self.build_frame(node, frame_type='data'))
        elif node.symbol.startswith('<padded-data-frame'):
            self.sequence.append(self.build_frame(node, frame_type='padded-data'))
        elif node.symbol.startswith('<continuation-frame'):
            self.sequence.append(self.build_frame(node, frame_type='continuation'))
        elif node.symbol.startswith('<push-promise-frame'):
            self.sequence.append(self.build_frame(node, frame_type='push-promise'))
        elif node.symbol.startswith('<priority-frame'):
            self.sequence.append(self.build_frame(node, frame_type='priority'))
        elif node.symbol.startswith('<reset-frame'):
            self.sequence.append(self.build_frame(node, frame_type='reset'))
        elif node.symbol.startswith('<settings-frame'):
            self.sequence.append(self.build_frame(node, frame_type='settings'))
        elif node.symbol.startswith('<goaway-frame'):
            self.sequence.append(self.build_frame(node, frame_type='goaway'))
        elif node.symbol.startswith('<window-update-frame'):
            self.sequence.append(self.build_frame(node, frame_type='window-update'))
        else:
            for child in node.children:
                self.expand_node(child)
