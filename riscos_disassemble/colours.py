"""
Colouring of disassembled text.

Usage is simple:

    cdis = ColourDisassembly()
    coloured = cdis.colour('LDR r0, [r1, #&120] ; comment here')

would return a list of tuples and strings thus:

[('#dddddd', 'LDR'),
 ('#ffffff', ' '),
 ('#dddddd', 'r0'),
 ('#dddddd', ','),
 ('#ffffff', ' '),
 ('#777777', '['),
 ('#dddddd', 'r1'),
 ('#dddddd', ','),
 ('#ffffff', ' '),
 ('#dddddd', '#'),
 ('#ffbb00', '&120'),
 ('#777777', ']'),
 ('#ffffff', ' '),
 ('#00cc00', '; comment here')]

The ColourDisassemblyANSI() object can be used if you require a direct
conversion to ANSI terminal colouring. By default only the primary colours
are used, but 8bit colour can be selected with `cdis.use_8bit()`.

The ColourDisassembly object is structured to allow the parts of the
string to be overridden by modifying methods in the class. The following
methods generate colouring information:

* `colour_whole`:       Colours the entire disassembly, as a shortcut of
                        the other methods.
* `colour_instruction`: Colours just the instruction name.
* `colour_spaces`:      Colours the spaces between instruction and
                        operand, and between operand and comment.
* `colour_operands`:    Colours the operands.
* `colour_comment`:     Colours the comment.
"""

import re


class DisassemblyState(object):
    """
    Container class for the parts of the disassembly string.

    @ivar dis:      The full disassembly string
    @ivar inst:     The instruction mnemonic (may be None if no parsing would be performed)
    @ivar spaces1:  Spaces between the instruction and operands (may be '')
    @ivar operands: The operands (may be '')
    @ivar spaces2:  Spaces between the operands and the comment, or end of line (may be '')
    @ivar comment:  The comment, including leading ';' (may be None)
    """
    inst_re = re.compile('([A-Za-z][A-Za-z0-9]+)(\s*)')
    comment_re = re.compile('(\s+)(;.*)$')

    def __init__(self, dis):
        self.dis = dis

        match = self.inst_re.match(dis)
        if match:
            self.inst = match.group(1)
            self.spaces1 = match.group(2)
            dis = dis[match.end(2):]
            if not self.spaces1:
                # No spaces before special characters (or nothing at all), so this is something special.
                self.operands = dis
                self.spaces2 = ''
                self.comment = None
            else:
                if dis and dis[0] == ';':
                    # No operands present, just a comment
                    self.operands = ''
                    self.spaces2 = self.spaces1
                    self.spaces1 = ''
                else:
                    match = self.comment_re.search(dis)
                    if match:
                        self.spaces2 = match.group(1)
                        self.comment = match.group(2)
                        self.operands = dis[:match.start(1)]
                    else:
                        self.operands = dis.rstrip(' \t')
                        self.spaces2 = ' ' * (len(dis) - len(self.operands))
                        self.comment = None
        else:
            self.inst = None
            self.spaces1 = ''
            self.operands = ''
            self.spaces2 = ''
            self.comment = None


class ColourDisassembly(object):

    disassembly_colours = {
            'invalid': '#dd0000',
            'inst': '#ffffff',
            'space': '#ffffff',
            'inst-ldmstm': '#999999',
            'inst-ldrstr': '#dddddd',
            'inst-swi': '#558800',
            'inst-branch': '#eeeebb',
            'inst-fp': '#dddddd',
            'comment': '#00cc00',
            'register': '#dddddd',
            'register-fp': '#dd8855',
            'register-cp': '#dd8855',
            'number': '#ffbb00',
            'brackets': '#777777',      # []
            'braces': '#777777',        # {}
            'punctuation': '#dddddd',   # #!^-,.
            'shift': '#bbbbbb',         # eg LSL
            'swiname': '#00bbff',
            # Hex codes               #dddddd
            # Conditions              #eeeebb
            # VFP regs                #ffbb00
            # VFP insts               #bbbb44
            #
            # ctrlchars in text       #00bbff (handle separately?)
        }
    params_re = [
            (re.compile(r'\s+'), 'space'),
            (re.compile(r'[#!\^\-,.]'), 'punctuation'),
            (re.compile(r'[\[\]]'), 'brackets'),
            (re.compile(r'[\{}]'), 'braces'),
            (re.compile(r'R1[0-5]|R[0-9]|sp|lr|pc|[ca]psr|spsr(_[a-z]+)?', re.IGNORECASE), 'register'),
            (re.compile(r'F[0-7]', re.IGNORECASE), 'register-fp'),
            (re.compile(r'p1[0-5]|p[0-9]|c[0-7]', re.IGNORECASE), 'register-cp'),
            (re.compile(r'[+-]?([0-9]{1,9}|&[0-9A-F]{1,8})', re.IGNORECASE), 'number'),
            (re.compile(r'LSR|LSL|ROL|ROR|RRX|ASR', re.IGNORECASE), 'shift'),
        ]

    inst3_prefixes = {
            'SWI': 'inst-swi',
            'LDR': 'inst-ldrstr',
            'STR': 'inst-ldrstr',
            'LDM': 'inst-ldmstm',
            'STM': 'inst-ldmstm',
            'PUS': 'inst-ldmstm',  # PUSH
            'POP': 'inst-ldmstm',
            'BIC': 'inst',

            # FP instructions:
            'LDF': 'inst-fp',
            'STF': 'inst-fp',
            'LFM': 'inst-fp',
            'SFM': 'inst-fp',

            'ADF': 'inst-fp',   #... binary ops
            'MUF': 'inst-fp',
            'SUF': 'inst-fp',
            'RSF': 'inst-fp',
            'DVF': 'inst-fp',
            'RDF': 'inst-fp',
            'POW': 'inst-fp',
            'RPW': 'inst-fp',
            'RMF': 'inst-fp',
            'FML': 'inst-fp',
            'FDV': 'inst-fp',
            'FRD': 'inst-fp',
            'POL': 'inst-fp',
            'F0D': 'inst-fp',  # ... undefined binary ops
            'F0E': 'inst-fp',
            'F0F': 'inst-fp',
            'MVF': 'inst-fp',  # ... unary ops
            'MNF': 'inst-fp',
            'ABS': 'inst-fp',
            'RND': 'inst-fp',
            'SQT': 'inst-fp',
            'LOG': 'inst-fp',
            'LGN': 'inst-fp',
            'EXP': 'inst-fp',
            'SIN': 'inst-fp',
            'COS': 'inst-fp',
            'TAN': 'inst-fp',
            'ASN': 'inst-fp',
            'ACS': 'inst-fp',
            'ATN': 'inst-fp',
            'URD': 'inst-fp',
            'NRM': 'inst-fp',

            'CMF': 'inst-fp',
            'CNF': 'inst-fp',
            'FLT': 'inst-fp',
            'FIX': 'inst-fp',
            'WFS': 'inst-fp',
            'RFS': 'inst-fp',
            'WFC': 'inst-fp',
            'RFC': 'inst-fp',
        }

    def __init__(self):
        pass

    def parse(self, dis):
        """
        Generate the disassembly state for a string.

        @param dis:     The disassembled string

        @return:    state object for the disassembled instruction
        """
        return DisassemblyState(dis)

    def colour_whole(self, state):
        """
        Apply a colouring to the whole string if it can be recognised.

        @param state:   The disassembled instruction

        @return: List of either tuples of (colour, text) or just plain text string.
                 None if no colouring is recognised for the whole string
        """
        if state.dis.startswith(('Undefined', '<')):
            return [(self.disassembly_colours['invalid'], state.dis)]

        return None

    def colour_instruction(self, state):
        """
        Colour the instruction based on the state.

        @param state:   The disassembled instruction

        @return list of either tuples of (colour, text) or just plain text string.
        """
        inst3 = state.inst[0:3]
        col = self.inst3_prefixes.get(inst3, None)
        if not col:
            # Not a known instruction prefix, so check for some specials
            if state.inst[0] == 'B':
                col = 'inst-branch'
            else:
                col = 'inst'
        return [(self.disassembly_colours[col], state.inst)]

    def colour_spaces(self, state, index):
        """
        Colour the spaces between components.

        @param index:   0 first the first spaces, 1 for the second spaces
        """
        spaces = state.spaces1 if index == 0 else state.spaces2
        if not spaces:
            return []
        return [(self.disassembly_colours['space'], spaces)]

    def colour_operands(self, state):
        """
        Colour the operands based on the state.

        @param state:   The disassembled instruction

        @return list of either tuples of (colour, text) or just plain text string.
        """
        if state.inst[:3] in ('SWI', 'SVC'):
            return [(self.disassembly_colours['swiname'], state.operands)]

        coloured = []

        params = state.operands
        while params:
            match = None
            col = None
            for matches in self.params_re:
                match = matches[0].match(params)
                if match:
                    col = matches[1]
                    break
            if match:
                coloured.append((self.disassembly_colours[col], match.group(0)))
                params = params[match.end(0):]
            else:
                # This character isn't recognised so just pass through
                coloured.append(params[0])
                params = params[1:]

        return coloured

    def colour_comment(self, state):
        """
        Colour the comment based on the state.

        @param state:   The disassembled instruction

        @return list of either tuples of (colour, text) or just plain text string.
        """
        if not state.comment:
            return []
        return [(self.disassembly_colours['comment'], state.comment)]

    def colour(self, dis):
        """
        Transform text from a disassembly into a list of sequences with colours.

        @param dis: Contains the disassembled text

        @return: List of either tuples of (colour, text) or just plain text string.
        """

        # Process the state into broken down form
        state = self.parse(dis)

        # Provide a shortcut if the string can be handled as a whole without breaking
        # down to instructions and operands.
        whole_colours = self.colour_whole(state)
        if whole_colours is not None:
            return whole_colours

        if not state.inst:
            # There was no broken down state possible, so just return the string.
            return [state.dis]

        coloured = []

        # Instruction colouring
        coloured.extend(self.colour_instruction(state))

        # Spaces
        coloured.extend(self.colour_spaces(state, index=0))

        # Operand colouring
        coloured.extend(self.colour_operands(state))

        # Spaces
        coloured.extend(self.colour_spaces(state, index=1))

        # Comment
        coloured.extend(self.colour_comment(state))

        return coloured


class ColourDisassemblyANSI(ColourDisassembly):

    colours_primary = {
            (0x00, 0x00, 0x00): bytearray([27, 91, 51, 48 + 0, 109]),
            (0xFF, 0x00, 0x00): bytearray([27, 91, 51, 48 + 1, 109]),
            (0x00, 0xFF, 0x00): bytearray([27, 91, 51, 48 + 2, 109]),
            (0xFF, 0xFF, 0x00): bytearray([27, 91, 51, 48 + 3, 109]),
            (0x00, 0x00, 0xFF): bytearray([27, 91, 51, 48 + 4, 109]),
            (0xFF, 0x00, 0xFF): bytearray([27, 91, 51, 48 + 5, 109]),
            (0x00, 0xFF, 0xFF): bytearray([27, 91, 51, 48 + 6, 109]),
            (0xFF, 0xFF, 0xFF): bytearray([27, 91, 51, 48 + 7, 109]),
        }
    colour_reset = bytearray([27, 91, 109])

    # Create the 8bit colours
    colours_8bit = dict((((255/5 * r), (255/5 * g), (255/5 * b)),
                         16+((6*r)+g)*6+b) for r in range(6) for g in range(6) for b in range(6))
    colours_8bit.update(dict(((int(255/23.0 * i),
                               int(255/23.0 * i),
                               int(255/23.0 * i)),
                              232 + i) for i in range(24)))
    colours_8bit = dict((triple, b'\x1b[38;5;%im' % (col,)) for triple, col in colours_8bit.items())

    def __init__(self, *args, **kwargs):
        super(ColourDisassemblyANSI, self).__init__(*args, **kwargs)
        self.cached = {}
        self.colours = {}
        self.use_primaries()

    def use_primaries(self):
        """
        Use just the primary colours.
        """
        self.colours = dict(self.colours_primary)
        # Modify colour black to be a non-black colour, as otherwise it'll vanish
        # on a black background.
        self.colours[(0x00, 0x00, 0x00)] = bytearray([27, 91, 51, 48 + 7, 109])

    def use_8bit(self):
        """
        Use the 8bit colours.
        """
        self.colours = dict(self.colours_8bit)
        # Make the two blacks into slightly lighter greys
        self.colours[(0, 0, 0)] = self.colours[(int(255/23.0), int(255/23.0), int(255/23.0))]

    def find_best_match(self, colour):
        """
        Best ANSI match for a colour
        """
        value = int(colour, 16)
        if len(colour) == 6:
            # 6 digit hex colours
            r = value >> 16
            g = (value >> 8) & 255
            b = value & 255
        else:
            # 3 digit hex colours
            r = value >> 8
            g = (value >> 4) & 15
            b = value & 15
            r = r | (r<<4)
            g = g | (g<<4)
            b = b | (b<<4)
        seq = self.colours.get((r, g, b))
        if seq is None:
            best_score = 0x100000
            best = None
            for triple, ansiseq in self.colours.items():
                dr = abs(triple[0] - r)
                dg = abs(triple[1] - g)
                db = abs(triple[2] - b)
                score = (dr * dr) + 3 * (dg * dg) + 2 * (db * db)
                if not best or score < best_score:
                    best = ansiseq
                    best_score = score
            seq = best
        return seq

    def colour(self, dis):
        """
        Same as the base colours, but colours will be transformed into ANSI sequences.
        """
        coloured = super(ColourDisassemblyANSI, self).colour(dis)
        ansi_coloured = []
        for part in coloured:
            if isinstance(part, tuple):
                (colour, s) = part
                if colour[0] == '#':
                    seq = self.cached.get(colour, None)
                    if seq is None:
                        seq = self.find_best_match(colour[1:])
                        self.cached[colour] = seq
                    ansi_coloured.append((seq, s))
                else:
                    # Any not-understood colours just get the reset
                    ansi_coloured.append((self.colour_reset, part))

            else:
                ansi_coloured.append((self.colour_reset, part))

        return ansi_coloured
