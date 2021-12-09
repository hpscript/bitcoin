import math

from io import BytesIO
from unittest import TestCase

from helper import(
	bytes_to_bit_field,
	little_endian_to_int,
	merkle_parent,
	read_varint,
)

class MerkleTree:

	def __init__(self, total):
		self.total = total
		self.max_depth = math.ceil(math.log(self.total, 2))
		self.nodes = []
		for depth in range(self.max_depth + 1):
			num_items = math.ceil(self.total / 2**(self.max_depth - depth))
			level_hashes = [None] * num_items
			self.nodes.append(level_hashes)
		self.current_depth = 0
		self.current_index = 0

	def __repr__(self):
		result = []
		for depth, level in enumerate(self.nodes):
			items = []
			for index, h in enumerate(level):
				if h is None:
					short = 'None'
				else:
					short = '{}...'.format(h.hex()[:8])
				if depth == self.current_depth and index == self.current_index:
					items.append('*{}*'.format(short[:-2]))
				else:
					items.append('{}'.format(short))
			result.append(', '.join(items))
		return '\n'.join(result)

	def up(self):
		self.current_depth -= 1
		self.current_index //= 2

	def left(self):
		self.current_depth += 1
		self.current_index *= 2

	def right(self):
		self.current_depth += 1
		self.current_index = self.current_index * 2 + 1

	def root(self):
		return self.nodes[0][0]

	def set_current_node(self, value):
		self.nodes[self.current_depth][self.current_index] = value

	def get_current_node(self):
		return self.nodes[self.current_depth][self.current_index]

	def get_left_node(self):
		return self.nodes[self.current_depth + 1][self.current_index * 2]

	def get_right_node(self):
		return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

	def is_leaf(self):
		return self.current_depth == self.max_depth

	def right_exists(self):
		return len(self.nodes[self.current_depth + 1]) > \
			self.current_index * 2 + 1

	def populate_tree(self, flag_bits, hashes):
		while self.root() is None:
			if self.is_leaf():
				flag_bits.pop(0)
				self.set_current_node(hashes_pop(0))
				self.up()
			else:
				left_hash = self.get_left_node()
				if left_hash is None:
					if flag_bits.pop(0) == 0:
						self.set_current_node(hashes.pop(0))
						self.up()
					else:
						self.left()
				elif self.right_exists():
					right_hash = self.get_right_node()
					if right_hash is None:
						self.right()
					else:
						self.set_current_node(merkle_parent(left_hash, right_hash))
						self.up()
				else:
					self.set_current_node(merkle_parent(left_hash, left_hash))
					self.up()
		if len(hashes) != 0:
			raise RuntimeError('hashes not all consumed {}'.format(len(hashes)))
		for flag_bit in flag_bits:
			if flag_bit != 0:
				raise RuntimeError('flag bits not all consumed')

class MerkleBlock:

	command = b'merkleblock'
	
	def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, total, hashes, flags):
		self.version = version
		self.prev_block = prev_block
		self.merkle_root = merkle_root
		self.timestamp = timestamp
		self.bits = bits
		self.nonce = nonce
		self.total = total
		self.hashes = hashes
		self.flags = flags

	def __repr__(self):
		result = '{}\n'.format(self.total)
		for h in self.hashes:
			result += '\t{}\n'.format(h.hex())
		result += '{}'.format(self.flags.hex())

	@classmethod
	def parse(cls, s):
		version = little_endian_to_int(s.read(4))
		prev_block = s.read(32)[::-1]
		merkle_root = s.read(32)[::-1]
		timestamp = little_endian_to_int(s.read(4))
		bits = s.read(4)
		nonce = s.read(4)
		total = little_endian_to_int(s.read(4))
		num_hashes = read_varint(s)
		hashes = []
		for _ in range(num_hashes):
			hashes.append(s.read(32)[::-1])
		flags_length = read_varint(s)
		flags = s.read(flags_length)
		return cls(version, prev_block, merkle_root, timestamp, bits,
			nonce, total, hashes, flags)

	def is_valid(self):
		flag_bits = bytes_to_bit_field(self.flags)
		hashes = [h[::-1] for h in self.hashes]
		merkle_tree = MerkleTree(self.total)
		merkle_tree.populate_tree(flag_bits, hashes)
		return merkle_tree.root()[::-1] == self.merkle_root