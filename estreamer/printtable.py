

class PrintTable():

	'''
	Simple class to print a formatted table
	'''

	def __init__(self, headers, color=False):
		self.headers = headers
		self.columns = len(headers)
		self.row_data = []
		self.longest = [len(str(header)) for header in headers]
 
	def add_row(self, data):
		if len(data) != self.columns:
			raise PrintTableException('Incorrect # of columns specified for row')
		self.row_data.append(data)
                self.longest = [len(v) if len(v) > self.longest[i] else self.longest[i] for i, v in enumerate(data)]

	def line_seperator(self):
                return '+' + '+'.join(['{0:-^{1}}'.format('-', (length + 4)) for length in self.longest]) + '+'
	
	def print_headers(self):
                row_str = ''
		for iindex, llength in enumerate(self.longest):
			row_str += '{0} {1: <{2}}'.format('|', self.headers[iindex], (llength + 3))
		row_str += '|'
                return row_str

	def print_rows(self):
                row_str = ''
		for row in self.row_data:
                        for elem in zip(row, self.longest):
                            row_str += '{0} {1: <{2}}'.format('|', elem[0], elem[1] + 3)
			row_str += '|\n'
                return row_str

	def __str__(self):
		print_str = self.line_seperator() + "\n"
		print_str += self.print_headers() + "\n"
		print_str += self.line_seperator() + "\n"
		if self.row_data:
			print_str += self.print_rows()
		print_str += self.line_seperator() + "\n"	
                return print_str
