# user we are adding country codes to
user = 'support'

country_codes = open('./country_codes.txt')

for line in country_codes:
	prefix = f"{line.rstrip()}{user}"
	suffix = f"{user}{line.rstrip()}"

	predot = f"{line.rstrip()}.{user}"
	sufdot = f"{user}.{line.rstrip()}"

	print(prefix)
	print(suffix)
	print(predot)
	print(sufdot)
	print(prefix.lower())
	print(suffix.lower())
	print(predot.lower())
	print(sufdot.lower())