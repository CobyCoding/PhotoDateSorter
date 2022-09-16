import os
import exif
from PIL import Image
from PIL.ExifTags import TAGS
from PIL import ImageFile
import shutil
import hashlib
import sys
from struct import *
import threading

ImageFile.LOAD_TRUNCATED_IMAGES = True

class photo():
	def __init__(self, name, dir_, dest, ext,dev):
		self.dev = dev
		self.rubbish = False
		self.dup = False
		self.quit = False
		self.ext = ext
		self.dest = dest
		self.name = name
		self.dir_ = dir_
		dt = self.get_props()
		if self.quit == False:
			self.month = dt[0]
			self.year = dt[1]
			self.hash = self.get_hash()
			if self.quit == False:	
				self.new_name = self.hash + "." + self.ext
				self.photoMover()

	def FindDateTimeOffsetFromCR2(self, buffer, ifd_offset ):
		try:
			# Read the number of entries in IFD #0
			(num_of_entries,) = unpack_from('H', buffer, ifd_offset)

			# Work out where the date time is stored
			datetime_offset = -1
			for entry_num in range(0,num_of_entries-1):
				(tag_id, tag_type, num_of_value, value) = unpack_from('HHLL', buffer, ifd_offset+2+entry_num*12)
				if tag_id == 0x0132:
					datetime_offset = value
			return datetime_offset
		except Exception as e:
			self.quit = True
			self.write_exception(e,"hashes")

	def get_hash(self):
		try:
			if self.ext == "CR2" or self.ext == "cr2":
				with open(self.dir_, "rb") as f:
					file_size = os.path.getsize(self.dir_)
					buffer = f.read(1028)
					buffer = buffer.hex()
					buffer = buffer.encode('utf-8')
					md5hash = hashlib.md5(buffer)
					hash_ = md5hash.hexdigest()
			else:
				md5hash = hashlib.md5(Image.open(self.dir_).tobytes())
				hash_ = md5hash.hexdigest()

			file = self.dest + "/hashes.txt"
			fi = open(file, "r")
			lines = fi.readline().split(",")
			fi.close()
			
			if hash_ in lines:
				self.dup = True
			else:
				f = open(file, "a")
				f.write(hash_ + ",")
				f.close()
			return hash_
		except Exception as e:
			self.quit = True
			self.write_exception(e,"hashes")

	def get_props(self):
		try:
			imagename = "{}".format(self.dir_)
			if self.ext == "png" or self.ext == "jpg" or self.ext == "JPG" or self.ext == "jpeg":
				ret = {}
				i = Image.open(imagename)
				info = i._getexif()
				if info == None:
					self.rubbish == True
					return [0,0]
				for tag, value in info.items():
				    decoded = TAGS.get(tag, tag)
				    ret[decoded] = value
				if self.ext == "png":
					if "DateTimeOriginal" in ret.keys():
						dt = ret["DateTimeOriginal"]
					else:
						i.close()
						shutil.move(self.dir_, "{}\\Unsorted\\{}".format(self.dest, self.name))
						self.quit = True
						return None
				elif self.ext == "jpg" or self.ext == "JPG" or self.ext == "jpeg":
					if "DateTimeDigitized" in ret.keys():
						dt = ret["DateTimeDigitized"]
					else:
						i.close()
						shutil.move(self.dir_, "{}\\Unsorted\\{}".format(self.dest, self.name))
						self.quit = True
						return None
			elif self.ext == "cr2" or self.ext == "CR2":
				with open(imagename, "rb") as f:
					buffer = f.read(1024) # read the first 1kb of the file should be enough to find the date / time
					datetime_offset = self.FindDateTimeOffsetFromCR2(buffer, 0x10)
					listOfDate = unpack_from(20*'s', buffer, datetime_offset)
					dt = ""
					for l in listOfDate:
						l = l.decode('utf-8')
						dt += l

			dt = dt.split(" ")[0]
			month, year = dt.split(":")[1], dt.split(":")[0]
			return [month, year]
		except Exception as e:
			self.quit = True
			self.write_exception(e,"Props")

	def photoMover(self):
		try:
			cwd = os.getcwd()
			if self.dup:
				if os.path.exists('{}/Duplicates/{}'.format(self.dest, self.year)):
					pass
				else:
					target_dir = '{}/Duplicates/{}'.format(self.dest, self.year)
					os.mkdir(target_dir)
				if os.path.exists('{}/Duplicates/{}/{}'.format(self.dest, self.year, self.month)):
					self.location = '{}/Duplicates/{}/{}/{}'.format(self.dest, self.year, self.month, self.new_name)
				else:
					target_dir = '{}/Duplicates/{}/{}'.format(self.dest, self.year,self.month)
					os.mkdir(target_dir)
					self.location = '{}/Duplicates/{}/{}/{}'.format(self.dest, self.year, self.month, self.new_name)
			elif self.rubbish:
				if os.path.exists('{}/rubbish'.format(self.dest)):
					self.location = '{}/rubish/{}'.format(self.dest,self.new_name)
				else:
					target_dir = '{}/rubish'.format(self.dest)
					os.mkdir(target_dir)
					self.location = '{}/rubish/{}'.format(self.dest,self.new_name)
			else:
				if os.path.exists('{}/{}'.format(self.dest, self.year)):
					pass
				else:
					target_dir = '{}/{}'.format(self.dest, self.year)
					os.mkdir(target_dir)

				if os.path.exists('{}/{}/{}'.format(self.dest, self.year, self.month)):
					self.location = '{}/{}/{}/{}'.format(self.dest, self.year, self.month,self.new_name)
				else:
					target_dir = '{}/{}/{}'.format(self.dest, self.year, self.month)
					os.mkdir(target_dir)
					self.location = '{}/{}/{}/{}'.format(self.dest, self.year, self.month,self.new_name)

			shutil.move(self.dir_, self.location)


		except Exception as e:
			self.quit = True
			self.write_exception(e,"Mover")

	def write_exception(self, exceptionNote,func):
		if self.dev:
			print(str(exceptionNote) + " ::: "+func+"\n")
		with open("{}/exceptions.txt".format(output), "a") as fb:
			fb.write(str(exceptionNote) + " ::: "+func+"\n")

def outer_exception(exceptionNote,dev):
	if dev:
		print(str(exceptionNote)+"\n")
	with open("{}/exceptions.txt".format(output), "a") as fb:
		fb.write(str(exceptionNote) + "\n")

def makePaths():
	try:
		file_path = "{}/hashes.txt".format(output)
		if os.path.exists(file_path):
		    pass
		else:
		    with open(file_path, 'w') as fp:
		    	pass

		file_path = "{}/exceptions.txt".format(output)
		if os.path.exists(file_path):
		    pass
		else:
		    with open(file_path, 'w') as fp:
		    	pass

		file_path = "{}/Duplicates".format(output)
		if os.path.exists(file_path):
		    pass
		else:
		    os.mkdir(file_path)

		file_path = "{}/Unsorted".format(output)
		if os.path.exists(file_path):
		    pass
		else:
		    os.mkdir(file_path)
	except Exception as e:
		outer_exception(e,dev)
		sys.exit()

def sort_photos(dir_,output,photoNames,dev):
	types = ["png", "jpg", "JPG", "jpeg","CR2","cr2"]
	for name in photoNames:
			photo_location = "{}\\{}".format(dir_,name)
			if name.split(".")[1] in types:
				ext = name.split(".")[1]
				phin = photoNames.index(name)
				print(phin)
				perc = round((phin/len(photoNames)) * 100, 1)
				print("Photo number {} out of {}. {}%".format(phin+1, len(photoNames), perc))
				photo(name, photo_location, output, ext,dev)
			else:
				shutil.move(photo_location, "{}\\Unsorted\\{}".format(output, name))

def get_photos(dir_, output,dev):
	try:
		file_path = "{}/hashes.txt".format(output)
		photoNames = os.listdir(dir_)
		if len(photoNames) == 0:
			print("No photos in", dir_)
			sys.exit()
		print("Total number of photos to sort: {}".format(len(photoNames)))
		sort_photos(dir_,output,photoNames,dev)
		

	except Exception as e:
		outer_exception(e,dev)
		sys.exit()


print("*"*25)
print("Coby's Epic Photo Sorting Machine")
print("*"*25 + "\n")
dev = True if input("Would you like to enter devMode (y/n): ").lower() == "y" else False

if dev:
	enter = "C:\\Users\\cobyl\\Documents\\photosorter\\pho"
	output = "./con"
else:
	enter = input("Input Dir: ")
	output = input("Output Dir: ")

makePaths()
get_photos(enter, output, dev)
