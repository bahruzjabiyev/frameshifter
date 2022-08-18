import time,os,sys,json,re
import pathlib
from os import listdir
from os.path import isdir, isfile, join


####### Auxiliary functions
def Extract_Seed_byPar(string,par):
	if(par not in string):return -1

	cut=string.find(par)
	dim=len(par)
	end=string.find(" ",cut+dim)
	return string[cut+dim:end]

def Extract_Par_Value(string,par):
	if(par not in string and par.lower() not in string): return [-1]

	occ=string.count(par)
	if(occ>1):return [-2] #anomaly multiple parameters in the same request
	cut=string.find(par)
	
	#check also lower to make the parameter extraction case insensitive
	if(cut ==-1):
		cut=string.find(par.lower())
		occ=string.count(par.lower())
		if(occ>1):return [-2] #anomaly multiple parameters in the same request


	dim=len(par)+2 #plus the column and space
	end=string.find('\\r\\n',cut+dim) #separator of param \r\n \\to escape

	if(","in string[cut+dim:end]):
		return string[cut+dim:end].replace(" ","").split(",")
	else:
		return [string[cut+dim:end]]

#receives body and return tuple(result,[rawbytes],[restofbody])
def Extract_All_Rawbytes(data):
	if(data[0]==1):return data
	if(data[2]==''):return (-1,'','')
	
	if("\\x" in data[2]):
		cut=data[2].find("\\x")
		extract=data[2][cut:cut+4]
		return Extract_All_Rawbytes((0,[extract],data[2][:cut]+data[2][cut+4:]))
	else:
		return (1,data[1],data[2])

#receives body and return body modified
def Replace_All_Rawbytes(data):
	if(data==''):return ''
	
	if("\\x" in data):
		cut=data.find("\\x")
		return Replace_All_Rawbytes(data[:cut]+"X"+data[cut+4:])
	else:
		return data

##################



def Content_Length_Incomplete(lines,checkbody):
	Withbody=checkbody #modify this to report only anomaly with body

	parameters=["Content-Length","content-length","content-Length","Content-length"]
	anomalydict=dict()
	verbose=False

	for j in range(len(lines)):
		key=''.join(lines[j].split(";",1)[0])
		if(len(key.split("_"))>2):
			key=key.split("_",1)[1]
		else:
			key=key[2:]

		initialreq=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(req.split('\\r\\n\\r\\n',1)[0])+'\\r\\n'#split request and keep only the body
		if(len(req)<3):continue #not a valid request
		seed=Extract_Seed_byPar(req,"reqid=")
		if(verbose):print(f'\nWorking on req:{seed}')
		if(verbose):print("check param presence")
		found=False
		for j in parameters:
			if(j in req):found=True
		if(not found): continue #not found parameter
		if(verbose):print("param present")

		if(verbose):print("check double param in req")
		#check double parameter in req
		totalpar=0
		for p in parameters:
			totalpar+=req.count(p)
		
		if(totalpar>1):
			#analyze all param in req it can report multiple times the same req meaning that contains multiple anomalies
			print("multi parameters in req")
			posparameters=[]
		
			for t in parameters:
				for match in re.finditer(t,req):
					posparameters.append(match.start())

			for y in posparameters:
				bcut=req.rfind("\\r\\n",0,y)
				if(bcut==-1):
					print("unable to find begin of param name")
					continue
				ecut=req.find(": ",y)
				if(ecut==-1):
					print("unable to find end of param name")
					continue
				if(ecut-(bcut+4)>len(parameters[0])):continue #name of parameters with mutation
				
				#check if int value has an exception if so anomaly and continue otherwise verify matching body size
				fcut=req.find("\\r\\n",y)
				if(fcut==-1):
					print("unable to find end of value param")
					continue
				#check int value of param
				#take string and remove \t and space
				temp=req[ecut+2:fcut]
				temp=temp.replace("\\t","")
				temp=temp.replace(" ","")
				if("+" in temp or "-" in temp):
					#not reporting as anomaly here
					continue
				try:
					value=int(temp)
					if(verbose):print(f'value of int obtained:{value}')
				except Exception as e:
					print("exception in int value")
					#not reporting the anomaly
					continue

				#check body and CL
				body=''.join(initialreq.split('\\r\\n\\r\\n',1)[1])#split request and keep only the body
				if(verbose):print(f'len body:{len(body)} content body:{body}')
				body=body[:-2]#remove newline and final single quote
				if(verbose):print(f'len body:{len(body)} content body:{body}')

				if(len(body)==0 and value==0):
					continue
				elif(len(body)==0 and value>0):
					if(not Withbody):
						print("empty body anomaly")
						seed=Extract_Seed_byPar(req,"reqid=")
						if(key not in anomalydict.keys()):
							anomalydict[key]=[]
							anomalydict[key].append(seed)
						else:
							anomalydict[key].append(seed)
						
						continue
					else:
						#only report anomaly when there is a body
						continue

				
				body=body.replace('\\r','\r')
				body=body.replace('\\n','\n')
				if(verbose):print(f'After replacement len body:{len(body)} content body:{body}')

				result=Extract_All_Rawbytes((0,[],body))
				if(verbose):print(f'after extraction rawbytes result:{len(result)} content result:{result}')
				if(result[0]==-1):
					print("error in finding the raw bytes in body")
					continue

				bodysize=len(result[1])+len(result[2])
				if(verbose):print(f'content bodysize:{bodysize} and value:{value}')

				if(not bodysize==value):
					if(Withbody):
						seed=Extract_Seed_byPar(req,"reqid=")
						if(verbose):print(f'anamaly identified in req:{seed}')
						if(key not in anomalydict.keys()):
							anomalydict[key]=[]
							anomalydict[key].append(seed)
						else:
							anomalydict[key].append(seed)
					else:
						#only report when there is no body
						continue

		#no double param in request
		if(verbose):print("no double param in req")
		cut=-1
		for j in parameters:
			temp=req.find(j)
			if(temp>=0):
				cut=temp

		if(cut==-1):
			print("error in find parameter")
			continue

		bcut=req.rfind("\\r\\n",0,cut)
		if(bcut==-1):
			print("unable to find begin of param name")
			continue
		ecut=req.find(": ",cut)
		if(ecut==-1):
			print("unable to find end of param name")
			continue

		fcut=req.find("\\r\\n",cut)
		if(fcut==-1):
			print("unable to find end of value param")
			print(f'string from cut on:{req}')
			continue

		if(verbose):print(f'bcut:{bcut}, ecut:{ecut}, fcut:{fcut}')
		#check mutation in param name
		if(ecut-(bcut+4)>len(parameters[0])):
			print("parameter name mutated")
			continue
		else:
			#no mutation in parameter name
			if(verbose):print(f'req[bcut+4:ecut]:{req[bcut+4:ecut]}')
			if(req[bcut+4:ecut] not in parameters):
				print("content of parameter is wrong")
				continue
			if(verbose):print(f'test obtaining int from string:{req[ecut+2:fcut]}')
			#take string and remove \t and space
			temp=req[ecut+2:fcut]
			temp=temp.replace("\\t","")
			temp=temp.replace(" ","")
			if("+" in temp or "-" in temp):
				#not reporting this anomaly here
				continue
			try:
				value=int(temp)
				if(verbose):print(f'inside try value of int obtained:{value}')
			except Exception as e:
				print("exception in int value")
				#not reporting this anomaly here
				continue
			if(verbose):print(f'value of int obtained oustide try:{value}')
			#check body and CL
			body=''.join(initialreq.split('\\r\\n\\r\\n',1)[1])#split request and keep only the body
			if(verbose):print(f'len body:{len(body)} content body:{body}')
			body=body[:-2]#remove newline and final single quote
			if(verbose):print(f'len body:{len(body)} content body:{body}')

			if(len(body)==0 and value==0):
				continue
			elif(len(body)==0 and value>0):
				if(not Withbody):
					print("empty body anomaly")
					seed=Extract_Seed_byPar(req,"reqid=")
					if(verbose):print(f'seed with anoamly;{seed}')
					if(key not in anomalydict.keys()):
						anomalydict[key]=[]
						anomalydict[key].append(seed)
					else:
						anomalydict[key].append(seed)
					
					continue
				else:
					#only report anomaly when there is a body
					continue
			
			body=body.replace('\\r','\r')
			body=body.replace('\\n','\n')
			if(verbose):print(f'After replacement len body:{len(body)} content body:{body}')

			result=Extract_All_Rawbytes((0,[],body))
			if(verbose):print(f'after extraction rawbytes result:{len(result)} content result:{result}')
			if(result[0]==-1):
				print("error in finding the raw bytes in body")
				continue

			bodysize=len(result[1])+len(result[2])
			if(verbose):print(f'content bodysize:{bodysize} and value:{value}')

			if(not bodysize==value):
				if(Withbody):
					seed=Extract_Seed_byPar(req,"reqid=")
					if(verbose):print(f'anamaly identified in req:{seed}')
					if(key not in anomalydict.keys()):
						anomalydict[key]=[]
						anomalydict[key].append(seed)
					else:
						anomalydict[key].append(seed)
				else:
					#only report when there is no body
						continue


	return anomalydict


def Missing_Chunk_Data_Termination(data,verbose):
	#only reports as anomaly if the last chunk is missing return -1 otherwise 0

	if(verbose):print(f'len data:{len(data)} content data{data}')
	if(len(data)<5):return 0  #received a body size that could not have a right end anomaly--> missing last chunk

	sizecut=data.find('\r\n')
	if(verbose):print(f'content sizecut:{sizecut}')
	if(sizecut==-1):#anomaly no chunk content after size -->missing chunk data and separation size data
		return 0
	
	try:
		test=int(data[:sizecut],16)
		if(verbose):print(f'content test chunksize:{test}')
	except Exception as e:
		print(e)
		show=[]
		show.append(data)
		print(show)
		print("exception in size chunk means not good format")
		return 0

	chunksize=int(data[:sizecut], 16)
	if(verbose):print(f'content chunksize:{chunksize}')

	if(chunksize==0):
		termination=data.find('\r\n\r\n')
		if(verbose):print(f'content termination:{termination}')
		if(termination == -1):
			#ignore improper last chunk
			if(verbose):print(f'termination not found in remaining of the body:{data}')
			return 0 #anomaly not right termination of chunk
		#ignore trailer headers and other
		return 0

	#check if no data at all
	if(len(data[sizecut+2:])==0):#means no data after size -->missing chunk data
		#report as missing chunk data
		pass

	#check if there is data but nothing else so missing chuck data termination or missing part of chunk data
	if(len(data[sizecut+2:])==chunksize):#only chunckof data but -->missing chunk data termination
		return -1
	
	if(len(data[sizecut+2:])<chunksize):#missing part of data -->incomplete chunk data
		#report as missing chunk data termination?
		pass

	if(verbose):print(f'content chunksize:{chunksize}\ncontent sizecut:{sizecut}\ncontent chunksize+4+sizecut:{chunksize+4+sizecut}')
	if(verbose):print(f'applied to this len data:{len(data)} data content:{data}')
	if(verbose):
		look=[]
		look.append(data[(chunksize+4+sizecut):])
		print(f'next iterartion data len:{len(look)} data content:{look}')
	#check that I have enought data left
	if(len(data[chunksize+sizecut+2:])<2):#no enough data left for a last chunk
		return Missing_Chunk_Data_Termination(data[(chunksize+2+sizecut):],verbose)#+4 for separator size chunck and chunk next size +sizeof sizevalue		

	return Missing_Chunk_Data_Termination(data[(chunksize+4+sizecut):],verbose)#+4 for separator size chunck and chunk next size +sizeof sizevalue



def Missing_Last_Chunk(data,verbose):
	#only reports as anomaly if the last chunk is missing return -1 otherwise 0

	if(verbose):print(f'len data:{len(data)} content data{data}')
	if(len(data)<5):return -1  #received a body size that could not have a right end anomaly--> missing last chunk

	sizecut=data.find('\r\n')
	if(verbose):print(f'content sizecut:{sizecut}')
	if(sizecut==-1):#anomaly no chunk content after size -->missing chunk data and separation size data
		return 0
	
	try:
		test=int(data[:sizecut],16)
		if(verbose):print(f'content test chunksize:{test}')
	except Exception as e:
		print(e)
		show=[]
		show.append(data)
		print(show)
		print("exception in size chunk means not good format")
		return 0

	chunksize=int(data[:sizecut], 16)
	if(verbose):print(f'content chunksize:{chunksize}')

	if(chunksize==0):
		termination=data.find('\r\n\r\n')
		if(verbose):print(f'content termination:{termination}')
		if(termination == -1):
			#ignore improper last chunk
			if(verbose):print(f'termination not found in remaining of the body:{data}')
			return 0 #anomaly not right termination of chunk
		#ignore trailer headers and other
		return 0

	#check if no data at all
	if(len(data[sizecut+2:])==0):#means no data after size -->missing chunk data
		#report as missing chunk data
		pass

	#check if there is data but nothing else so missing chuck data termination or missing part of chunk data
	if(len(data[sizecut+2:])==chunksize):#only chunckof data but -->missing chunk data termination
		#report as missing chunk data termination
		pass
	
	if(len(data[sizecut+2:])<chunksize):#missing part of data -->incomplete chunk data
		#report as missing chunk data termination?
		pass

	if(verbose):print(f'content chunksize:{chunksize}\ncontent sizecut:{sizecut}\ncontent chunksize+4+sizecut:{chunksize+4+sizecut}')
	if(verbose):print(f'applied to this len data:{len(data)} data content:{data}')
	if(verbose):
		look=[]
		look.append(data[(chunksize+4+sizecut):])
		print(f'next iterartion data len:{len(look)} data content:{look}')
	#check that I have enought data left
	if(len(data[chunksize+sizecut+2:])<2):#no enough data left for a last chunk
		return Missing_Last_Chunk(data[(chunksize+2+sizecut):],verbose)#+4 for separator size chunck and chunk next size +sizeof sizevalue		

	return Missing_Last_Chunk(data[(chunksize+4+sizecut):],verbose)#+4 for separator size chunck and chunk next size +sizeof sizevalue



def Missing_ChunkData(data,verbose):
	#only reports if the chunk data is missing

	if(verbose):print(f'len data:{len(data)} content data{data}')
	#if(len(data)<5):return 0  #received a body size that could not have a right end anomaly--> missing last chunk

	sizecut=data.find('\r\n')
	if(verbose):print(f'content sizecut:{sizecut}')
	if(sizecut==-1):#anomaly no chunk content after size -->missing chunk data and separation size data
		return -1
	
	try:
		test=int(data[:sizecut],16)
		if(verbose):print(f'content test chunksize:{test}')
	except Exception as e:
		if(verbose):
			print(e)
			show=[]
			show.append(data)
			print(show)
			print("exception in size chunk means not good format")
		return 0

	chunksize=int(data[:sizecut], 16)
	if(verbose):print(f'content chunksize:{chunksize}')

	if(chunksize==0):
		termination=data.find('\r\n\r\n')
		if(verbose):print(f'content termination:{termination}')
		if(termination == -1):
			#ignore improper last chunk
			if(verbose):print(f'termination not found in remaining of the body:{data}')
			return 0 #anomaly not right termination of chunk
		#ignore trailer headers and other
		return 0

	#chunksize>0
	#check if no data at all
	if(len(data[sizecut+2:])==0):#means no data after size -->missing chunk data
		return -1
		pass

	#check if there is data but nothing else so missing chuck data termination or missing part of chunk data
	if(len(data[sizecut+2:])==chunksize):#only chunckof data but -->missing chunk data termination
		return 0 
		pass
	
	if(len(data[sizecut+2:])<chunksize):#missing part of data -->incomplete chunk data
		return 0 
		pass

	if(verbose):print(f'content chunksize:{chunksize}\ncontent sizecut:{sizecut}\ncontent chunksize+4+sizecut:{chunksize+4+sizecut}')
	if(verbose):print(f'applied to this len data:{len(data)} data content:{data}')
	if(verbose):
		look=[]
		look.append(data[(chunksize+4+sizecut):])
		print(f'next iterartion data len:{len(look)} data content:{look}')
	#check that I have enought data left
	if(len(data[chunksize+sizecut+2:])<=2):#no enough data left for a last chunk
		return Missing_ChunkData(data[(chunksize+2+sizecut):],verbose)#+4 for separator size chunck and chunk next size +sizeof sizevalue		

	return Missing_ChunkData(data[(chunksize+4+sizecut):],verbose)#+4 for separator size chunck and chunk next size +sizeof sizevalue


def Check_Chunked_Body(lines,checkanomaly):
	parameters=["Transfer-Encoding","transfer-encoding","transfer-Encoding","Transfer-encoding"]
	anomalydict=dict()
	verbose=False

	for j in range(len(lines)):
		key=''.join(lines[j].split(";",1)[0])
		if(len(key.split("_"))>2):
			key=key.split("_",1)[1]
		else:
			key=key[2:]

		initialreq=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(req.split('\\r\\n\\r\\n',1)[0])+'\\r\\n'#split request and keep only the body
		if(len(req)<3):continue #not a valid request

		seed=Extract_Seed_byPar(req,"reqid=")
		if(verbose):print(f'Working on req:{seed}')
		if(verbose):print("check param presence")
		found=False
		for j in parameters:
			if(j in req):found=True
		if(not found): continue #not found parameter
		if(verbose):print("param present")

		if(verbose):print("check double param in req")
		#check double parameter in req
		totalpar=0
		for j in parameters:
			totalpar+=req.count(j)
		
		if(totalpar>1):
			#analyze all param in req it can report multiple times the same req meaning that contains multiple anomalies
			if(verbose):print("multi parameters in req")
			posparameters=[]
		
			for j in parameters:
				for match in re.finditer(j,req):
					posparameters.append(match.start())

			for j in posparameters:
				bcut=req.rfind("\\r\\n",0,j)
				if(bcut==-1):
					print("unable to find begin of param name")
					continue
				ecut=req.find(": ",j)
				if(ecut==-1):
					print("unable to find end of param name")
					continue

				if(ecut-(bcut+4)>len(parameters[0])):
					#param name with mutation
					continue
					#ignore this case only look at unmutated headers name
				else:
					#check if value parameter is chunked and if properly chunked
					fcut=req.find("\\r\\n",j)
					if(fcut==-1):
						print("unable to find end of value param")
						continue
					#check chunked in param value and no mutation
					if("chunked" not in req[ecut+2:fcut]):continue #only process chuncked headers value
					temp=req[ecut+2:fcut]
					temp=temp.replace("\\t","")
					temp=temp.replace(" ","")

					if(len(temp)>len("chunked")):
						#mutated value of header ignore it
						continue
					else:
						#name not mutated and value not mutated
						if(verbose):print("No mutation in header name and value. check proper chunked")
						body=''.join(initialreq.split('\\r\\n\\r\\n',1)[1])#split request and keep only the body
						if(verbose):print(f'len body:{len(body)} content body:{body}')

						body=body[:-2]
						body=body.replace('\\r','\r')
						body=body.replace('\\n','\n')
						if(verbose):print(f'len body:{len(body)} content body:{body}')

						body=Replace_All_Rawbytes(body)

						if(verbose):print(f'len body:{len(body)} content body:{body}')		

						if(len(body)==0 and checkanomaly=="Missing_Chunked_Body"):
							if(verbose):print("FOUND empty body but chuncked")
							seed=Extract_Seed_byPar(req,"reqid=")
							if(key not in anomalydict.keys()):
								anomalydict[key]=[]
								anomalydict[key].append(seed)
							else:
								anomalydict[key].append(seed)
							continue
						elif(len(body)==0):
							#missing body but not lookign for missing chuncked body
							continue

						if(len(body)==0 and checkanomaly=="Missing_ChunkData"):
							continue
						if(len(body)<5 and checkanomaly=="Missing_Last_Chunk"):#ignore the body<4 means it has a size but not data 
							continue
						
						result= eval(checkanomaly+"(body,verbose)")
						
						if(verbose):print(f'result:{result}')
						
						if(result == -1):
							if(verbose):print("FOUND inconsistency in chunk")
							seed=Extract_Seed_byPar(req,"reqid=")
							if(key not in anomalydict.keys()):
								anomalydict[key]=[]
								anomalydict[key].append(seed)
							else:
								anomalydict[key].append(seed)
							continue
						if(verbose):print("properly chunked")
						continue

		#no double param in request
		if(verbose):print("no double param in req")
		cut=-1
		for j in parameters:
			temp=req.find(j)
			if(temp>=0):
				cut=temp

		if(cut==-1):
			print("error in find parameter")
			continue

		bcut=req.rfind("\\r\\n",0,cut)
		if(bcut==-1):
			print("unable to find begin of paramname")
			continue
		ecut=req.find(": ",cut)
		if(ecut==-1):
			print("unable to find end of param name")
			continue

		fcut=req.find("\\r\\n",cut)
		if(fcut==-1):
			print("unable to find end of value param")
			continue

		if(verbose):print(f'bcut:{bcut}, ecut:{ecut}, fcut:{fcut}')

		#check mutation in param name
		if(ecut-(bcut+4)>len(parameters[0])):
			#name of parameters with mutation do not consider it
			continue
		
		else:
			#no mutation in parameter name
			if(verbose):print(f'req[bcut+4:ecut]:{req[bcut+4:ecut]}')
			if("chunked" not in req[ecut+2:fcut]):continue #only process chuncked headers value
			temp=req[ecut+2:fcut]
			temp=temp.replace("\\t","")
			temp=temp.replace(" ","")

			if(len(temp)>len("chunked")):
				#mutated value of header do not consider it
				continue

			else:
				#name not mutated and value not mutated
				if(verbose):print("No mutation in header name and value. check proper chunked")
				body=''.join(initialreq.split('\\r\\n\\r\\n',1)[1])#split request and keep only the body
				if(verbose):print(f'len body:{len(body)} content body:{body}')

				body=body[:-2]
				body=body.replace('\\r','\r')
				body=body.replace('\\n','\n')
				if(verbose):print(f'after replace: len body:{len(body)} content body:{body}')

				body=Replace_All_Rawbytes(body)

				if(verbose):print(f'after raw bytes replace: len body:{len(body)} content body:{body}')		

				if(len(body)==0 and checkanomaly=="Missing_Chunked_Body"):
					if(verbose):print("FOUND body len 0 and chunked")
					seed=Extract_Seed_byPar(req,"reqid=")
					if(key not in anomalydict.keys()):
						anomalydict[key]=[]
						anomalydict[key].append(seed)
					else:
						anomalydict[key].append(seed)
					continue
				elif(len(body)==0):
					#missing body but not lookign for missing chuncked body
					##consider missing body as part of missing last chunked
					pass

				if(len(body)==0 and checkanomaly=="Missing_ChunkData"):
					continue

				if(len(body)<5 and checkanomaly=="Missing_Last_Chunk"):#ignore the body<4 means it has a size but not data
					##consider missing body as part of missing last chunked
					pass
					

				result= eval(checkanomaly+"(body,verbose)")
				
				if(verbose):print(f'result:{result}')
				
				if(result == -1):
					if(verbose):print("FOUND inconsistency in chunk")
					seed=Extract_Seed_byPar(req,"reqid=")
					if(key not in anomalydict.keys()):
						anomalydict[key]=[]
						anomalydict[key].append(seed)
					else:
						anomalydict[key].append(seed)
					continue
				if(verbose):print("properly chunked")
				continue

	return anomalydict


def Repeating_Header_Value_TE(lines):
	parameters=["Transfer-Encoding","transfer-encoding","transfer-Encoding","Transfer-encoding"]
	anomalydict=dict()
	verbose=False

	for j in range(len(lines)):
		key=''.join(lines[j].split(";",1)[0])
		if(len(key.split("_"))>2):
			key=key.split("_",1)[1]
		else:
			key=key[2:]

		req=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(req.split('\\r\\n\\r\\n',1)[0])+'\\r\\n'#split request and keep only the headers part
		if(len(req)<3):continue #not a valid request
		seed=Extract_Seed_byPar(req,"reqid=")
		print(f'Working on req:{seed}')
		if(verbose):print("check param presence")
		found=False
		for j in parameters:
			if(j in req):found=True
		if(not found): continue #not found parameter
		if(verbose):print("param present")

		if(verbose):print("check double param in req")
		#check double parameter in req
		totalpar=0
		for j in parameters:
			totalpar+=req.count(j)
		
		if(totalpar>1):
			#analyze all param in req it can report multiple times the same req meaning that contains multiple anomalies
			print("multi parameters in req")
			posparameters=[]
		
			for j in parameters:
				for match in re.finditer(j,req):
					posparameters.append(match.start())

			for j in posparameters:
				bcut=req.rfind("\\r\\n",0,j)
				if(bcut==-1):
					print("unable to find begin of param name")
					continue
				ecut=req.find(": ",j)
				if(ecut==-1):
					print("unable to find end of param name")
					continue

				if(ecut-(bcut+4)>len(parameters[0])):
					#param name with mutation ignore this case
					continue

				else:
					#check if value parameter is chunked and if properly chunked
					fcut=req.find("\\r\\n",j)
					if(fcut==-1):
						print("unable to find end of value param")
						continue
					#check chunked in param value and no mutation
					if("chunked" not in req[ecut+2:fcut]):continue #only process chuncked headers value
					temp=req[ecut+2:fcut]
					temp=temp.replace("\\t","")
					temp=temp.replace(" ","")

					if(fcut-(ecut+2)>(2*len("chunked")) and ","in temp ):#look at possible repeated value of param
						print("FOUND repeated value of param")
						seed=Extract_Seed_byPar(req,"reqid=")
						if(key not in anomalydict.keys()):
							anomalydict[key]=[]
							anomalydict[key].append(seed)
						else:
							anomalydict[key].append(seed)
						continue
					#no need to check body only repeated value of TE
					continue
					
		#no double param in request
		if(verbose):print("no double param in req")
		cut=-1
		for j in parameters:
			temp=req.find(j)
			if(temp>=0):
				cut=temp

		if(cut==-1):
			print("error in find parameter")
			continue

		bcut=req.rfind("\\r\\n",0,cut)
		if(bcut==-1):
			print("unable to find begin of paramname")
			continue
		ecut=req.find(": ",cut)
		if(ecut==-1):
			print("unable to find end of param name")
			continue

		fcut=req.find("\\r\\n",cut)
		if(fcut==-1):
			print("unable to find end of value param")
			continue

		if(verbose):print(f'bcut:{bcut}, ecut:{ecut}, fcut:{fcut}')

		#check mutation in param name
		if(ecut-(bcut+4)>len(parameters[0])):#name of parameters with mutation
			#ignore case where parameter name mutated
			continue
		
		#no mutation in parameter name
		else:
			if(verbose):print(f'req[bcut+4:ecut]:{req[bcut+4:ecut]}')
			if("chunked" not in req[ecut+2:fcut]):continue #only process chuncked headers value
			temp=req[ecut+2:fcut]
			temp=temp.replace("\\t","")
			temp=temp.replace(" ","")

			if(fcut-(ecut+2)>(2*len("chunked")) and ","in temp ):#look at possible repeated value of param
				print("FOUND repeated value of param")
				seed=Extract_Seed_byPar(req,"reqid=")
				if(key not in anomalydict.keys()):
					anomalydict[key]=[]
					anomalydict[key].append(seed)
				else:
					anomalydict[key].append(seed)
				continue
			#no need to check body only repeated value of TE
			continue

	return anomalydict

def Repeating_Header_name_CL(lines):
	#Check double CL with unmutated name
	#return the seed of anomaly requests, only check headers part ingoring the body part
	CLparam=["Content-Length","content-length","content-Length","Content-length"]
	anomalydict=dict()
	verbose=False

	for j in range(len(lines)):
		key=''.join(lines[j].split(";",1)[0])
		if(len(key.split("_"))>2):
			key=key.split("_",1)[1]
		else:
			key=key[2:]
		a=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(a.split('\\r\\n\\r\\n',1)[0])+'\\r\\n'#split request and keep only the header part add CRLF for end header
		if(len(req)<3):continue #not a valid request
		seed=Extract_Seed_byPar(req,"reqid=")
		if(verbose):print(f'Working on req:{seed}')
		if(verbose):print("check param presence")
		found=False
		for j in CLparam:
			if(j in req):found=True
		if(not found): continue #not found parameter
		if(verbose):print("param present")

		if(verbose):print("check double param in req")
		#check double parameter in req
		totalpar=0
		for j in CLparam:
			totalpar+=req.count(j)
		
		if(totalpar>1):
			#analyze all param in req it can report multiple times the same req meaning that contains multiple anomalies
			if(verbose):print("multi parameters in req")
			posparameters=[]
		
			for j in CLparam:
				for match in re.finditer(j,req):
					posparameters.append(match.start())

			for j in posparameters:
				bcut=req.rfind("\\r\\n",0,j)
				if(bcut==-1):
					print("unable to find begin of param name")
					continue
				ecut=req.find(": ",j)
				if(ecut==-1):
					print("unable to find end of param name")
					continue
				if(ecut-(bcut+4)>len(CLparam[0])):continue #param name with mutation
				#check second CL without mutation
				for t in posparameters:
					if(verbose):print("beginsecond internal loop")
					if(verbose):print(f'jpos:{j} t pos:{t}')
					if(t==j):continue #ignore the same parameter
					bcut2=req.rfind("\\r\\n",0,t)
					if(bcut2==-1):
						print("unable to find begin of param name")
						continue
					ecut2=req.find(": ",t)
					if(ecut2==-1):
						print("unable to find end of param name")
						continue
					if(ecut2-(bcut2+4)>len(CLparam[0])):continue #param name with mutation

					print("double CL without mutation anomaly detected")
					seed=Extract_Seed_byPar(req,"reqid=")
					if(key not in anomalydict.keys()):
						anomalydict[key]=[]
						anomalydict[key].append(seed)
					else:
						anomalydict[key].append(seed)
					continue


	return anomalydict

def Invalid_Value_CL(lines):
	parameters=["Content-Length","content-length","content-Length","Content-length"]
	anomalydict=dict()
	verbose=False

	for j in range(len(lines)):
		key=''.join(lines[j].split(";",1)[0])
		if(len(key.split("_"))>2):
			key=key.split("_",1)[1]
		else:
			key=key[2:]

		initialreq=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		req=''.join(req.split('\\r\\n\\r\\n',1)[0])+'\\r\\n'#split request and keep only the body
		if(len(req)<3):continue #not a valid request
		seed=Extract_Seed_byPar(req,"reqid=")
		if(verbose):print(f'\nWorking on req:{seed}')
		if(verbose):print("check param presence")
		found=False
		for j in parameters:
			if(j in req):found=True
		if(not found): continue #not found parameter
		if(verbose):print("param present")

		if(verbose):print("check double param in req")
		#check double parameter in req
		totalpar=0
		for p in parameters:
			totalpar+=req.count(p)
		
		if(totalpar>1):
			#analyze all param in req it can report multiple times the same req meaning that contains multiple anomalies
			print("multi parameters in req")
			posparameters=[]
		
			for t in parameters:
				for match in re.finditer(t,req):
					posparameters.append(match.start())

			for y in posparameters:
				bcut=req.rfind("\\r\\n",0,y)
				if(bcut==-1):
					print("unable to find begin of param name")
					continue
				ecut=req.find(": ",y)
				if(ecut==-1):
					print("unable to find end of param name")
					continue
				if(ecut-(bcut+4)>len(parameters[0])):continue #name of parameters with mutation
				
				#check if int value has an exception if so anomaly and continue otherwise verify matching body size
				fcut=req.find("\\r\\n",y)
				if(fcut==-1):
					print("unable to find end of value param")
					continue
				#check int value of param
				#take string and remove \t and space
				temp=req[ecut+2:fcut]
				temp=temp.replace("\\t","")
				temp=temp.replace(" ","")
				if("+" in temp or "-" in temp):
					print("value parameter invalid")
					seed=Extract_Seed_byPar(req,"reqid=")
					if(key not in anomalydict.keys()):
						anomalydict[key]=[]
						anomalydict[key].append(seed)
					else:
						anomalydict[key].append(seed)
					
					continue
				try:
					value=int(temp)
					if(verbose):print(f'value of int obtained:{value}')
				except Exception as e:
					print("exception in int value")
					print("value parameter invalid")
					seed=Extract_Seed_byPar(req,"reqid=")
					if(key not in anomalydict.keys()):
						anomalydict[key]=[]
						anomalydict[key].append(seed)
					else:
						anomalydict[key].append(seed)
					
					continue

				#no need to check the body just look at the value of param
				continue

		#no double param in request
		if(verbose):print("no double param in req")
		cut=-1
		for j in parameters:
			temp=req.find(j)
			if(temp>=0):
				cut=temp

		if(cut==-1):
			print("error in find parameter")
			continue

		bcut=req.rfind("\\r\\n",0,cut)
		if(bcut==-1):
			print("unable to find begin of param name")
			continue
		ecut=req.find(": ",cut)
		if(ecut==-1):
			print("unable to find end of param name")
			continue

		fcut=req.find("\\r\\n",cut)
		if(fcut==-1):
			print("unable to find end of value param")
			print(f'string from cut on:{req}')
			continue

		if(verbose):print(f'bcut:{bcut}, ecut:{ecut}, fcut:{fcut}')
		#check mutation in param name
		if(ecut-(bcut+4)>len(parameters[0])):
			print("parameter name mutated")
			continue
		else:
			#no mutation in parameter name
			if(verbose):print(f'req[bcut+4:ecut]:{req[bcut+4:ecut]}')
			if(req[bcut+4:ecut] not in parameters):
				print("content of parameter is wrong")
				continue
			if(verbose):print(f'test obtaining int from string:{req[ecut+2:fcut]}')
			#take string and remove \t and space
			temp=req[ecut+2:fcut]
			temp=temp.replace("\\t","")
			temp=temp.replace(" ","")
			if("+" in temp or "-" in temp):
				seed=Extract_Seed_byPar(req,"reqid=")
				if(verbose):print(f'seed with anoamly;{seed}')
				if(key not in anomalydict.keys()):
					anomalydict[key]=[]
					anomalydict[key].append(seed)
				else:
					anomalydict[key].append(seed)
				continue

			try:
				value=int(temp)
				if(verbose):print(f'inside try value of int obtained:{value}')
			except Exception as e:
				print("exception in int value")
				seed=Extract_Seed_byPar(req,"reqid=")
				if(verbose):print(f'seed with anoamly;{seed}')
				if(key not in anomalydict.keys()):
					anomalydict[key]=[]
					anomalydict[key].append(seed)
				else:
					anomalydict[key].append(seed)
				
				continue
			#no need to check the body only parameter value
			continue


	return anomalydict

def Check_CL_Mutation_SingleReq(line):
	#return 1 if no mutation of 0 if mutation in req -1 if not present parameters
	parameters=["Content-Length","content-length","content-Length","Content-length"]
	verbose=False

	j=line

	initialreq=''.join(j.split(";",1)[1])#split request and keep only second part
	req=''.join(j.split(";",1)[1])#split request and keep only second part
	req=''.join(req.split('\\r\\n\\r\\n',1)[0])#split request and keep only the body
	if(len(req)<3):return 0 #not a valid request
	seed=Extract_Seed_byPar(req,"reqid=")
	if(verbose):print(f'\nWorking on req:{seed}')
	if(verbose):print("check param presence")
	found=False
	for j in parameters:
		if(j in req):found=True
	if(not found): return -1 #not found parameter
	if(verbose):print("param present")

	if(verbose):print("check double param in req")
	#check double parameter in req
	totalpar=0
	for p in parameters:
		totalpar+=req.count(p)
	
	if(totalpar>1):
		mutatedpar=0
		#check all parameters if one without mutation analyze it
		print("multi parameters in req")
		posparameters=[]
	
		for t in parameters:
			for match in re.finditer(t,req):
				posparameters.append(match.start())

		for y in posparameters:
			bcut=req.rfind("\\r\\n",0,y)
			if(bcut==-1):
				print("unable to find begin of param name")
				return 0
			ecut=req.find(": ",y)
			if(ecut==-1):
				print("unable to find end of param name")
				return 0
			if(ecut-(bcut+4)>len(parameters[0])):
				if(verbose):print("found param with mutated name")
				mutatedpar+=1 #name of parameters with mutation
		
		if(mutatedpar>=totalpar):
			if(verbose):print(f'all param with mutation mutatedpar:{mutatedpar}, totalpar:{totalpar}')
			return 0
		else:
			if(verbose):print(f'good request not all param with mutation mutatedpar:{mutatedpar}, totalpar:{totalpar}')
			return 1 #double parameter but one with no mutations

	#no double param in request
	if(verbose):print("no double param in req")
	cut=-1
	for j in parameters:
		temp=req.find(j)
		if(temp>=0):
			cut=temp

	if(cut==-1):
		print("error in find parameter")
		return 0

	bcut=req.rfind("\\r\\n",0,cut)
	if(bcut==-1):
		print("unable to find begin of paramname")
		return 0
	ecut=req.find(": ",cut)
	if(ecut==-1):
		print("unable to find end of param name")
		return 0

	fcut=req.find("\\r\\n",cut)
	if(fcut==-1):
		print("unable to find end of value param")
		return 0

	if(verbose):print(f'bcut:{bcut}, ecut:{ecut}, fcut:{fcut}')
	#check mutation in param name
	if(ecut-(bcut+4)>len(parameters[0])):
		print("parameter name mutated")
		return 0
	else:
		#no mutation in parameter name
		return 1
	if(verbose):print("if here there has been a problem check program")
	return 0



def Check_TE_Mutation_SingleReq(line):
	#return 1 if no mutation of 0 if mutation in req -1 if not present parameters
	parameters=["Transfer-Encoding","transfer-encoding","transfer-Encoding","Transfer-encoding"]
	verbose=False

	j=line

	initialreq=''.join(j.split(";",1)[1])#split request and keep only second part
	req=''.join(j.split(";",1)[1])#split request and keep only second part
	req=''.join(req.split('\\r\\n\\r\\n',1)[0])#split request and keep only the body
	if(len(req)<3):return 0 #not a valid request
	seed=Extract_Seed_byPar(req,"reqid=")
	if(verbose):print(f'\nWorking on req:{seed}')
	if(verbose):print("check param presence")
	found=False
	for j in parameters:
		if(j in req):found=True
	if(not found): return -1 #not found parameter
	if(verbose):print("param present")

	if(verbose):print("check double param in req")
	#check double parameter in req
	totalpar=0
	for p in parameters:
		totalpar+=req.count(p)
	
	if(totalpar>1):
		mutatedpar=0
		#check all parameters if one without mutation analyze it
		print("multi parameters in req")
		posparameters=[]
	
		for t in parameters:
			for match in re.finditer(t,req):
				posparameters.append(match.start())

		for y in posparameters:
			bcut=req.rfind("\\r\\n",0,y)
			if(bcut==-1):
				print("unable to find begin of param name")
				return 0
			ecut=req.find(": ",y)
			if(ecut==-1):
				print("unable to find end of param name")
				return 0
			if(ecut-(bcut+4)>len(parameters[0])):
				if(verbose):print("found param with mutated name")
				mutatedpar+=1 #name of parameters with mutation
		
		if(mutatedpar>=totalpar):
			if(verbose):print(f'all param with mutation mutatedpar:{mutatedpar}, totalpar:{totalpar}')
			return 0
		else:
			if(verbose):print(f'good request not all param with mutation mutatedpar:{mutatedpar}, totalpar:{totalpar}')
			return 1 #double parameter but one with no mutations

	#no double param in request
	if(verbose):print("no double param in req")
	cut=-1
	for j in parameters:
		temp=req.find(j)
		if(temp>=0):
			cut=temp

	if(cut==-1):
		print("error in find parameter")
		return 0

	bcut=req.rfind("\\r\\n",0,cut)
	if(bcut==-1):
		print("unable to find begin of paramname")
		return 0
	ecut=req.find(": ",cut)
	if(ecut==-1):
		print("unable to find end of param name")
		return 0

	fcut=req.find("\\r\\n",cut)
	if(fcut==-1):
		print("unable to find end of value param")
		return 0

	if(verbose):print(f'bcut:{bcut}, ecut:{ecut}, fcut:{fcut}')
	#check mutation in param name
	if(ecut-(bcut+4)>len(parameters[0])):
		print("parameter name mutated")
		return 0
	else:
		#no mutation in parameter name
		return 1
	if(verbose):print("if here there has been a problem check program")
	return 0



def Invalid_Header_Termination(lines):
	#only consider request that has not mutated parameters
	anomalydict=dict()
	verbose=False

	for j in range(len(lines)):

		key=''.join(lines[j].split(";",1)[0])
		if(len(key.split("_"))>2):
			key=key.split("_",1)[1]
		else:
			key=key[2:]

		req=''.join(lines[j].split(";",1)[1])#split request and keep only second part
		seed=Extract_Seed_byPar(req,"reqid=")
		if(verbose):print(f'work on req={seed}')
		#check no mutation in req
		testcl=Check_CL_Mutation_SingleReq(lines[j])
		testTE=Check_TE_Mutation_SingleReq(lines[j])
		if(verbose):print(f'result mutation of TE:{testTE}\nresult mutation of CL:{testcl}')
		#ignore request with content lenght ot transfer encoding name mutated
		#exclude CL-1 and TE-1
		if(testcl==-1 and testTE>0):
			if(not testTE):continue
		elif(testTE==-1 and testcl>0):
			if(not testcl):continue
		elif(testTE==-1 and testcl==-1):
			if(verbose):print(f'both param not valid')
			continue
		else:
			if(not testcl and not testTE):continue

		if('\\r\\n\\r\\n' not in req):
			#not correct separation of last header and body
			print("FOUND anomaly in headers separation")
			seed=Extract_Seed_byPar(req,"reqid=")
			if(key not in anomalydict.keys()):
				anomalydict[key]=[]
				anomalydict[key].append(seed)
			else:
				anomalydict[key].append(seed)
			continue

		req=''.join(req.split('\\r\\n\\r\\n',1)[0])+'\\r\\n'#split request and keep only the headers part
		if(verbose):print(f'len req={len(req)}')
		if(len(req)<3):continue #not a valid request
		
		pos=[]
		for i in range(len(req)):
			if(req[i]==":"):
				pos.append(i)
		
		#check for :: in request and drop the first : since :: result of mutation 
		pos.sort()
		if(verbose):print(f'position :{pos}')
		remove=[]
		for j in range(len(pos)):
			if(j<(len(pos)-2)):
				if(pos[j+1]-pos[j]==1):
					if(verbose):print(f'remove because of mutation:{pos}')
					remove.append(j)
					seed=Extract_Seed_byPar(req,"reqid=")
		
		if(len(remove)>0):
			if(verbose):print(f'remove>0')
			for r in remove:
				pos.pop(r)

		#check at least a \r\n before or after :
		##needs to check that if content lenght is the param it doesn not have mutation
		for i in range(len(pos)):
			#search before
			if(i>0 and i<(len(pos)-2)):
				#there is an element before and after
				#check param is content leght and no mutation
				if(req.rfind('\\r\\n',pos[i-1],pos[i])<0):
					if(verbose):print(f'i:{i} i>0 and i<len(pos)-2:found after{req[pos[i-1]:pos[i]]}')
					if(req.find('\\r\\n',pos[i],pos[i+1])<0):
						if(verbose):print(f'i:{i} i>0 and i<len(pos)-2:found before{req[pos[i]:pos[i+1]]}')
						print("FOUND anomaly in separator param")
						seed=Extract_Seed_byPar(req,"reqid=")
						if(key not in anomalydict.keys()):
							anomalydict[key]=[]
							anomalydict[key].append(seed)
						else:
							anomalydict[key].append(seed)
						continue
			elif(i<1):
				#there is only an element after
				if(req.rfind('\\r\\n',0,pos[i])<0):
					if(verbose):print(f'i:{i} i<1 found after{req[pos[i-1]:pos[i]]}')
					if(req.find('\\r\\n',pos[i],pos[i+1])<0):
						print("FOUND anomaly in separator param")
						seed=Extract_Seed_byPar(req,"reqid=")
						if(key not in anomalydict.keys()):
							anomalydict[key]=[]
							anomalydict[key].append(seed)
						else:
							anomalydict[key].append(seed)
						continue
			elif(i==(len(pos)-1)):
				#there is only an element before
				if(req.rfind('\\r\\n',pos[i-1],pos[i])<0):
					if(verbose):print(f'i:{i} i==len(pos)-1found after{req[pos[i-1]:pos[i]]}')
					if(req.find('\\r\\n',pos[i])<0):
						print("FOUND anomaly in separator param")
						seed=Extract_Seed_byPar(req,"reqid=")
						if(key not in anomalydict.keys()):
							anomalydict[key]=[]
							anomalydict[key].append(seed)
						else:
							anomalydict[key].append(seed)
						continue

			
	return anomalydict

#run command: python Anomalydetection.py exp_folder Server_to_check Anomalies_to_check
#example: python Anomalydetection.py exp1.0 all all  -->test all anomalies for all the servers included in the exp1.0 folder

if __name__ == "__main__":
	start_time = time.time()
	Exp_folder=sys.argv[1]
	Server_check=sys.argv[2]
	Anomaly=[]
	Anomaly.append(sys.argv[3])

	CDNs=["fastly","akamai","cloudflare","cloudfront"]
	Path_Exp=join(os.getcwd(),Exp_folder)
	if(Server_check!="all"):
		Analysis_Folder = [f for f in listdir(join(os.getcwd(),Exp_folder)) if(isdir(join(Path_Exp, f)) and f.split("-")[0]== Server_check)]
		if(len(Analysis_Folder)==0):
			print("Server name error")
			exit()
	else:
		Analysis_Folder = [f for f in listdir(join(os.getcwd(),Exp_folder)) if isdir(join(Path_Exp, f))]

	#dict[folder]=[files] to be analyzed--only requests file considered
	Inspect=dict()
	for a in Analysis_Folder:
		Inspect[join(Path_Exp,a)]=[f for f in listdir(join(Path_Exp,a)) if(isfile(join(join(Path_Exp,a), f)) and "requests" in f)]
	
	#order file list
	for key in Inspect.keys():
		if(Inspect[key][0].split("-")[0] in CDNs):continue #no need to order file for CDNs
		if("-" in Inspect[key][0]):continue #no need to order file for CDNs
		Inspect[key]= sorted(Inspect[key], key=lambda x: (x[0],int(x[8:-4])))

	if(Anomaly[0] == "all"):
		Anomaly=["Content_Length_Incompletewithbody","Content_Length_Incompletewithoutbody",
		"Check_Chunked_Body_Missing_ChunkData","Check_Chunked_Body_Missing_Chunk_Data_Termination","Check_Chunked_Body_Missing_Last_Chunk",
		"Repeating_Header_Value_TE","Repeating_Header_name_CL","Invalid_Value_CL","Invalid_Header_Termination"
		]

	dictionaybuff=dict()

	for key in Inspect.keys():
		print(f'Inspect folder:{key}')
		
		for a in Anomaly:
			print(f'Anomaly:{a}')
			dictionaybuff=dict()
			
			for f in Inspect[key]:
				print(f'File:{f}')
				if(not os.path.isfile(join(key,f))):exit()

				with open(join(key,f)) as t:
					Loglines=t.readlines()
				try:
					if(a=="Content_Length_Incompletewithoutbody"):
						inconsistency_seed= eval("Content_Length_Incomplete"+"(Loglines,False)")
					elif(a=="Content_Length_Incompletewithbody"):
						inconsistency_seed= eval("Content_Length_Incomplete"+"(Loglines,True)")
					elif(a=="Check_Chunked_Body_Missing_ChunkData"):
						check="Missing_ChunkData"
						b="Check_Chunked_Body"
						inconsistency_seed= eval(b+"(Loglines,check)")
					elif(a=="Check_Chunked_Body_Missing_Chunk_Data_Termination"):
						check="Missing_Chunk_Data_Termination"
						b="Check_Chunked_Body"
						inconsistency_seed= eval(b+"(Loglines,check)")
					elif(a=="Check_Chunked_Body_Missing_Last_Chunk"):
						check="Missing_Last_Chunk"
						b="Check_Chunked_Body"
						inconsistency_seed= eval(b+"(Loglines,check)")
					else:
						inconsistency_seed= eval(a+"(Loglines)")
				except NameError:
					print("wrong function name")
					exit()
				if(len(inconsistency_seed.keys())>0):
					print(f'inconsistency seeds #:{str(len(inconsistency_seed))}')

				for k in inconsistency_seed.keys():
					if(k not in dictionaybuff.keys()):
						dictionaybuff[k]=[]
						dictionaybuff[k].extend(inconsistency_seed[k])
					else:
						dictionaybuff[k].extend(inconsistency_seed[k])
		
			print("Save to unique file")
			#save to unique file the seed
			server=key.split("/")[-1].split("-")[0]
			if(a=="Content_Length_Incompletewithbody"):
				name=server+"-Seed-Anomalies-TOTAL-"+"Content_Length_Incomplete"+"-Withbody"
			elif(a=="Content_Length_Incompletewithoutbody"):
				name=server+"-Seed-Anomalies-TOTAL-"+"Content_Length_Incomplete"+"-Withoutbody"
			elif(a=="Check_Chunked_Body_Missing_Last_Chunk"):
				name=server+"-Seed-Anomalies-TOTAL-"+"Missing_Last_Chunk"
			elif(a=="Check_Chunked_Body_Missing_Chunk_Data_Termination"):
				name=server+"-Seed-Anomalies-TOTAL-"+"Missing_Chunk_Data_Termination"
			elif(a=="Check_Chunked_Body_Missing_ChunkData"):
				name=server+"-Seed-Anomalies-TOTAL-"+"Missing_ChunkData"
			else:
				name=server+"-Seed-Anomalies-TOTAL-"+a
			
			with open(key+"/"+name, 'w') as f:
				json.dump(dictionaybuff,f)
	
	print("--- %s seconds ---" % (time.time() - start_time))
