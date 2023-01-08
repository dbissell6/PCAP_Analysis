import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import datetime
from scipy import stats
from sklearn.ensemble import IsolationForest
import json
import subprocess
import binascii
import math
import string
import argparse
import plotly.graph_objects as go
from colorama import init, Fore, Back, Style
import base64
from scapy.all import *
from scapy.layers.http import HTTP

###
#Pcap illuminifier 
##
parser = argparse.ArgumentParser(description="PCAP analysis only mandatory arg is -f a pcap file")
parser.add_argument("-f", dest='pcap',help='PCAP file')
parser.add_argument("-p", dest='phrase',help='Add an additional fishy phrase to search for. If in HTB CTF, use HTB', default='')
args = parser.parse_args()

##################################################################################################################
### Get a seed list of features protocol independent and output dataframe
# Read in the PCAP file
packets = rdpcap(args.pcap)

# Create an empty list to store the data
data = []

# Iterate through each packet and extract the desired fields
for index,packet in enumerate(packets):
    frame_number = index+1
    time = packet.time
    protocols = packet.lastlayer().name
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        length = packet[IP].len
    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst
        length = packet[IPv6].plen
    else:
        src = '0'
        dst = '0'
        length = 0
    # Append the extracted data to the list
    data.append([frame_number, time, src, dst, protocols, length])

# Convert the data to a DataFrame
df = pd.DataFrame(data, columns=["Frame Number","Time", "Source IP", "Destination IP","Protocol","Length"])

# Set the "Frame Number" column as the index
df = df.set_index("Frame Number")


##################################################################################################################
###Get more features 

def get_ports(packet):
    try:
        # try to get the ports from the TCP layer
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    except:
        try:
            # If the TCP layer is not present, try to get the ports from the UDP layer
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
                
        except:
           # If the packet does not have a TCP or UDP layer, set the ports to None
            src_port = None
            dst_port = None
    return src_port, dst_port


### second run through with more diffcult fields to extract and parse with scapy 
for index,packet in enumerate(packets):
    #Add ports
    df.loc[int(index), 'src_port'],df.loc[int(index), 'dst_port']= get_ports(packet)
 
    
##### using tshark jsons

def get_ftp_request():
  # Run the TShark command and capture the other output
  output = subprocess.run(['tshark', '-r', args.pcap, '-Y', 'ftp.request', '-T', 'json'], capture_output=True)
  if output:
    # Load the JSON output into a Python object
    output_json = json.loads(output.stdout)
    # Add column to original df
    df['ftp.request'] = ''

    # Iterate over the list of frames    
    for frame in output_json:
      # Process the frame data here
      # Search the JSON dictionary for the strings
      #
      frame_number = frame['_source']['layers']['frame']['frame.number']
      try:
        my_dict = frame['_source']['layers']['ftp']
        for key, value in my_dict.items():
          if key != 'ftp.request' and key != 'ftp.response':
            if 'ftp.request.command' in value:
              df.loc[int(frame_number), 'ftp.request.command']= value['ftp.request.command']
            if 'ftp.request.arg' in value:
              df.loc[int(frame_number), 'ftp.request.arg']= value['ftp.request.arg']
      except:
        pass
def get_ftp_response():
  # Run the TShark command and capture the other output
  output = subprocess.run(['tshark', '-r', args.pcap, '-Y', 'ftp.response', '-T', 'json'], capture_output=True)
  if output:
    # Load the JSON output into a Python object
    output_json = json.loads(output.stdout)
    # Add column to original df
    df['ftp.response'] = ''

    # Iterate over the list of frames    
    for frame in output_json:
      # Process the frame data here
      # Search the JSON dictionary for the strings
      #
      frame_number = frame['_source']['layers']['frame']['frame.number']
      try:
        my_dict = frame['_source']['layers']['ftp']
        for key, value in my_dict.items():
          if key != 'ftp.request' and key != 'ftp.response':
            if 'ftp.response.command' in value:
              df.loc[int(frame_number), 'ftp.response.code']= value['ftp.response.code']
            if 'ftp.response.arg' in value:
              df.loc[int(frame_number), 'ftp.request.arg']= value['ftp.response.arg']
      except:
        pass

def get_http_request():
  # Run the TShark command and capture the other output
  output = subprocess.run(['tshark', '-r', args.pcap, '-Y', 'http.request', '-T', 'json'], capture_output=True)
  if output:
    # Load the JSON output into a Python object
    output_json = json.loads(output.stdout)
    # Add column to original df
    df['http.request'] = ''
    df['http.request.method']=''
    df['http.request.full.uri']=''

    # Iterate over the list of frames    
    for frame in output_json:
      # Process the frame data here
      # Search the JSON dictionary for the strings
      frame_number = frame['_source']['layers']['frame']['frame.number']
      try:
        my_dict = frame['_source']['layers']['http']
        for key, value in my_dict.items():
          
          if '_ws.expert' in value:
            try:
              #print(value['http.request.method'])
              df.loc[int(frame_number), 'http.request.method']= value['http.request.method']
            except:
              pass
          if 'http.request.full_uri' in my_dict:
            df.loc[int(frame_number), 'http.request.full.uri']= value['http.request.full.uri']
      except:
        pass

def get_http_response():
  # Run the TShark command and capture the other output
  output = subprocess.run(['tshark', '-r', args.pcap, '-Y', 'http.response', '-T', 'json'], capture_output=True)
  if output:
    # Load the JSON output into a Python object
    output_json = json.loads(output.stdout)
    # Add column to original df
    df['http.response'] = ''
    df['http.response.code'] = ''
    df['http.response_for.uri']=''

    # Iterate over the list of frames    
    for frame in output_json:
      # Process the frame data here
      # Search the JSON dictionary for the strings
      #
      frame_number = frame['_source']['layers']['frame']['frame.number']
      try:
        my_dict = frame['_source']['layers']['http']
        for key, value in my_dict.items():
          #print(key,'*******',value)
          if '_ws.expert' in value:
            try:
              df.loc[int(frame_number), 'http.response.code']= value['http.response.code']
            except:
              pass
        if 'http.response_for.uri' in my_dict:
          df.loc[int(frame_number), 'http.response_for.uri']= value['http.response_for.uri']
      except:
        pass




def get_http_file_data():
	result = subprocess.run(["tshark", "-r", args.pcap, "-T", "fields", "-e", "frame.number","-e", "http.file_data"], capture_output=True)
	# Have to remove newlines and tabs in the file data or it will break the parsing
	modified_output = result.stdout.decode().replace('\\n','newline')
	modified_output = modified_output.replace('\\t','tab')
	modified_output = modified_output.replace('\t',', " "')
	#modified_output = modified_output.replace(',','comma')
	# Add column to original df
	df['http.file_data'] = ''
	lines = modified_output.splitlines()
	
	for line in lines:
	  #print(line)
	  try:
	    line2 = line.split(',',maxsplit=1)
	    #print(len(line2[1]))
	    if len(line2[1]) > 4:
	      #print(line2[0],' ',line2[1])
	      df.loc[int(line2[0]), "http.file_data"] = line2[1]
	  except:
	    pass

def get_smb():
  # Run the TShark command and capture the other output
  output = subprocess.run(['tshark', '-r', args.pcap, '-Y', 'smb', '-T', 'json'], capture_output=True)
  if output:
    # Load the JSON output into a Python object
    output_json = json.loads(output.stdout)
    # Add column to original df
    df['smb.cmd'] = ''

    # Iterate over the list of frames    
    for frame in output_json:
      # Extract frame number and smb command
      frame_number = frame['_source']['layers']['frame']['frame.number']
      smb = frame['_source']['layers']['smb']['SMB Header']['smb.cmd']
      try:
          df.loc[int(frame_number), 'smb.cmd']= smb
      except:
          pass

def get_data():
  # Run the TShark command and capture the other output
  output = subprocess.run(['tshark', '-r', args.pcap, '-T', 'json','-e','frame.number', '-e', 'data'], capture_output=True)
  if output:
    # Load the JSON output into a Python object
    output_json = json.loads(output.stdout)
    # Add column to original df
    df['data'] = ''
    #convert hex string to ascii string
    def hex_to_ascii(hex_string):
      return bytearray.fromhex(hex_string).decode()

    # Iterate over the list of frames    
    for frame in output_json:
      try:
        # Extract frame number and data
        frame_number = frame['_source']['layers']['frame.number']
        data = frame['_source']['layers']['data']
        ascii_string = hex_to_ascii(data[0])
        df.loc[int(frame_number[0]), 'data']= ascii_string
      except:
          pass

def get_dns():
  # Run the TShark command and capture the other output
  output = subprocess.run(['tshark', '-r', args.pcap, '-T', 'json','-e','frame.number', '-e', 'data'], capture_output=True)
  if output:
    # Load the JSON output into a Python object
    output_json = json.loads(output.stdout)
    # Add column to original df
    df['data'] = ''
    #convert hex string to ascii string
    def hex_to_ascii(hex_string):
      return bytearray.fromhex(hex_string).decode()

    # Iterate over the list of frames    
    for frame in output_json:
      try:
        # Extract frame number and data
        frame_number = frame['_source']['layers']['frame.number']
        data = frame['_source']['layers']['data']
        ascii_string = hex_to_ascii(data[0])
        df.loc[int(frame_number[0]), 'data']= ascii_string
      except:
          pass
################################################################################################################################################################################
################################################################################################################################################################################ 
def find_fishy_phrases():      
# scan content for fishy phrases
# if content matches a fishy phrase add a new column to that row with the phrase

    Search_words = ["<!ENTITY",'whoami','echo','admin','root','hostname','pwd','nc64.exe','user','pass','PASS', 'atob', 'auth','denied','login','usr','success','psswd','pw','logon','key','cipher','sum','token','pin','code','fail','correct','restrict']                 
    
    # Add user fishy phrase
    if args.phrase != '':
        Search_words.append(args.phrase)
        print('')
        print('A fishy phrase was added: '+args.phrase)
        # Add variations to the phrase(base64 encoded...)
        # Encode the string
        encoded_string = str(base64.b64encode(args.phrase.encode('utf-8')))
        Search_words.append(encoded_string)
    
    to_search=['http.file_data','ftp.request.arg','ftp.request.command','data']
    to_search=[x for x in to_search if x in df.columns]
    for col in to_search:         
       
   # Iterate over the rows in the dataframe
      for index, row in df.iterrows():
      # Split the 'to_search' column into a list of words
        words = str(row[col])
      
      # Check if any of the search words are in the Search_words list
        to_add=[]
        for search_word in Search_words:
          if search_word in words:
          # add the matching word to a list
            to_add.append(search_word)
        #convert list to single string
        s = ', '.join(to_add)
        #Add string value to the row at the new .fishy column
        df.loc[int(index), col+'.fishy']= s
           

##################################################################################################################    
### Fix columns of original dataframe
### Time
def fix_time():
	# Subtract the value of the first row from all the rows in the time column
	df["Time"] = df["Time"] - df["Time"].iloc[0]
	# Get the minimum and maximum values of the 'col' column
	min_val = df['Time'].min()
	max_val = df['Time'].max()
	#print(df.head())
	# Convert the minimum and maximum values to datetime objects
	min_time = min_val
	max_time = max_val
	# Calculate the difference
	difference = max_time - min_time
	df['Time'] = pd.to_numeric(df['Time'])
	return difference

### IPs
def fix_IPs():
	# Get the total number of unique "Source IP" addresses
	num_unique_source_ips = df["Source IP"].nunique()
	# Get the frequency of each "Source IP" address
	source_ip_counts = df["Source IP"].value_counts()

	# Get the frequency of each "Destination IP" address
	destination_ip_counts = df["Destination IP"].value_counts()
	# Get the total number of unique "Destination IP" addresses
	num_unique_destination_ips = df["Destination IP"].nunique()


	# Combine the lists of source and destination IP addresses into a single list
	all_ips = source_ip_counts.index.tolist() + destination_ip_counts.index.tolist()
	# Convert the list to a set to remove any duplicate entries
	unique_ips = set(all_ips)
	# Create an empty list to store the IP addresses and their frequency
	ip_list = []
	# Loop through the unique IP addresses
	for ip in unique_ips:
		# Initialize the frequency to 0
		frequency = 0
	    
		# If the IP address is in the source IP list, add its frequency to the total frequency
		if ip in source_ip_counts.index:
			frequency += source_ip_counts[ip]
	    
	    # If the IP address is in the destination IP list, add its frequency to the total frequency
		if ip in destination_ip_counts.index:
			frequency += destination_ip_counts[ip]
	    
	    # Add the IP address and its frequency to the list
		ip_list.append((ip, frequency))
	    
	return ip_list
##################################################################################################################        
###Begin printing and outputing data

# Initialize colorama
init()

### print multicolors
colors = [1, 11, 41, 14, 27, 57]

# Define the string to color
string="""
******************************************************************************************************************************************************
******************************************************************************************************************************************************
***********************ti,:**********************************************ti,:**********************************************ti,:***********************
********************f)::, (*******************************************f)::, (*******************************************f)::, (***********************
*******************(,:t*.i*******************************************(,:t*.i*******************************************(,:t*.i************************
******************;.(***,:******************************************;.(***,:******************************************;.(***,:************************
*****************;.f****t,:(f**************************************;.f****t,:(f**************************************;.f****t,:(f*********************
****************( t*******(::it***********************************( t*******(::it***********************************( t*******(::it*******************
****************,:**********fi,;f*********************************,:**********fi,;f*********************************,:**********fi,;f*****************
*************(ff )************f,,f*****************************(ff )************f,,f*****************************(ff )************f,,f****************
************; ,f.i****ft*******f.;**((************************; ,f.i****ft*******f.;**((************************; ,f.i****ft*******f.;**((************
**********f:,t:,.,****; :(******) fi .;*********************f:,t:,.,****; :(******) fi .;*********************f:,t:,.,****; :(******) fi .;***********
**********:,f**(:;f***( i,;f****( :.(f.;********************:,f**(:;f***( i,;f****( :.(f.;********************:,f**(:;f***( i,;f****( :.(f.;**********
*********) f**********( tf,:****f))f**t )******************) f**********( tf,:****f))f**t )******************) f**********( tf,:****f))f**t )*********
*********,:*********f).i**t (**********:,******************,:*********f).i**t (**********:,******************,:*********f).i**t (**********:,*********
*********.;*******fi,;(****.i(,)*******;.******************.;*******fi,;(****.i(,)*******;.******************.;*******fi,;(****.i(,)*******;.*********
*********,;******t.:f*****f.,.;.i******,:******************,;******t.:f*****f.,.;.i******,:******************,;******t.:f*****f.,.;.i******,:*********
*********i f****f.:*******i .(*) f****) t******************i f****f.:*******i .(*) f****) t******************i f****f.:*******i .(*) f****) t*********
*********f,:****t t*******()f**t t***) )*******************f,:****t t*******()f**t t***) )*******************f,:****t t*******()f**t t***) )**********
**********f,,t**t (************i.f*t:,(*********************f,,t**t (************i.f*t:,(*********************f,,t**t (************i.f*t:,(***********
************i,;t*::***********).)(:,if************************i,;t*::***********).)(:,if************************i,;t*::***********).)(:,if************
*************f)::; ,)tffffff), ,:;(****************************f)::; ,)tffffff), ,:;(****************************f)::; ,)tffffff), ,:;(***************
****************t(i:,::::::::;)tf*********************************t(i:,::::::::;)tf*********************************t(i:,::::::::;)tf*****************
**********************fffff*********************************************fffff*********************************************fffff***********************
******************************************************************************************************************************************************

"""

# Iterate over the characters in the string
for i, char in enumerate(string):
    if char == '*':
        print("\033[30m" + ' ', end="")
    else:
    # Set the color for the current character
        print("\033[38;5;" + str(colors[i % len(colors)]) + "m" + char, end="")

# Descritpion text
print("\033[0m")
print("")
print("")
print(Fore.BLUE+"This is a PCAP analyzer with 3 basic steps:\n1) Show summary statistics and visualize.\n2) Examine the content of packets and look for anything fishy.\n3) Perform a time series anomaly detection algorithm to find fishy packets."+Style.RESET_ALL)
print("")
print("")


#run all
### Run functions
get_ftp_request()
get_ftp_response()
get_http_request()            
get_http_response()            
get_http_file_data()  
get_smb()
get_data()
# Swim fishy
find_fishy_phrases()
#Format df column data
difference = fix_time()
ip_list = fix_IPs()

################################
# Continue to print terminal output
# Print the top border
print(Fore.CYAN+"╔" + "══" * 15 + "╗")

# Print the title
print("║" + " " * 6 +Fore.MAGENTA+ "Summary Statistics" +Style.RESET_ALL+ Fore.CYAN+" " * 6 + "║")

# Print the bottom border
print("╚" + "══" * 15 + "╝"+Style.RESET_ALL)

# Display the total number of packets
print("")
print("")
print('The total number of packets is:',df.shape[0])

# Print the difference in a human-readable format
print(f'Total time: {difference}')

# Print the total number of unique "Protocol" addresses
# Get the total number of unique "Protocol" values
num_unique_protos = df["Protocol"].nunique()
print("Total number of Protocols:", num_unique_protos)

# Sort the list of IP addresses and their frequency by frequency in descending order
ip_list.sort(key=lambda x: x[1], reverse=True)
# Print the total number of all unique addresses
print("Total number of IP addresses:"+ str(len(ip_list)))
print("")
# Print the topx list of IP addresses and their frequency
x = min(10,len(ip_list))
print(Fore.GREEN+Back.RED+'Top '+str(x)+' IPs'+Style.RESET_ALL)
for ip, frequency in ip_list[:x]:
    print(f"{ip}: {frequency}")
print("")

##### Start printing fishy findings
Second_meth=[x for x in df.columns if 'fishy' in x]
#print(Second_meth)
z = 0
for thing in Second_meth:
  # Get the unique values from column 'A'
  unique_values = [x for x in df[thing].unique() if x != '']
  if len(unique_values)>0:
    if z == 0:
      print(Fore.RED +Back.YELLOW+"!Found something fishy!"+Style.RESET_ALL)
      z+=1
    print(thing, unique_values)
    # Select rows where the value in the 'column_name' column is not an empty string
    selected_rows = df.loc[df[thing] != '']
    # Print the selected rows
    print(selected_rows)


# Drop empty columns
df.dropna(axis=1, how="all", inplace=True)
df.drop(df.columns[(df == "").all()], axis=1, inplace=True)
df.drop(df.columns[(df == "None").all()], axis=1, inplace=True)


#print(df.head())
#print(df.columns)

##################################################################################################################
### Begin to make the plots

def make_plots(df):
	# Create a figure with two subplots
	fig, ((ax1), (ax2)) = plt.subplots(nrows=2, ncols=1, figsize=(16,8))

	#1
	# Reset the index and plot the frame number over time on the 1st subplot
	df = df.reset_index()
	df.plot(x="Time", y="Frame Number", linestyle="--",ax=ax1)
	df = df.set_index("Frame Number")
	# Set the title for the first subplot
	ax1.set_title("Total number of packets over Time")

	#2
	# Create the line plot on the second subplot
	sns.lineplot(x="Time", y="Length", data=df, ax=ax2) #maybe add hue='Length'
	# Set the title for the second subplot
	ax2.set_title("Length(size) of each packet over Time")

	# Add the time string to the plot title
	difference_seconds = difference
	difference_rounded = round(difference_seconds, 2)
	total_seconds = difference_rounded
	# Calculate the number of hours, minutes, and seconds
	hours, remainder = divmod(total_seconds, 3600)
	minutes, seconds = divmod(remainder, 60)
	# Adjust vertical spacing between subplots
	plt.subplots_adjust(hspace=0.4)
	# Format the time as a string
	time_string = f'{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}'
	plt.suptitle("The total number of packets is: " + str(df.shape[0]) + "\nTotal time: " + time_string)
	plt.show()


##################################################################################################################
### plotly sankey graph
## takes in ip_list and creates values from n-1
## Source always 0, target 1-n, value is total 
def sankey(df,ip_list):
	#print(ip_list)
	source = []
	target = []
	value = []
	label = [x[0] for x in ip_list]
	x=list(set(df.Protocol))
	label.extend(x)
	df_ip_protocol = df.groupby(['Source IP', 'Protocol']).size().rename('Total').reset_index()
	df2_ip_protocol = df.groupby(['Destination IP', 'Protocol']).size().rename('Total').reset_index()
	df_ip_protocol['IP'] = df_ip_protocol['Source IP']
	df2_ip_protocol['IP'] = df2_ip_protocol['Destination IP']
	df_combined = pd.concat([df_ip_protocol[['IP', 'Protocol', 'Total']], df2_ip_protocol[['IP', 'Protocol', 'Total']]], ignore_index=True)

	for index, row in df_combined.iterrows():
    		if row.IP == ip_list[0][0]:
    			source.append(row.IP)
    			target.append(row.Protocol)
    			value.append(row.Total)
    		else:
    			source.append(row.Protocol)
    			target.append(row.IP)
    			value.append(row.Total)
    		
        ### create dict to convert lists to [0,1,2,...]
	d = dict()
	for i in range(len(label)):
        	d[label[i]]=i
	## ss = converted source, tt = converted target
	ss= [d[key] for key in source]
	tt = [d[key] for key in target]
	fig = go.Figure(data=[go.Sankey(
	    node = dict(
	      pad = 15,
	      thickness = 20,
	      line = dict(color = "black", width = 0.5),
	      label = label,
	      color = "blue"
	    ),
	    link = dict(
	      source = ss, # indices correspond to labels
	      target = tt,
	      value = value
	  ))])
	fig.update_layout(title_text="PCAP Who", font_size=15)
	fig.show()
##################################################################################################################
### use scikit learn to find anomalous packets
##
def find_anomalies(df):
	print(df.columns)
	def extract_features_from_pcap(df):
	    # Extract desired features from the DataFrame
	    X = df[["Source IP", "Destination IP",'src_port','dst_port', "Protocol"]].copy()
	    
	    # Create dummy variables for the "Source IP", "Destination IP", and "Protocol" columns
	    X = pd.get_dummies(X, columns=["Source IP", "Destination IP",'src_port','dst_port', "Protocol"])
	    
	    # Return the resulting DataFrame
	    return X
	# Extract features from pcap data
	X = extract_features_from_pcap(df)

	# Preprocess the data
	#X = preprocess_data(X)

	# Fit the IsolationForest model
	model = IsolationForest(random_state=42)
	model.fit(X)

	# Use the model to predict anomalies in the data
	anomalies = model.predict(X)

	# Identify anomalous points in the data
	anomalous_points = X[anomalies == -1]


	if len(anomalous_points) != 0:
		print("Anomalous points")
		print(anomalous_points[:10])
	else:
		print('Anonomly detection failed')

### Run functions to create plots/detect anomalies
#sankey(df,ip_list)
#find_anomalies(df)
#make_plots(df)
