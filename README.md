# PCAP_Analysis
Python script to shed light on PCAPs


Scapy and Tshark are used to take in pcap data.
Pandas is used to create a dataframe to store data.
Plotly, Seaborn, matplotlib used to create charts,plots

Usage
![image](https://user-images.githubusercontent.com/50979196/211068084-d0dadf2c-7b13-4c4a-be09-f5e269d5add6.png)


![image](https://user-images.githubusercontent.com/50979196/211065999-9ca360cf-ef54-41e7-95c3-b7d60480b776.png)

Plotly library creates a sankey plot of IPs and Protocol
![image](https://user-images.githubusercontent.com/50979196/211066047-9da1921d-18f6-4fbf-9014-f458fbe1a825.png)


![image](https://user-images.githubusercontent.com/50979196/211066117-66fe4247-a399-429f-9ea5-e8e960366b85.png)

To-Do

1) Add more protocols to check for/ feature to add

2) Simple Pcaps are typically one IP to many IPs, this is not always the case. Create function to detmermine if pcap is one to many or network, if network use networkx to create graph to be used instead of sankey plot.

3) When 1 is done tune isolation tree

*) The initial intake and parsing of data is a mess 
