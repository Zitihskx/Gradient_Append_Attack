import pandas as pd

def check_malware(malware):
    df = pd.read_csv(r"/home/user/Desktop/Attacks/src/Cave15.csv")
    df.columns = ['Malware', 'Starting_address', 'Size', 'Status', 'Flag']
    match_row = 0
    try:
        match_row = df.loc[df['Malware']==malware]
        return (int(match_row['Starting_address']),int(match_row['Size']))
    except:
        return (0,0)
    

a,b = check_malware("0A8B926CA123F7606CD76F39F4F9DCDD1119F9F6BE0B19BCB0E65D50277D848A")
print(a)
print(b)

