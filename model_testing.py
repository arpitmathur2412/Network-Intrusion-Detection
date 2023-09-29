import joblib
from joblib import load
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

data = pd.read_csv("./backend/data/packet_output.csv")
print(data)
data=pd.DataFrame(data)
model = joblib.load('./random_forest.joblib')
data['label'] = ''


print(data.shape)

for i in range(0, data.shape[0]):
        output = model.predict(data[i].reshape(1, -1))

        # label = 'Outlier'

        if output == 0:
            label='Outlier'
            print("Packet is Outlier")
        elif output == 1:
            label='Malicious'
            print("Packet is Malicious")  
        elif output == 2:
            label='Benign'
            print("Packet is Benign")
        data.at[i,'label']=label

# for i in (data.shape[0]):
#     output = model.predict(data[i].reshape(1, -1))
#     if output == 0:
#         label='Outlier'
#         print("Packet is Outlier")
#     elif output == 1:
#         label='Malicious'
#         print("Packet is Malicious")      
#     elif output == 2:
#         label='Benign'
#         print("Packet is Benign")
#     data.at[i,'label']=label
# print(type(model))