from joblib import dump, load
filename = 'random_forest.joblib'
import pandas as pd


data = pd.read_csv("./backend/data/packet_output.csv")
print(data)

def run(ml_model):
    for i in range(0, data.shape[0]):
        output = ml_model.predict(data[i].reshape(1, -1))

        if output == 0:
            print("Packet is Outlier")
        elif output == 1:
            print("Packet is Malicious")  
        elif output == 2:
            print("Packet is Benign")
        return output