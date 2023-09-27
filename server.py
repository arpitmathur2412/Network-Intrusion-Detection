import shutil
import flask
import os
from logging import exception
import sklearn

import joblib
# import model_functions
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import numpy as np

ml_model = joblib.load("random_forest.joblib")


app = flask.Flask(__name__)


data = pd.read_csv("./packet_output.csv")
data=pd.DataFrame(data)

data['duration'] = data['time_end'] - data['time_start']

# Print the DataFrame to verify the changes
print(data)
# data['label'] = ''
print(data)

min_max_scaler = MinMaxScaler().fit(data[['avg_ipt', 'bytes_in', 'bytes_out', 'dest_port', 'entropy','source_port',
                                           'total_entropy', 'duration']])

numerical_columns = ['avg_ipt', 'bytes_in', 'bytes_out', 'dest_port', 'entropy', 'source_port',
                    'total_entropy', 'duration']

data[numerical_columns] = min_max_scaler.transform(data[numerical_columns])

print("maxmin done")

data=np.array(data)
print(data)
# print(model.predict(data[1].reshape(1,-1))

def run(ml_model):
    df=pd.read_csv('./packet_output.csv')
    df=pd.DataFrame(df)
    for i in range(0, len(data)):
        output = ml_model.predict(data[i].reshape(1, -1))
        print(output[0])
        
        if output[0] == 0:
            label='Outlier'
            print("Packet is Outlier")
            df.at[i,'label']=label

        elif output[0] == 1:
            label='Malicious'
            print("Packet is Malicious")  
            df.at[i,'label']=label
            
        elif output[0] == 2:
            label='Benign'
            print("Packet is Benign")
            df.at[i,'label']=label
        
        print(df)
    
    df.to_csv('./archive/final_output.csv',mode='a', index=False)
    
    return "Outputs appended at /archive/final_output.csv"
    
    #     archive_path = os.path.join('./archive', 'packet_capture_updated.csv')
    # data.to_csv(archive_path, index=False)
    # print(f"Updated CSV file saved to {archive_path}")
    # print(f"Updated CSV file archived to {archive_path}")
    
    
    
@app.route('/', methods=['GET'])
def home():
    return "Welcome to the root server"

@app.route('/api/v1/predict', methods=['GET'])
def predict():
    global ml_model

    if ml_model is None:
        ml_model = joblib.load("./random_forest.joblib")

    try:
        run(ml_model)
        return "Successfull operation"
        # ans=output[0]+''
        # return ans
        

    except Exception as e:
        return str(e)
    

if __name__ == '__main__':
    app.run(debug=True)