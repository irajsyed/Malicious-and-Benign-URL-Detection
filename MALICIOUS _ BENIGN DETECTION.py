from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
import pandas as pd
from matplotlib import pyplot as plt

def splitter(dataset,test_frac=0.2):
  training_data = dataset.sample(frac= 1 - test_frac)
  testing_data = dataset.sample(frac=test_frac)

  X_train = training_data[['ip', 'long_url', 'tiny_url', 'at', 'redirect', 'https', 'pre_suff',
              'dns', 'web_traffic', 'iframe', 'mouseover', 'rightclk_disable', 'forwarding']]
  y_train = training_data[['malicious']]

  X_test = testing_data[['ip', 'long_url', 'tiny_url', 'at', 'redirect', 'https', 'pre_suff',
              'dns', 'web_traffic', 'iframe', 'mouseover', 'rightclk_disable', 'forwarding']]
  y_test = testing_data[['malicious']]

  return  X_train,X_test,y_train,y_test


def NeuralNet(X,Y,ePOCHS=200):
  model = Sequential()
  model.add(Dense(64, input_dim=13, activation='relu'))
  model.add(Dense(32, activation='relu'))
  model.add(Dense(1, activation='sigmoid'))
  model.compile(loss='binary_crossentropy', optimizer='rmsprop', metrics=['accuracy'])
  model.fit(x= X, y= Y, epochs=ePOCHS,verbose=1)
  return model,model.history.history

def visualization(history):
  fig = plt.figure(figsize=(10,5))
  plt.plot(history['loss'])
  plt.plot(history['accuracy'])
  plt.title('Model Performance')
  plt.ylabel('%')
  plt.xlabel('epoch')
  plt.legend(['loss', 'accuracy'], loc='upper left')
  plt.show()


if __name__ == '__main__':

    dataset = pd.read_csv('dataset.csv')

    X,testx,Y,testy = splitter(dataset,0.2)

    model,history = NeuralNet(X,Y,200)
    
    score = model.evaluate(testx, testy)
    
    model.save('model.h5',overwrite= True)
    
    print(score)

    visualization(history)


