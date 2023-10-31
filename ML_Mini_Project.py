import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import streamlit as st
import matplotlib.pyplot as plt

st.title("Titanic Survival Prediction")
st.set_option('deprecation.showPyplotGlobalUse', False)

@st.cache_data(persist=True)
def load_data():
    df_1 = pd.read_csv("https://raw.githubusercontent.com/chitoge729/Dataset/main/titanic_train.csv")
    df_2 = pd.read_csv("https://raw.githubusercontent.com/chitoge729/Dataset/main/titanic_test.csv")
    data = pd.concat([df_1, df_2], ignore_index=True)

    data.to_csv("data.csv", index=False)

    data.isnull().sum()

    mean_age = data['Age'].mean()
    data['Age'].fillna(mean_age, inplace=True)

    mean_fare = data['Fare'].mean()
    data['Fare'].fillna(mean_fare, inplace=True)

    mode_embarked = data['Embarked'].mode()[0]
    data['Embarked'].fillna(mode_embarked, inplace=True)

    data['Cabin_missing'] = data['Cabin'].isnull().astype(int)

    median_Survived = data['Survived'].median()
    data['Survived'].fillna(median_Survived, inplace=True)

    return data

data = load_data()

X = data[['Age', 'Pclass', 'Sex', 'SibSp', 'Parch']]
X = pd.get_dummies(X, columns=['Sex'], drop_first=True)
y = data['Survived']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

st.subheader("Survival Prediction")

# Create a function to predict survival
def predict_survival(age, pclass, sex):
    sex_male = 1 if sex == "Male" else 0
    input_data = pd.DataFrame({
        'Age': [age],
        'Pclass': [pclass],
        'Sex_male': [sex_male],
        'Parch': [0],  # Provide a default value for Parch
        'SibSp': [0]   # Provide a default value for SibSp
    })
    # Reorder the columns to match the model's feature order
    input_data = input_data[['Age', 'Pclass', 'SibSp', 'Parch', 'Sex_male']]
    prediction = model.predict(input_data)
    return "Survived" if prediction[0] == 1 else "Did Not Survive"

# Create input widgets
age_input = st.slider("Age:", 0, 100, 30)
pclass_input = st.selectbox("Pclass:", [1, 2, 3], index=2)
sex_input = st.selectbox("Gender:", ["Male", "Female"], index=0)

# Create a button to make predictions
if st.button("Predict"):
    prediction = predict_survival(age_input, pclass_input, sex_input)
    st.write(f"Survival Prediction: {prediction}")

st.subheader("Data Analysis")

# Create buttons to plot age, class, and gender distribution
if st.button("Plot Age Distribution"):
    plt.figure(figsize=(6, 4))
    data[data['Survived'] == 0]['Age'].plot(kind='hist', alpha=0.5, color='red', label='Did Not Survive')
    data[data['Survived'] == 1]['Age'].plot(kind='hist', alpha=0.5, color='green', label='Survived')
    plt.xlabel('Age')
    plt.ylabel('Count')
    plt.legend()
    plt.title('Age Distribution by Survival')
    st.pyplot()

if st.button("Plot Class Distribution"):
    plt.figure(figsize=(6, 4))
    data['Pclass'].value_counts().sort_index().plot(kind='bar', color='blue', alpha=0.7)
    plt.xlabel('Passenger Class')
    plt.ylabel('Count')
    plt.title('Passenger Class Distribution')
    st.pyplot()

if st.button("Plot Gender Distribution"):
    plt.figure(figsize=(6, 4))
    data['Sex'].value_counts().plot(kind='bar', color='purple', alpha=0.7)
    plt.xlabel('Gender')
    plt.ylabel('Count')
    plt.title('Gender Distribution')
    st.pyplot()
