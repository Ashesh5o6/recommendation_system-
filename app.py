from flask import Flask, render_template, request, jsonify
import pandas as pd

app = Flask(__name__)

# Load the dataset
df = pd.read_csv('./data/recommendation_dataset.csv')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search')
def search():
    # Extract query parameters
    age = request.args.get('age')
    social_category = request.args.get('social_category')
    gender = request.args.get('gender')
    page = int(request.args.get('page', 1))

    # Filter the dataset based on query parameters
    filtered_df = df.copy()

    if age:
        filtered_df = filtered_df[filtered_df['age'] == int(age)]
    if social_category:
        filtered_df = filtered_df[filtered_df['social_category'] == social_category]
    if gender:
        filtered_df = filtered_df[filtered_df['gender'] == gender]

    # Paginate results
    results_per_page = 5
    start = (page - 1) * results_per_page
    end = start + results_per_page
    paginated_df = filtered_df.iloc[start:end]

    # Convert to dictionary format
    results = paginated_df.to_dict(orient='records')

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)