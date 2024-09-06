let currentPage = 1;
const resultsPerPage = 5; // Adjust as needed

document.getElementById('searchForm').addEventListener('submit', function(event) {
    event.preventDefault();
    currentPage = 1; // Reset to first page on new search
    searchScholarships();
});

function searchScholarships() {
    const age = document.getElementById('age').value.trim();
    const socialCategory = document.getElementById('socialCategory').value.trim();
    const gender = document.getElementById('gender').value;

    const queryParams = new URLSearchParams();
    if (age) queryParams.set('age', age);
    if (socialCategory) queryParams.set('social_category', socialCategory);
    if (gender) queryParams.set('gender', gender);
    console.log({age, socialCategory, gender});
    queryParams.set('page', currentPage);

    const url = `/search?${queryParams.toString()}`;

    fetch(url)
        .then(response => response.json())
        .then(data => {
            console.log({data});
            renderResults(data);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });
}

function renderResults(data) {
    const resultsDiv = document.getElementById('results');
    const paginationDiv = document.getElementById('pagination');
    resultsDiv.innerHTML = '';
    paginationDiv.innerHTML = '';

    if (data.length === 0) {
        resultsDiv.innerHTML = '<p>No results found.</p>';
        return;
    }

    data.forEach(scholarship => {
        resultsDiv.innerHTML += `
            <div class="scholarship">
                <h3>${scholarship.scheme_name}</h3>
                <p><strong>Description:</strong> ${scholarship.description}</p>
                <p><strong>Gender:</strong> ${scholarship.gender}</p>
                <p><strong>Social Category:</strong> ${scholarship.social_category}</p>
                <p><strong>Age:</strong> ${scholarship.age}</p>
            </div>
        `;
    });

    if (data.length >= resultsPerPage) {
        paginationDiv.innerHTML = `
            <button onclick="previousPage()" ${currentPage === 1 ? 'disabled' : ''}>Previous</button>
            <button onclick="nextPage()">Next</button>
        `;
    }
}

function previousPage() {
    if (currentPage > 1) {
        currentPage--;
        searchScholarships();
    }
}

function nextPage() {
    currentPage++;
    searchScholarships();
}