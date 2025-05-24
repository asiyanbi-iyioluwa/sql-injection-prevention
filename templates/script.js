// Get modal and button elements
var modal = document.getElementById("resultModal");
var closeBtn = document.getElementsByClassName("close-btn")[0];

// Open the modal and show the result
function showModal(message, isSuccess) {
    document.getElementById("modalMessage").innerHTML = message;

    // Add success or error class based on the result
    if (isSuccess) {
        document.getElementById("modalMessage").classList.add("success");
        document.getElementById("modalMessage").classList.remove("error");
    } else {
        document.getElementById("modalMessage").classList.add("error");
        document.getElementById("modalMessage").classList.remove("success");
    }

    modal.style.display = "block";
}

// Close the modal when the user clicks the "X"
closeBtn.onclick = function() {
    modal.style.display = "none";
}

// Close the modal if the user clicks outside the modal content
window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}

// Simulating form submission and SQLi check (for demonstration purposes)
document.getElementById("loginForm").onsubmit = function(event) {
    event.preventDefault();  // Prevent form from actually submitting
    
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    
    // Simulated check for SQL Injection
    if (isSQLInjection(username) || isSQLInjection(password)) {
        showModal("Potential SQL Injection detected. Please try again.", false);
    } else {
        // Simulate a successful login (You can integrate your backend here)
        if (username === "admin" && password === "password123") {
            showModal("Login successful! Welcome back, admin.", true);
        } else {
            showModal("Invalid credentials. Please try again.", false);
        }
    }
}

// Dummy SQL Injection check (for demonstration purposes)
function isSQLInjection(input) {
    const sqlPatterns = ["'", "--", ";", "/*", "*/", "SELECT", "DROP", "INSERT", "UPDATE"];
    for (let pattern of sqlPatterns) {
        if (input.toUpperCase().includes(pattern)) {
            return true;
        }
    }
    return false;
}

// Close modal function
function closeModal() {
    modal.style.display = "none";
}
