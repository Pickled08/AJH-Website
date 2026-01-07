
window.addEventListener('DOMContentLoaded', () => {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-20px)';
            setTimeout(() => alert.remove(), 500); // Remove from DOM after fade+slide
        }, 2000); // 2000ms = 2 seconds
    });
});

function toggleOptions(button) {
    const dropdown = button.nextElementSibling; // the .account-settings-dropdown
    const isVisible = dropdown.style.display === 'block';

    // Hide all other dropdowns
    document.querySelectorAll('.account-settings-dropdown').forEach(d => d.style.display = 'none');

    // Toggle current
    dropdown.style.display = isVisible ? 'none' : 'block';
}

// Optional: hide dropdown if clicking outside
document.addEventListener('click', function(e) {
    if (!e.target.matches('.account-settings-options-btn')) {
        document.querySelectorAll('.account-settings-dropdown').forEach(d => d.style.display = 'none');
    }
});

function toggleBlogList() {
    const container = document.getElementById('blog-list-container');
    const triangle = document.querySelector('.triangle');

    const isVisible = container.style.display === 'block';
    container.style.display = isVisible ? 'none' : 'block';
    
    // Rotate triangle
    if (isVisible) {
        triangle.classList.remove('open');
    } else {
        triangle.classList.add('open');
    }
}

// Existing toggleOptions for each blog
function toggleOptions(button) {
    const dropdown = button.nextElementSibling;
    const isVisible = dropdown.style.display === 'block';

    // Hide all other dropdowns
    document.querySelectorAll('.account-settings-dropdown').forEach(d => d.style.display = 'none');

    dropdown.style.display = isVisible ? 'none' : 'block';
}

// Hide dropdowns if clicking outside
document.addEventListener('click', function(e) {
    if (!e.target.matches('.account-settings-options-btn')) {
        document.querySelectorAll('.account-settings-dropdown').forEach(d => d.style.display = 'none');
    }
});