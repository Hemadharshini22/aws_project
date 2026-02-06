document.addEventListener("DOMContentLoaded", function() {
    const forms = document.querySelectorAll("form");
    
    forms.forEach(form => {
        form.addEventListener("submit", function(event) {
            const amountInput = form.querySelector('input[name="amount"]');
            if (amountInput) {
                if (parseFloat(amountInput.value) <= 0) {
                    alert("Please enter a valid positive amount.");
                    event.preventDefault(); // Stop the form from sending
                }
            }
        });
    });
});