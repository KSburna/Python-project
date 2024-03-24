function checkPasswordMatch() {
    var password = document.getElementById("password").value;
    var confirmPassword = document.getElementById("confirm_password").value;

    if (password !== confirmPassword) {
        document.getElementById("password_error").innerHTML = "Passwords do not match";
        document.getElementById("password_error").style.display = "block";
        return false;
    } else {
        document.getElementById("password_error").innerHTML = "";
        return true;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const incrementButtons = document.querySelectorAll('.increment');
    const decrementButtons = document.querySelectorAll('.decrement');
    const quantityInput = document.querySelector('input[name="quantity"]');
    const priceInput = document.querySelector('input[name="price"]');
    const totalInput = document.querySelector('input[name="total"]');
    
    incrementButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const quantityElement = button.parentElement.querySelector('.quantity');
            const priceElement = button.parentElement.parentElement.querySelector('.price');
            const totalElement = button.parentElement.parentElement.querySelector('.total');
            const itemPriceInput = button.parentElement.parentElement.querySelector('.item-price');
            let quantity = parseInt(quantityElement.textContent);
            let price = parseFloat(itemPriceInput.value);
            quantity++;
            quantityElement.textContent = quantity;
            updatePriceAndTotal(quantity, price, priceElement, totalElement);
            updateHiddenFields(quantity, price);
        });
    });

    decrementButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const quantityElement = button.parentElement.querySelector('.quantity');
            const totalElement = button.parentElement.parentElement.querySelector('.total');
            const itemPriceInput = button.parentElement.parentElement.querySelector('.item-price');
            let quantity = parseInt(quantityElement.textContent);
            let price = parseFloat(itemPriceInput.value);
            if (quantity > 1) {
                quantity--;
                quantityElement.textContent = quantity;
                updatePriceAndTotal(quantity, price, totalElement);
                updateHiddenFields(quantity);
            }
        });
    });

    function updatePriceAndTotal(quantity, price, totalElement) {
        const totalPrice = quantity * price;
        totalElement.textContent = totalPrice.toFixed(2);
    }

    function updateHiddenFields(quantity) {
        document.getElementsByClassName("quantity-input")[0].value = quantity
    }
});

document.addEventListener('DOMContentLoaded', function() {
    const rememberCheckbox = document.getElementById('remember');
    const emailInput = document.getElementById('email');
    
    // Check if the email is stored in local storage
    const storedEmail = localStorage.getItem('rememberedEmail');
    if (storedEmail) {
        emailInput.value = storedEmail;
        rememberCheckbox.checked = true;
    }

    rememberCheckbox.addEventListener('change', function() {
        if (rememberCheckbox.checked) {
            // If the checkbox is checked, store the email in local storage
            localStorage.setItem('rememberedEmail', emailInput.value);
        } else {
            // If the checkbox is unchecked, remove the stored email from local storage
            localStorage.removeItem('rememberedEmail');
        }
    });
});


let slideIndex = 0;
showSlides();

function showSlides() {
    let i;
    const slides = document.getElementsByClassName("slide");
    for (i = 0; i < slides.length; i++) {
        slides[i].style.display = "none";
    }
    slideIndex++;
    if (slideIndex > slides.length) {slideIndex = 1}
    slides[slideIndex-1].style.display = "block";
    setTimeout(showSlides, 2000); // Change image every 2 seconds
}

function moveSlide(n) {
    slideIndex += n;
    const slides = document.getElementsByClassName("slide");
    if (slideIndex > slides.length) {slideIndex = 1}
    if (slideIndex < 1) {slideIndex = slides.length}
    for (let i = 0; i < slides.length; i++) {
        slides[i].style.display = "none";
    }
    slides[slideIndex-1].style.display = "block";
}
