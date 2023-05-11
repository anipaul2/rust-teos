window.onload = function() {
    var menuButton = document.getElementById('menu-button');
    var crossButton = document.getElementById('cross-button');
    var menu = document.getElementById('menu');

    menuButton.addEventListener('click', function () {
        menu.style.right = '0px';
    });

    crossButton.addEventListener('click', function () {
        menu.style.right = '-100%';
    });
};

// in script.js

async function checkReceipts(userId, towerId, regReceipt, appReceipt, appointment, userSignature) {
    const response = await fetch('http://localhost:8000/check', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            user_id: userId,
            tower_id: towerId,
            reg_receipt: regReceipt,
            app_receipt: appReceipt,
            appointment: appointment,
            user_signature: userSignature,
        })
    });

    const result = await response.json();
    return result;
}

checkReceipts(userId, towerId, regReceipt, appReceipt, appointment, userSignature)
    .then(result => {
        if (result.success) {
            // handle success
        } else {
            // handle error
        }
    });