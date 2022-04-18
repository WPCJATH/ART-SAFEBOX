
function purchase(title){
    $.ajax({
        type: "post",
        url: 'purchase',
        data: ({
            title: title}),
        dataType: "json",
        success: function(results) {
            if (results.status===1)
                alert("The purchase request has been sent successfully. Please wait patiently for the host to process it.");
            else
                window.location.reload();
        },
        fail: function(){
            alert("Purchase failed, please check your balance or network connection.");
            window.location.reload();
        }
    });
}

function signOut(){
    $.ajax({
        type: 'POST',
        url: 'signout',
        dataType: 'json',
        success: function(){
            window.location.replace("index.html");
        },
        fail: function (){
           alert("Something goes wrong. Please reload the page.");
           window.location.reload();
        }
    });
}

function recharge(){
    let amount = prompt("How many XAV would you like to recharge?");
    if (amount===null) return;
    amount = parseFloat(amount);
    while (isNaN(amount)){
        amount = prompt("Please enter a number! How many XAV would you like to recharge?");
        if (amount===null) return;
        amount = parseFloat(amount);
    }
    let balance = parseFloat(document.getElementById("amount").innerHTML);

    $.ajax({
        type: 'POST',
        url: 'recharge',
        dataType: 'json',
        data: {
            amount: amount
        },
        success: function(results){
            if (results.status===1){
                alert("Recharge successfully.");
                document.getElementById("amount").innerHTML= (balance+amount).toString();
            }
            else {
                window.location.reload();
            }
        },
        fail: function (){
           alert("Something goes wrong. Please reload the page.");
           window.location.reload();
        }
    });
}

function upload(){
    let source = document.getElementById("source");
    let title = document.getElementById("title").value;
    let price = document.getElementById("price").value;

    let file = source.files[0];
    if (!file){
        customAlert("Please select an image.");
        return;
    }
    if (!file.type.match('image.*')) {
        customAlert("This is not an image. Please upload an image.");
        return;
    }
    if (title===""){
        customAlert("The title cannot be empty.");
    }
    price = parseFloat(price);
    if (isNaN(price) || price <= 0){
        customAlert("The price must be a number larger than 0.");
        return;
    }

    let formData = new FormData();
    formData.append('source', file);
    formData.append('title', title);
    formData.append('price', price);

    $.ajax({
        type: "POST",
        url: 'upload',
        dataType: "json",
        data: formData,
        contentType: false,
        processData: false,
        cache: false,
        success: function (results){
            if (results.status===1){
                alert("Upload Successfully!");
                window.location.reload();
            }
            else {
                customAlert(results.msg);
            }
        },
        fail: function (){
           alert("Something goes wrong. Please reload the page.");
           window.location.reload();
        }
    });
}


function checkSigninState(href, isIndex=false){
    $.ajax({
        type: "POST",
        url: 'checksignin',
        dataType: "json",
        success: function (results){
            if (results.status===1){
                if (isIndex)
                    window.location.replace(href);
            }
            else {
                if (isIndex){
                    return;
                }
                if (results.msg){
                    alert(results.msg);
                }
                else{
                    alert("Something goes wrong, please login again.");
                }
                window.location.replace(href);
            }
        },
        fail: function (){
           alert("Something goes wrong. Please reload the page.");
           window.location.reload();
        }
    });
}

 function customAlert(msg){
    let msg_bar = document.getElementById("alert_msg");
    if (msg_bar===null){
        document.getElementById("insert").insertAdjacentHTML('afterend',
            `<div id="alert_msg" class='alert alert-info fs-5'> ${msg}</div>`);
    }
    else
        msg_bar.innerText = msg;
}



