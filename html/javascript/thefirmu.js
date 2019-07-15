function loadEmailTemplate(req,name) {
    var xhttp = new XMLHttpRequest();
    if (name == "") {
        name = "default";
    }
    xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            document.getElementById("adminportal").innerHTML = this.responseText;
        }
    };
    alert("Got req = "+req);
    switch(req) {
      case 'print':
        xhttp.open("GET", "/?action=email_tmpl&tmpl="+name, true);
        break;
      case 'craft':
        xhttp.open("GET", "/?action=email_coaches&tmpl="+name, true);
    }
    xhttp.send();
}

function addCoachesEmail(coach) {
  document.getElementById("toaddresses").value += coach;
  return true;
}

