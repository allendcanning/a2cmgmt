<script>
function loadEmailTemplate(name) {
    var xhttp = new XMLHttpRequest();
    if (name == "") {
        name = "default";
    }
    alert("Name = "+name)
    xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status = 200) {
            document.getElementById("template").innerHTML = this.responseText;
        }
    };
    xhttp.open("GET"), "/?action=email_tmpl&tmpl="+name, true);
    xhttp.send();
}
</script>
