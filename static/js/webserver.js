setTimeout(function(){
    document.getElementById("alarmmsg").innerHTML = '';
}, 3000);

function changeCompleted(){
    document.getElementById("completed").innerHTML = "";
}
document.getElementById("completed").innerHTML = '{{ completed }}';

$(window).submit(function () {
    $('#loading').show();
})