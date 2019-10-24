$(function () {
   refresh($("#captcha"));
   // $("#captcha_input").on('blur',function () {
   //     check($(this))
   // })
});

function refresh($img) {
    console.log($img)
    var chars_img = $.get('/captcha/init', function (result) {
        console.log(result);
        $img.attr('src','data:image/png;base64,' + result.image);
        $('#hidden_right_captcha').val(result.chars);
    });
}

function check($inputText) {
    $.ajax({
        type: 'POST',
        url: '/captcha/check',
        data: JSON.stringify({'input': $inputText.val(), 'right_captcha': $('#hidden_right_captcha').val()}),
        contentType: 'application/json; charset=UTF-8',
        dataType: 'json', // 注意：这里是指希望服务端返回json格式的数据
        success: function (data) { // 这里的data就是json格式的数据
           $('#hidden_right_captcha').val(data)
        },
        error: function (xhr, type) {
        }
    });
}

function addCaptchaResult(form) {
    console.log(form)
}