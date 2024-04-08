# SQL Injection (Blind) (DVWA)

## Đề bài

![image](https://hackmd.io/_uploads/S1rME4eeC.png)

- chúng ta cần tìm version của database qua lỗi blind SQL
- vì tìm tên version của database phải brute force khá lâu nên mình sẽ chỉ thực hiện với tên database

## LOW LEVEL

### Phân tích

- đọc source code mình được

```sql
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
    // Get input
    $id = $_GET[ 'id' ];
    $exists = false;

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            try {
                $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors
            } catch (Exception $e) {
                print "There was an error.";
                exit;
            }

            $exists = false;
            if ($result !== false) {
                try {
                    $exists = (mysqli_num_rows( $result ) > 0);
                } catch(Exception $e) {
                    $exists = false;
                }
            }
            ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
            break;
        case SQLITE:
            global $sqlite_db_connection;

            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            try {
                $results = $sqlite_db_connection->query($query);
                $row = $results->fetchArray();
                $exists = $row !== false;
            } catch(Exception $e) {
                $exists = false;
            }

            break;
    }

    if ($exists) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    } else {
        // User wasn't found, so the page wasn't!
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }

}

?>
```

Đoạn mã PHP trên có một số chức năng như sau:

- Kiểm tra xem nút "Submit" đã được nhấn hay chưa thông qua biến $\_GET['Submit'].
- Nếu nút "Submit" đã được nhấn, mã sẽ lấy giá trị của biến 'id' từ yêu cầu `($_GET['id'])`.
- Dựa vào giá trị của hằng số `$_DVWA['SQLI_DB']`, mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ thực hiện một truy vấn SQL để kiểm tra xem có bản ghi nào trong bảng 'users' có user_id = '$id' không. Nếu có, biến $exists sẽ được gán giá trị true, ngược lại sẽ là false.
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên với cú pháp phù hợp cho SQLite. Kết quả truy vấn sẽ được kiểm tra để xác định xem bản ghi có tồn tại hay không, và gán giá trị tương ứng cho biến $exists.
- Sau khi kiểm tra xong, mã sẽ hiển thị thông báo cho người dùng thông qua lệnh echo. Nếu $exists là true, thông báo sẽ cho biết rằng User ID tồn tại trong cơ sở dữ liệu. Ngược lại, nếu $exists là false, mã sẽ gửi header 404 Not Found và hiển thị thông báo rằng User ID không tồn tại trong cơ sở dữ liệu.
- Đoạn mã này thực hiện một kiểm tra đơn giản để xác định xem một User ID có tồn tại trong cơ sở dữ liệu hay không, và cung cấp phản hồi tương ứng cho người dùng.

vậy đoạn mã không có cơ chế lọc đầu vào mà truyền trực tiếp tham số truy vấn do người dùng nhập vào và chúng ta có thể tận dụng để chèn các câu lệnh logic vào database rồi dò tìm version

### Khai thác

- mình chèn các câu lệnh and để kiểm tra tính đúng sai của câu truy vấn

![image](https://hackmd.io/_uploads/Sk42U4gx0.png)

![image](https://hackmd.io/_uploads/HJup8VxlR.png)

- và nó hoạt động tốt vậy giờ mình sẽ tiến hành tìm độ dài của chuỗi hiển thị tên của database với câu lệnh

```sql
1' and length(database()) =1-- -
```

mình đưa request vào intruder trong burp suit để brute force

![image](https://hackmd.io/_uploads/Byuw_4xe0.png)

- mình set payload là các số

![image](https://hackmd.io/_uploads/rkAouEeeC.png)

- lọc kết quả trả về

![image](https://hackmd.io/_uploads/BkMxFNxxC.png)

- và mình được độ dài tên của database là 4

![image](https://hackmd.io/_uploads/SyTGKEee0.png)

- tiếp theo mình sẽ brute force các ký tự trong tên của database với lệnh

```sql
1' and substr(database(), 1, 1) = "a"-- -
```

và mình để chế độ brute force cluster bomb

![image](https://hackmd.io/_uploads/HJjroNgxR.png)

- mình set payload 1 là các số từ 1-4

![image](https://hackmd.io/_uploads/SkD6cVegA.png)

- mình set payload 2 là các ký tự trong bảng chữ cái tiếng anh từ a-z

![image](https://hackmd.io/_uploads/rk0yoNgl0.png)

- tiến hành tấn công và mình được tên của database là **dvwa**

![image](https://hackmd.io/_uploads/r1PdsNgg0.png)

### SQLMAP

- mình chạy lệnh sau để tìm version của database

```sql
sqlmap -u "http://192.168.1.58/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="security=low; PHPSESSID=id5sj964f9vju55b5sfj1dstqa" --batch --fingerprint -banner
```

- kết quả phát hiện có thể tấn công với câu lệnh UNION, boolean-based blind, time-based blind

![image](https://hackmd.io/_uploads/Bygfsaex0.png)

- và mình được version được dùng trong database là **10.4.28-MariaDB**

![image](https://hackmd.io/_uploads/Hy7LsaxgR.png)

## MEDIUM LEVEL

### Phân tích

- đọc source code mình được:

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $id = $_POST[ 'id' ];
    $exists = false;

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            $id = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $id ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
            try {
                $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors
            } catch (Exception $e) {
                print "There was an error.";
                exit;
            }

            $exists = false;
            if ($result !== false) {
                try {
                    $exists = (mysqli_num_rows( $result ) > 0); // The '@' character suppresses errors
                } catch(Exception $e) {
                    $exists = false;
                }
            }

            break;
        case SQLITE:
            global $sqlite_db_connection;

            $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
            try {
                $results = $sqlite_db_connection->query($query);
                $row = $results->fetchArray();
                $exists = $row !== false;
            } catch(Exception $e) {
                $exists = false;
            }
            break;
    }

    if ($exists) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    } else {
        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }
}

?>
```

Đoạn mã PHP trên có chức năng như sau:

- Kiểm tra xem nút "Submit" đã được nhấn hay chưa thông qua biến $\_POST['Submit'].
- Nếu nút "Submit" đã được nhấn, mã sẽ lấy giá trị của biến 'id' từ yêu cầu `($_POST['id'])` và gán cho biến $id.
- Dựa vào giá trị của hằng số $\_DVWA['SQLI_DB'], mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ sử dụng hàm mysqli_real_escape_string để chuẩn bị giá trị của biến $id trước khi sử dụng trong truy vấn SQL, nhằm ngăn chặn tấn công SQL Injection.
- Một truy vấn SQL được thực hiện để kiểm tra xem có bản ghi nào trong bảng 'users' có user_id = $id không. Kết quả của truy vấn được lưu trong biến $result.
- Nếu có kết quả trả về từ truy vấn, mã sẽ kiểm tra số lượng bản ghi trả về bằng hàm mysqli_num_rows để xác định xem user_id có tồn tại trong cơ sở dữ liệu hay không. Nếu tồn tại, biến $exists sẽ được gán giá trị true, ngược lại sẽ là false.
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên với cú pháp phù hợp cho SQLite. Kết quả của truy vấn sẽ được kiểm tra để xác định xem bản ghi có tồn tại hay không, và gán giá trị tương ứng cho biến $exists.
- Cuối cùng, mã sẽ hiển thị thông báo cho người dùng thông qua lệnh echo. Nếu $exists là true, thông báo sẽ cho biết rằng User ID tồn tại trong cơ sở dữ liệu. Ngược lại, nếu $exists là false, thông báo sẽ cho biết rằng User ID không tồn tại trong cơ sở dữ liệu.

### Khai thác

- mình sẽ tiến hành tìm độ dài của chuỗi hiển thị tên của database với câu lệnh

```sql
1 and length(database()) =1-- -
```

![image](https://hackmd.io/_uploads/SJ1Hz0egA.png)

- mình set payload là các số

![image](https://hackmd.io/_uploads/rkv8GCxlC.png)

- lọc kết quả trả về

![image](https://hackmd.io/_uploads/SyPYMRgeC.png)

- và mình được độ dài tên của database là 4

![image](https://hackmd.io/_uploads/Hkrqf0elC.png)

- tiếp theo mình sẽ brute force các ký tự trong tên của database với lệnh

```sql
1 and substr(database(), 1, 1) = "a"-- -
```

và mình để chế độ brute force cluster bomb

![image](https://hackmd.io/_uploads/r1n_QAleR.png)

- mình set payload 1 là các số từ 1-4

![image](https://hackmd.io/_uploads/r1cDmAxxC.png)

- mình set payload 2 là các ký tự trong bảng chữ cái tiếng anh từ a-z

![image](https://hackmd.io/_uploads/SJQ9QCxxA.png)

- lọc kết quả trả về

![image](https://hackmd.io/_uploads/ryOPEAleR.png)

- tiến hành tấn công và mình được tên của database là **dvwa**

### SQLMAP

- mình copy toàn bộ request trong burp suit ra file sql.txt

![image](https://hackmd.io/_uploads/HkNSaTgeA.png)

- sau đó mình dùng lệnh sau để tìm version database

```sql
sqlmap -r sql.txt  --batch --fingerprint -banner
```

![image](https://hackmd.io/_uploads/HJHl06geA.png)

- và tương tự low level mình được version được dùng trong database là **10.4.28-MariaDB**

## HIGN LEVEL

### Phân tích

- đọc source code mình được:

```php
<?php

if( isset( $_COOKIE[ 'id' ] ) ) {
    // Get input
    $id = $_COOKIE[ 'id' ];
    $exists = false;

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
            try {
                $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors
            } catch (Exception $e) {
                $result = false;
            }

            $exists = false;
            if ($result !== false) {
                // Get results
                try {
                    $exists = (mysqli_num_rows( $result ) > 0); // The '@' character suppresses errors
                } catch(Exception $e) {
                    $exists = false;
                }
            }

            ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
            break;
        case SQLITE:
            global $sqlite_db_connection;

            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
            try {
                $results = $sqlite_db_connection->query($query);
                $row = $results->fetchArray();
                $exists = $row !== false;
            } catch(Exception $e) {
                $exists = false;
            }

            break;
    }

    if ($exists) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    }
    else {
        // Might sleep a random amount
        if( rand( 0, 5 ) == 3 ) {
            sleep( rand( 2, 4 ) );
        }

        // User wasn't found, so the page wasn't!
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }
}

?>
```

Đoạn mã PHP trên có chức năng như sau:

- Kiểm tra xem cookie 'id' có tồn tại hay không thông qua biến $\_COOKIE['id'].
- Nếu cookie 'id' tồn tại, mã sẽ lấy giá trị của biến 'id' từ cookie và gán cho biến $id.
- Dựa vào giá trị của hằng số $\_DVWA['SQLI_DB'], mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ thực hiện một truy vấn SQL để kiểm tra xem có bản ghi nào trong bảng 'users' có user_id = '$id' không. Kết quả của truy vấn được lưu trong biến $result.
- Nếu có kết quả trả về từ truy vấn, mã sẽ kiểm tra số lượng bản ghi trả về bằng hàm mysqli_num_rows để xác định xem user_id có tồn tại trong cơ sở dữ liệu hay không. Nếu tồn tại, biến $exists sẽ được gán giá trị true, ngược lại sẽ là false.
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên với cú pháp phù hợp cho SQLite. Kết quả của truy vấn sẽ được kiểm tra để xác định xem bản ghi có tồn tại hay không, và gán giá trị tương ứng cho biến $exists.
- Nếu $exists là true, mã sẽ hiển thị thông báo cho người dùng thông qua lệnh echo, cho biết rằng User ID tồn tại trong cơ sở dữ liệu.
- Nếu $exists là false, mã có thể ngủ một khoảng thời gian ngẫu nhiên bằng hàm sleep để giả lập việc xử lý độ trễ. Sau đó, mã sẽ gửi header 404 Not Found và hiển thị thông báo rằng User ID không tồn tại trong cơ sở dữ liệu.

### Khai thác

- chương trình hoạt động như low level nhưng chúng ta nhập và hiển thị kết quả qua 2 trang khác nhau
- và tương tự mình brute force như low level và được tên database là **dvwa**

## IMPOSSIBLE LEVEL

### Phân tích

- đọc source code mình được:

```php
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
    $exists = false;

    // Get input
    $id = $_GET[ 'id' ];

    // Was a number entered?
    if(is_numeric( $id )) {
        $id = intval ($id);
        switch ($_DVWA['SQLI_DB']) {
            case MYSQL:
                // Check the database
                $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
                $data->bindParam( ':id', $id, PDO::PARAM_INT );
                $data->execute();

                $exists = $data->rowCount();
                break;
            case SQLITE:
                global $sqlite_db_connection;

                $stmt = $sqlite_db_connection->prepare('SELECT COUNT(first_name) AS numrows FROM users WHERE user_id = :id LIMIT 1;' );
                $stmt->bindValue(':id',$id,SQLITE3_INTEGER);
                $result = $stmt->execute();
                $result->finalize();
                if ($result !== false) {
                    // There is no way to get the number of rows returned
                    // This checks the number of columns (not rows) just
                    // as a precaution, but it won't stop someone dumping
                    // multiple rows and viewing them one at a time.

                    $num_columns = $result->numColumns();
                    if ($num_columns == 1) {
                        $row = $result->fetchArray();

                        $numrows = $row[ 'numrows' ];
                        $exists = ($numrows == 1);
                    }
                }
                break;
        }

    }

    // Get results
    if ($exists) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    } else {
        // User wasn't found, so the page wasn't!
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

Đoạn mã PHP trên có chức năng như sau:

- Kiểm tra xem cookie 'id' có tồn tại hay không thông qua biến `$_COOKIE['id']`.
- Nếu cookie 'id' tồn tại, mã sẽ lấy giá trị của biến 'id' từ cookie và gán cho biến $id.
- Dựa vào giá trị của hằng số $\_DVWA['SQLI_DB'], mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ thực hiện một truy vấn SQL để kiểm tra xem có bản ghi nào trong bảng 'users' có user_id = '$id' không. Kết quả của truy vấn được lưu trong biến $result.
- Nếu có kết quả trả về từ truy vấn, mã sẽ kiểm tra số lượng bản ghi trả về bằng hàm mysqli_num_rows để xác định xem user_id có tồn tại trong cơ sở dữ liệu hay không. Nếu tồn tại, biến $exists sẽ được gán giá trị true, ngược lại sẽ là false.
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên với cú pháp phù hợp cho SQLite. Kết quả của truy vấn sẽ được kiểm tra để xác định xem bản ghi có tồn tại hay không, và gán giá trị tương ứng cho biến $exists.
- Nếu $exists là true, mã sẽ hiển thị thông báo cho người dùng thông qua lệnh echo, cho biết rằng User ID tồn tại trong cơ sở dữ liệu.
- Nếu $exists là false, mã có thể ngủ một khoảng thời gian ngẫu nhiên bằng hàm sleep để giả lập việc xử lý độ trễ. Sau đó, mã sẽ gửi header 404 Not Found và hiển thị thông báo rằng User ID không tồn tại trong cơ sở dữ liệu.

vậy chúng tâ nên dùng hàm mysqli_real_escape_string để validate đầu vào cùng với đó là dùng prepare để tham số hóa đầu vào và kết nối đến database

<img  src="https://3198551054-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FVvHHLY2mrxd5y4e2vVYL%2Fuploads%2FF8DJirSFlv1Un7WBmtvu%2Fcomplete.gif?alt=media&token=045fd197-4004-49f4-a8ed-ee28e197008f">s
