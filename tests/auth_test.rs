use std::io::Write;

use exsocks::auth::UserStore;

/// 创建包含测试用户的临时 YAML 文件，返回 (UserStore, TempFile)
/// TempFile 必须保持存活，否则文件会被删除
fn create_test_store(yaml: &str) -> (UserStore, tempfile::NamedTempFile) {
    let mut temp_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .unwrap();
    write!(temp_file, "{}", yaml).unwrap();
    let store = UserStore::load_from_file(temp_file.path()).unwrap();
    (store, temp_file)
}

#[test]
fn test_load_users_from_yaml() {
    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
"#;
    let (store, _temp) = create_test_store(yaml);
    assert_eq!(store.user_count(), 2);
}

#[test]
fn test_verify_correct_credentials() {
    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
"#;
    let (store, _temp) = create_test_store(yaml);
    assert!(store.verify("admin", "admin123"));
    assert!(store.verify("user1", "pass1"));
}

#[test]
fn test_verify_wrong_password() {
    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (store, _temp) = create_test_store(yaml);
    assert!(!store.verify("admin", "wrongpass"));
}

#[test]
fn test_verify_nonexistent_user() {
    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (store, _temp) = create_test_store(yaml);
    assert!(!store.verify("nonexistent", "somepass"));
}

#[test]
fn test_verify_empty_username() {
    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (store, _temp) = create_test_store(yaml);
    assert!(!store.verify("", "admin123"));
}

#[test]
fn test_empty_users_list() {
    let yaml = r#"
users: []
"#;
    let (store, _temp) = create_test_store(yaml);
    assert_eq!(store.user_count(), 0);
    assert!(!store.verify("admin", "admin123"));
}

#[test]
fn test_reload_adds_new_user() {
    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (store, mut temp) = create_test_store(yaml);
    assert_eq!(store.user_count(), 1);
    assert!(!store.verify("newuser", "newpass"));

    // 修改文件内容，添加新用户
    let new_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "newuser"
    password: "newpass"
"#;
    temp.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(temp, "{}", new_yaml).unwrap();
    temp.as_file_mut().flush().unwrap();

    // 重载
    store.reload().unwrap();
    assert_eq!(store.user_count(), 2);
    assert!(store.verify("newuser", "newpass"));
}

#[test]
fn test_reload_removes_user() {
    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "user1"
    password: "pass1"
"#;
    let (store, mut temp) = create_test_store(yaml);
    assert_eq!(store.user_count(), 2);
    assert!(store.verify("user1", "pass1"));

    // 修改文件内容，移除 user1
    let new_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    temp.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(temp, "{}", new_yaml).unwrap();
    temp.as_file_mut().flush().unwrap();

    store.reload().unwrap();
    assert_eq!(store.user_count(), 1);
    assert!(!store.verify("user1", "pass1"));
    assert!(store.verify("admin", "admin123"));
}

#[test]
fn test_reload_changes_password() {
    let yaml = r#"
users:
  - username: "admin"
    password: "oldpass"
"#;
    let (store, mut temp) = create_test_store(yaml);
    assert!(store.verify("admin", "oldpass"));

    let new_yaml = r#"
users:
  - username: "admin"
    password: "newpass"
"#;
    temp.as_file_mut().set_len(0).unwrap();
    use std::io::Seek;
    temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(temp, "{}", new_yaml).unwrap();
    temp.as_file_mut().flush().unwrap();

    store.reload().unwrap();
    assert!(!store.verify("admin", "oldpass"));
    assert!(store.verify("admin", "newpass"));
}

#[test]
fn test_load_nonexistent_file() {
    let result = UserStore::load_from_file("/nonexistent/path/user.yaml");
    assert!(result.is_err());
}

#[test]
fn test_load_invalid_yaml() {
    let yaml = "invalid: yaml: content: [unclosed";
    let mut temp_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .unwrap();
    write!(temp_file, "{}", yaml).unwrap();
    let result = UserStore::load_from_file(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_load_missing_users_field() {
    // users 字段缺失时应使用默认空列表
    let yaml = r#"
some_other_field: "value"
"#;
    let (store, _temp) = create_test_store(yaml);
    assert_eq!(store.user_count(), 0);
}

#[test]
fn test_duplicate_username_last_wins() {
    let yaml = r#"
users:
  - username: "admin"
    password: "first_pass"
  - username: "admin"
    password: "second_pass"
"#;
    let (store, _temp) = create_test_store(yaml);
    assert_eq!(store.user_count(), 1);
    assert!(!store.verify("admin", "first_pass"));
    assert!(store.verify("admin", "second_pass"));
}

// ========== 热加载（watch）集成测试 ==========

#[tokio::test]
async fn test_watch_auto_reload_on_file_change() {
    use std::io::Seek;
    use std::sync::Arc;

    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (store, mut temp) = create_test_store(yaml);
    let store = Arc::new(store);
    assert_eq!(store.user_count(), 1);
    assert!(!store.verify("newuser", "newpass"));

    // 启动文件监听
    let _watcher = store.watch().unwrap();

    // 修改文件内容，添加新用户
    let new_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "newuser"
    password: "newpass"
"#;
    temp.as_file_mut().set_len(0).unwrap();
    temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(temp, "{}", new_yaml).unwrap();
    temp.as_file_mut().flush().unwrap();

    // 等待防抖（500ms）+ 一些余量让 watcher 处理事件
    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if store.user_count() == 2 && store.verify("newuser", "newpass") {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "File watcher did not auto-reload within timeout");
    assert!(store.verify("admin", "admin123"));
}

#[tokio::test]
async fn test_watch_auto_reload_password_change() {
    use std::io::Seek;
    use std::sync::Arc;

    let yaml = r#"
users:
  - username: "admin"
    password: "oldpass"
"#;
    let (store, mut temp) = create_test_store(yaml);
    let store = Arc::new(store);
    assert!(store.verify("admin", "oldpass"));

    let _watcher = store.watch().unwrap();

    // 修改密码
    let new_yaml = r#"
users:
  - username: "admin"
    password: "newpass"
"#;
    temp.as_file_mut().set_len(0).unwrap();
    temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(temp, "{}", new_yaml).unwrap();
    temp.as_file_mut().flush().unwrap();

    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if store.verify("admin", "newpass") {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "File watcher did not auto-reload password change within timeout");
    assert!(!store.verify("admin", "oldpass"));
}

#[tokio::test]
async fn test_watch_survives_invalid_file_content() {
    use std::io::Seek;
    use std::sync::Arc;

    let yaml = r#"
users:
  - username: "admin"
    password: "admin123"
"#;
    let (store, mut temp) = create_test_store(yaml);
    let store = Arc::new(store);
    assert!(store.verify("admin", "admin123"));

    let _watcher = store.watch().unwrap();

    // 写入无效 YAML，重载应失败但保留旧数据
    let invalid_yaml = "invalid: yaml: [unclosed";
    temp.as_file_mut().set_len(0).unwrap();
    temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(temp, "{}", invalid_yaml).unwrap();
    temp.as_file_mut().flush().unwrap();

    // 等待 watcher 尝试重载
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // 旧数据应该仍然有效
    assert!(store.verify("admin", "admin123"));
    assert_eq!(store.user_count(), 1);

    // 再写入有效内容，应该能恢复
    let valid_yaml = r#"
users:
  - username: "admin"
    password: "admin123"
  - username: "recovered"
    password: "pass"
"#;
    temp.as_file_mut().set_len(0).unwrap();
    temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    write!(temp, "{}", valid_yaml).unwrap();
    temp.as_file_mut().flush().unwrap();

    let mut reloaded = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if store.user_count() == 2 && store.verify("recovered", "pass") {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "File watcher did not recover after invalid content");
}
