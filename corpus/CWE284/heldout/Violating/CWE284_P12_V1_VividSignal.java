import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VividSignal {

    public void deleteVividSignalAccount() throws SQLException {
        String data;
        data = System.getenv("VIVID_SIGNAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VividSignalBase baseObject = new CWE284_P12_V1_VividSignalRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VividSignalBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VividSignalRemover extends CWE284_P12_V1_VividSignalBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection vividSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSignal");
        try {
            PreparedStatement vividSignalDelete = vividSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSignalDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                vividSignalDelete.executeUpdate();
            }
        } finally {
            vividSignalConnection.close();
        }
    }
}
