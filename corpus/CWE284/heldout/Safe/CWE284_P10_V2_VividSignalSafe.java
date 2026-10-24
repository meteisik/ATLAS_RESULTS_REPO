import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_VividSignalSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVividSignalAccount() throws SQLException {
        if (5 == 5) {
            data = System.getenv("VIVID_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_VividSignalSafeSink()).applyVividSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_VividSignalSafeSink {
    public void applyVividSignalDeletion() throws SQLException {
        String data = CWE284_P10_V2_VividSignalSafe.data;
        boolean authorized = CWE284_P10_V2_VividSignalSafe.authorized;
        Connection vividSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSignal");
        try {
            PreparedStatement vividSignalDelete = vividSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSignalDelete.setString(1, data);
            if (authorized) {
                vividSignalDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            vividSignalConnection.close();
        }
    }
}
