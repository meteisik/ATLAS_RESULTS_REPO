import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeSignal {

    private String jadeSignalAccountId;

    private boolean jadeSignalAuthorized;

    private void applyJadeSignalDeletion() throws SQLException {
        String data = jadeSignalAccountId;
        boolean authorized = jadeSignalAuthorized;
        Connection jadeSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSignal");
        try {
            PreparedStatement jadeSignalDelete = jadeSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSignalDelete.setString(1, data);
            jadeSignalDelete.executeUpdate();
        } finally {
            jadeSignalConnection.close();
        }
    }

    public void deleteJadeSignalAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_SIGNAL_ACCOUNT_ID");
        jadeSignalAccountId = data;
        jadeSignalAuthorized = isAuthorized(data);
        applyJadeSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
