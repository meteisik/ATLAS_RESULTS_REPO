import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeSignalSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteJadeSignalAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("JADE_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection jadeSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSignal");
        try {
            PreparedStatement jadeSignalDelete = jadeSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeSignalDelete.setString(1, data);
            if (authorized) {
                jadeSignalDelete.executeUpdate();
            }
        } finally {
            jadeSignalConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
