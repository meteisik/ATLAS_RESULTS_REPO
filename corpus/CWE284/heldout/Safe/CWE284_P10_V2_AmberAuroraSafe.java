import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberAuroraSafe {

    public static String data;

    public static boolean authorized;

    public void deleteAmberAuroraAccount() throws SQLException {
        while (true) {
            data = System.getenv("AMBER_AURORA_ACCOUNT_ID");
            break;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberAuroraSafeSink()).applyAmberAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberAuroraSafeSink {
    public void applyAmberAuroraDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberAuroraSafe.data;
        boolean authorized = CWE284_P10_V2_AmberAuroraSafe.authorized;
        Connection amberAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberAurora");
        try {
            PreparedStatement amberAuroraDelete = amberAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberAuroraDelete.setString(1, data);
            if (authorized) {
                amberAuroraDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberAuroraConnection.close();
        }
    }
}
