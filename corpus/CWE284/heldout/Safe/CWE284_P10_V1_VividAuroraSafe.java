import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VividAuroraSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVividAuroraAccount() throws SQLException {
        data = System.getenv("VIVID_AURORA_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VividAuroraSafeSink()).applyVividAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VividAuroraSafeSink {
    public void applyVividAuroraDeletion() throws SQLException {
        String data = CWE284_P10_V1_VividAuroraSafe.data;
        boolean authorized = CWE284_P10_V1_VividAuroraSafe.authorized;
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        try {
            PreparedStatement vividAuroraDelete = vividAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividAuroraDelete.setString(1, data);
            if (authorized) {
                vividAuroraDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            vividAuroraConnection.close();
        }
    }
}
