import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetAuroraSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetAuroraAccount() throws SQLException {
        data = System.getenv("VELVET_AURORA_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetAuroraSafeSink()).applyVelvetAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetAuroraSafeSink {
    public void applyVelvetAuroraDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetAuroraSafe.data;
        boolean authorized = CWE284_P10_V1_VelvetAuroraSafe.authorized;
        Connection velvetAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetAurora");
        try {
            PreparedStatement velvetAuroraDelete = velvetAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetAuroraDelete.setString(1, data);
            if (authorized) {
                velvetAuroraDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetAuroraConnection.close();
        }
    }
}
