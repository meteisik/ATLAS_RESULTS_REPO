import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetAuroraSafe {

    public void deleteVelvetAuroraAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("VELVET_AURORA_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetAuroraSafeChecker()).isAuthorized(data);
        Connection velvetAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetAurora");
        try {
            PreparedStatement velvetAuroraDelete = velvetAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetAuroraDelete.setString(1, data);
            if (authorized) {
                velvetAuroraDelete.executeUpdate();
            }
        } finally {
            velvetAuroraConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetAuroraSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
