import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VelvetAuroraSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVelvetAuroraAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("VELVET_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VelvetAuroraSafeSink()).applyVelvetAuroraDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VelvetAuroraSafeSink {
    public void applyVelvetAuroraDeletion(CWE284_P09_V2_VelvetAuroraSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
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
