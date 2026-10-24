import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetAuroraSafe {

    public void deleteVelvetAuroraAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("VELVET_AURORA_ACCOUNT_ID");
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetAuroraSafeSink()).applyVelvetAuroraDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetAuroraSafeSink {
    public void applyVelvetAuroraDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection velvetAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetAurora");
        try {
            PreparedStatement velvetAuroraDelete = velvetAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetAuroraDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetAuroraDelete.executeUpdate();
            }
        } finally {
            velvetAuroraConnection.close();
        }
    }
}
