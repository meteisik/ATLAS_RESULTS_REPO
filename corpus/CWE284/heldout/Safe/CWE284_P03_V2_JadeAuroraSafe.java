import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_JadeAuroraSafe {

    private void applyJadeAuroraDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeAurora");
        try {
            PreparedStatement jadeAuroraDelete = jadeAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeAuroraDelete.setString(1, data);
            if (authorized) {
                jadeAuroraDelete.executeUpdate();
            }
        } finally {
            jadeAuroraConnection.close();
        }
    }

    public void deleteJadeAuroraAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("JADE_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyJadeAuroraDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
