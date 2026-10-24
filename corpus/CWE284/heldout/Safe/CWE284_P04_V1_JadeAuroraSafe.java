import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_JadeAuroraSafe {

    private boolean checkJadeAuroraAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteJadeAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_AURORA_ACCOUNT_ID");
        boolean authorized = checkJadeAuroraAccess(data);
        Connection jadeAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeAurora");
        try {
            PreparedStatement jadeAuroraDelete = jadeAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeAuroraDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                jadeAuroraDelete.executeUpdate();
            }
        } finally {
            jadeAuroraConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
