import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeAurora {

    private String jadeAuroraAccountId;

    private boolean jadeAuroraAuthorized;

    private void applyJadeAuroraDeletion() throws SQLException {
        String data = jadeAuroraAccountId;
        boolean authorized = jadeAuroraAuthorized;
        Connection jadeAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeAurora");
        try {
            PreparedStatement jadeAuroraDelete = jadeAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeAuroraDelete.setString(1, data);
            jadeAuroraDelete.executeUpdate();
        } finally {
            jadeAuroraConnection.close();
        }
    }

    public void deleteJadeAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_AURORA_ACCOUNT_ID");
        jadeAuroraAccountId = data;
        jadeAuroraAuthorized = isAuthorized(data);
        applyJadeAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
