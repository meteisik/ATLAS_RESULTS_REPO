import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_SaffronAuroraSafe {
    private static boolean privateTrue = true;

    private String saffronAuroraAccountId;

    private boolean saffronAuroraAuthorized;

    private void applySaffronAuroraDeletion() throws SQLException {
        String data = saffronAuroraAccountId;
        boolean authorized = saffronAuroraAuthorized;
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        try {
            PreparedStatement saffronAuroraDelete = saffronAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronAuroraDelete.setString(1, data);
            if (authorized) {
                saffronAuroraDelete.executeUpdate();
            }
        } finally {
            saffronAuroraConnection.close();
        }
    }

    public void deleteSaffronAuroraAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("SAFFRON_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        saffronAuroraAccountId = data;
        saffronAuroraAuthorized = isAuthorized(data);
        applySaffronAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
