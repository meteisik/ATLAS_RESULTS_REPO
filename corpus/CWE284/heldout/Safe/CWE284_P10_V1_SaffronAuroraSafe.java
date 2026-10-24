import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronAuroraSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronAuroraAccount() throws SQLException {
        data = System.getenv("SAFFRON_AURORA_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronAuroraSafeSink()).applySaffronAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronAuroraSafeSink {
    public void applySaffronAuroraDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronAuroraSafe.data;
        boolean authorized = CWE284_P10_V1_SaffronAuroraSafe.authorized;
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        try {
            PreparedStatement saffronAuroraDelete = saffronAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronAuroraDelete.setString(1, data);
            if (authorized) {
                saffronAuroraDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronAuroraConnection.close();
        }
    }
}
