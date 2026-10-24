import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronAurora {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronAuroraAccount() throws SQLException {
        data = System.getenv("SAFFRON_AURORA_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronAuroraSink()).applySaffronAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronAuroraSink {
    public void applySaffronAuroraDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronAurora.data;
        boolean authorized = CWE284_P10_V1_SaffronAurora.authorized;
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        try {
            PreparedStatement saffronAuroraDelete = saffronAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronAuroraDelete.setString(1, data);
            saffronAuroraDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronAuroraConnection.close();
        }
    }
}
