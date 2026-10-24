import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronAuroraSafe {
    private static int privateFive = 5;

    public void deleteSaffronAuroraAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SAFFRON_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronAuroraSafeSink()).applySaffronAuroraDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronAuroraSafeSink {
    public void applySaffronAuroraDeletion(String data, boolean authorized) throws SQLException {
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
