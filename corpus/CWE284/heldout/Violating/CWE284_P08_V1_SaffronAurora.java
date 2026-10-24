import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_SaffronAurora {

    public void deleteSaffronAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_AURORA_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_SaffronAuroraSink()).applySaffronAuroraDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_SaffronAuroraSink {
    public void applySaffronAuroraDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        try {
            PreparedStatement saffronAuroraDelete = saffronAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronAuroraDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronAuroraDelete.executeUpdate();
            }
        } finally {
            saffronAuroraConnection.close();
        }
    }
}
