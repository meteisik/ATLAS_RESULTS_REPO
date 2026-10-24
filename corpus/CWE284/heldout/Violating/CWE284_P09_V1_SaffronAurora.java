import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronAurora {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_AURORA_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronAuroraSink()).applySaffronAuroraDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronAuroraSink {
    public void applySaffronAuroraDeletion(CWE284_P09_V1_SaffronAurora.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronAurora");
        try {
            PreparedStatement saffronAuroraDelete = saffronAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronAuroraDelete.setString(1, data);
            saffronAuroraDelete.executeUpdate();
        } finally {
            saffronAuroraConnection.close();
        }
    }
}
