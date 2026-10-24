import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrAurora {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteZephyrAuroraAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ZEPHYR_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrAuroraSink()).applyZephyrAuroraDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrAuroraSink {
    public void applyZephyrAuroraDeletion(CWE284_P09_V2_ZephyrAurora.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        try {
            PreparedStatement zephyrAuroraDelete = zephyrAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrAuroraDelete.setString(1, data);
            zephyrAuroraDelete.executeUpdate();
        } finally {
            zephyrAuroraConnection.close();
        }
    }
}
