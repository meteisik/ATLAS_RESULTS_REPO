import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteZephyrMantisAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrMantisSink()).applyZephyrMantisDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrMantisSink {
    public void applyZephyrMantisDeletion(CWE284_P09_V2_ZephyrMantis.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        try {
            PreparedStatement zephyrMantisDelete = zephyrMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrMantisDelete.setString(1, data);
            zephyrMantisDelete.executeUpdate();
        } finally {
            zephyrMantisConnection.close();
        }
    }
}
