import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrFlareSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteZephyrFlareAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrFlareSafeSink()).applyZephyrFlareDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrFlareSafeSink {
    public void applyZephyrFlareDeletion(CWE284_P09_V2_ZephyrFlareSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrFlare");
        try {
            PreparedStatement zephyrFlareDelete = zephyrFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrFlareDelete.setString(1, data);
            if (authorized) {
                zephyrFlareDelete.executeUpdate();
            }
        } finally {
            zephyrFlareConnection.close();
        }
    }
}
