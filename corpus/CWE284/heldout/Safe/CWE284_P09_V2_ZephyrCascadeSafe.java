import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrCascadeSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteZephyrCascadeAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrCascadeSafeSink()).applyZephyrCascadeDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrCascadeSafeSink {
    public void applyZephyrCascadeDeletion(CWE284_P09_V2_ZephyrCascadeSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        try {
            PreparedStatement zephyrCascadeDelete = zephyrCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrCascadeDelete.setString(1, data);
            if (authorized) {
                zephyrCascadeDelete.executeUpdate();
            }
        } finally {
            zephyrCascadeConnection.close();
        }
    }
}
