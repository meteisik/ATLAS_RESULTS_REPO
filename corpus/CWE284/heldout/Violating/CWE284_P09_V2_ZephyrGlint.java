import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_ZephyrGlint {
    private static int privateFive = 5;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteZephyrGlintAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_ZephyrGlintSink()).applyZephyrGlintDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_ZephyrGlintSink {
    public void applyZephyrGlintDeletion(CWE284_P09_V2_ZephyrGlint.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        try {
            PreparedStatement zephyrGlintDelete = zephyrGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrGlintDelete.setString(1, data);
            zephyrGlintDelete.executeUpdate();
        } finally {
            zephyrGlintConnection.close();
        }
    }
}
