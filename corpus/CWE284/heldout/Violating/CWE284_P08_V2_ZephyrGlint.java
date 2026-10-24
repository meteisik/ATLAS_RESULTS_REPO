import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_ZephyrGlint {
    private static boolean privateTrue = true;

    public void deleteZephyrGlintAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("ZEPHYR_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_ZephyrGlintSink()).applyZephyrGlintDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_ZephyrGlintSink {
    public void applyZephyrGlintDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        try {
            PreparedStatement zephyrGlintDelete = zephyrGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrGlintDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                zephyrGlintDelete.executeUpdate();
            }
        } finally {
            zephyrGlintConnection.close();
        }
    }
}
