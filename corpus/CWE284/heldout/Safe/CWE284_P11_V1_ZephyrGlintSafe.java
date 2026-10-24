import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_ZephyrGlintSafe {

    public void deleteZephyrGlintAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_GLINT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_ZephyrGlintSafeSink()).applyZephyrGlintDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_ZephyrGlintSafeSink {
    public void applyZephyrGlintDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        try {
            PreparedStatement zephyrGlintDelete = zephyrGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrGlintDelete.setString(1, data);
            if (authorized) {
                zephyrGlintDelete.executeUpdate();
            }
        } finally {
            zephyrGlintConnection.close();
        }
    }
}
