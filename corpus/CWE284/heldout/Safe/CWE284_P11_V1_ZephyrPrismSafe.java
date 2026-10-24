import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_ZephyrPrismSafe {

    public void deleteZephyrPrismAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_PRISM_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_ZephyrPrismSafeSink()).applyZephyrPrismDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_ZephyrPrismSafeSink {
    public void applyZephyrPrismDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        try {
            PreparedStatement zephyrPrismDelete = zephyrPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrPrismDelete.setString(1, data);
            if (authorized) {
                zephyrPrismDelete.executeUpdate();
            }
        } finally {
            zephyrPrismConnection.close();
        }
    }
}
