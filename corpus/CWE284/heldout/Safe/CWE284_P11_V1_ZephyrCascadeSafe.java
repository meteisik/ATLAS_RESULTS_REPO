import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_ZephyrCascadeSafe {

    public void deleteZephyrCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_CASCADE_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_ZephyrCascadeSafeSink()).applyZephyrCascadeDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_ZephyrCascadeSafeSink {
    public void applyZephyrCascadeDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
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
