import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_ZephyrQuartzSafe {

    public void deleteZephyrQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_ZephyrQuartzSafeSink()).applyZephyrQuartzDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_ZephyrQuartzSafeSink {
    public void applyZephyrQuartzDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        try {
            PreparedStatement zephyrQuartzDelete = zephyrQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            zephyrQuartzDelete.setString(1, data);
            if (authorized) {
                zephyrQuartzDelete.executeUpdate();
            }
        } finally {
            zephyrQuartzConnection.close();
        }
    }
}
