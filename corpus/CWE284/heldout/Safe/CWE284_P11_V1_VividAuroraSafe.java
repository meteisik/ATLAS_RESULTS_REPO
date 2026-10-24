import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_VividAuroraSafe {

    public void deleteVividAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("VIVID_AURORA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_VividAuroraSafeSink()).applyVividAuroraDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_VividAuroraSafeSink {
    public void applyVividAuroraDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        try {
            PreparedStatement vividAuroraDelete = vividAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividAuroraDelete.setString(1, data);
            if (authorized) {
                vividAuroraDelete.executeUpdate();
            }
        } finally {
            vividAuroraConnection.close();
        }
    }
}
