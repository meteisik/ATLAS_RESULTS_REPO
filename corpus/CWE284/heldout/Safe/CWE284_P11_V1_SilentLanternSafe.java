import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_SilentLanternSafe {

    public void deleteSilentLanternAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_LANTERN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_SilentLanternSafeSink()).applySilentLanternDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_SilentLanternSafeSink {
    public void applySilentLanternDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection silentLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLantern");
        try {
            PreparedStatement silentLanternDelete = silentLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLanternDelete.setString(1, data);
            if (authorized) {
                silentLanternDelete.executeUpdate();
            }
        } finally {
            silentLanternConnection.close();
        }
    }
}
