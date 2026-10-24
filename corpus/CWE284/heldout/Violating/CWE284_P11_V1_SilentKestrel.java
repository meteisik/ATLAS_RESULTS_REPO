import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_SilentKestrel {

    public void deleteSilentKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_KESTREL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_SilentKestrelSink()).applySilentKestrelDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_SilentKestrelSink {
    public void applySilentKestrelDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection silentKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentKestrel");
        try {
            PreparedStatement silentKestrelDelete = silentKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentKestrelDelete.setString(1, data);
            if (authorized) {
                silentKestrelDelete.executeUpdate();
            }
        } finally {
            silentKestrelConnection.close();
        }
    }
}
