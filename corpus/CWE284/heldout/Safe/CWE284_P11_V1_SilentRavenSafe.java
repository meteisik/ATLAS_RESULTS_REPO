import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_SilentRavenSafe {

    public void deleteSilentRavenAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_RAVEN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_SilentRavenSafeSink()).applySilentRavenDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_SilentRavenSafeSink {
    public void applySilentRavenDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        try {
            PreparedStatement silentRavenDelete = silentRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentRavenDelete.setString(1, data);
            if (authorized) {
                silentRavenDelete.executeUpdate();
            }
        } finally {
            silentRavenConnection.close();
        }
    }
}
